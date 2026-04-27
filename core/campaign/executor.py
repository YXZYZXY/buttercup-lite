from __future__ import annotations

import json
import logging
import shutil
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from apps.workers.binary_seed.main import process_task as process_binary_seed_task
from apps.workers.binary_execution.main import process_task as process_binary_execution_task
from apps.workers.fuzzer.main import process_task as process_fuzzer_task
from apps.workers.reproducer.main import process_task as process_reproducer_task
from apps.workers.seed.main import process_task as process_seed_task
from apps.workers.tracer.main import process_task as process_tracer_task
from core.campaign.coverage_feedback import analyze_coverage_feedback
from core.campaign.coverage_feedback import consume_coverage_feedback_for_scheduler
from core.campaign.coverage_feedback import record_reseeding_feedback
from core.campaign.models import CampaignRound
from core.campaign.session_state import finalize_continuous_session_workspace
from core.campaign.session_state import prepare_continuous_session_workspace
from core.campaign.runtime_state import prepare_session_round_task
from core.models.task import TaskSource, TaskSpec, TaskStatus
from core.queues.redis_queue import QueueNames
from core.seed.harness_selector import select_harness, select_harness_by_name
from core.seed.llm_client import LLMCallError
from core.state.task_state import TaskRecord, TaskStateStore
from core.storage.layout import create_task_layout, execution_plan_path
from core.utils.settings import resolve_int_setting, settings

logger = logging.getLogger(__name__)

_TRANSIENT_SEED_ERROR_MARKERS = (
    "timed out",
    "timeout",
    "connection reset",
    "connectionreseterror",
    "network error",
    "transport error",
    "http error status=429",
    "http error status=500",
    "http error status=502",
    "http error status=503",
    "http error status=504",
)
_TASK_ROOT_MARKER = "/data/tasks/"


class InMemoryQueue:
    def __init__(self) -> None:
        self._queues: dict[str, list[str]] = {}

    def push(self, queue_name: str, payload: str) -> int:
        items = self._queues.setdefault(queue_name, [])
        items.append(payload)
        return len(items)

    def pop(self, queue_name: str, timeout: int = 0) -> str | None:
        _ = timeout
        items = self._queues.get(queue_name, [])
        if not items:
            return None
        return items.pop(0)

    def ack(self, queue_name: str, payload: str) -> None:
        _ = (queue_name, payload)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _replace_task_paths(value: Any, donor_root: Path, round_root: Path, donor_task_id: str, round_task_id: str) -> Any:
    if isinstance(value, dict):
        return {
            key: _replace_task_paths(item, donor_root, round_root, donor_task_id, round_task_id)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_replace_task_paths(item, donor_root, round_root, donor_task_id, round_task_id) for item in value]
    if isinstance(value, str):
        updated = value.replace(str(donor_root), str(round_root))
        updated = updated.replace(f"/data/tasks/{donor_task_id}", str(round_root))
        if _TASK_ROOT_MARKER in updated:
            _, suffix = updated.split(_TASK_ROOT_MARKER, 1)
            parts = suffix.split("/", 1)
            if len(parts) == 1:
                updated = str(round_root)
            else:
                updated = str(round_root / parts[1])
        return updated
    return value


def _normalize_round_task_payloads(round_root: Path, round_task_id: str) -> None:
    for json_path in [
        round_root / "build" / "build_registry.json",
        round_root / "build" / "harnesses.json",
        round_root / "index" / "manifest.json",
        round_root / "seed" / "seed_manifest.json",
    ]:
        if not json_path.exists():
            continue
        payload = _replace_task_paths(
            _load_json(json_path),
            round_root,
            round_root,
            round_task_id,
            round_task_id,
        )
        if json_path.name == "build_registry.json" and isinstance(payload, dict):
            payload["task_id"] = round_task_id
        _write_json(json_path, payload)


def _resolve_round_source_harness(
    *,
    round_root: Path,
    project: str | None,
    requested_name: str | None,
):
    build_registry_path = round_root / "build" / "build_registry.json"
    if not build_registry_path.exists():
        return None
    candidate = None
    requested = str(requested_name or "").strip()
    if requested:
        candidate = select_harness_by_name(build_registry_path, requested, project)
    if candidate is None:
        try:
            candidate = select_harness(build_registry_path, project)
        except RuntimeError:
            return None
    return candidate


def _count_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for candidate in path.rglob("*") if candidate.is_file())


def _load_optional_json(path_str: str | None) -> dict[str, Any]:
    if not path_str:
        return {}
    path = Path(path_str)
    if not path.exists():
        return {}
    try:
        return _load_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _normalize_reseed_target_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for item in value:
        name = str(item.get("name") or "").strip() if isinstance(item, dict) else str(item or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def _extract_coverage_queue_targets(task, *, limit: int = 8) -> list[dict[str, Any]]:
    request_plan = dict(task.runtime.get("campaign_coverage_request_plan") or {})
    raw_targets = list(request_plan.get("target_entries") or task.runtime.get("campaign_coverage_selected_entries") or [])
    consumption_path = str(task.runtime.get("campaign_coverage_queue_consumption_path") or "").strip()
    if not raw_targets and consumption_path and Path(consumption_path).exists():
        payload = _load_json(Path(consumption_path))
        raw_targets = list(payload.get("selected_target_functions") or payload.get("selected_entries") or [])
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_targets:
        if isinstance(item, dict):
            target_type = str(item.get("target_type") or "function").strip() or "function"
            if target_type != "function":
                continue
            name = str(item.get("name") or "").strip()
            payload = {
                "name": name,
                "coverage_fraction": item.get("coverage_fraction"),
                "total_lines": int(item.get("total_lines", 0) or 0),
                "covered_lines": int(item.get("covered_lines", 0) or 0),
                "function_paths": list(item.get("function_paths") or []),
                "queue_kind": item.get("queue_kind"),
                "priority": int(item.get("priority", 0) or 0),
                "reason": item.get("reason"),
                "source_level": item.get("source_level"),
                "degraded_reason": item.get("degraded_reason"),
            }
        else:
            name = str(item or "").strip()
            payload = {"name": name}
        if not name or name in seen:
            continue
        seen.add(name)
        selected.append(payload)
        if len(selected) >= limit:
            break
    return selected


def _coverage_target_queue_counts(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in entries:
        queue_kind = str(item.get("queue_kind") or "coverage_gap").strip() or "coverage_gap"
        counts[queue_kind] = counts.get(queue_kind, 0) + 1
    return counts


def _extract_uncovered_functions_from_summary(path: Path, *, limit: int = 8) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = _load_json(path)
    rows = payload.get("per_function_summary") or []
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in rows:
        name = str(item.get("name") or item.get("function_name") or "").strip()
        if not name or name in seen or int(item.get("total_lines", 0) or 0) <= 0:
            continue
        covered_lines = int(item.get("covered_lines", 0) or 0)
        if covered_lines > 0:
            continue
        seen.add(name)
        selected.append(
            {
                "name": name,
                "covered_lines": covered_lines,
                "total_lines": int(item.get("total_lines", 0) or 0),
                "coverage_fraction": float(item.get("coverage_fraction", 0.0) or 0.0),
                "function_paths": list(item.get("function_paths") or []),
            },
        )
    selected.sort(key=lambda item: (-int(item.get("total_lines") or 0), str(item.get("name") or "")))
    return selected[:limit]


def _copy_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore_dangling_symlinks=True)


def _copy_file(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _task_root_for_record(task_id: str, task_store: TaskStateStore) -> Path:
    record = task_store.load_task(task_id)
    candidate = Path(record.task_dir)
    if candidate.exists():
        return candidate
    return Path(settings.data_root) / task_id


def _classify_seed_exception(exc: Exception) -> tuple[str, bool]:
    if isinstance(exc, LLMCallError):
        message = exc.metadata.llm_failure_reason or str(exc)
    else:
        message = str(exc)
    normalized = message.lower()
    retriable = any(marker in normalized for marker in _TRANSIENT_SEED_ERROR_MARKERS)
    return message, retriable


def _record_round_failure(
    *,
    task_id: str,
    task_store: TaskStateStore,
    status: TaskStatus,
    stage: str,
    reason: str,
    exception_type: str,
    attempt: int | None = None,
    retriable: bool | None = None,
) -> None:
    runtime_patch: dict[str, Any] = {
        "campaign_round_failure_stage": stage,
        "campaign_round_failure_reason": reason,
        "campaign_round_failure_exception_type": exception_type,
        "campaign_round_failure_at": task_store.now(),
    }
    if attempt is not None:
        runtime_patch["campaign_round_failure_attempt"] = attempt
    if retriable is not None:
        runtime_patch["campaign_round_failure_retriable"] = retriable
    task_store.update_status(task_id, status, runtime_patch=runtime_patch)


def _write_round_execution_plan(task_id: str, *, target_mode: str) -> Path:
    if target_mode == "binary":
        plan = {
            "task_id": task_id,
            "adapter_resolution": "binary",
            "execution_mode": "hybrid",
            "target_mode": "binary",
            "target_priority": "normal",
            "target_weight": 1.0,
            "workers_to_run": ["binary-seed-worker", "binary-execution-worker", "tracer-worker", "reproducer-worker"],
            "stages": {
                "binary_seed": {
                    "mode": "hybrid",
                    "execute": True,
                    "queue": QueueNames.BINARY_SEED,
                    "task_mode_default": "SEED_INIT",
                    "budget_multiplier": 1.0,
                    "priority": "normal",
                },
                "binary_execution": {"mode": "hybrid", "execute": True, "queue": QueueNames.BINARY_EXECUTION},
                "trace": {"mode": "hybrid", "execute": True, "queue": QueueNames.TRACE},
                "repro": {"mode": "hybrid", "execute": True, "queue": QueueNames.REPRO},
                "patch": {"mode": "reserved", "execute": False},
            },
        }
    else:
        plan = {
            "task_id": task_id,
            "adapter_resolution": "ossfuzz",
            "execution_mode": "hybrid",
            "target_mode": "source",
            "target_priority": "normal",
            "target_weight": 1.0,
            "workers_to_run": ["seed-worker", "fuzzer-worker", "tracer-worker", "reproducer-worker"],
            "stages": {
                "seed": {
                    "mode": "hybrid",
                    "execute": True,
                    "queue": QueueNames.SEED,
                    "task_mode_default": "SEED_INIT",
                    "budget_multiplier": 1.0,
                    "priority": "normal",
                },
                "fuzz": {"mode": "hybrid", "execute": True, "queue": QueueNames.FUZZ},
                "trace": {"mode": "hybrid", "execute": True, "queue": QueueNames.TRACE},
                "repro": {"mode": "hybrid", "execute": True, "queue": QueueNames.REPRO},
                "patch": {"mode": "reserved", "execute": False},
            },
        }
    plan_path = execution_plan_path(task_id)
    _write_json(plan_path, plan)
    return plan_path


def _prepare_task_record(
    *,
    donor_task_id: str,
    round_task_id: str,
    round_root: Path,
    task_store: TaskStateStore,
    spec: TaskSpec,
    initial_status: TaskStatus,
    metadata_patch: dict[str, Any],
    runtime_patch: dict[str, Any],
) -> None:
    layout = create_task_layout(round_task_id)
    task_store.update_task(
        round_task_id,
        status=initial_status,
        execution_mode=spec.execution_mode,
        layout=layout,
        metadata=metadata_patch,
        runtime=runtime_patch,
    )


def _campaign_round_metadata_overrides(campaign_task: TaskRecord | None) -> dict[str, Any]:
    if campaign_task is None:
        return {}
    overrides: dict[str, Any] = {}
    for key in ("ENABLE_PATCH_ATTEMPT", "PATCH_DISABLED", "slot_controller_patch_policy_source"):
        if key in campaign_task.metadata:
            overrides[key] = deepcopy(campaign_task.metadata.get(key))
    return overrides


def _prepare_source_round_task(
    *,
    base_task_id: str,
    donor_task_id: str,
    round_number: int,
    task_store: TaskStateStore,
    duration_seconds: int,
    campaign_task_id: str | None = None,
    reusable_task_id: str | None = None,
) -> str:
    base_task = task_store.load_task(base_task_id)
    campaign_task = task_store.load_task(campaign_task_id) if campaign_task_id else None
    campaign_metadata_overrides = _campaign_round_metadata_overrides(campaign_task)
    if reusable_task_id:
        donor_task = task_store.load_task(reusable_task_id)
        round_root = _task_root_for_record(reusable_task_id, task_store)
        round_task_id = reusable_task_id
        spec = TaskSpec(
            source=TaskSource.model_validate(base_task.source.model_dump()),
            execution_mode=base_task.execution_mode,
            metadata={
                **deepcopy(base_task.metadata),
                **campaign_metadata_overrides,
            },
        )
    else:
        donor_task = task_store.load_task(donor_task_id)
        donor_root = _task_root_for_record(donor_task_id, task_store)
        spec = TaskSpec(
            source=TaskSource.model_validate(base_task.source.model_dump()),
            execution_mode=base_task.execution_mode,
            metadata={
                **deepcopy(base_task.metadata),
                **campaign_metadata_overrides,
            },
        )
        record = task_store.create_task(spec, status=TaskStatus.SEEDED)
        round_root = Path(record.task_dir)
        round_task_id = record.task_id

        _copy_tree(donor_root / "build" / "out", round_root / "build" / "out")
        _copy_tree(donor_root / "build" / "coverage_out", round_root / "build" / "coverage_out")
        _copy_tree(donor_root / "build" / "logs", round_root / "build" / "logs")
        _copy_file(donor_root / "build" / "build_registry.json", round_root / "build" / "build_registry.json")
        _copy_file(donor_root / "build" / "harnesses.json", round_root / "build" / "harnesses.json")
        _copy_tree(donor_root / "index", round_root / "index")
        _copy_tree(donor_root / "seed", round_root / "seed")
        _copy_tree(donor_root / "src", round_root / "src")
        # Do not pre-populate round-local corpus from the donor task. The round corpus
        # must be staged from campaign/system shared pools so shared-corpus flow stays
        # observable and actually drives the next session's input set.
        _copy_tree(donor_root / "coverage" / "snapshots", round_root / "coverage" / "snapshots")

        for json_path in [
            round_root / "build" / "build_registry.json",
            round_root / "index" / "manifest.json",
            round_root / "seed" / "seed_manifest.json",
        ]:
            if json_path.exists():
                payload = _replace_task_paths(
                    _load_json(json_path),
                    donor_root,
                    round_root,
                    donor_task_id,
                    round_task_id,
                )
                _write_json(json_path, payload)

    _normalize_round_task_payloads(round_root, round_task_id)
    seed_manifest_path = round_root / "seed" / "seed_manifest.json"
    seed_manifest = _load_optional_json(str(seed_manifest_path))
    selected_harness_name = (
        str(seed_manifest.get("selected_harness") or "").strip()
        or str(donor_task.runtime.get("selected_harness") or donor_task.runtime.get("active_harness") or "").strip()
        or None
    )
    selected_harness_path = seed_manifest.get("selected_harness_path")
    harness_source_path = seed_manifest.get("harness_source_path")
    resolved_harness = _resolve_round_source_harness(
        round_root=round_root,
        project=base_task.metadata.get("project"),
        requested_name=selected_harness_name,
    )
    if resolved_harness is not None:
        selected_harness_name = resolved_harness.name
        selected_harness_path = str(resolved_harness.executable_path)
        if resolved_harness.source_path:
            harness_source_path = str(resolved_harness.source_path)
        if seed_manifest_path.exists():
            seed_manifest["selected_harness"] = selected_harness_name
            seed_manifest["selected_harness_path"] = selected_harness_path
            seed_manifest["harness_source_path"] = harness_source_path
            _write_json(seed_manifest_path, seed_manifest)
    runtime_patch = {
        "adapter_resolution": "ossfuzz",
        "build_registry_path": str(round_root / "build" / "build_registry.json"),
        "index_manifest_path": str(round_root / "index" / "manifest.json"),
        "build_status": donor_task.runtime.get("build_status") or TaskStatus.BUILT.value,
        "seed_manifest_path": str(round_root / "seed" / "seed_manifest.json"),
        "seed_task_mode": "SEED_INIT",
        "seed_task_mode_default": "SEED_INIT",
        "seed_generation_backend": str(spec.metadata.get("SEED_GENERATION_BACKEND", "auto")),
        "active_harness": selected_harness_name,
        "active_harness_path": selected_harness_path,
        "selected_harness": selected_harness_name,
        "selected_harness_path": selected_harness_path,
        "selected_target": selected_harness_name,
        "harness_source_path": harness_source_path,
        "active_harness_launcher_path": "/home/buttercup2/Project/buttercup-lite/scripts/glibc239_binary_launcher.sh",
        "crash_source_policy": "live_raw_only",
        "target_mode": "source",
        "coverage_last_snapshot_path": (
            str(round_root / "coverage" / "snapshots" / Path(donor_task.runtime.get("coverage_last_snapshot_path", "")).name)
            if donor_task.runtime.get("coverage_last_snapshot_path")
            else None
        ),
    }
    for key in ("campaign_last_reseed_round", "campaign_last_reseed_at", "campaign_reseed_cooldown_rounds"):
        if donor_task.runtime.get(key) is not None:
            runtime_patch[key] = deepcopy(donor_task.runtime.get(key))
    if round_number > 1:
        if donor_task.runtime.get("coverage_feedback_manifest_path"):
            runtime_patch["coverage_feedback_manifest_path"] = donor_task.runtime.get("coverage_feedback_manifest_path")
        if donor_task.runtime.get("scheduler_feedback_consumption_path"):
            runtime_patch["scheduler_feedback_consumption_path"] = donor_task.runtime.get("scheduler_feedback_consumption_path")
        if donor_task.runtime.get("seed_task_mode"):
            runtime_patch["seed_task_mode_default"] = donor_task.runtime.get("seed_task_mode")
    metadata_patch = {
        **campaign_metadata_overrides,
        "campaign_parent_task_id": base_task_id,
        "base_task_id": base_task_id,
        "campaign_round": round_number,
        "FUZZ_MAX_TOTAL_TIME_SECONDS": duration_seconds,
        "FUZZ_TIMEOUT_SECONDS": max(10, min(duration_seconds, 10)),
        "FUZZ_LAUNCHER_PATH": "/home/buttercup2/Project/buttercup-lite/scripts/glibc239_binary_launcher.sh",
        "existing_launcher_path": "/home/buttercup2/Project/buttercup-lite/scripts/glibc239_binary_launcher.sh",
    }
    if reusable_task_id:
        task_store.update_task(
            round_task_id,
            status=TaskStatus.SEEDED,
            execution_mode=spec.execution_mode,
            metadata=metadata_patch,
            runtime=runtime_patch,
        )
    else:
        _prepare_task_record(
            donor_task_id=donor_task_id,
            round_task_id=round_task_id,
            round_root=round_root,
            task_store=task_store,
            spec=spec,
            initial_status=TaskStatus.SEEDED,
            metadata_patch=metadata_patch,
            runtime_patch=runtime_patch,
        )
    task_store.update_runtime(
        round_task_id,
        {
            "execution_plan_path": str(_write_round_execution_plan(round_task_id, target_mode="source")),
        },
    )
    return round_task_id


def _prepare_binary_round_task(
    *,
    base_task_id: str,
    donor_task_id: str,
    round_number: int,
    task_store: TaskStateStore,
) -> str:
    base_task = task_store.load_task(base_task_id)
    donor_task = task_store.load_task(donor_task_id)
    donor_root = _task_root_for_record(donor_task_id, task_store)
    spec = TaskSpec(
        source=TaskSource.model_validate(base_task.source.model_dump()),
        execution_mode=base_task.execution_mode,
        metadata=deepcopy(base_task.metadata),
    )
    record = task_store.create_task(spec, status=TaskStatus.BINARY_ANALYZED)
    round_root = Path(record.task_dir)

    _copy_tree(donor_root / "imports", round_root / "imports")
    _copy_tree(donor_root / "binary", round_root / "binary")
    _copy_tree(donor_root / "binary_slice", round_root / "binary_slice")
    _copy_tree(donor_root / "binary_seed" / "generated", round_root / "imports" / "seeds" / "current")
    _copy_tree(donor_root / "corpus" / "binary_active", round_root / "imports" / "corpus" / "current")
    _copy_tree(donor_root / "crashes" / "binary_candidates", round_root / "imports" / "crashes" / "raw" / "current")
    _copy_tree(donor_root / "coverage" / "snapshots", round_root / "coverage" / "snapshots")

    manifest_paths = [
        donor_root / "runtime" / "binary_analysis_manifest.json",
    ]
    for src in manifest_paths:
        if src.exists():
            payload = _replace_task_paths(
                _load_json(src),
                donor_root,
                round_root,
                donor_task_id,
                record.task_id,
            )
            target = round_root / "runtime" / src.name
            _write_json(target, payload)

    resolved_imports = deepcopy(donor_task.runtime.get("resolved_imports", {}))
    resolved_imports.update(
        {
            "existing_binary_path": str(round_root / "imports" / "binaries" / "current"),
            "existing_harness_dir": str(round_root / "imports" / "harnesses" / "current"),
            "existing_seed_path": str(round_root / "imports" / "seeds" / "current"),
            "existing_corpus_path": str(round_root / "imports" / "corpus" / "current"),
            "existing_crashes_path": str(round_root / "imports" / "crashes" / "raw" / "current"),
            "existing_binary_analysis_path": str(round_root / "binary"),
        },
    )
    runtime_patch = {
        "adapter_resolution": "binary",
        "binary_analysis_backend": donor_task.runtime.get("binary_analysis_backend", "ida_mcp"),
        "binary_analysis_manifest_path": str(round_root / "runtime" / "binary_analysis_manifest.json"),
        "binary_execution_status": "PENDING",
        "binary_slice_manifest_path": (
            str(round_root / "binary_slice" / "slice_manifest.json")
            if (round_root / "binary_slice" / "slice_manifest.json").exists()
            else donor_task.runtime.get("binary_slice_manifest_path")
        ),
        "seed_task_mode": "SEED_INIT",
        "seed_task_mode_default": "SEED_INIT",
        "selected_target": donor_task.metadata.get("binary_target_name") or donor_task.runtime.get("active_harness"),
        "selected_binary_slice_focus": donor_task.runtime.get("selected_binary_slice_focus"),
        "seed_generation_backend": str(spec.metadata.get("SEED_GENERATION_BACKEND", "auto")),
        "resolved_imports": resolved_imports,
        "target_mode": "binary",
        "binary_provenance": donor_task.runtime.get("binary_provenance", "source_derived_binary"),
        "binary_origin_task_id": donor_task.runtime.get("binary_origin_task_id"),
        "launcher_semantics_source": donor_task.runtime.get("launcher_semantics_source"),
        "seed_provenance": donor_task.runtime.get("seed_provenance"),
        "corpus_provenance": donor_task.runtime.get("corpus_provenance"),
        "crash_source_policy": "live_raw_only",
        "coverage_last_snapshot_path": (
            str(round_root / "coverage" / "snapshots" / Path(donor_task.runtime.get("coverage_last_snapshot_path", "")).name)
            if donor_task.runtime.get("coverage_last_snapshot_path")
            else None
        ),
    }
    for key in ("campaign_last_reseed_round", "campaign_last_reseed_at", "campaign_reseed_cooldown_rounds"):
        if donor_task.runtime.get(key) is not None:
            runtime_patch[key] = deepcopy(donor_task.runtime.get(key))
    if round_number > 1:
        if donor_task.runtime.get("coverage_feedback_manifest_path"):
            runtime_patch["coverage_feedback_manifest_path"] = donor_task.runtime.get("coverage_feedback_manifest_path")
        if donor_task.runtime.get("scheduler_feedback_consumption_path"):
            runtime_patch["scheduler_feedback_consumption_path"] = donor_task.runtime.get("scheduler_feedback_consumption_path")
        if donor_task.runtime.get("seed_task_mode"):
            runtime_patch["seed_task_mode_default"] = donor_task.runtime.get("seed_task_mode")
    metadata_patch = {
        "campaign_parent_task_id": base_task_id,
        "base_task_id": base_task_id,
        "campaign_round": round_number,
        "binary_mode": base_task.metadata.get("binary_mode", donor_task.runtime.get("binary_mode", "binary_native_proof")),
        "binary_provenance": base_task.metadata.get(
            "binary_provenance",
            donor_task.runtime.get("binary_provenance", "source_derived_binary"),
        ),
        "binary_input_contract": base_task.metadata.get(
            "binary_input_contract",
            donor_task.runtime.get("binary_input_contract", "file"),
        ),
        "binary_input_contract_source": base_task.metadata.get(
            "binary_input_contract_source",
            donor_task.runtime.get("binary_input_contract_source", "campaign_reuse"),
        ),
        "existing_seed_provenance": "binary_native_generated",
        "existing_corpus_provenance": "binary_native_generated",
    }
    _prepare_task_record(
        donor_task_id=donor_task_id,
        round_task_id=record.task_id,
        round_root=round_root,
        task_store=task_store,
        spec=spec,
        initial_status=TaskStatus.BINARY_ANALYZED,
        metadata_patch=metadata_patch,
        runtime_patch=runtime_patch,
    )
    task_store.update_runtime(
        record.task_id,
        {
            "execution_plan_path": str(_write_round_execution_plan(record.task_id, target_mode="binary")),
            "binary_execution_plan_path": str(round_root / "runtime" / "binary_execution_plan.json"),
        },
    )
    donor_plan_path = donor_task.runtime.get("binary_execution_plan_path")
    copied_plan_path = round_root / "runtime" / "binary_execution_plan.json"
    if donor_plan_path and Path(donor_plan_path).exists():
        payload = _replace_task_paths(
            _load_json(Path(donor_plan_path)),
            donor_root,
            round_root,
            donor_task_id,
            record.task_id,
        )
        payload["task_id"] = record.task_id
        _write_json(copied_plan_path, payload)
    return record.task_id


def _apply_round_scheduler_arbitration(task_id: str, task_store: TaskStateStore) -> TaskRecord:
    task = task_store.load_task(task_id)
    plan_path = execution_plan_path(task_id)
    plan = _load_json(plan_path)
    updated_plan, consumption = consume_coverage_feedback_for_scheduler(
        task=task,
        plan=plan,
        now=task_store.now(),
    )
    _write_json(plan_path, updated_plan)
    runtime_patch = {
        "execution_plan_path": str(plan_path),
        "selected_target": updated_plan.get("selected_target"),
        "selected_binary_slice_focus": updated_plan.get("selected_binary_slice_focus"),
        "target_priority": updated_plan.get("target_priority"),
        "target_weight": updated_plan.get("target_weight"),
        "seed_task_mode_default": (
            updated_plan.get("stages", {}).get("seed", {}).get("task_mode_default")
            or updated_plan.get("stages", {}).get("binary_seed", {}).get("task_mode_default")
            or task.runtime.get("seed_task_mode_default")
        ),
    }
    if consumption:
        runtime_patch["scheduler_feedback_consumption_path"] = consumption["scheduler_feedback_consumption_path"]
    task_store.update_runtime(task_id, runtime_patch)
    return task_store.load_task(task_id)


def _run_round_seed_phase(task_id: str, task_store: TaskStateStore, target_mode: str) -> InMemoryQueue | None:
    max_attempts = 1 if target_mode == "binary" else 3
    for attempt in range(1, max_attempts + 1):
        queue = InMemoryQueue()
        try:
            task_store.update_runtime(
                task_id,
                {
                    "campaign_round_seed_attempt": attempt,
                    "campaign_round_seed_attempts_max": max_attempts,
                },
            )
            if target_mode == "binary":
                process_binary_seed_task(task_id, task_store, queue)
            else:
                process_seed_task(task_id, task_store, queue)
            task_store.update_runtime(
                task_id,
                {
                    "campaign_round_seed_attempts_used": attempt,
                    "campaign_round_seed_retry_count": max(0, attempt - 1),
                    "campaign_round_failure_stage": None,
                    "campaign_round_failure_reason": None,
                },
            )
            return queue
        except Exception as exc:
            reason, retriable = _classify_seed_exception(exc)
            if target_mode != "binary" and retriable and attempt < max_attempts:
                logger.warning(
                    "[%s] round seed attempt %s/%s failed with retriable error: %s",
                    task_id,
                    attempt,
                    max_attempts,
                    reason,
                )
                task_store.update_runtime(
                    task_id,
                    {
                        "campaign_round_seed_attempts_used": attempt,
                        "campaign_round_seed_retry_count": attempt,
                        "campaign_round_failure_stage": "seed_retry_pending",
                        "campaign_round_failure_reason": reason,
                        "campaign_round_failure_exception_type": exc.__class__.__name__,
                        "campaign_round_failure_retriable": True,
                    },
                )
                time.sleep(min(5 * attempt, 15))
                continue
            failure_status = TaskStatus.BINARY_SEED_FAILED if target_mode == "binary" else TaskStatus.SEED_FAILED
            logger.warning(
                "[%s] round seed failed after %s/%s attempts: %s",
                task_id,
                attempt,
                max_attempts,
                reason,
            )
            _record_round_failure(
                task_id=task_id,
                task_store=task_store,
                status=failure_status,
                stage="binary_seed" if target_mode == "binary" else "seed",
                reason=reason,
                exception_type=exc.__class__.__name__,
                attempt=attempt,
                retriable=retriable,
            )
            return None
    return None


def _drain_round_pipeline(task_id: str, task_store: TaskStateStore, target_mode: str, queue: InMemoryQueue | None = None) -> bool:
    queue = queue or InMemoryQueue()
    if target_mode == "binary":
        try:
            queued_execution = queue.pop(QueueNames.BINARY_EXECUTION, timeout=0)
            if queued_execution == task_id:
                process_binary_execution_task(task_id, task_store, queue)
            else:
                process_binary_execution_task(task_id, task_store, queue)
        except Exception as exc:
            _record_round_failure(
                task_id=task_id,
                task_store=task_store,
                status=TaskStatus.BINARY_EXECUTION_FAILED,
                stage="binary_execution",
                reason=str(exc),
                exception_type=exc.__class__.__name__,
            )
            logger.exception("[%s] binary execution stage failed", task_id)
            return False
    else:
        try:
            queued_fuzz = queue.pop(QueueNames.FUZZ, timeout=0)
            if queued_fuzz == task_id:
                process_fuzzer_task(task_id, task_store, queue)
            else:
                process_fuzzer_task(task_id, task_store, queue)
        except Exception as exc:
            _record_round_failure(
                task_id=task_id,
                task_store=task_store,
                status=TaskStatus.FUZZ_FAILED,
                stage="fuzz",
                reason=str(exc),
                exception_type=exc.__class__.__name__,
            )
            logger.exception("[%s] fuzz stage failed", task_id)
            return False
    queued_trace = queue.pop(QueueNames.TRACE, timeout=0)
    if queued_trace == task_id:
        try:
            process_tracer_task(task_id, task_store, queue)
        except Exception as exc:
            _record_round_failure(
                task_id=task_id,
                task_store=task_store,
                status=TaskStatus.TRACE_FAILED,
                stage="trace",
                reason=str(exc),
                exception_type=exc.__class__.__name__,
            )
            logger.exception("[%s] trace stage failed", task_id)
            return False
    queued_repro = queue.pop(QueueNames.REPRO, timeout=0)
    if queued_repro == task_id:
        try:
            process_reproducer_task(task_id, task_store, queue)
        except Exception as exc:
            _record_round_failure(
                task_id=task_id,
                task_store=task_store,
                status=TaskStatus.REPRO_FAILED,
                stage="repro",
                reason=str(exc),
                exception_type=exc.__class__.__name__,
            )
            logger.exception("[%s] repro stage failed", task_id)
            return False
    return True


def _run_round_reseed_phase(
    task_id: str,
    task_store: TaskStateStore,
    target_mode: str,
    feedback: dict[str, Any],
    *,
    round_number: int,
) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    cooldown_rounds = resolve_int_setting(
        task.metadata,
        "CAMPAIGN_RESEED_COOLDOWN_ROUNDS",
        settings.campaign_reseed_cooldown_rounds,
    )
    if target_mode == "binary":
        binary_manifest = _load_optional_json(
            task.runtime.get("binary_execution_manifest_path")
            or str(Path(task.task_dir) / "runtime" / "binary_execution_manifest.json"),
        )
        if int(binary_manifest.get("crash_candidate_count") or 0) > 0:
            reason = "binary execution already produced promoted candidates; reseed not needed"
            record_reseeding_feedback(
                task_id,
                task_store,
                attempted=False,
                triggered=False,
                target_functions=[],
                reason=reason,
            )
            task_store.update_runtime(
                task_id,
                {
                    "campaign_reseed_skip_reason": reason,
                    "campaign_reseed_cooldown_rounds": cooldown_rounds,
                },
            )
            return {"attempted": False, "triggered": False, "reason": reason}
        last_reseed_round = int(task.runtime.get("campaign_last_reseed_round") or 0)
        if last_reseed_round and round_number - last_reseed_round < cooldown_rounds:
            reason = (
                f"binary reseed cooldown active: round={round_number}, "
                f"last_reseed_round={last_reseed_round}, cooldown_rounds={cooldown_rounds}"
            )
            record_reseeding_feedback(
                task_id,
                task_store,
                attempted=False,
                triggered=False,
                target_functions=[],
                reason=reason,
            )
            task_store.update_runtime(
                task_id,
                {
                    "campaign_reseed_skip_reason": reason,
                    "campaign_reseed_cooldown_rounds": cooldown_rounds,
                },
            )
            logger.info("[%s] binary reseed skipped: %s", task_id, reason)
            return {"attempted": False, "triggered": False, "reason": reason}

        binary_feedback = _load_optional_json(
            task.runtime.get("binary_feedback_bridge_path")
            or str(Path(task.task_dir) / "runtime" / "binary_feedback_bridge.json"),
        )
        binary_ida_view = _load_optional_json(
            task.runtime.get("binary_ida_runtime_view_path")
            or str(Path(task.task_dir) / "runtime" / "binary_ida_runtime_view.json"),
        )
        signal_counts = dict(binary_manifest.get("signal_category_counts") or {})
        signal_examples = list(binary_manifest.get("per_input_execution_summary") or [])[:5]
        reseed_targets = [
            str(item.get("name") or "").strip()
            for item in (binary_feedback.get("recommended_reseed_targets") or [])
            if isinstance(item, dict) and str(item.get("name") or "").strip()
        ]
        if not reseed_targets:
            for item in (binary_ida_view.get("focus_candidates") or []):
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                if name and name not in reseed_targets:
                    reseed_targets.append(name)
                if len(reseed_targets) >= 4:
                    break
        feedback_state = str(binary_feedback.get("feedback_state") or "").strip() or "binary_signal_stalled"
        if not bool(binary_feedback.get("needs_reseed", True)) and not reseed_targets:
            reason = f"binary feedback state={feedback_state} did not request reseed"
            record_reseeding_feedback(
                task_id,
                task_store,
                attempted=False,
                triggered=False,
                target_functions=[],
                reason=reason,
            )
            task_store.update_runtime(
                task_id,
                {
                    "campaign_reseed_skip_reason": reason,
                    "campaign_reseed_cooldown_rounds": cooldown_rounds,
                },
            )
            logger.info("[%s] binary reseed skipped: %s", task_id, reason)
            return {"attempted": False, "triggered": False, "reason": reason}
        focus = (
            reseed_targets[0]
            if reseed_targets
            else str(
                task.runtime.get("selected_binary_slice_focus")
                or task.runtime.get("selected_target_function")
                or task.runtime.get("selected_target")
                or task.metadata.get("binary_target_name")
                or ""
            ).strip()
        )
        reason = (
            f"binary feedback requested reseed state={feedback_state} "
            f"target={focus or 'binary_target'} signals={signal_counts}"
        )
        previous_status = task.status
        previous_active_corpus_count = _count_files(Path(task.layout.get("corpus_binary_active", Path(task.task_dir) / "corpus" / "binary_active")))
        task_store.update_runtime(
            task_id,
            {
                "seed_task_mode_override": "SEED_EXPLORE",
                "selected_binary_slice_focus": focus,
                "selected_target_function": focus or task.runtime.get("selected_target_function"),
                "selected_target_functions": reseed_targets[:3],
                "binary_reseed_signal_feedback": {
                    "reason": reason,
                    "feedback_state": feedback_state,
                    "signal_category_counts": signal_counts,
                    "top_examples": signal_examples,
                    "selected_binary_slice_focus": focus,
                    "binary_feedback_bridge_path": task.runtime.get("binary_feedback_bridge_path")
                    or str(Path(task.task_dir) / "runtime" / "binary_feedback_bridge.json"),
                    "binary_ida_runtime_view_path": task.runtime.get("binary_ida_runtime_view_path")
                    or str(Path(task.task_dir) / "runtime" / "binary_ida_runtime_view.json"),
                    "recommended_targets": reseed_targets[:6],
                    "requested_action": "contract_aware_binary_native_reseed",
                },
                "campaign_reseed_requested_at": task_store.now(),
                "campaign_reseed_reason": reason,
                "campaign_reseeding_attempted": True,
                "campaign_reseeding_triggered": False,
                "campaign_reseed_cooldown_rounds": cooldown_rounds,
            },
        )
        queue = InMemoryQueue()
        try:
            process_binary_seed_task(task_id, task_store, queue)
            if queue.pop(QueueNames.BINARY_EXECUTION, timeout=0) == task_id:
                process_binary_execution_task(task_id, task_store, queue)
            else:
                process_binary_execution_task(task_id, task_store, queue)
        except Exception as exc:
            error_reason = f"binary campaign reseed failed: {exc}"
            task_store.update_status(
                task_id,
                previous_status,
                runtime_patch={
                    "seed_task_mode_override": None,
                    "campaign_reseed_error": str(exc),
                    "campaign_reseeding_attempted": True,
                    "campaign_reseeding_triggered": False,
                    "campaign_reseed_skip_reason": error_reason,
                    "campaign_reseed_cooldown_rounds": cooldown_rounds,
                    "binary_reseed_failed": True,
                },
            )
            record_reseeding_feedback(
                task_id,
                task_store,
                attempted=True,
                triggered=False,
                target_functions=reseed_targets[:3] or ([focus] if focus else []),
                reason=error_reason,
            )
            logger.exception("[%s] binary campaign reseed failed", task_id)
            return {"attempted": True, "triggered": False, "reason": error_reason, "error": str(exc)}
        updated_task = task_store.load_task(task_id)
        active_corpus_count = _count_files(Path(updated_task.layout.get("corpus_binary_active", Path(updated_task.task_dir) / "corpus" / "binary_active")))
        generated_seed_count = int(updated_task.runtime.get("binary_seed_generated_count") or 0)
        task_store.update_runtime(
            task_id,
            {
                "seed_task_mode_override": None,
                "campaign_reseeding_attempted": True,
                "campaign_reseeding_triggered": True,
                "campaign_last_reseed_round": round_number,
                "campaign_last_reseed_at": task_store.now(),
                "campaign_reseed_target_functions": reseed_targets[:3] or ([focus] if focus else []),
                "campaign_reseed_generated_seed_count": generated_seed_count,
                "campaign_reseed_active_corpus_count": active_corpus_count,
                "campaign_reseed_active_corpus_delta": max(0, active_corpus_count - previous_active_corpus_count),
                "campaign_reseed_skip_reason": None,
                "campaign_reseed_cooldown_rounds": cooldown_rounds,
                "binary_reseed_triggered": True,
            },
        )
        record_reseeding_feedback(
            task_id,
            task_store,
            attempted=True,
            triggered=True,
            target_functions=reseed_targets[:3] or ([focus] if focus else []),
            reason=reason,
            generated_seed_count=generated_seed_count,
            active_corpus_count=active_corpus_count,
        )
        logger.info(
            "[%s] binary campaign reseed completed: generated=%s active_corpus=%s delta=%s",
            task_id,
            generated_seed_count,
            active_corpus_count,
            max(0, active_corpus_count - previous_active_corpus_count),
        )
        return {
            "attempted": True,
            "triggered": True,
            "reason": reason,
            "target_functions": reseed_targets[:3] or ([focus] if focus else []),
            "generated_seed_count": generated_seed_count,
            "active_corpus_count": active_corpus_count,
        }

    uncovered_functions = list(
        feedback.get("uncovered_functions")
        or task.runtime.get("coverage_feedback_uncovered_functions")
        or []
    )
    if not uncovered_functions:
        queue_targets = _extract_coverage_queue_targets(task)
        if queue_targets:
            queue_counts = _coverage_target_queue_counts(queue_targets)
            uncovered_functions = queue_targets
            task_store.update_runtime(
                task_id,
                {
                    "coverage_feedback_uncovered_functions": uncovered_functions,
                    "coverage_feedback_uncovered_function_count": len(uncovered_functions),
                    "coverage_feedback_reseed_target_entries": queue_targets,
                    "coverage_feedback_target_queue_kind_counts": queue_counts,
                    "coverage_feedback_primary_queue_kind": next(iter(queue_counts), None),
                    "campaign_reseed_coverage_fallback_path": str(
                        task.runtime.get("campaign_coverage_queue_consumption_path")
                        or task.runtime.get("campaign_coverage_queue_path")
                        or ""
                    ),
                },
            )
            record_reseeding_feedback(
                task_id,
                task_store,
                attempted=False,
                triggered=False,
                target_functions=uncovered_functions,
                reason="coverage guidance fell back to durable coverage queue",
            )
            task = task_store.load_task(task_id)
    if not uncovered_functions:
        base_task_id = str(
            task.metadata.get("base_task_id")
            or task.metadata.get("campaign_parent_task_id")
            or ""
        ).strip()
        if base_task_id:
            base_summary_path = Path(settings.data_root) / base_task_id / "coverage" / "coverage_summary_manifest.json"
            uncovered_functions = _extract_uncovered_functions_from_summary(base_summary_path)
            if uncovered_functions:
                queue_counts = _coverage_target_queue_counts(uncovered_functions)
                logger.info(
                    "[%s] reseed fallback: using base task coverage summary %s with %s uncovered targets",
                    task_id,
                    base_summary_path,
                    len(uncovered_functions),
                )
                task_store.update_runtime(
                    task_id,
                    {
                        "coverage_feedback_uncovered_functions": uncovered_functions,
                        "coverage_feedback_uncovered_function_count": len(uncovered_functions),
                        "coverage_feedback_reseed_target_entries": uncovered_functions,
                        "coverage_feedback_target_queue_kind_counts": queue_counts,
                        "coverage_feedback_primary_queue_kind": next(iter(queue_counts), None),
                        "campaign_reseed_coverage_fallback_path": str(base_summary_path),
                    },
                )
                record_reseeding_feedback(
                    task_id,
                    task_store,
                    attempted=False,
                    triggered=False,
                    target_functions=uncovered_functions,
                    reason=f"coverage guidance fell back to base task summary: {base_summary_path}",
                )
                task = task_store.load_task(task_id)
        if not uncovered_functions:
            reason = "coverage feedback did not provide uncovered functions for reseeding"
            record_reseeding_feedback(
                task_id,
                task_store,
                attempted=False,
                triggered=False,
                target_functions=[],
                reason=reason,
            )
            task_store.update_runtime(
                task_id,
                {
                    "campaign_reseed_skip_reason": reason,
                    "campaign_reseed_cooldown_rounds": cooldown_rounds,
                },
            )
            logger.info("[%s] reseed skipped: %s", task_id, reason)
            return {"attempted": False, "triggered": False, "reason": reason}

    last_reseed_round = int(task.runtime.get("campaign_last_reseed_round") or 0)
    if last_reseed_round and round_number - last_reseed_round < cooldown_rounds:
        reason = (
            f"reseed cooldown active: round={round_number}, last_reseed_round={last_reseed_round}, "
            f"cooldown_rounds={cooldown_rounds}"
        )
        record_reseeding_feedback(
            task_id,
            task_store,
            attempted=False,
            triggered=False,
            target_functions=uncovered_functions[:8],
            reason=reason,
        )
        task_store.update_runtime(
            task_id,
            {
                "campaign_reseed_skip_reason": reason,
                "campaign_reseed_cooldown_rounds": cooldown_rounds,
            },
        )
        logger.info("[%s] reseed skipped: %s", task_id, reason)
        return {"attempted": False, "triggered": False, "reason": reason}

    previous_status = task.status
    previous_seed_manifest_path = task.runtime.get("seed_manifest_path")
    previous_seed_task_manifest_path = task.runtime.get("seed_task_manifest_path")
    if previous_seed_manifest_path:
        _copy_file(Path(previous_seed_manifest_path), Path(task.task_dir) / "seed" / "seed_manifest.pre_reseed.json")
    if previous_seed_task_manifest_path:
        _copy_file(Path(previous_seed_task_manifest_path), Path(task.task_dir) / "seed" / "seed_task_manifest.pre_reseed.json")
    previous_active_corpus_count = _count_files(Path(task.layout.get("corpus_active", Path(task.task_dir) / "corpus" / "active")))
    target_functions = uncovered_functions[:8]
    target_names = _normalize_reseed_target_names(target_functions)
    target_queue_counts = _coverage_target_queue_counts(target_functions)
    dominant_queue_kind = next(iter(target_queue_counts), "coverage_gap")
    reason = (
        "coverage stalled in current round; append exploratory seeds targeting durable coverage gaps "
        f"(dominant_queue_kind={dominant_queue_kind}) "
        f"{', '.join(target_names[:5])}"
    )
    task_store.update_runtime(
        task_id,
        {
            "seed_task_mode_override": "SEED_EXPLORE",
            "uncovered_functions": target_functions,
            "campaign_reseed_target_functions": target_functions,
            "campaign_reseed_target_entries": target_functions,
            "coverage_feedback_reseed_target_entries": target_functions,
            "coverage_feedback_reseed_target_functions": target_functions,
            "coverage_feedback_target_queue_kind_counts": target_queue_counts,
            "coverage_feedback_primary_queue_kind": next(iter(target_queue_counts), None),
            "campaign_reseed_requested_at": task_store.now(),
            "campaign_reseed_reason": reason,
            "campaign_reseed_cooldown_rounds": cooldown_rounds,
            "campaign_reseeding_attempted": True,
            "campaign_reseeding_triggered": False,
        },
    )
    logger.info(
        "[%s] campaign reseed triggered in round %s with %s uncovered targets: %s",
        task_id,
        round_number,
        len(target_names),
        ", ".join(target_names[:5]) or "none",
    )
    queue = InMemoryQueue()
    try:
        process_seed_task(task_id, task_store, queue)
    except Exception as exc:
        error_reason = f"campaign reseed failed: {exc}"
        task_store.update_status(
            task_id,
            previous_status,
            runtime_patch={
                "seed_task_mode_override": None,
                "campaign_reseed_error": str(exc),
                "campaign_reseeding_attempted": True,
                "campaign_reseeding_triggered": False,
                "campaign_reseed_skip_reason": error_reason,
                "campaign_reseed_target_functions": target_functions,
                "campaign_reseed_cooldown_rounds": cooldown_rounds,
            },
        )
        record_reseeding_feedback(
            task_id,
            task_store,
            attempted=True,
            triggered=False,
            target_functions=target_functions,
            reason=error_reason,
        )
        logger.exception("[%s] campaign reseed failed", task_id)
        return {"attempted": True, "triggered": False, "reason": error_reason, "error": str(exc)}

    updated_task = task_store.load_task(task_id)
    active_corpus_count = _count_files(Path(updated_task.layout.get("corpus_active", Path(updated_task.task_dir) / "corpus" / "active")))
    generated_seed_count = int(updated_task.runtime.get("seed_generated_count") or 0)
    task_store.update_status(
        task_id,
        previous_status,
        runtime_patch={
            "seed_task_mode_override": None,
            "campaign_reseeding_attempted": True,
            "campaign_reseeding_triggered": True,
            "campaign_last_reseed_round": round_number,
            "campaign_last_reseed_at": task_store.now(),
            "campaign_reseed_target_functions": target_functions,
            "campaign_reseed_generated_seed_count": generated_seed_count,
            "campaign_reseed_active_corpus_count": active_corpus_count,
            "campaign_reseed_active_corpus_delta": max(0, active_corpus_count - previous_active_corpus_count),
            "campaign_reseed_skip_reason": None,
            "campaign_reseed_cooldown_rounds": cooldown_rounds,
        },
    )
    record_reseeding_feedback(
        task_id,
        task_store,
        attempted=True,
        triggered=True,
        target_functions=target_functions,
        reason=reason,
        generated_seed_count=generated_seed_count,
        active_corpus_count=active_corpus_count,
    )
    logger.info(
        "[%s] campaign reseed completed: generated=%s active_corpus=%s delta=%s",
        task_id,
        generated_seed_count,
        active_corpus_count,
        max(0, active_corpus_count - previous_active_corpus_count),
    )
    return {
        "attempted": True,
        "triggered": True,
        "reason": reason,
        "target_functions": target_names,
        "generated_seed_count": generated_seed_count,
        "active_corpus_count": active_corpus_count,
    }


def _round_duration_seconds(task: dict[str, Any]) -> float:
    runtime = task.get("runtime", {})
    started = runtime.get("binary_execution_started_at") or runtime.get("fuzz_started_at")
    completed = (
        runtime.get("repro_completed_at")
        or runtime.get("trace_completed_at")
        or runtime.get("binary_execution_completed_at")
        or runtime.get("fuzz_completed_at")
    )
    if not started or not completed:
        return 0.0
    return (
        datetime.fromisoformat(completed) - datetime.fromisoformat(started)
    ).total_seconds()


def _collect_trace_signatures(root: Path, trace_manifest: dict[str, Any]) -> list[str]:
    signatures: set[str] = set()
    trace_dir = root / "trace" / "traced_crashes"
    for traced_path in trace_dir.glob("*.json"):
        payload = _load_optional_json(str(traced_path))
        signature = str(payload.get("signature") or "").strip()
        if signature:
            signatures.add(signature)
    if not signatures:
        dedup_index = _load_optional_json(str(root / "trace" / "dedup_index.json"))
        if isinstance(dedup_index, dict):
            signatures.update(str(signature).strip() for signature in dedup_index if str(signature).strip())
    if not signatures:
        for item in trace_manifest.get("traced_crashes") or []:
            if not isinstance(item, dict):
                continue
            signature = str(item.get("signature") or "").strip()
            if signature:
                signatures.add(signature)
    return sorted(signatures)


def collect_round_stats(
    task_id: str,
    data_root: Path,
    cumulative_signatures: set[str],
    *,
    session_summary: dict[str, Any] | None = None,
) -> tuple[CampaignRound, set[str]]:
    root = data_root / task_id
    task = _load_json(root / "task.json")
    metadata = task.get("metadata", {})
    runtime = task.get("runtime", {})
    session_summary = dict(session_summary or {})
    target_mode = metadata.get("target_mode") or runtime.get("target_mode") or "source"
    is_binary_target = bool(metadata.get("binary_mode")) or target_mode == "binary"
    fuzz_manifest = _load_json(Path(runtime["fuzz_manifest_path"])) if runtime.get("fuzz_manifest_path") else {}
    binary_manifest = (
        _load_json(Path(runtime["binary_execution_manifest_path"]))
        if runtime.get("binary_execution_manifest_path")
        else {}
    )
    trace_manifest = _load_json(Path(runtime["trace_manifest_path"])) if runtime.get("trace_manifest_path") else {}
    coverage_feedback = _load_optional_json(runtime.get("coverage_feedback_manifest_path"))
    pov_dir = root / "pov" / "confirmed"
    pov_count = len(list(pov_dir.glob("*.json")))
    signatures = set(_collect_trace_signatures(root, trace_manifest))
    new_signatures = signatures - cumulative_signatures
    updated = cumulative_signatures | signatures
    crash_count = 0
    new_corpus_files = 0
    corpus_before = 0
    corpus_path = root / "corpus" / ("binary_active" if is_binary_target else "active")
    corpus_after = sum(1 for candidate in corpus_path.glob("*") if candidate.is_file()) if corpus_path.exists() else 0
    if is_binary_target:
        crash_count = int(binary_manifest.get("crash_candidate_count", 0))
        corpus_before = int(binary_manifest.get("input_count", 0))
    else:
        crash_count = len(fuzz_manifest.get("raw_crashes", []))
        fuzz_new_corpus = fuzz_manifest.get("new_corpus_files", 0)
        new_corpus_files = len(fuzz_new_corpus) if isinstance(fuzz_new_corpus, list) else int(fuzz_new_corpus)
        corpus_before = max(corpus_after - new_corpus_files, 0)
    round_record = CampaignRound(
        round=int(task["metadata"].get("campaign_round", 0)),
        origin_task_id=task_id,
        target_mode=target_mode,
        status=task["status"],
        pov_count=int(session_summary.get("confirmed_pov_count") or pov_count),
        traced_crash_count=int(session_summary.get("traced_crash_count") or len(trace_manifest.get("traced_crashes", []))),
        crash_count=crash_count,
        new_confirmed_pov_count=int(session_summary.get("confirmed_pov_count") or pov_count),
        new_raw_crash_count=crash_count,
        new_traced_crash_count=int(session_summary.get("traced_crash_count") or len(trace_manifest.get("traced_crashes", []))),
        corpus_count_before=corpus_before,
        corpus_count_after=corpus_after,
        new_corpus_files=new_corpus_files,
        new_signature_count=len(new_signatures),
        cumulative_distinct_signature_count=len(updated),
        traced_crash_signatures=sorted(signatures),
        duration_seconds=float(session_summary.get("duration_seconds") or _round_duration_seconds(task)),
        coverage_snapshot_path=runtime.get("coverage_last_snapshot_path"),
        coverage_feedback_manifest_path=runtime.get("coverage_feedback_manifest_path"),
        scheduler_feedback_consumption_path=runtime.get("scheduler_feedback_consumption_path"),
        seed_mode=runtime.get("seed_task_mode"),
        seed_task_manifest_path=runtime.get("seed_task_manifest_path") or runtime.get("binary_seed_task_manifest_path"),
        selected_target=runtime.get("selected_target") or runtime.get("active_harness"),
        selected_harness=runtime.get("selected_harness") or runtime.get("active_harness"),
        selected_target_function=runtime.get("selected_target_function"),
        selected_binary_slice_focus=runtime.get("selected_binary_slice_focus"),
        reseeding_attempted=bool(runtime.get("campaign_reseeding_attempted") or runtime.get("coverage_feedback_reseeding_attempted")),
        reseeding_triggered=bool(runtime.get("campaign_reseeding_triggered") or runtime.get("coverage_feedback_reseeding_triggered")),
        reseeding_target_functions=_normalize_reseed_target_names(
            runtime.get("campaign_reseed_target_functions") or runtime.get("coverage_feedback_reseed_target_functions")
        ),
        reseeding_generated_seed_count=int(
            runtime.get("campaign_reseed_generated_seed_count")
            or runtime.get("coverage_feedback_reseed_generated_seed_count")
            or 0
        ),
        stalled=bool(coverage_feedback.get("stalled")),
        proxy_stalled=bool(coverage_feedback.get("proxy_stalled")),
        coverage_stalled=bool(coverage_feedback.get("coverage_stalled")),
        triggered_action_type=str(
            (coverage_feedback.get("triggered_action") or {}).get("type")
            or runtime.get("coverage_feedback_action")
            or ""
        )
        or None,
        uncovered_function_count=int(
            coverage_feedback.get("uncovered_function_count")
            or runtime.get("coverage_feedback_uncovered_function_count")
            or 0
        ),
        low_growth_function_count=len(runtime.get("campaign_low_growth_functions") or []),
        session_index=int(runtime.get("campaign_session_index") or 0),
        session_budget_seconds=int(runtime.get("campaign_session_budget_seconds") or 0),
        trace_exact_signature_count=len(signatures),
        family_diversification_triggered=bool(runtime.get("campaign_family_diversification_triggered")),
        family_stagnation_count=int(runtime.get("campaign_family_stagnation_count") or 0),
        candidate_bridge_count=int(runtime.get("campaign_candidate_bridge_queue_size") or 0),
        binary_feedback_queue_count=int(runtime.get("binary_feedback_queue_size") or 0),
        binary_trace_admission_count=int(runtime.get("binary_trace_admission_count") or 0),
        binary_ida_focus_count=int(runtime.get("binary_ida_candidate_count") or 0),
        binary_provenance_class=runtime.get("binary_provenance_class"),
        binary_feedback_action=runtime.get("binary_feedback_action"),
        binary_feedback_bridge_path=runtime.get("binary_feedback_bridge_path"),
        binary_ida_runtime_view_path=runtime.get("binary_ida_runtime_view_path"),
        confirmed_pov_names=list(session_summary.get("confirmed_pov_names") or []),
        session_summary_path=session_summary.get("session_summary_path"),
        session_continuity_mode=runtime.get("campaign_session_continuity_mode") or session_summary.get("continuity_mode"),
        session_workspace_reused=bool(
            runtime.get("campaign_session_workspace_reused")
            or session_summary.get("workspace_reused")
        ),
        previous_session_summary_path=runtime.get("campaign_previous_session_summary_path") or session_summary.get("previous_session_summary_path"),
        session_archive_root=runtime.get("campaign_session_archive_root")
        or ((session_summary.get("archived_previous_live_workspace") or {}).get("archive_root")),
        session_corpus_state_reference=session_summary.get("corpus_state_reference"),
        session_coverage_snapshot_reference=(
            session_summary.get("coverage_snapshot_reference") or runtime.get("coverage_last_snapshot_path")
        ),
        session_stagnation_state=dict(session_summary.get("last_stagnation_state") or {}),
        next_action="continue_campaign",
    )
    return round_record, updated


def execute_campaign_iteration(
    *,
    base_task_id: str,
    donor_task_id: str,
    target_mode: str,
    round_number: int,
    task_store: TaskStateStore,
    data_root: Path,
    cumulative_signatures: set[str] | None = None,
    duration_seconds: int = 30,
    campaign_task_id: str | None = None,
    session_plan: dict[str, Any] | None = None,
    reusable_round_task_id: str | None = None,
) -> tuple[str, dict[str, Any], set[str]]:
    signatures = cumulative_signatures or set()
    if target_mode == "binary":
        round_task_id = _prepare_binary_round_task(
            base_task_id=base_task_id,
            donor_task_id=donor_task_id,
            round_number=round_number,
            task_store=task_store,
        )
    else:
        round_task_id = _prepare_source_round_task(
            base_task_id=base_task_id,
            donor_task_id=donor_task_id,
            round_number=round_number,
            task_store=task_store,
            duration_seconds=duration_seconds,
            campaign_task_id=campaign_task_id,
            reusable_task_id=reusable_round_task_id,
        )
    _apply_round_scheduler_arbitration(round_task_id, task_store)
    session_summary: dict[str, Any] | None = None
    if campaign_task_id and session_plan:
        if target_mode != "binary":
            session_summary = prepare_continuous_session_workspace(
                round_task_id,
                session_index=int(session_plan.get("session_index") or 0),
                task_store=task_store,
                continuity={
                    "workspace_reused": bool(session_plan.get("reuse_existing_round_task")),
                    "continuity_mode": session_plan.get("continuity_mode"),
                    "previous_session_summary_path": session_plan.get("previous_session_summary_path"),
                    "selected_harness": session_plan.get("selected_harness"),
                    "selected_target_function": session_plan.get("selected_target_function"),
                    "last_corpus_state_reference": session_plan.get("last_corpus_state_reference"),
                    "last_coverage_snapshot_reference": session_plan.get("last_coverage_snapshot_reference"),
                    "last_stagnation_state": session_plan.get("last_stagnation_state") or {},
                },
            )
        prepare_session_round_task(
            campaign_task_id,
            round_task_id=round_task_id,
            session_plan=session_plan,
            task_store=task_store,
        )
    queue = _run_round_seed_phase(round_task_id, task_store, target_mode)
    pipeline_completed = False
    if queue is not None:
        pipeline_completed = _drain_round_pipeline(round_task_id, task_store, target_mode, queue)
    if pipeline_completed:
        _, feedback = analyze_coverage_feedback(round_task_id, task_store)
        if bool(feedback.get("stalled")):
            _run_round_reseed_phase(
                round_task_id,
                task_store,
                target_mode,
                feedback,
                round_number=round_number,
            )
    if target_mode != "binary" and campaign_task_id and session_plan:
        session_summary = finalize_continuous_session_workspace(
            round_task_id,
            session_index=int(session_plan.get("session_index") or 0),
            task_store=task_store,
        )
    round_record, updated = collect_round_stats(
        round_task_id,
        data_root,
        signatures,
        session_summary=session_summary,
    )
    return round_task_id, round_record.to_dict(), updated


def execute_campaign_rounds(
    *,
    base_task_id: str,
    target_mode: str,
    rounds: int,
    task_store: TaskStateStore,
    data_root: Path,
    duration_seconds: int = 30,
) -> tuple[list[str], list[dict[str, Any]]]:
    origin_task_ids: list[str] = []
    round_records: list[dict[str, Any]] = []
    donor_task_id = base_task_id
    cumulative_signatures: set[str] = set()
    for round_number in range(1, rounds + 1):
        round_task_id, round_record, cumulative_signatures = execute_campaign_iteration(
            base_task_id=base_task_id,
            donor_task_id=donor_task_id,
            target_mode=target_mode,
            round_number=round_number,
            task_store=task_store,
            data_root=data_root,
            cumulative_signatures=cumulative_signatures,
            duration_seconds=duration_seconds,
        )
        origin_task_ids.append(round_task_id)
        round_records.append(round_record)
        donor_task_id = round_task_id
    return origin_task_ids, round_records

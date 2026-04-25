from __future__ import annotations

import json
import os
import shutil
import time
import zipfile
from pathlib import Path
from typing import Any

from apps.workers.binary_analysis.main import process_task as binary_analysis_task
from apps.workers.binary_execution.main import process_task as binary_execution_task
from apps.workers.binary_seed.main import process_task as binary_seed_task
from apps.workers.builder.main import process_task as build_task
from apps.workers.downloader.main import process_task as download_task
from apps.workers.fuzzer.main import process_task as fuzzer_task
from apps.workers.program_model.main import process_task as index_task
from apps.workers.reproducer.main import process_task as repro_task
from apps.workers.scheduler.main import process_task as schedule_task
from apps.workers.seed.main import process_task as seed_task
from apps.workers.tracer.main import process_task as trace_task
from core.analysis.pov_inventory import build_campaign_reports
from core.campaign.coverage_feedback import analyze_coverage_feedback, consume_coverage_feedback_for_scheduler
from core.datasets import package_binary
from core.models.task import AdapterType, ExecutionMode, TaskSource, TaskSpec, TaskStatus
from core.state.task_state import TaskStateStore
from core.storage.layout import create_task_layout, execution_plan_path
from scripts.run_original_semantic_closure import (
    _classify_repo_first_task,
    _run_source_repo_first,
    _run_source_sanity,
    _save_json,
    _source_metrics,
    _write_source_generalization_reports,
)
from scripts.run_plane_strengthening_short_validations import _binary_metrics
from scripts.verification_common import LocalQueue, configure_llm_from_env, write_report

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_ROOT = REPO_ROOT / "reports"
DATASET_ROOT = REPO_ROOT / "data" / "datasets"
FUZZ_TARGETS_ROOT = Path("/home/buttercup2/Project/fuzz_targets")
OSS_FUZZ_ROOT = Path("/home/buttercup2/Project/oss-fuzz/oss-fuzz")
LIBXML2_OUT = Path("/home/buttercup2/AI/Run_data/fuzz-tooling/oss-fuzz/build/out/libxml2")
GLIBC239_LAUNCHER = REPO_ROOT / "scripts" / "glibc239_binary_launcher.sh"

INJECTED_SOURCE_REPOS = {
    "cjson": {
        "repo_url": "https://github.com/baiyujun/cjson.git",
        "git_ref": "fix/buttercup-build",
    },
    "inih": {
        "repo_url": "https://github.com/Misat0N/inih.git",
        "git_ref": "main",
    },
}

GENERALIZATION_REPOS = {
    "libyaml": {"repo_url": "https://github.com/yaml/libyaml.git", "git_ref": "master"},
    "libplist": {"repo_url": "https://github.com/libimobiledevice/libplist.git", "git_ref": "master"},
    "zlib": {"repo_url": "https://github.com/madler/zlib.git", "git_ref": "master"},
}

FUZZ_TARGET_PROJECTS = {
    "cjson": {
        "project_name": "cjson",
        "display_name": "cJSON",
        "source_dir": FUZZ_TARGETS_ROOT / "cJSON",
        "oss_fuzz_project": "cjson",
        "main_repo": "https://github.com/DaveGamble/cJSON.git",
    },
    "inih": {
        "project_name": "inih",
        "display_name": "inih",
        "source_dir": FUZZ_TARGETS_ROOT / "inih",
        "oss_fuzz_project": "inih",
        "main_repo": "https://github.com/benhoyt/inih",
    },
    "libxml2": {
        "project_name": "libxml2",
        "display_name": "libxml2",
        "source_dir": FUZZ_TARGETS_ROOT / "libxml2",
        "oss_fuzz_project": "libxml2",
        "main_repo": "https://gitlab.gnome.org/GNOME/libxml2.git",
    },
    "miniz": {
        "project_name": "miniz",
        "display_name": "miniz",
        "source_dir": FUZZ_TARGETS_ROOT / "miniz",
        "oss_fuzz_project": "miniz",
        "main_repo": "https://github.com/richgel999/miniz.git",
    },
    "libspng": {
        "project_name": "libspng",
        "display_name": "libspng",
        "source_dir": FUZZ_TARGETS_ROOT / "libspng",
        "oss_fuzz_project": "libspng",
        "main_repo": "https://github.com/randy408/libspng.git",
    },
    "h3": {
        "project_name": "h3",
        "display_name": "h3",
        "source_dir": FUZZ_TARGETS_ROOT / "h3",
        "oss_fuzz_project": "h3",
        "main_repo": "https://github.com/uber/h3",
    },
}

FUZZ_TARGET_BUILD_ONLY_REPOS = {
    "miniz": {"repo_url": "https://github.com/richgel999/miniz.git", "git_ref": "master"},
    "libspng": {"repo_url": "https://github.com/randy408/libspng.git", "git_ref": "master"},
    "h3": {"repo_url": "https://github.com/uber/h3.git", "git_ref": "master"},
}


def _project_contract_hints(project_name: str, binary_name: str) -> list[str]:
    normalized_project = project_name.strip().lower()
    hints: list[str] = []
    if normalized_project == "cjson":
        hints.extend(
            [
                "source-derived leverage: cJSON harness expects 4 ASCII control flag bytes ('0' or '1') before the JSON payload",
                "source-derived leverage: cJSON replay requires the final byte to be a NUL terminator",
                "source-derived leverage: after the 4-byte prefix, the remaining content should be JSON text suitable for ParseWithOpts/Print/Minify paths",
            ]
        )
    elif normalized_project == "inih":
        hints.extend(
            [
                "source-derived leverage: inih harness copies the buffer and appends a trailing NUL before ini_parse_string",
                "source-derived leverage: payload should be INI-like text with sections, keys, values, comments, and malformed bracket variants",
            ]
        )
    elif normalized_project == "libyaml":
        hints.extend(
            [
                "source-derived leverage: libyaml parser fuzzers expect whole-document YAML bytes delivered via file path",
                "source-derived leverage: emphasize indentation, anchors/aliases, tags, nested mappings/sequences, and truncated documents",
            ]
        )
    elif normalized_project == "libxml2":
        hints.extend(
            [
                "source-derived leverage: libxml2 fuzzers expect whole-document XML/HTML-style bytes via argv file replay",
            ]
        )
    if binary_name:
        hints.append(f"selected_binary_name={binary_name}")
    return hints


def _write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _read_json(path: str | Path | None, default: Any = None) -> Any:
    if not path:
        return {} if default is None else default
    candidate = Path(path)
    if not candidate.exists():
        return {} if default is None else default
    return json.loads(candidate.read_text(encoding="utf-8"))


def _copy_if_exists(source: str | Path | None, destination: Path) -> None:
    if not source:
        return
    source_path = Path(source)
    if not source_path.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, destination)


def _consume_scheduler_feedback(task_id: str, task_store: TaskStateStore) -> dict[str, Any] | None:
    task = task_store.load_task(task_id)
    plan_path = execution_plan_path(task_id)
    plan = _read_json(plan_path, {})
    if not plan:
        return None
    updated_plan, consumption = consume_coverage_feedback_for_scheduler(task=task, plan=plan, now=task_store.now())
    if not consumption:
        return None
    _save_json(plan_path, updated_plan)
    task_store.update_runtime(
        task_id,
        {
            "execution_plan_path": str(plan_path),
            "scheduler_consumed_feedback": True,
            "scheduler_feedback_consumption_path": consumption["scheduler_feedback_consumption_path"],
            "scheduler_feedback_reason": consumption["reason"],
            "scheduler_feedback_before": consumption["before"],
            "scheduler_feedback_after": consumption["after"],
            "selected_target": updated_plan.get("selected_target"),
            "selected_binary_slice_focus": updated_plan.get("selected_binary_slice_focus"),
            "target_priority": updated_plan.get("target_priority"),
            "target_weight": updated_plan.get("target_weight"),
        },
    )
    return consumption


def _run_build_only_repo(
    task_store: TaskStateStore,
    queue: LocalQueue,
    *,
    repo_url: str,
    git_ref: str | None,
    run_label: str,
) -> str:
    spec = TaskSpec(
        repo_url=repo_url,
        git_ref=git_ref,
        source_type="git_repo",
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "run_label": run_label,
            "verification_mode": "source_derived_binary_build_only",
            "ENABLE_PATCH_ATTEMPT": False,
        },
    )
    record = task_store.create_task(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)
    return record.task_id


def _drain_patch_queue(queue: LocalQueue, task_store: TaskStateStore, seen_patch_tasks: set[str]) -> list[str]:
    from apps.workers.patch.main import process_task as patch_task
    from core.queues.redis_queue import QueueNames

    launched: list[str] = []
    for queue_name, payload in queue.pushed:
        if queue_name != QueueNames.PATCH or payload in seen_patch_tasks:
            continue
        patch_task(payload, task_store, queue)
        seen_patch_tasks.add(payload)
        launched.append(payload)
    return launched


def _run_source_repo_first_resilient(
    task_store: TaskStateStore,
    queue: LocalQueue,
    *,
    label: str,
    repo_url: str,
    git_ref: str | None,
    fuzz_seconds: int,
    max_len: int,
    backend: str,
) -> tuple[str, list[str]]:
    task_partition = "official_main" if backend == "llm" else "explicit_control_fallback"
    ground_truth = REPO_ROOT / "benchmarks" / f"{label}_injected" / "ground_truth.json"
    spec = TaskSpec(
        repo_url=repo_url,
        git_ref=git_ref,
        source_type="git_repo",
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "run_label": f"{label}_source_binary_hard_convergence",
            "SEED_GENERATION_BACKEND": backend,
            "SEED_GENERATION_ATTEMPTS": 2,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": max_len,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": fuzz_seconds,
            "FUZZ_TIMEOUT_SECONDS": 5,
            "FUZZ_MAX_LEN": max_len,
            "FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES": False,
            "ALLOW_IMPORTED_CRASH_FALLBACK": False,
            "verification_mode": "source_binary_hard_convergence",
            "task_partition": task_partition,
            "seed_material_policy": "clean_generated_only",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": backend != "llm",
            "ENABLE_PATCH_ATTEMPT": True,
            "ground_truth_path": str(ground_truth),
            "LLM_TEMPERATURE": 0.2,
        },
    )
    record = task_store.create_task(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    seen_patch_tasks: set[str] = set()
    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)
    build_task_result = task_store.load_task(record.task_id)
    if not build_task_result.runtime.get("build_registry_path"):
        return record.task_id, []

    max_rounds = 1 if backend == "llm" else 2
    for round_index in range(1, max_rounds + 1):
        task = task_store.load_task(record.task_id)
        if task.status in {
            TaskStatus.INDEXED,
            TaskStatus.BUILT,
            TaskStatus.SEEDED,
            TaskStatus.FUZZ_FAILED,
            TaskStatus.TRACED,
            TaskStatus.POV_CONFIRMED,
        }:
            task_store.update_status(
                record.task_id,
                TaskStatus.QUEUED_SEED,
                runtime_patch={
                    "repo_first_reseed_round": round_index,
                    "reseed_requested_at": task_store.now(),
                },
            )
        try:
            seed_task(record.task_id, task_store, queue)
        except Exception as exc:
            task_store.update_status(
                record.task_id,
                TaskStatus.SEED_FAILED,
                runtime_patch={
                    "source_real_llm_failure": str(exc),
                    "source_real_llm_failed_round": round_index,
                },
            )
            break
        task = task_store.load_task(record.task_id)
        task_dir = Path(task.task_dir)
        _copy_if_exists(task.runtime.get("seed_init_chain_manifest_path"), task_dir / "seed" / f"seed_init_chain_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_task_manifest_path"), task_dir / "seed" / f"seed_task_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_manifest_path"), task_dir / "seed" / f"seed_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("harness_selector_manifest_path"), task_dir / "seed" / f"harness_selector_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("function_selector_manifest_path"), task_dir / "seed" / f"function_selector_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_family_plan_manifest_path"), task_dir / "seed" / f"seed_family_plan_manifest_run{round_index}.json")
        _copy_if_exists(task_dir / "index" / "context_package.json", task_dir / "index" / f"context_package_run{round_index}.json")
        if task.status == TaskStatus.QUEUED_FUZZ:
            fuzzer_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        _copy_if_exists(task.runtime.get("fuzz_manifest_path"), task_dir / "crashes" / f"fuzz_manifest_run{round_index}.json")
        analyze_coverage_feedback(record.task_id, task_store)
        _copy_if_exists(task_store.load_task(record.task_id).runtime.get("coverage_summary_manifest_path"), task_dir / "coverage" / f"coverage_summary_manifest_run{round_index}.json")
        _copy_if_exists(task_store.load_task(record.task_id).runtime.get("coverage_feedback_manifest_path"), task_dir / "coverage" / f"feedback_manifest_run{round_index}.json")
        _consume_scheduler_feedback(record.task_id, task_store)
        task = task_store.load_task(record.task_id)
        next_mode = "VULN_DISCOVERY" if int(task.runtime.get("raw_crash_count") or 0) > 0 else "SEED_EXPLORE"
        task_store.update_runtime(
            record.task_id,
            {
                "seed_task_mode_override": next_mode,
                "targeted_reseed_reason": (
                    "live raw crash exists; switch to exploit-oriented seed family"
                    if next_mode == "VULN_DISCOVERY"
                    else "no live raw crash yet; switch to parser exploration seed family"
                ),
            },
        )
        if task.status == TaskStatus.QUEUED_TRACE:
            trace_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        if task.status == TaskStatus.QUEUED_REPRO:
            repro_task(record.task_id, task_store, queue)
        _drain_patch_queue(queue, task_store, seen_patch_tasks)
        task = task_store.load_task(record.task_id)
        if backend == "llm" and task.status in {
            TaskStatus.POV_CONFIRMED,
            TaskStatus.PATCH_ACCEPTED,
            TaskStatus.PATCH_SUPPRESSED,
            TaskStatus.PATCH_RETRY_REQUESTED,
            TaskStatus.PATCH_ESCALATED,
            TaskStatus.SEED_FAILED,
        }:
            break

    if ground_truth.exists():
        try:
            build_campaign_reports(
                campaign_task_id=record.task_id,
                origin_task_ids=[record.task_id],
                ground_truth_path=ground_truth,
                data_root=REPO_ROOT / "data" / "tasks",
            )
        except Exception:
            pass
    return record.task_id, sorted(seen_patch_tasks)


def _pick_registry_fuzzer(build_registry: dict[str, Any], preferred_names: list[str] | None = None) -> dict[str, Any] | None:
    fuzzers = build_registry.get("fuzzers") or []
    if not fuzzers:
        return None
    preferred_names = preferred_names or []
    by_name = {str(item.get("name")): item for item in fuzzers if item.get("name")}
    for candidate in preferred_names:
        if candidate in by_name:
            return by_name[candidate]
    return fuzzers[0]


def _extract_seed_corpus(zip_path: Path, destination_dir: Path) -> str | None:
    if not zip_path.exists():
        return None
    destination_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(destination_dir)
    except zipfile.BadZipFile:
        return None
    return str(destination_dir)


def _collect_sidecars(build_registry: dict[str, Any], fuzzer_name: str) -> tuple[dict[str, Path], dict[str, str]]:
    prefix = (
        fuzzer_name.replace("_replay", "")
        .replace("_fuzzer", "")
        .replace(".stripped", "")
    )
    sidecars: dict[str, Path] = {}
    metadata: dict[str, str] = {}
    for key, collection_name in (
        ("dict", "dicts"),
        ("options", "options"),
        ("seed_corpus", "seed_corpora"),
    ):
        entries = build_registry.get(collection_name) or []
        chosen = None
        for entry in entries:
            name = str(entry.get("name") or "")
            if prefix and prefix in name:
                chosen = entry
                break
        if chosen is None and entries:
            chosen = entries[0]
        if chosen and chosen.get("path"):
            sidecars[key] = Path(str(chosen["path"]))
            metadata[f"{key}_source_name"] = str(chosen.get("name") or Path(str(chosen["path"])).name)
    return sidecars, metadata


def _package_from_task(
    *,
    task_id: str,
    project_name: str,
    layer: str,
    preferred_fuzzers: list[str] | None = None,
    strip_symbols: bool = False,
) -> dict[str, Any] | None:
    task_root = REPO_ROOT / "data" / "tasks" / task_id
    source_src_path = task_root / "src"
    source_index_path = task_root / "index"
    build_registry = _read_json(REPO_ROOT / "data" / "tasks" / task_id / "build" / "build_registry.json", {})
    selected: dict[str, Any] | None = None
    binary_kind = "fuzzer_binary"
    replay_binaries = build_registry.get("tracer_replay_binaries") or []
    preferred_fuzzers = preferred_fuzzers or []
    preferred_replay_names = {f"{name}_replay" for name in preferred_fuzzers}
    for entry in replay_binaries:
        if preferred_replay_names and str(entry.get("name") or Path(str(entry.get("path") or "")).name) not in preferred_replay_names:
            continue
        if entry.get("path"):
            selected = {
                "name": str(entry.get("name") or Path(str(entry["path"])).name),
                "path": str(entry["path"]),
            }
            binary_kind = "replay_binary"
            break
    if selected is None and replay_binaries:
        entry = replay_binaries[0]
        if entry.get("path"):
            selected = {
                "name": str(entry.get("name") or Path(str(entry["path"])).name),
                "path": str(entry["path"]),
            }
            binary_kind = "replay_binary"
    if selected is None:
        selected = _pick_registry_fuzzer(build_registry, preferred_fuzzers)
    if selected is None:
        return None
    sidecars, sidecar_meta = _collect_sidecars(build_registry, str(selected.get("name") or ""))
    package = package_binary(
        project_name=project_name,
        layer=layer,
        binary_path=Path(str(selected["path"])),
        launcher_path=GLIBC239_LAUNCHER,
        output_root=DATASET_ROOT,
        binary_kind=binary_kind,
        contract_kind="argv-file-driven",
        contract_hints=[
            (
                "dedicated replay binary via glibc239 launcher"
                if binary_kind == "replay_binary"
                else "libFuzzer-style argv file replay via glibc239 launcher"
            ),
            f"binary_source_task_id={task_id}",
            *_project_contract_hints(project_name, str(selected.get('name') or '')),
        ],
        optional_sidecars=sidecars,
        provenance={
            "source_task_id": task_id,
            "project_name": project_name,
            "selected_binary": selected.get("name"),
            "binary_kind": binary_kind,
            "sidecar_metadata": sidecar_meta,
        },
        source_task_id=task_id,
        source_src_path=source_src_path if source_src_path.exists() else None,
        source_index_path=source_index_path if source_index_path.exists() else None,
        strip_symbols=strip_symbols,
    )
    if sidecars.get("seed_corpus"):
        extracted_dir = DATASET_ROOT / layer / project_name / "seed_corpus_extracted"
        extracted = _extract_seed_corpus(sidecars["seed_corpus"], extracted_dir)
        if extracted:
            package["extracted_seed_corpus_dir"] = extracted
            manifest_path = Path(package["binary_package_manifest_path"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["extracted_seed_corpus_dir"] = extracted
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return package


def _package_from_libxml2_out(*, project_name: str, layer: str, binary_name: str) -> dict[str, Any]:
    sidecars: dict[str, Path] = {}
    for candidate_name in [f"{binary_name}.dict", f"{binary_name}.options", f"{binary_name}_seed_corpus.zip"]:
        candidate = LIBXML2_OUT / candidate_name
        if candidate.exists():
            key = "dict" if candidate_name.endswith(".dict") else "options" if candidate_name.endswith(".options") else "seed_corpus"
            sidecars[key] = candidate
    package = package_binary(
        project_name=project_name,
        layer=layer,
        binary_path=LIBXML2_OUT / binary_name,
        launcher_path=GLIBC239_LAUNCHER,
        output_root=DATASET_ROOT,
        contract_kind="argv-file-driven",
        contract_hints=[
            "oss-fuzz prebuilt libxml2 fuzzer",
            "libFuzzer-style argv file replay via glibc239 launcher",
            *_project_contract_hints(project_name, binary_name),
        ],
        optional_sidecars=sidecars,
        provenance={
            "source_kind": "prebuilt_oss_fuzz_out",
            "binary_name": binary_name,
            "source_out_dir": str(LIBXML2_OUT),
        },
        strip_symbols=False,
    )
    if sidecars.get("seed_corpus"):
        extracted_dir = DATASET_ROOT / layer / project_name / "seed_corpus_extracted"
        extracted = _extract_seed_corpus(sidecars["seed_corpus"], extracted_dir)
        if extracted:
            package["extracted_seed_corpus_dir"] = extracted
            manifest_path = Path(package["binary_package_manifest_path"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["extracted_seed_corpus_dir"] = extracted
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return package


def _copy_run_manifests(task_dir: Path, runtime: dict[str, Any], round_index: int) -> None:
    _copy_if_exists(runtime.get("binary_seed_task_manifest_path"), task_dir / "binary_seed" / f"binary_seed_task_manifest_run{round_index}.json")
    _copy_if_exists(runtime.get("binary_seed_manifest_path"), task_dir / "binary_seed" / f"binary_seed_manifest_run{round_index}.json")
    _copy_if_exists(runtime.get("binary_slice_manifest_path"), task_dir / "binary_slice" / f"slice_manifest_run{round_index}.json")
    _copy_if_exists(runtime.get("binary_execution_manifest_path"), task_dir / "runtime" / f"binary_execution_manifest_run{round_index}.json")


def _run_binary_package_task(
    task_store: TaskStateStore,
    queue: LocalQueue,
    *,
    label: str,
    package: dict[str, Any],
    backend: str,
    binary_mode: str,
    native_rounds: int | None = None,
) -> str:
    task_partition = "official_main" if backend == "llm" else "explicit_control_fallback"
    package_manifest = _read_json(Path(package["binary_package_manifest_path"]), {})
    metadata: dict[str, Any] = {
        "run_label": label,
        "task_partition": task_partition,
        "binary_target_name": Path(package["binary_path"]).name,
        "binary_kind": package.get("binary_kind", "fuzzer_binary"),
        "binary_mode": binary_mode,
        "binary_provenance": binary_mode,
        "binary_input_contract": "file",
        "binary_input_contract_source": "dataset_package_contract",
        "binary_analysis_backend": "ida_mcp",
        "existing_launcher_path": package["launcher_path"],
        "argv_template": [package["launcher_path"], "{binary_path}", "{input_path}"],
        "SEED_GENERATION_BACKEND": backend,
        "SEED_GENERATION_ATTEMPTS": 2,
        "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
        "SEED_MAX_BYTES": 131072,
        "LLM_TIMEOUT_SECONDS": int(os.getenv("FINAL_BINARY_LLM_TIMEOUT_SECONDS", os.getenv("LLM_TIMEOUT_SECONDS", "180"))),
        "LLM_MAX_RETRIES": int(os.getenv("FINAL_BINARY_LLM_MAX_RETRIES", os.getenv("LLM_MAX_RETRIES", "0"))),
        "LLM_MAX_TOKENS": int(os.getenv("FINAL_BINARY_LLM_MAX_TOKENS", "900")),
        "verification_mode": "binary_tool_orchestration_hard_convergence",
        "seed_material_policy": "llm_only" if backend == "llm" else "heuristic_only",
        "allow_imported_seed_material": False,
        "allow_cached_seed_material": False,
        "allow_fallback_non_llm": backend != "llm",
        "task_should_fail_if_llm_missing": backend == "llm",
        "dataset_binary_package_manifest_path": package["binary_package_manifest_path"],
        "binary_dataset_provenance_manifest_path": package["binary_dataset_provenance_manifest_path"],
        "binary_visibility_constraints_path": package["binary_visibility_constraints_path"],
        "binary_contract_kind": package["contract_kind"],
        "binary_contract_hints": package.get("contract_hints", []),
    }
    if binary_mode == "source_derived_binary":
        source_src_path = package_manifest.get("source_src_path")
        source_index_path = package_manifest.get("source_index_path")
        if source_src_path:
            metadata["existing_src_path"] = source_src_path
        if source_index_path:
            metadata["existing_index_path"] = source_index_path
    sidecars = package.get("optional_sidecar") or {}
    if sidecars.get("dict"):
        metadata["existing_dict_path"] = sidecars["dict"]
    if sidecars.get("options"):
        metadata["existing_options_path"] = sidecars["options"]
    if package.get("extracted_seed_corpus_dir"):
        metadata["existing_corpus_path"] = package["extracted_seed_corpus_dir"]
    spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.BINARY, uri=package["binary_path"], ref=label),
        execution_mode=ExecutionMode.IMPORT_ASSISTED,
        metadata=metadata,
    )
    record = task_store.create_task(spec, status=TaskStatus.READY)
    task_store.update_task(record.task_id, layout=create_task_layout(record.task_id))

    def _record_binary_round_failure(round_index: int, exc: Exception) -> str:
        path = Path(task_store.load_task(record.task_id).task_dir) / "runtime" / "binary_round_timeout_accounting_manifest.json"
        previous = _read_json(path, {"task_id": record.task_id, "round_failures": [], "successful_rounds_preserved": True})
        previous.setdefault("task_id", record.task_id)
        previous.setdefault("round_failures", [])
        previous["generated_at"] = task_store.now()
        previous["round_failures"].append(
            {
                "round": round_index,
                "error": str(exc),
                "requested_seed_backend": backend,
                "failure_does_not_reclassify_previous_successful_rounds": True,
            }
        )
        return _write_json(path, previous)

    schedule_task(record.task_id, task_store, queue)
    binary_analysis_task(record.task_id, task_store, queue)

    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_BINARY_SEED:
        try:
            binary_seed_task(record.task_id, task_store, queue)
        except Exception as exc:
            failure_path = _record_binary_round_failure(1, exc)
            task_store.update_status(
                record.task_id,
                TaskStatus.BINARY_SEED_FAILED,
                runtime_patch={
                    "binary_real_llm_failure": str(exc),
                    "binary_real_llm_failed_round": 1,
                    "binary_round_timeout_accounting_manifest_path": failure_path,
                },
            )
    task = task_store.load_task(record.task_id)
    _copy_run_manifests(Path(task.task_dir), task.runtime, 1)
    if task.status == TaskStatus.QUEUED_BINARY_EXECUTION:
        binary_execution_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_run_manifests(Path(task.task_dir), task.runtime, 1)
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(record.task_id, task_store, queue)

    analyze_coverage_feedback(record.task_id, task_store)
    analyze_coverage_feedback(record.task_id, task_store)
    _consume_scheduler_feedback(record.task_id, task_store)

    task = task_store.load_task(record.task_id)
    rounds_to_run = max(1, int(native_rounds or os.getenv("FINAL_BINARY_NATIVE_ROUNDS", "1")))
    if task.status in {
        TaskStatus.BINARY_EXECUTED,
        TaskStatus.BINARY_CRASH_CANDIDATE_FOUND,
        TaskStatus.TRACED,
        TaskStatus.POV_CONFIRMED,
    }:
        if backend == "llm" and rounds_to_run <= 1:
            try:
                build_campaign_reports(
                    campaign_task_id=record.task_id,
                    origin_task_ids=[record.task_id],
                    ground_truth_path=None,
                    data_root=REPO_ROOT / "data" / "tasks",
                )
            except Exception:
                pass
            return record.task_id
        task_store.update_status(
            record.task_id,
            TaskStatus.QUEUED_BINARY_SEED,
            runtime_patch={
                "binary_reseed_requested_at": task_store.now(),
                "seed_task_mode_override": "VULN_DISCOVERY",
                "binary_native_promotion_round": 2,
                "binary_native_promotion_rounds_requested": rounds_to_run,
            },
        )
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_BINARY_SEED:
        try:
            binary_seed_task(record.task_id, task_store, queue)
        except Exception as exc:
            failure_path = _record_binary_round_failure(2, exc)
            task_store.update_status(
                record.task_id,
                TaskStatus.BINARY_SEED_FAILED,
                runtime_patch={
                    "binary_real_llm_failure": str(exc),
                    "binary_real_llm_failed_round": 2,
                    "binary_round_timeout_accounting_manifest_path": failure_path,
                },
            )
    task = task_store.load_task(record.task_id)
    _copy_run_manifests(Path(task.task_dir), task.runtime, 2)
    if task.status == TaskStatus.QUEUED_BINARY_EXECUTION:
        binary_execution_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_run_manifests(Path(task.task_dir), task.runtime, 2)
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if backend == "llm" and rounds_to_run >= 3 and task.status in {
        TaskStatus.BINARY_EXECUTED,
        TaskStatus.BINARY_CRASH_CANDIDATE_FOUND,
        TaskStatus.TRACED,
        TaskStatus.POV_CONFIRMED,
    }:
        task_store.update_status(
            record.task_id,
            TaskStatus.QUEUED_BINARY_SEED,
            runtime_patch={
                "binary_reseed_requested_at": task_store.now(),
                "seed_task_mode_override": "SEED_EXPLORE",
                "binary_native_promotion_round": 3,
                "binary_native_promotion_rounds_requested": rounds_to_run,
            },
        )
        try:
            binary_seed_task(record.task_id, task_store, queue)
        except Exception as exc:
            failure_path = _record_binary_round_failure(3, exc)
            task_store.update_status(
                record.task_id,
                TaskStatus.BINARY_SEED_FAILED,
                runtime_patch={
                    "binary_real_llm_failure": str(exc),
                    "binary_real_llm_failed_round": 3,
                    "binary_round_timeout_accounting_manifest_path": failure_path,
                },
            )
        task = task_store.load_task(record.task_id)
        _copy_run_manifests(Path(task.task_dir), task.runtime, 3)
        if task.status == TaskStatus.QUEUED_BINARY_EXECUTION:
            binary_execution_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        _copy_run_manifests(Path(task.task_dir), task.runtime, 3)
        if task.status == TaskStatus.QUEUED_TRACE:
            trace_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        if task.status == TaskStatus.QUEUED_REPRO:
            repro_task(record.task_id, task_store, queue)
    analyze_coverage_feedback(record.task_id, task_store)
    _consume_scheduler_feedback(record.task_id, task_store)
    try:
        build_campaign_reports(
            campaign_task_id=record.task_id,
            origin_task_ids=[record.task_id],
            ground_truth_path=None,
            data_root=REPO_ROOT / "data" / "tasks",
        )
    except Exception:
        pass
    return record.task_id


def _collect_task_llm_audit(task_store: TaskStateStore, task_id: str, *, target_mode: str) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    runtime = task.runtime
    audit = _read_json(runtime.get("llm_seed_audit_manifest_path"), {})
    integrity = _read_json(runtime.get("llm_backend_integrity_report_path"), {})
    degradation = _read_json(runtime.get("seed_backend_degradation_report_path"), {})
    strict_block = _read_json(runtime.get("strict_llm_block_report_path"), {})
    return {
        "task_id": task_id,
        "target_mode": target_mode,
        "status": task.status.value,
        "task_partition": audit.get("task_partition") or task.metadata.get("task_partition"),
        "requested_seed_backend": audit.get("requested_seed_backend"),
        "actual_seed_backend": audit.get("actual_seed_backend"),
        "llm_real_call_verified": audit.get("llm_real_call_verified"),
        "provider": audit.get("provider"),
        "model": audit.get("model"),
        "request_id_or_response_id_hash": audit.get("request_id_or_response_id_hash"),
        "prompt_hash": audit.get("prompt_hash"),
        "response_hash": audit.get("response_hash"),
        "token_usage": audit.get("token_usage"),
        "fallback_used": audit.get("fallback_used"),
        "fallback_reason": audit.get("fallback_reason"),
        "seed_provenance": audit.get("seed_provenance"),
        "prompt_template_id": audit.get("prompt_template_id"),
        "task_should_fail_if_llm_missing": audit.get("task_should_fail_if_llm_missing"),
        "degraded": degradation.get("degraded") or integrity.get("degraded"),
        "strict_llm_blocked": strict_block.get("strict_llm_blocked") or integrity.get("strict_llm_blocked"),
        "silent_fallback_eliminated": integrity.get("silent_fallback_eliminated"),
        "llm_seed_audit_manifest_path": runtime.get("llm_seed_audit_manifest_path"),
        "llm_backend_integrity_report_path": runtime.get("llm_backend_integrity_report_path"),
        "seed_backend_degradation_report_path": runtime.get("seed_backend_degradation_report_path"),
        "strict_llm_block_report_path": runtime.get("strict_llm_block_report_path"),
    }


def _source_binary_gap_entry(
    *,
    project_name: str,
    source_metrics: dict[str, Any] | None,
    binary_metrics: dict[str, Any] | None,
    binary_task_id: str | None,
    package_manifest_path: str | None,
) -> dict[str, Any]:
    return {
        "project_name": project_name,
        "source_full": source_metrics,
        "source_derived_binary": binary_metrics,
        "binary_task_id": binary_task_id,
        "binary_package_manifest_path": package_manifest_path,
        "source_lane_visibility": {
            "program_model_context": bool(source_metrics and source_metrics.get("context_package_path")),
            "coverage_summary": bool(source_metrics and source_metrics.get("coverage_summary_manifest_path")),
            "trace_manifest": bool(source_metrics and source_metrics.get("trace_manifest_path")),
            "repro_manifest": bool(source_metrics and source_metrics.get("repro_manifest_path")),
            "patch_attempts": len((source_metrics or {}).get("patch_metrics") or []),
        },
        "binary_lane_visibility": {
            "ida_context": bool(binary_metrics and task_store_global.load_task(binary_task_id).runtime.get("ida_integration_manifest_path")) if binary_task_id else False,
            "binary_context_package": bool(binary_metrics and task_store_global.load_task(binary_task_id).runtime.get("binary_context_package_path")) if binary_task_id else False,
            "signal_categories": (binary_metrics or {}).get("signal_category_counts", {}),
            "trace_manifest": bool(binary_metrics and binary_metrics.get("trace_manifest_path")),
        },
        "binary_missing_to_match_source": [
            "typed source semantics and patch synthesis context"
        ]
        if binary_metrics
        else ["binary task unavailable"],
    }


task_store_global: TaskStateStore


def _retry_call(attempts: int, delay_seconds: int, fn, *args, **kwargs):
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - recovery path
            last_exc = exc
            if attempt == attempts:
                raise
            time.sleep(delay_seconds * attempt)
    if last_exc is not None:
        raise last_exc


def main() -> int:
    llm_config = configure_llm_from_env()
    task_store = TaskStateStore()
    queue = LocalQueue()

    global task_store_global
    task_store_global = task_store

    cjson_task_id, cjson_patch_ids = _retry_call(
        2,
        15,
        _run_source_repo_first_resilient,
        task_store,
        queue,
        label="cjson",
        repo_url=INJECTED_SOURCE_REPOS["cjson"]["repo_url"],
        git_ref=INJECTED_SOURCE_REPOS["cjson"]["git_ref"],
        fuzz_seconds=18,
        max_len=262144,
        backend="llm",
    )
    inih_task_id, inih_patch_ids = _retry_call(
        2,
        15,
        _run_source_repo_first_resilient,
        task_store,
        queue,
        label="inih",
        repo_url=INJECTED_SOURCE_REPOS["inih"]["repo_url"],
        git_ref=INJECTED_SOURCE_REPOS["inih"]["git_ref"],
        fuzz_seconds=18,
        max_len=1024,
        backend="llm",
    )

    libyaml_task_id = _run_source_sanity(task_store, queue, label="libyaml_repo_first_sanity", **GENERALIZATION_REPOS["libyaml"])
    libplist_task_id = _run_source_sanity(task_store, queue, label="libplist_repo_first_sanity", **GENERALIZATION_REPOS["libplist"])
    zlib_task_id = _run_source_sanity(task_store, queue, label="zlib_repo_first_sanity", **GENERALIZATION_REPOS["zlib"])

    build_only_task_ids: dict[str, str] = {}
    for project_name, repo in FUZZ_TARGET_BUILD_ONLY_REPOS.items():
        build_only_task_ids[project_name] = _run_build_only_repo(
            task_store,
            queue,
            repo_url=repo["repo_url"],
            git_ref=repo.get("git_ref"),
            run_label=f"{project_name}_dataset_build_only",
        )

    binary_packages: dict[str, dict[str, Any]] = {}
    cjson_package = _package_from_task(task_id=cjson_task_id, project_name="cjson", layer="source-derived-binary", preferred_fuzzers=["cjson_read_fuzzer"])
    if cjson_package:
        binary_packages["cjson"] = cjson_package
        opaque_package = _package_from_task(
            task_id=cjson_task_id,
            project_name="cjson_opaque",
            layer="opaque-binary-like",
            preferred_fuzzers=["cjson_read_fuzzer"],
            strip_symbols=True,
        )
        if opaque_package:
            binary_packages["cjson_opaque"] = opaque_package

    inih_package = _package_from_task(task_id=inih_task_id, project_name="inih", layer="source-derived-binary", preferred_fuzzers=["inihfuzz"])
    if inih_package:
        binary_packages["inih"] = inih_package

    libyaml_package = _package_from_task(task_id=libyaml_task_id, project_name="libyaml", layer="source-derived-binary", preferred_fuzzers=["libyaml_parser_fuzzer"])
    if libyaml_package:
        binary_packages["libyaml"] = libyaml_package

    libplist_package = _package_from_task(task_id=libplist_task_id, project_name="libplist", layer="source-derived-binary", preferred_fuzzers=["bplist_fuzzer"])
    if libplist_package:
        binary_packages["libplist"] = libplist_package

    zlib_package = _package_from_task(task_id=zlib_task_id, project_name="zlib", layer="source-derived-binary", preferred_fuzzers=["zlib_uncompress_fuzzer", "zlib_uncompress2_fuzzer"])
    if zlib_package:
        binary_packages["zlib"] = zlib_package

    libxml2_package = _package_from_libxml2_out(project_name="libxml2", layer="source-derived-binary", binary_name="xml")
    binary_packages["libxml2"] = libxml2_package

    for project_name, task_id in build_only_task_ids.items():
        if project_name in binary_packages:
            continue
        package = _package_from_task(task_id=task_id, project_name=project_name, layer="source-derived-binary")
        if package:
            binary_packages[project_name] = package

    binary_real_task_ids: dict[str, str] = {}
    binary_fallback_task_ids: dict[str, str] = {}
    for project_name in ["cjson", "inih", "libxml2", "libyaml"]:
        package = binary_packages.get(project_name)
        if not package:
            continue
        binary_real_task_ids[project_name] = _retry_call(
            2,
            15,
            _run_binary_package_task,
            task_store,
            queue,
            label=f"{project_name}_source_derived_binary_real_llm",
            package=package,
            backend="llm",
            binary_mode="source_derived_binary",
        )
    if "cjson" in binary_packages:
        binary_fallback_task_ids["cjson"] = _run_binary_package_task(
            task_store,
            queue,
            label="cjson_source_derived_binary_fallback",
            package=binary_packages["cjson"],
            backend="heuristic_fallback",
            binary_mode="source_derived_binary",
        )
    if "cjson_opaque" in binary_packages:
        binary_real_task_ids["cjson_opaque"] = _run_binary_package_task(
            task_store,
            queue,
            label="cjson_opaque_binary_like_real_llm",
            package=binary_packages["cjson_opaque"],
            backend="llm",
            binary_mode="opaque_binary_like",
        )

    source_generalization = _write_source_generalization_reports(
        task_store,
        [
            cjson_task_id,
            inih_task_id,
            libyaml_task_id,
            libplist_task_id,
            zlib_task_id,
            *build_only_task_ids.values(),
        ],
    )

    dataset_registry = {
        "generated_at": task_store.now(),
        "llm_config": llm_config,
        "fuzz_targets_reference_projects": [
            {
                **entry,
                "source_dir_exists": entry["source_dir"].exists(),
                "source_dir": str(entry["source_dir"]),
                "binary_package_available": project_name in binary_packages,
                "binary_package_manifest_path": binary_packages.get(project_name, {}).get("binary_package_manifest_path"),
            }
            for project_name, entry in FUZZ_TARGET_PROJECTS.items()
        ],
        "binary_packages": binary_packages,
    }
    dataset_registry_path = write_report("dataset_registry_manifest.json", dataset_registry)

    dataset_layering = {
        "generated_at": task_store.now(),
        "layers": {
            "source-full": [
                {
                    "project_name": "cjson",
                    "task_id": cjson_task_id,
                    "repo_url": INJECTED_SOURCE_REPOS["cjson"]["repo_url"],
                },
                {
                    "project_name": "inih",
                    "task_id": inih_task_id,
                    "repo_url": INJECTED_SOURCE_REPOS["inih"]["repo_url"],
                },
            ],
            "source-derived-binary": [
                {
                    "project_name": project_name,
                    "binary_package_manifest_path": package.get("binary_package_manifest_path"),
                    "binary_dataset_provenance_manifest_path": package.get("binary_dataset_provenance_manifest_path"),
                }
                for project_name, package in binary_packages.items()
                if project_name != "cjson_opaque"
            ],
            "opaque-binary-like": [
                {
                    "project_name": "cjson_opaque",
                    "binary_package_manifest_path": binary_packages["cjson_opaque"]["binary_package_manifest_path"],
                }
            ]
            if "cjson_opaque" in binary_packages
            else [],
        },
    }
    dataset_layering_path = write_report("dataset_layering_manifest.json", dataset_layering)

    source_binary_map = {
        "generated_at": task_store.now(),
        "mapping": {
            "cjson": {
                "source_full_task_id": cjson_task_id,
                "binary_package_manifest_path": binary_packages.get("cjson", {}).get("binary_package_manifest_path"),
                "binary_real_task_id": binary_real_task_ids.get("cjson"),
                "binary_fallback_task_id": binary_fallback_task_ids.get("cjson"),
                "opaque_binary_like_task_id": binary_real_task_ids.get("cjson_opaque"),
            },
            "inih": {
                "source_full_task_id": inih_task_id,
                "binary_package_manifest_path": binary_packages.get("inih", {}).get("binary_package_manifest_path"),
                "binary_real_task_id": binary_real_task_ids.get("inih"),
            },
            "libyaml": {
                "source_full_task_id": libyaml_task_id,
                "binary_package_manifest_path": binary_packages.get("libyaml", {}).get("binary_package_manifest_path"),
                "binary_real_task_id": binary_real_task_ids.get("libyaml"),
            },
            "libxml2": {
                "binary_package_manifest_path": binary_packages.get("libxml2", {}).get("binary_package_manifest_path"),
                "binary_real_task_id": binary_real_task_ids.get("libxml2"),
            },
        },
    }
    source_binary_map_path = write_report("source_vs_binary_dataset_map.json", source_binary_map)

    unified_evaluation_matrix = {
        "generated_at": task_store.now(),
        "llm_config": {
            "llm_enabled": settings.llm_enabled,
            "llm_base_url": settings.llm_base_url.rstrip("/"),
            "llm_model": settings.llm_model,
            "llm_max_tokens": None if settings.llm_max_tokens <= 0 else settings.llm_max_tokens,
        },
        "source_full": {
            "official_main": {
                "cjson": {"task_id": cjson_task_id, "status": task_store.load_task(cjson_task_id).status.value},
                "inih": {"task_id": inih_task_id, "status": task_store.load_task(inih_task_id).status.value},
            },
            "explicit_control_fallback": {},
        },
        "source_derived_binary": {
            "official_main": dict(binary_real_task_ids),
            "explicit_control_fallback": dict(binary_fallback_task_ids),
        },
        "opaque_binary_like": {
            "official_main": {
                key: task_id
                for key, task_id in binary_real_task_ids.items()
                if key.endswith("_opaque")
            },
            "explicit_control_fallback": {
                key: task_id
                for key, task_id in binary_fallback_task_ids.items()
                if key.endswith("_opaque")
            },
        },
        "generalized_source": source_generalization,
    }
    unified_evaluation_matrix_path = write_report("unified_evaluation_matrix.json", unified_evaluation_matrix)

    source_llm_audits = [
        _collect_task_llm_audit(task_store, cjson_task_id, target_mode="source"),
        _collect_task_llm_audit(task_store, inih_task_id, target_mode="source"),
    ]
    binary_llm_audits = [
        _collect_task_llm_audit(task_store, task_id, target_mode="binary")
        for task_id in list(binary_real_task_ids.values()) + list(binary_fallback_task_ids.values())
    ]
    llm_integrity = {
        "generated_at": task_store.now(),
        "source_lane": source_llm_audits,
        "binary_lane": binary_llm_audits,
        "summary": {
            "source_real_llm_verified_count": sum(1 for item in source_llm_audits if item.get("llm_real_call_verified")),
            "binary_real_llm_verified_count": sum(
                1
                for item in binary_llm_audits
                if item.get("requested_seed_backend") == "llm" and item.get("llm_real_call_verified")
            ),
            "degraded_task_ids": [
                item["task_id"]
                for item in [*source_llm_audits, *binary_llm_audits]
                if item.get("degraded")
            ],
            "silent_fallback_eliminated": all(
                item.get("silent_fallback_eliminated", False)
                for item in [*source_llm_audits, *binary_llm_audits]
            ),
        },
    }
    llm_integrity_path = write_report("llm_backend_integrity_report.json", llm_integrity)
    mainline_vs_control_partition = {
        "generated_at": task_store.now(),
        "official_main": [
            cjson_task_id,
            inih_task_id,
            *binary_real_task_ids.values(),
        ],
        "explicit_control_fallback": list(binary_fallback_task_ids.values()),
        "local_plumbing": list(build_only_task_ids.values()),
    }
    mainline_vs_control_partition_path = write_report(
        "mainline_vs_control_task_partition.json",
        mainline_vs_control_partition,
    )
    strict_llm_block_report = {
        "generated_at": task_store.now(),
        "blocked_task_ids": [
            item["task_id"]
            for item in [*source_llm_audits, *binary_llm_audits]
            if item.get("strict_llm_blocked")
        ],
        "source_blocked_task_ids": [
            item["task_id"] for item in source_llm_audits if item.get("strict_llm_blocked")
        ],
        "binary_blocked_task_ids": [
            item["task_id"] for item in binary_llm_audits if item.get("strict_llm_blocked")
        ],
        "official_main_degraded_count": sum(
            1
            for item in [*source_llm_audits, *binary_llm_audits]
            if item.get("task_partition") == "official_main" and item.get("degraded")
        ),
    }
    strict_llm_block_report_path = write_report("strict_llm_block_report.json", strict_llm_block_report)
    explicit_fallback_control_report = {
        "generated_at": task_store.now(),
        "control_task_ids": list(binary_fallback_task_ids.values()),
        "controls": {
            project_name: _binary_metrics(task_id, task_store)
            for project_name, task_id in binary_fallback_task_ids.items()
        },
    }
    explicit_fallback_control_report_path = write_report(
        "explicit_fallback_control_report.json",
        explicit_fallback_control_report,
    )
    mainline_vs_control_report = {
        "generated_at": task_store.now(),
        "source_official_main": source_llm_audits,
        "binary_official_main": [
            item for item in binary_llm_audits if item.get("task_partition") == "official_main"
        ],
        "explicit_control_fallback": [
            item for item in binary_llm_audits if item.get("task_partition") == "explicit_control_fallback"
        ],
        "summary": {
            "official_main_count": len(mainline_vs_control_partition["official_main"]),
            "explicit_control_fallback_count": len(mainline_vs_control_partition["explicit_control_fallback"]),
            "strict_blocked_main_count": len(strict_llm_block_report["blocked_task_ids"]),
            "degraded_main_count": strict_llm_block_report["official_main_degraded_count"],
        },
    }
    mainline_vs_control_report_path = write_report("mainline_vs_control_report.json", mainline_vs_control_report)

    binary_visibility_summary = {
        "generated_at": task_store.now(),
        "tasks": {},
    }
    binary_upgrade_blockers = {
        "generated_at": task_store.now(),
        "entries": [],
    }
    for project_name, task_id in binary_real_task_ids.items():
        task = task_store.load_task(task_id)
        binary_visibility_summary["tasks"][project_name] = {
            "task_id": task_id,
            "binary_signal_visibility_manifest_path": task.runtime.get("binary_signal_visibility_manifest_path"),
            "binary_observation_gap_report_path": task.runtime.get("binary_observation_gap_report_path"),
            "binary_backend_requirements_manifest_path": task.runtime.get("binary_backend_requirements_manifest_path"),
            "semantic_signal_upgrade_attempts_path": task.runtime.get("semantic_signal_upgrade_attempts_path"),
        }
        binary_upgrade_blockers["entries"].append(
            {
                "project_name": project_name,
                "task_id": task_id,
                "binary_observation_gap_report_path": task.runtime.get("binary_observation_gap_report_path"),
                "binary_backend_requirements_manifest_path": task.runtime.get("binary_backend_requirements_manifest_path"),
                "semantic_signal_upgrade_attempts_path": task.runtime.get("semantic_signal_upgrade_attempts_path"),
                "signal_category_counts": _read_json(task.runtime.get("binary_execution_manifest_path"), {}).get("signal_category_counts", {}),
            }
        )
    binary_visibility_path = write_report("binary_signal_visibility_manifest.json", binary_visibility_summary)
    binary_upgrade_path = write_report("binary_semantic_upgrade_blockers.json", binary_upgrade_blockers)

    source_metrics = {
        "cjson": _source_metrics(cjson_task_id, task_store, cjson_patch_ids),
        "inih": _source_metrics(inih_task_id, task_store, inih_patch_ids),
        "libyaml": _source_metrics(libyaml_task_id, task_store, []),
    }
    binary_metrics = {
        project_name: _binary_metrics(task_id, task_store)
        for project_name, task_id in binary_real_task_ids.items()
    }

    source_binary_gap = {
        "generated_at": task_store.now(),
        "comparisons": [
            _source_binary_gap_entry(
                project_name="cjson",
                source_metrics=source_metrics["cjson"],
                binary_metrics=binary_metrics.get("cjson"),
                binary_task_id=binary_real_task_ids.get("cjson"),
                package_manifest_path=binary_packages.get("cjson", {}).get("binary_package_manifest_path"),
            ),
            _source_binary_gap_entry(
                project_name="inih",
                source_metrics=source_metrics["inih"],
                binary_metrics=binary_metrics.get("inih"),
                binary_task_id=binary_real_task_ids.get("inih"),
                package_manifest_path=binary_packages.get("inih", {}).get("binary_package_manifest_path"),
            ),
            _source_binary_gap_entry(
                project_name="libyaml",
                source_metrics=source_metrics["libyaml"],
                binary_metrics=binary_metrics.get("libyaml"),
                binary_task_id=binary_real_task_ids.get("libyaml"),
                package_manifest_path=binary_packages.get("libyaml", {}).get("binary_package_manifest_path"),
            ),
        ],
    }
    source_binary_gap_path = write_report("source_binary_gap_report.json", source_binary_gap)

    summary = {
        "cjson_source_full": source_metrics["cjson"],
        "inih_source_full": source_metrics["inih"],
        "libyaml_source_sanity": source_metrics["libyaml"],
        "libplist_source_sanity": _classify_repo_first_task(libplist_task_id, task_store),
        "zlib_source_sanity": _classify_repo_first_task(zlib_task_id, task_store),
        "build_only_sanity": {
            project_name: _classify_repo_first_task(task_id, task_store)
            for project_name, task_id in build_only_task_ids.items()
        },
        "binary_real": binary_metrics,
        "binary_fallback": {
            project_name: _binary_metrics(task_id, task_store)
            for project_name, task_id in binary_fallback_task_ids.items()
        },
        "dataset_registry_manifest_path": str(dataset_registry_path),
        "dataset_layering_manifest_path": str(dataset_layering_path),
        "source_vs_binary_dataset_map_path": str(source_binary_map_path),
        "unified_evaluation_matrix_path": str(unified_evaluation_matrix_path),
        "llm_backend_integrity_report_path": str(llm_integrity_path),
        "strict_llm_block_report_path": str(strict_llm_block_report_path),
        "explicit_fallback_control_report_path": str(explicit_fallback_control_report_path),
        "mainline_vs_control_task_partition_path": str(mainline_vs_control_partition_path),
        "mainline_vs_control_report_path": str(mainline_vs_control_report_path),
        "binary_signal_visibility_manifest_path": str(binary_visibility_path),
        "binary_semantic_upgrade_blockers_path": str(binary_upgrade_path),
        "source_binary_gap_report_path": str(source_binary_gap_path),
        "source_generalization_matrix_path": str(REPORTS_ROOT / "source_generalization_matrix.json"),
        "source_generalization": source_generalization,
    }
    write_report("source_binary_hard_convergence_summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

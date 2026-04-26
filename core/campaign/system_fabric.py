from __future__ import annotations

import fcntl
import json
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.campaign.corpus_merger import (
    corpus_policy,
    merge_into_slot_local_corpus,
    merge_into_system_shared_corpus,
    system_corpus_namespace_root,
)
from core.campaign.corpus_quality import safe_corpus_component
from core.campaign.fabric_store import FabricStore, fabric_events_path, fabric_state_path
from core.storage.layout import task_root, tasks_root


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def system_fabric_root() -> Path:
    root = tasks_root() / "_system_fabric"
    root.mkdir(parents=True, exist_ok=True)
    return root


def system_orchestrator_state_path() -> Path:
    return system_fabric_root() / "orchestrator_state.json"


def system_coverage_queue_path() -> Path:
    return system_fabric_root() / "coverage_queue.json"


def system_family_inventory_path() -> Path:
    return system_fabric_root() / "family_inventory.json"


def system_candidate_queue_path() -> Path:
    return system_fabric_root() / "candidate_queue.json"


def system_shared_corpus_root() -> Path:
    root = system_fabric_root() / "shared_corpus"
    root.mkdir(parents=True, exist_ok=True)
    return root


def system_corpus_index_path() -> Path:
    return system_fabric_root() / "shared_corpus_index.json"


@contextmanager
def _system_lock():
    root = system_fabric_root()
    lock_path = root / ".lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _safe_name(value: str | None) -> str:
    return safe_corpus_component(value or "default")


def _system_corpus_key(*, project: str, lane: str, target_mode: str, scope: str, selected_harness: str | None = None) -> str:
    base = f"{_safe_name(project)}/{_safe_name(lane)}/{_safe_name(target_mode)}"
    if scope == "shared":
        return f"{base}/shared"
    return f"{base}/harnesses/{_safe_name(selected_harness)}"


def system_project_shared_corpus_path(*, project: str, lane: str, target_mode: str) -> Path:
    return system_corpus_namespace_root(
        base_root=system_shared_corpus_root(),
        project=project,
        lane=lane,
        target_mode=target_mode,
    ) / "shared"


def system_project_harness_corpus_path(*, project: str, lane: str, target_mode: str, selected_harness: str | None) -> Path:
    return system_corpus_namespace_root(
        base_root=system_shared_corpus_root(),
        project=project,
        lane=lane,
        target_mode=target_mode,
    ) / "harnesses" / _safe_name(selected_harness)


def _compatible_corpus_group(*, lane: str, target_mode: str) -> str | None:
    normalized_lane = str(lane or "").strip().lower()
    normalized_target_mode = str(target_mode or "").strip().lower()
    if normalized_target_mode == "source" and normalized_lane in {"source", "generalized"}:
        return "source_generalized"
    return None


def _system_compatible_corpus_key(*, compatibility_group: str, target_mode: str) -> str:
    return f"_compatible/{_safe_name(compatibility_group)}/{_safe_name(target_mode)}/shared"


def system_compatible_shared_corpus_path(*, compatibility_group: str, target_mode: str) -> Path:
    root = (
        system_shared_corpus_root()
        / "_compatible"
        / _safe_name(compatibility_group)
        / _safe_name(target_mode)
        / "shared"
    )
    root.mkdir(parents=True, exist_ok=True)
    return root


def system_compatible_shared_corpus_index_path(*, compatibility_group: str, target_mode: str) -> Path:
    root = system_compatible_shared_corpus_path(
        compatibility_group=compatibility_group,
        target_mode=target_mode,
    )
    return root.parent / "shared_index.json"


def _initial_orchestrator_state() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "created_at": _now(),
        "updated_at": _now(),
        "active_slots": {},
        "active_campaigns": {},
        "completed_campaigns": [],
        "continuation_queue": [],
        "project_sequence": [],
        "idle_gap_seconds_total": 0.0,
        "failed_campaigns": [],
    }


def _initial_coverage_queue() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "updated_at": _now(),
        "uncovered_functions": [],
        "low_growth_functions": [],
        "stalled_targets": [],
        "per_harness_low_yield": {},
    }


def _initial_family_inventory() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "updated_at": _now(),
        "trace_exact_signatures": [],
        "loose_vulnerable_state_clusters": [],
        "confirmed_families": [],
        "lane_scoped": {},
        "family_feedback_queue": [],
    }


def _initial_candidate_queue() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "updated_at": _now(),
        "candidates": [],
        "trace_worthy": [],
        "reseed_requests": [],
    }


def _upsert_named(items: list[dict[str, Any]], item: dict[str, Any], *, key_fields: tuple[str, ...]) -> None:
    key = tuple(str(item.get(field) or "") for field in key_fields)
    for existing in items:
        if tuple(str(existing.get(field) or "") for field in key_fields) == key:
            existing.update(item)
            existing["hit_count"] = int(existing.get("hit_count") or 0) + 1
            existing["last_seen_at"] = _now()
            return
    payload = dict(item)
    payload.setdefault("first_seen_at", _now())
    payload.setdefault("last_seen_at", _now())
    payload.setdefault("hit_count", 1)
    items.append(payload)


def register_campaign(
    *,
    campaign_task_id: str,
    benchmark: str,
    target_mode: str,
    base_task_id: str | None,
    deadline_at: str,
    slot_label: str | None = None,
) -> dict[str, str]:
    with _system_lock():
        state = _read_json(system_orchestrator_state_path(), _initial_orchestrator_state())
        now = _now()
        label = slot_label or benchmark or campaign_task_id
        state.setdefault("active_slots", {})[label] = {
            "label": label,
            "campaign_task_id": campaign_task_id,
            "benchmark": benchmark,
            "target_mode": target_mode,
            "deadline_at": deadline_at,
            "last_heartbeat_at": now,
            "status": "active",
        }
        state.setdefault("active_campaigns", {})[campaign_task_id] = {
            "campaign_task_id": campaign_task_id,
            "slot_label": label,
            "benchmark": benchmark,
            "target_mode": target_mode,
            "base_task_id": base_task_id,
            "deadline_at": deadline_at,
            "registered_at": now,
            "last_heartbeat_at": now,
            "status": "active",
        }
        sequence = state.setdefault("project_sequence", [])
        if label not in sequence:
            sequence.append(label)
        state["updated_at"] = now
        _write_json(system_orchestrator_state_path(), state)
    lane = _infer_lane(campaign_task_id, benchmark=benchmark, target_mode=target_mode)
    FabricStore().observe_campaign_registration(
        campaign_task_id=campaign_task_id,
        benchmark=benchmark,
        lane=lane,
        target_mode=target_mode,
        base_task_id=base_task_id,
        slot_label=label,
    )
    return {
        "system_fabric_root": str(system_fabric_root()),
        "system_orchestrator_state_path": str(system_orchestrator_state_path()),
        "system_coverage_queue_path": str(system_coverage_queue_path()),
        "system_family_inventory_path": str(system_family_inventory_path()),
        "system_candidate_queue_path": str(system_candidate_queue_path()),
        "system_corpus_index_path": str(system_corpus_index_path()),
        "fabric_state_path": str(fabric_state_path()),
        "fabric_events_path": str(fabric_events_path()),
    }


def heartbeat_campaign(
    *,
    campaign_task_id: str,
    status: str,
    round_count: int,
    metrics: dict[str, Any] | None = None,
) -> None:
    with _system_lock():
        state = _read_json(system_orchestrator_state_path(), _initial_orchestrator_state())
        campaign = state.setdefault("active_campaigns", {}).get(campaign_task_id)
        if campaign:
            campaign["last_heartbeat_at"] = _now()
            campaign["status"] = status
            campaign["round_count"] = round_count
            campaign["metrics"] = metrics or {}
            slot_label = campaign.get("slot_label")
            if slot_label and slot_label in state.setdefault("active_slots", {}):
                state["active_slots"][slot_label]["last_heartbeat_at"] = campaign["last_heartbeat_at"]
                state["active_slots"][slot_label]["status"] = status
        state["updated_at"] = _now()
        _write_json(system_orchestrator_state_path(), state)
    FabricStore().heartbeat_by_campaign(
        campaign_task_id=campaign_task_id,
        status=status,
        round_count=round_count,
        metrics=metrics or {},
    )


def complete_campaign(
    *,
    campaign_task_id: str,
    completed_reason: str,
    next_base_task_id: str | None,
    remaining_seconds: int,
    min_continuation_seconds: int = 90,
) -> dict[str, Any]:
    label = None
    existing_completed: dict[str, Any] | None = None
    with _system_lock():
        state = _read_json(system_orchestrator_state_path(), _initial_orchestrator_state())
        for item in state.setdefault("completed_campaigns", []):
            if item.get("campaign_task_id") == campaign_task_id:
                existing_completed = dict(item)
                label = existing_completed.get("slot_label")
                break
        if existing_completed is None:
            campaign = state.setdefault("active_campaigns", {}).pop(campaign_task_id, None)
            completed = dict(campaign or {"campaign_task_id": campaign_task_id})
            completed.update(
                {
                    "completed_at": _now(),
                    "completed_reason": completed_reason,
                    "next_base_task_id": next_base_task_id,
                    "remaining_seconds": int(remaining_seconds),
                }
            )
            label = completed.get("slot_label")
            state.setdefault("completed_campaigns", []).append(completed)
            if int(remaining_seconds) > 0:
                work_item = {
                    "kind": "campaign_continuation",
                    "campaign_task_id": campaign_task_id,
                    "slot_label": completed.get("slot_label"),
                    "benchmark": completed.get("benchmark"),
                    "target_mode": completed.get("target_mode"),
                    "next_base_task_id": next_base_task_id,
                    "deadline_remaining_seconds": int(remaining_seconds),
                    "created_at": _now(),
                    "reason": completed_reason,
                }
                state.setdefault("continuation_queue", []).append(work_item)
            state["updated_at"] = _now()
            _write_json(system_orchestrator_state_path(), state)
        else:
            completed = existing_completed
    fabric_record = FabricStore().complete_by_campaign(
        campaign_task_id=campaign_task_id,
        completed_reason=completed_reason,
        next_base_task_id=next_base_task_id,
        remaining_seconds=remaining_seconds,
        min_continuation_seconds=min_continuation_seconds,
    )
    if fabric_record:
        completed["fabric_work_item_id"] = fabric_record.get("work_item_id")
        completed["fabric_continuation_work_item_id"] = fabric_record.get("continuation_work_item_id")
        completed["fabric_state_path"] = str(fabric_state_path())
        completed["fabric_events_path"] = str(fabric_events_path())
        if label:
            completed["slot_label"] = label
    return completed


def fail_campaign(
    *,
    campaign_task_id: str,
    failure_reason: str,
    remaining_seconds: int,
    next_base_task_id: str | None = None,
    requeue_on_failure: bool = True,
    min_continuation_seconds: int = 90,
) -> dict[str, Any]:
    existing_completed: dict[str, Any] | None = None
    with _system_lock():
        state = _read_json(system_orchestrator_state_path(), _initial_orchestrator_state())
        for item in state.setdefault("failed_campaigns", []):
            if item.get("campaign_task_id") == campaign_task_id:
                return item
        for item in state.setdefault("completed_campaigns", []):
            if item.get("campaign_task_id") == campaign_task_id:
                existing_completed = dict(item)
                break
        if existing_completed is not None:
            failed = existing_completed
        else:
            campaign = state.setdefault("active_campaigns", {}).pop(campaign_task_id, None)
            failed = dict(campaign or {"campaign_task_id": campaign_task_id})
            failed.update(
                {
                    "failed_at": _now(),
                    "failure_reason": failure_reason,
                    "next_base_task_id": next_base_task_id,
                    "remaining_seconds": int(remaining_seconds),
                    "requeue_on_failure": bool(requeue_on_failure),
                }
            )
            state.setdefault("failed_campaigns", []).append(failed)
            state["updated_at"] = _now()
            _write_json(system_orchestrator_state_path(), state)
    if existing_completed is not None:
        target_base = (
            next_base_task_id
            or failed.get("next_base_task_id")
            or failed.get("base_task_id")
        )
        late_record = None
        if requeue_on_failure and int(remaining_seconds) > 0 and target_base:
            late_record = FabricStore().complete_by_campaign(
                campaign_task_id=campaign_task_id,
                completed_reason=str(failed.get("completed_reason") or failure_reason),
                next_base_task_id=str(target_base),
                remaining_seconds=remaining_seconds,
                min_continuation_seconds=min_continuation_seconds,
                completion_source="late_slot_failure_after_completion",
            )
        if late_record:
            failed["fabric_work_item_id"] = late_record.get("work_item_id")
            failed["fabric_continuation_work_item_id"] = late_record.get("continuation_work_item_id")
            failed["fabric_state_path"] = str(fabric_state_path())
            failed["fabric_events_path"] = str(fabric_events_path())
        failed["late_failure_reason"] = failure_reason
        failed["slot_failure_after_completion"] = True
        return failed
    fabric_record = FabricStore().fail_by_campaign(
        campaign_task_id=campaign_task_id,
        failure_reason=failure_reason,
        remaining_seconds=remaining_seconds,
        next_base_task_id=next_base_task_id,
        requeue_on_failure=requeue_on_failure,
        min_continuation_seconds=min_continuation_seconds,
    )
    if fabric_record:
        failed["fabric_work_item_id"] = fabric_record.get("work_item_id")
        failed["fabric_requeued_work_item_id"] = fabric_record.get("requeued_work_item_id")
        failed["fabric_state_path"] = str(fabric_state_path())
        failed["fabric_events_path"] = str(fabric_events_path())
    return failed


def _infer_lane(campaign_task_id: str, *, benchmark: str, target_mode: str) -> str:
    payload = _read_json(task_root(campaign_task_id) / "task.json", {})
    metadata = payload.get("metadata") or {}
    runtime = payload.get("runtime") or {}
    raw = (
        runtime.get("fabric_lane")
        or runtime.get("campaign_lane")
        or metadata.get("fabric_lane")
        or metadata.get("campaign_lane")
    )
    normalized = str(raw or "").strip().lower()
    if normalized in {"source", "generalized", "binary"}:
        return normalized
    if bool(runtime.get("generalized_source")) or bool(metadata.get("generalized_source")):
        return "generalized"
    if "generalized" in str(benchmark or "").lower():
        return "generalized"
    if bool(metadata.get("binary_mode")) or str(target_mode or "").strip().lower() == "binary":
        return "binary"
    return "source"


def _campaign_fabric_context(campaign_task_id: str) -> dict[str, Any]:
    payload = _read_json(task_root(campaign_task_id) / "task.json", {})
    metadata = payload.get("metadata") or {}
    runtime = payload.get("runtime") or {}
    return {
        "namespace": (
            str(runtime.get("fabric_namespace") or metadata.get("fabric_namespace") or "").strip() or None
        ),
        "slot_label": (
            str(runtime.get("slot_controller_label") or metadata.get("slot_controller_label") or "").strip()
            or str(metadata.get("benchmark") or "").strip()
            or campaign_task_id
        ),
    }


def claim_planning_feedback(
    *,
    campaign_task_id: str,
    target_mode: str,
    selected_harness: str | None,
    limit: int = 8,
) -> dict[str, Any]:
    coverage = _read_json(system_coverage_queue_path(), _initial_coverage_queue())
    family = _read_json(system_family_inventory_path(), _initial_family_inventory())
    candidates = _read_json(system_candidate_queue_path(), _initial_candidate_queue())
    harness_key = _safe_name(selected_harness)
    fabric_context = _campaign_fabric_context(campaign_task_id)

    def _select(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered = []
        for item in items:
            if item.get("target_mode") and item.get("target_mode") != target_mode:
                continue
            if item.get("cooldown_campaign_task_id") == campaign_task_id:
                continue
            filtered.append(item)
        filtered.sort(key=lambda x: (int(x.get("priority") or 0), int(x.get("hit_count") or 0)), reverse=True)
        return filtered[:limit]

    claimed_feedback_items: list[dict[str, Any]] = []
    claimed_coverage: list[dict[str, Any]] = []
    claimed_candidates: list[dict[str, Any]] = []
    claimed_family: list[dict[str, Any]] = []
    fabric = FabricStore()
    for _ in range(max(1, min(int(limit), 4))):
        item = fabric.claim_feedback_work_item(
            campaign_task_id=campaign_task_id,
            namespace=fabric_context.get("namespace"),
            lease_seconds=300,
            consumer_id=f"planning::{campaign_task_id}",
            allowed_item_types=["coverage", "candidate_bridge", "family_promotion"],
        )
        if not item:
            break
        claimed_feedback_items.append(
            {
                "item_id": item.get("item_id") or item.get("work_item_id"),
                "item_type": item.get("item_type"),
                "source_campaign": item.get("source_campaign"),
                "source_round": item.get("source_round"),
                "source_slot": item.get("source_slot"),
                "queue_name": item.get("queue_name"),
            }
        )
        payload = dict(item.get("payload") or {})
        if str(item.get("item_type") or "") == "coverage":
            claimed_coverage.extend(list(payload.get("coverage_entries") or []))
        elif str(item.get("item_type") or "") == "candidate_bridge":
            claimed_candidates.extend(list(payload.get("candidate_entries") or []))
        elif str(item.get("item_type") or "") == "family_promotion":
            claimed_family.extend(list(payload.get("family_entries") or []))
        fabric.ack_feedback_work_item(
            work_item_id=str(item.get("work_item_id") or ""),
            ack_source="planning_feedback_consumed",
        )
    claimed_uncovered = [item for item in claimed_coverage if str(item.get("queue_kind") or "") == "uncovered"]
    claimed_low_growth = [item for item in claimed_coverage if str(item.get("queue_kind") or "") == "low_growth"]
    claimed_stalled = [item for item in claimed_coverage if str(item.get("queue_kind") or "") == "stalled"]

    return {
        "system_uncovered_functions": _select(list(coverage.get("uncovered_functions") or []) + claimed_uncovered),
        "system_low_growth_functions": _select(list(coverage.get("low_growth_functions") or []) + claimed_low_growth),
        "system_stalled_targets": _select(list(coverage.get("stalled_targets") or []) + claimed_stalled),
        "system_candidate_bridge": _select(list(candidates.get("candidates") or []) + claimed_candidates),
        "system_trace_worthy_candidates": _select(list(candidates.get("trace_worthy") or [])),
        "system_family_feedback_queue": _select(list(family.get("family_feedback_queue") or []) + claimed_family),
        "per_harness_low_yield": (coverage.get("per_harness_low_yield") or {}).get(harness_key, {}),
        "system_coverage_queue_path": str(system_coverage_queue_path()),
        "system_candidate_queue_path": str(system_candidate_queue_path()),
        "system_family_inventory_path": str(system_family_inventory_path()),
        "claimed_feedback_items": claimed_feedback_items,
        "claimed_feedback_item_count": len(claimed_feedback_items),
    }


def stage_system_corpus(
    *,
    project: str,
    lane: str,
    target_mode: str,
    selected_harness: str | None,
    round_corpus_root: Path,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    corpus_index = _read_json(system_corpus_index_path(), {"corpora": {}})
    compatibility_group = _compatible_corpus_group(lane=lane, target_mode=target_mode)
    shared_index_path = (
        (corpus_index.get("corpora") or {})
        .get(_system_corpus_key(project=project, lane=lane, target_mode=target_mode, scope="shared"), {})
        .get("last_index_path")
    )
    harness_index_path = (
        (corpus_index.get("corpora") or {})
        .get(
            _system_corpus_key(
                project=project,
                lane=lane,
                target_mode=target_mode,
                scope="harness",
                selected_harness=selected_harness,
            ),
            {},
        )
        .get("last_index_path")
    )
    compatible_index_path = (
        str(
            system_compatible_shared_corpus_index_path(
                compatibility_group=compatibility_group,
                target_mode=target_mode,
            )
        )
        if compatibility_group
        else None
    )
    shared_root = system_project_shared_corpus_path(project=project, lane=lane, target_mode=target_mode)
    harness_root = system_project_harness_corpus_path(
        project=project,
        lane=lane,
        target_mode=target_mode,
        selected_harness=selected_harness,
    )
    compatible_root = (
        system_compatible_shared_corpus_path(compatibility_group=compatibility_group, target_mode=target_mode)
        if compatibility_group
        else None
    )
    index_path = manifest_path.with_name("system_corpus_stage_index.json") if manifest_path else None
    layers: list[dict[str, Any]] = [
        {
            "root": str(shared_root),
            "label": "system_shared",
            "scope": "system_shared",
            "project": project,
            "lane": lane,
            "target_mode": target_mode,
            "priority_weight": 3.9,
            "index_path": shared_index_path,
            "import_reason": "same_project_system_shared_pool",
            "selection_reason": "stage_system_shared_pool_into_round_active",
        },
        {
            "root": str(harness_root),
            "label": "system_harness",
            "scope": "system_harness",
            "project": project,
            "lane": lane,
            "target_mode": target_mode,
            "harness": selected_harness,
            "priority_weight": 4.3,
            "index_path": harness_index_path,
            "import_reason": "same_project_system_harness_pool",
            "selection_reason": "stage_system_harness_pool_into_round_active",
        },
    ]
    if compatibility_group and compatible_root is not None:
        layers.append(
            {
                "root": str(compatible_root),
                "label": "system_compatible_shared",
                "scope": "system_compatible_shared",
                "project": None,
                "lane": None,
                "target_mode": target_mode,
                "priority_weight": 4.6,
                "index_path": compatible_index_path,
                "import_reason": "compatible_cross_lane_shared_pool",
                "selection_reason": "stage_compatible_cross_lane_pool_into_round_active",
                "cross_lane_priority_bonus": 50.0,
                "cross_project_priority_bonus": 25.0,
            }
        )
    return merge_into_slot_local_corpus(
        round_corpus_root,
        layers,
        destination_project=project,
        destination_lane=lane,
        destination_target_mode=target_mode,
        destination_harness=selected_harness,
        decision_log_path=manifest_path,
        index_path=index_path,
        consumer_task_id=round_corpus_root.parent.parent.name,
        **corpus_policy("round_local"),
    )


def update_after_round(
    *,
    campaign_task_id: str,
    round_task_id: str,
    project: str,
    lane: str,
    target_mode: str,
    selected_harness: str | None,
    selected_target_function: str | None,
    round_corpus_root: Path,
    coverage_state: dict[str, Any],
    family_inventory: dict[str, list[str]],
    round_record: dict[str, Any],
    now_iso: str,
    compatible_export_layers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    with _system_lock():
        compatibility_group = _compatible_corpus_group(lane=lane, target_mode=target_mode)
        shared_root = system_project_shared_corpus_path(project=project, lane=lane, target_mode=target_mode)
        harness_root = system_project_harness_corpus_path(
            project=project,
            lane=lane,
            target_mode=target_mode,
            selected_harness=selected_harness,
        )
        compatible_root = (
            system_compatible_shared_corpus_path(compatibility_group=compatibility_group, target_mode=target_mode)
            if compatibility_group
            else None
        )
        shared_manifest_path = task_root(round_task_id) / "runtime" / "system_shared_corpus_merge_manifest.json"
        harness_manifest_path = task_root(round_task_id) / "runtime" / "system_harness_corpus_merge_manifest.json"
        compatible_manifest_path = task_root(round_task_id) / "runtime" / "system_compatible_shared_corpus_merge_manifest.json"
        shared_growth = merge_into_system_shared_corpus(
            shared_root,
            [
                {
                    "root": str(round_corpus_root),
                    "label": "round_local",
                    "scope": "round_local",
                    "project": project,
                    "lane": lane,
                    "target_mode": target_mode,
                    "harness": selected_harness,
                    "priority_weight": 5.8,
                    "task_id": round_task_id,
                    "campaign_task_id": campaign_task_id,
                    "selected_target_function": selected_target_function,
                    "selection_reason": "export_round_local_into_project_system_shared_pool",
                    "export_reason": "same_project_system_shared_export",
                }
            ],
            destination_kind="system_shared",
            destination_scope="system_shared",
            destination_project=project,
            destination_lane=lane,
            destination_target_mode=target_mode,
            destination_harness=None,
            decision_log_path=shared_manifest_path,
            index_path=shared_manifest_path.with_name("system_shared_corpus_index.json"),
            consumer_task_id=round_task_id,
            consumer_campaign_task_id=campaign_task_id,
            **corpus_policy("system_shared"),
        )
        harness_growth = merge_into_system_shared_corpus(
            harness_root,
            [
                {
                    "root": str(round_corpus_root),
                    "label": "round_local",
                    "scope": "round_local",
                    "project": project,
                    "lane": lane,
                    "target_mode": target_mode,
                    "harness": selected_harness,
                    "priority_weight": 5.8,
                    "task_id": round_task_id,
                    "campaign_task_id": campaign_task_id,
                    "selected_target_function": selected_target_function,
                    "selection_reason": "export_round_local_into_project_system_harness_pool",
                    "export_reason": "same_project_system_harness_export",
                }
            ],
            destination_kind="system_harness",
            destination_scope="system_harness",
            destination_project=project,
            destination_lane=lane,
            destination_target_mode=target_mode,
            destination_harness=selected_harness,
            decision_log_path=harness_manifest_path,
            index_path=harness_manifest_path.with_name("system_harness_corpus_index.json"),
            consumer_task_id=round_task_id,
            consumer_campaign_task_id=campaign_task_id,
            **corpus_policy("system_harness"),
        )
        compatible_growth = {
            "new_files": 0,
            "selected_count": 0,
            "quality_gate_pass_rate": 0.0,
            "quality_gate_rejected_count": 0,
            "cross_lane_selected_count": 0,
            "cross_project_selected_count": 0,
            "decision_log_path": str(compatible_manifest_path),
        }
        if compatibility_group and compatible_root is not None and compatible_export_layers:
            compatible_growth = merge_into_system_shared_corpus(
                compatible_root,
                compatible_export_layers,
                destination_kind="system_shared",
                destination_scope="system_compatible_shared",
                destination_project=None,
                destination_lane=compatibility_group,
                destination_target_mode=target_mode,
                destination_harness=None,
                decision_log_path=compatible_manifest_path,
                index_path=system_compatible_shared_corpus_index_path(
                    compatibility_group=compatibility_group,
                    target_mode=target_mode,
                ),
                consumer_task_id=round_task_id,
                consumer_campaign_task_id=campaign_task_id,
                **corpus_policy("system_shared"),
            )
        corpus_index = _read_json(system_corpus_index_path(), {"schema_version": 1, "corpora": {}, "updated_at": now_iso})
        shared_key = _system_corpus_key(project=project, lane=lane, target_mode=target_mode, scope="shared")
        shared_entry = corpus_index.setdefault("corpora", {}).setdefault(
            shared_key,
            {"project": project, "lane": lane, "target_mode": target_mode, "scope": "shared", "file_count": 0, "growth_count": 0},
        )
        shared_entry["file_count"] = sum(1 for p in shared_root.rglob("*") if p.is_file())
        shared_entry["growth_count"] = int(shared_entry.get("growth_count") or 0) + int(shared_growth.get("new_files") or 0)
        shared_entry["last_round_task_id"] = round_task_id
        shared_entry["updated_at"] = now_iso
        shared_entry["last_merge_manifest_path"] = str(shared_manifest_path)
        shared_entry["last_index_path"] = str(shared_manifest_path.with_name("system_shared_corpus_index.json"))
        shared_entry["last_cross_harness_selected_count"] = int(shared_growth.get("cross_harness_selected_count") or 0)
        harness_key = _system_corpus_key(
            project=project,
            lane=lane,
            target_mode=target_mode,
            scope="harness",
            selected_harness=selected_harness,
        )
        harness_entry = corpus_index.setdefault("corpora", {}).setdefault(
            harness_key,
            {
                "project": project,
                "lane": lane,
                "target_mode": target_mode,
                "scope": "harness",
                "harness": selected_harness,
                "file_count": 0,
                "growth_count": 0,
            },
        )
        harness_entry["file_count"] = sum(1 for p in harness_root.rglob("*") if p.is_file())
        harness_entry["growth_count"] = int(harness_entry.get("growth_count") or 0) + int(harness_growth.get("new_files") or 0)
        harness_entry["last_round_task_id"] = round_task_id
        harness_entry["updated_at"] = now_iso
        harness_entry["last_merge_manifest_path"] = str(harness_manifest_path)
        harness_entry["last_index_path"] = str(harness_manifest_path.with_name("system_harness_corpus_index.json"))
        if compatibility_group and compatible_root is not None:
            compatible_key = _system_compatible_corpus_key(
                compatibility_group=compatibility_group,
                target_mode=target_mode,
            )
            compatible_entry = corpus_index.setdefault("corpora", {}).setdefault(
                compatible_key,
                {
                    "compatibility_group": compatibility_group,
                    "target_mode": target_mode,
                    "scope": "compatible_shared",
                    "file_count": 0,
                    "growth_count": 0,
                },
            )
            compatible_entry["file_count"] = sum(1 for p in compatible_root.rglob("*") if p.is_file())
            compatible_entry["growth_count"] = int(compatible_entry.get("growth_count") or 0) + int(
                compatible_growth.get("new_files") or 0
            )
            compatible_entry["last_round_task_id"] = round_task_id
            compatible_entry["updated_at"] = now_iso
            compatible_entry["last_merge_manifest_path"] = str(compatible_manifest_path)
            compatible_entry["last_index_path"] = str(
                system_compatible_shared_corpus_index_path(
                    compatibility_group=compatibility_group,
                    target_mode=target_mode,
                )
            )
        corpus_index["updated_at"] = now_iso
        _write_json(system_corpus_index_path(), corpus_index)

        coverage = _read_json(system_coverage_queue_path(), _initial_coverage_queue())
        for item in coverage_state.get("uncovered_function_queue") or []:
            name = str(item.get("name") if isinstance(item, dict) else item).strip()
            if name:
                _upsert_named(
                    coverage.setdefault("uncovered_functions", []),
                    {
                        "name": name,
                        "target_mode": target_mode,
                        "harness": selected_harness,
                        "queue_kind": "uncovered",
                        "priority": 50,
                        "source_campaign_task_id": campaign_task_id,
                        "source_round_task_id": round_task_id,
                        "reason": "uncovered_function",
                    },
                    key_fields=("target_mode", "name"),
                )
        for item in coverage_state.get("low_growth_function_queue") or []:
            name = str(item.get("name") if isinstance(item, dict) else item).strip()
            if name:
                _upsert_named(
                    coverage.setdefault("low_growth_functions", []),
                    {
                        "name": name,
                        "target_mode": target_mode,
                        "harness": selected_harness,
                        "queue_kind": "low_growth",
                        "priority": 60,
                        "source_campaign_task_id": campaign_task_id,
                        "source_round_task_id": round_task_id,
                        "reason": "low_growth_function",
                    },
                    key_fields=("target_mode", "name"),
                )
        if coverage_state.get("coverage_stalled") or round_record.get("stalled") or round_record.get("coverage_stalled"):
            stalled_name = selected_target_function or selected_harness or f"{target_mode}_target"
            _upsert_named(
                coverage.setdefault("stalled_targets", []),
                {
                    "name": stalled_name,
                    "target_mode": target_mode,
                    "harness": selected_harness,
                    "queue_kind": "stalled",
                    "priority": 70,
                    "source_campaign_task_id": campaign_task_id,
                    "source_round_task_id": round_task_id,
                    "reason": "coverage_or_proxy_stalled",
                },
                key_fields=("target_mode", "name"),
            )
            harness_key = _safe_name(selected_harness)
            per_harness = coverage.setdefault("per_harness_low_yield", {}).setdefault(harness_key, {})
            per_harness["harness"] = selected_harness
            per_harness["target_mode"] = target_mode
            per_harness["stalled_count"] = int(per_harness.get("stalled_count") or 0) + 1
            per_harness["last_round_task_id"] = round_task_id
            per_harness["updated_at"] = now_iso
        coverage["updated_at"] = now_iso
        _write_json(system_coverage_queue_path(), coverage)

        family = _read_json(system_family_inventory_path(), _initial_family_inventory())
        lane_key = _safe_name(target_mode)
        lane = family.setdefault("lane_scoped", {}).setdefault(
            lane_key,
            {"trace_exact_signatures": [], "loose_vulnerable_state_clusters": [], "confirmed_families": []},
        )

        def _merge_family(key: str, values: list[str]) -> list[str]:
            existing = set(family.setdefault(key, []) or [])
            lane_existing = set(lane.setdefault(key, []) or [])
            new_values = []
            for value in values:
                if not value:
                    continue
                if value not in existing:
                    new_values.append(value)
                existing.add(value)
                lane_existing.add(value)
            family[key] = sorted(existing)
            lane[key] = sorted(lane_existing)
            return sorted(new_values)

        new_exact = _merge_family("trace_exact_signatures", family_inventory.get("trace_exact_signatures") or [])
        new_loose = _merge_family("loose_vulnerable_state_clusters", family_inventory.get("loose_vulnerable_state_clusters") or [])
        new_confirmed = _merge_family("confirmed_families", family_inventory.get("confirmed_families") or [])
        if not new_loose and not new_confirmed and (
            coverage_state.get("coverage_stalled") or round_record.get("family_stagnation_count", 0) >= 1
        ):
            feedback_name = selected_target_function or selected_harness or f"{target_mode}_target"
            _upsert_named(
                family.setdefault("family_feedback_queue", []),
                {
                    "name": feedback_name,
                    "target_mode": target_mode,
                    "harness": selected_harness,
                    "queue_kind": "family_promotion",
                    "priority": 80,
                    "source_campaign_task_id": campaign_task_id,
                    "source_round_task_id": round_task_id,
                    "reason": "family_stagnation_or_no_new_loose_cluster",
                },
                key_fields=("target_mode", "name"),
            )
        family["updated_at"] = now_iso
        _write_json(system_family_inventory_path(), family)

        candidates = _read_json(system_candidate_queue_path(), _initial_candidate_queue())
        candidate_count_before = len(candidates.get("candidates") or [])
        trace_worthy_before = len(candidates.get("trace_worthy") or [])
        suspicious_name = selected_target_function or selected_harness or f"{target_mode}_target"
        no_crash = int(round_record.get("new_raw_crash_count") or round_record.get("crash_count") or 0) <= 0
        no_trace = int(round_record.get("new_traced_crash_count") or round_record.get("traced_crash_count") or 0) <= 0
        stalled = bool(coverage_state.get("coverage_stalled") or round_record.get("stalled") or round_record.get("proxy_stalled"))
        if no_crash and (stalled or coverage_state.get("low_growth_function_queue") or coverage_state.get("uncovered_function_queue")):
            candidate = {
                "name": suspicious_name,
                "candidate_kind": "suspicious_no_crash_coverage_or_low_growth",
                "target_mode": target_mode,
                "harness": selected_harness,
                "queue_kind": "candidate_bridge",
                "priority": 65,
                "source_campaign_task_id": campaign_task_id,
                "source_round_task_id": round_task_id,
                "reason": "no_crash_but_coverage_low_growth_or_stalled",
            }
            _upsert_named(candidates.setdefault("candidates", []), candidate, key_fields=("target_mode", "candidate_kind", "name"))
            # Repeated no-crash low-yield candidates become trace-worthy scheduling candidates,
            # even if an actual tracer still needs a replayable input before confirmation.
            for existing in candidates.get("candidates") or []:
                if (
                    existing.get("target_mode") == candidate["target_mode"]
                    and existing.get("candidate_kind") == candidate["candidate_kind"]
                    and existing.get("name") == candidate["name"]
                    and int(existing.get("hit_count") or 0) >= 2
                ):
                    trace_item = dict(existing)
                    trace_item["candidate_kind"] = "trace_worthy_suspicious_no_crash"
                    trace_item["queue_kind"] = "candidate_bridge"
                    trace_item["priority"] = 90
                    trace_item["trace_gate"] = "queue_when_replayable_input_available"
                    _upsert_named(candidates.setdefault("trace_worthy", []), trace_item, key_fields=("target_mode", "candidate_kind", "name"))
        if target_mode == "binary" and (stalled or no_trace):
            reseed_item = {
                "name": suspicious_name,
                "target_mode": target_mode,
                "harness": selected_harness,
                "queue_kind": "candidate_bridge",
                "priority": 75,
                "source_campaign_task_id": campaign_task_id,
                "source_round_task_id": round_task_id,
                "reason": "binary_signal_or_trace_stalled_reseed",
            }
            _upsert_named(candidates.setdefault("reseed_requests", []), reseed_item, key_fields=("target_mode", "name"))
        candidates["updated_at"] = now_iso
        _write_json(system_candidate_queue_path(), candidates)

        fabric_context = _campaign_fabric_context(campaign_task_id)

        def _current_round_entries(items: list[dict[str, Any]], *, queue_kind: str | None = None, limit: int = 8) -> list[dict[str, Any]]:
            selected: list[dict[str, Any]] = []
            seen: set[tuple[str, str]] = set()
            for entry in items:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("source_round_task_id") or "") != round_task_id:
                    continue
                key = (str(entry.get("queue_kind") or queue_kind or ""), str(entry.get("name") or ""))
                if key in seen:
                    continue
                seen.add(key)
                payload = dict(entry)
                if queue_kind and not payload.get("queue_kind"):
                    payload["queue_kind"] = queue_kind
                selected.append(payload)
                if len(selected) >= limit:
                    break
            return selected

        coverage_feedback_entries = (
            _current_round_entries(list(coverage.get("uncovered_functions") or []), queue_kind="uncovered")
            + _current_round_entries(list(coverage.get("low_growth_functions") or []), queue_kind="low_growth")
            + _current_round_entries(list(coverage.get("stalled_targets") or []), queue_kind="stalled")
        )[:10]
        if coverage_feedback_entries:
            FabricStore().enqueue_work_item(
                lane=lane,
                target_mode=target_mode,
                project=project,
                benchmark=str(fabric_context.get("slot_label") or project),
                namespace=fabric_context.get("namespace"),
                slot_label=str(fabric_context.get("slot_label") or campaign_task_id),
                base_task_id=campaign_task_id,
                donor_task_id=campaign_task_id,
                priority=75,
                dedupe_key=f"fabric-feedback::{campaign_task_id}::{round_task_id}::coverage",
                kind="coverage",
                item_type="coverage",
                payload={
                    "coverage_entries": coverage_feedback_entries,
                    "system_coverage_queue_path": str(system_coverage_queue_path()),
                },
                source_campaign=campaign_task_id,
                source_round=round_task_id,
                source_slot=str(fabric_context.get("slot_label") or campaign_task_id),
                metadata={
                    "feedback_reason": "round_coverage_feedback",
                    "system_coverage_queue_path": str(system_coverage_queue_path()),
                },
            )

        candidate_feedback_entries = (
            _current_round_entries(list(candidates.get("candidates") or []), queue_kind="candidate_bridge")
            + _current_round_entries(list(candidates.get("trace_worthy") or []), queue_kind="candidate_bridge")
        )[:10]
        if candidate_feedback_entries:
            FabricStore().enqueue_work_item(
                lane=lane,
                target_mode=target_mode,
                project=project,
                benchmark=str(fabric_context.get("slot_label") or project),
                namespace=fabric_context.get("namespace"),
                slot_label=str(fabric_context.get("slot_label") or campaign_task_id),
                base_task_id=campaign_task_id,
                donor_task_id=campaign_task_id,
                priority=70,
                dedupe_key=f"fabric-feedback::{campaign_task_id}::{round_task_id}::candidate",
                kind="candidate_bridge",
                item_type="candidate_bridge",
                payload={
                    "candidate_entries": candidate_feedback_entries,
                    "system_candidate_queue_path": str(system_candidate_queue_path()),
                },
                source_campaign=campaign_task_id,
                source_round=round_task_id,
                source_slot=str(fabric_context.get("slot_label") or campaign_task_id),
                metadata={
                    "feedback_reason": "round_candidate_bridge_feedback",
                    "system_candidate_queue_path": str(system_candidate_queue_path()),
                },
            )

        family_feedback_entries = _current_round_entries(list(family.get("family_feedback_queue") or []), queue_kind="family_promotion")
        if family_feedback_entries:
            FabricStore().enqueue_work_item(
                lane=lane,
                target_mode=target_mode,
                project=project,
                benchmark=str(fabric_context.get("slot_label") or project),
                namespace=fabric_context.get("namespace"),
                slot_label=str(fabric_context.get("slot_label") or campaign_task_id),
                base_task_id=campaign_task_id,
                donor_task_id=campaign_task_id,
                priority=68,
                dedupe_key=f"fabric-feedback::{campaign_task_id}::{round_task_id}::family",
                kind="family_promotion",
                item_type="family_promotion",
                payload={
                    "family_entries": family_feedback_entries,
                    "system_family_inventory_path": str(system_family_inventory_path()),
                },
                source_campaign=campaign_task_id,
                source_round=round_task_id,
                source_slot=str(fabric_context.get("slot_label") or campaign_task_id),
                metadata={
                    "feedback_reason": "round_family_feedback",
                    "system_family_inventory_path": str(system_family_inventory_path()),
                },
            )

    return {
        "system_fabric_root": str(system_fabric_root()),
        "system_orchestrator_state_path": str(system_orchestrator_state_path()),
        "system_coverage_queue_path": str(system_coverage_queue_path()),
        "system_family_inventory_path": str(system_family_inventory_path()),
        "system_candidate_queue_path": str(system_candidate_queue_path()),
        "system_corpus_index_path": str(system_corpus_index_path()),
        "system_shared_corpus_new_files": int(shared_growth.get("new_files") or 0),
        "system_harness_corpus_new_files": int(harness_growth.get("new_files") or 0),
        "system_compatible_shared_new_files": int(compatible_growth.get("new_files") or 0),
        "system_shared_corpus_merge_manifest_path": str(shared_manifest_path),
        "system_harness_corpus_merge_manifest_path": str(harness_manifest_path),
        "system_compatible_shared_corpus_merge_manifest_path": str(compatible_manifest_path),
        "system_shared_corpus_index_path": str(shared_manifest_path.with_name("system_shared_corpus_index.json")),
        "system_harness_corpus_index_path": str(harness_manifest_path.with_name("system_harness_corpus_index.json")),
        "system_compatible_shared_corpus_index_path": str(
            system_compatible_shared_corpus_index_path(
                compatibility_group=compatibility_group,
                target_mode=target_mode,
            )
            if compatibility_group
            else compatible_manifest_path.with_name("system_compatible_shared_corpus_index.json")
        ),
        "system_cross_harness_selected_count": int(shared_growth.get("cross_harness_selected_count") or 0),
        "system_compatible_selected_count": int(compatible_growth.get("selected_count") or 0),
        "system_compatible_cross_lane_selected_count": int(compatible_growth.get("cross_lane_selected_count") or 0),
        "system_compatible_cross_project_selected_count": int(compatible_growth.get("cross_project_selected_count") or 0),
        "system_compatible_quality_gate_pass_rate": float(compatible_growth.get("quality_gate_pass_rate") or 0.0),
        "system_compatible_quality_gate_rejected_count": int(
            compatible_growth.get("quality_gate_rejected_count") or 0
        ),
        "system_candidate_bridge_new_count": max(0, len(candidates.get("candidates") or []) - candidate_count_before),
        "system_trace_worthy_new_count": max(0, len(candidates.get("trace_worthy") or []) - trace_worthy_before),
        "system_new_exact_signature_count": len(new_exact),
        "system_new_loose_cluster_count": len(new_loose),
        "system_new_confirmed_family_count": len(new_confirmed),
        "system_low_growth_queue_count": len(coverage.get("low_growth_functions") or []),
        "system_uncovered_queue_count": len(coverage.get("uncovered_functions") or []),
        "system_stalled_target_count": len(coverage.get("stalled_targets") or []),
    }

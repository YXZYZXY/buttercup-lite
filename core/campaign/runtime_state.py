from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.analysis.loose_cluster import derive_loose_cluster_features
from core.binary.ida_runtime_view import build_binary_ida_runtime_view
from core.campaign.coverage_plane import (
    claim_coverage_targets_for_session,
    initialize_campaign_coverage_plane,
    load_round_coverage_snapshot,
    peek_coverage_plane_inputs,
    update_coverage_plane_after_round,
)
from core.campaign.corpus_merger import (
    corpus_policy,
    merge_into_campaign_local_corpus,
    merge_into_slot_local_corpus,
)
from core.campaign.corpus_quality import safe_corpus_component
from core.seed.harness_selector import load_harness_candidates
from core.campaign.system_fabric import (
    claim_planning_feedback,
    register_campaign,
    stage_system_corpus,
    system_candidate_queue_path,
    system_compatible_shared_corpus_index_path,
    system_compatible_shared_corpus_path,
    system_coverage_queue_path,
    system_family_inventory_path,
    system_fabric_root,
    system_orchestrator_state_path,
    update_after_round,
)
from core.storage.layout import (
    binary_feedback_bridge_path,
    binary_ida_runtime_view_path,
    campaign_coverage_plane_state_path,
    campaign_coverage_queue_consumption_path,
    campaign_coverage_queue_path,
    campaign_corpus_merge_manifest_path,
    campaign_corpus_stage_manifest_path,
    campaign_harness_corpora_root_path,
    campaign_runtime_state_path,
    campaign_shared_corpus_path,
    campaign_slot_manifest_path,
    campaign_strength_report_path,
    coverage_plane_snapshot_path,
    fuzz_manifest_path,
    repro_family_manifest_path,
    task_root,
    trace_family_manifest_path,
)

if TYPE_CHECKING:
    from core.state.task_state import TaskStateStore


STACK_OFFSET_PATTERN = re.compile(r"\+0x([0-9a-fA-F]+)")
ACCESS_KIND_PATTERN = re.compile(r"\b(READ|WRITE)\s+of\s+size\b", re.IGNORECASE)
COVERAGE_TARGET_STALL_THRESHOLD = 3
FAMILY_STAGNATION_TRIGGER_THRESHOLD = 2
FAMILY_CONFIRMED_VULN_DISCOVERY_THRESHOLD = 2
FAMILY_RECONFIRMATION_THRESHOLD_ROUNDS = 5


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _normalize_campaign_runtime_state_path(raw_path: Any) -> Path | None:
    if not raw_path:
        return None
    candidate = Path(str(raw_path))
    if candidate.name == "campaign_runtime_state.json":
        return candidate
    if candidate.parent.name == "runtime":
        return candidate.parent / "campaign_runtime_state.json"
    if candidate.name == "runtime":
        return candidate / "campaign_runtime_state.json"
    return None


def _load_donor_campaign_runtime_state(base_task: Any) -> tuple[str | None, dict[str, Any]]:
    base_task_runtime = dict(getattr(base_task, "runtime", {}) or {})
    donor_runtime_state_path = None
    for field_name in (
        "campaign_runtime_state_path",
        "campaign_coverage_plane_state_path",
        "campaign_coverage_queue_path",
        "campaign_coverage_queue_consumption_path",
    ):
        donor_runtime_state_path = _normalize_campaign_runtime_state_path(base_task_runtime.get(field_name))
        if donor_runtime_state_path:
            break
    if not donor_runtime_state_path:
        return None, {}
    donor_campaign_task_id = (
        donor_runtime_state_path.parent.parent.name
        if donor_runtime_state_path.parent.name == "runtime"
        else None
    )
    donor_runtime_state = _read_json(donor_runtime_state_path, {})
    if not isinstance(donor_runtime_state, dict):
        return donor_campaign_task_id, {}
    return donor_campaign_task_id, donor_runtime_state


def _dedupe_names(raw_items: list[dict[str, Any]] | list[str] | None, *, limit: int = 16) -> list[dict[str, Any]]:
    if not raw_items:
        return []
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_items:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            payload = {
                "name": name,
                "target_type": str(item.get("target_type") or "function").strip() or "function",
                "queue_kind": str(item.get("queue_kind") or "").strip() or None,
                "priority": int(item.get("priority", 0) or 0),
                "reason": str(item.get("reason") or "").strip() or None,
                "source_level": str(item.get("source_level") or "").strip() or None,
                "degraded_reason": str(item.get("degraded_reason") or "").strip() or None,
                "degraded_detail": dict(item.get("degraded_detail") or {}) or None,
                "harness": str(item.get("harness") or "").strip() or None,
                "coverage_fraction": float(item.get("coverage_fraction", 0.0) or 0.0),
                "total_lines": int(item.get("total_lines", 0) or 0),
                "covered_lines": int(item.get("covered_lines", 0) or 0),
                "function_paths": list(item.get("function_paths") or []),
                "selection_scope": str(item.get("selection_scope") or "").strip() or None,
                "consume_count": int(item.get("consume_count", 0) or 0),
                "hit_count": int(item.get("hit_count", 0) or 0),
                "activation_state": str(item.get("activation_state") or "").strip() or None,
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


def _build_coverage_request_plan(selected_targets: list[dict[str, Any]]) -> dict[str, Any]:
    if not selected_targets:
        return {
            "primary_queue_kind": None,
            "queue_kind_counts": {},
            "target_entries": [],
            "focus_groups": [],
        }
    queue_kind_counts: dict[str, int] = {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in selected_targets:
        queue_kind = str(item.get("queue_kind") or "coverage_gap").strip() or "coverage_gap"
        queue_kind_counts[queue_kind] = queue_kind_counts.get(queue_kind, 0) + 1
        grouped.setdefault(queue_kind, []).append(dict(item))
    ordering = {
        "family_confirmation": 0,
        "binary_reseed": 1,
        "binary_candidate": 2,
        "binary_family": 3,
        "binary_feedback": 4,
        "binary_trace_admission": 5,
        "binary_focus": 6,
        "uncovered": 7,
        "low_growth": 8,
        "stalled": 9,
        "partial_degraded": 10,
        "harness_focus": 11,
        "candidate_bridge": 12,
        "coverage_gap": 13,
    }
    focus_groups: list[dict[str, Any]] = []
    for queue_kind, entries in sorted(
        grouped.items(),
        key=lambda item: (
            ordering.get(item[0], 99),
            -max(int(entry.get("priority") or 0) for entry in item[1]),
            item[0],
        ),
    ):
        sorted_entries = sorted(
            entries,
            key=lambda entry: (
                0 if str(entry.get("selection_scope") or "") == "system" else 1,
                -int(entry.get("priority") or 0),
                float(entry.get("coverage_fraction") if entry.get("coverage_fraction") is not None else 2.0),
                int(entry.get("consume_count") or 0),
                entry.get("name") or "",
            ),
        )
        focus_groups.append(
            {
                "queue_kind": queue_kind,
                "target_names": [str(entry.get("name") or "") for entry in sorted_entries if entry.get("name")][:5],
                "target_entries": sorted_entries[:5],
            },
        )
    return {
        "primary_queue_kind": focus_groups[0]["queue_kind"] if focus_groups else None,
        "queue_kind_counts": queue_kind_counts,
        "target_entries": selected_targets[:12],
        "focus_groups": focus_groups[:5],
    }


def _safe_harness_dir(name: str) -> str:
    return safe_corpus_component(name or "default_harness")


def _coverage_claim_limit(*, lane: str, target_mode: str) -> int:
    if target_mode == "binary":
        return 3
    if lane == "generalized":
        return 5
    return 6


def _find_harness_pool_entry(harness_pool: list[dict[str, Any]], harness_name: str | None) -> dict[str, Any] | None:
    target = str(harness_name or "").strip()
    if not target:
        return None
    for entry in harness_pool:
        if str(entry.get("harness_name") or "").strip() == target:
            return dict(entry)
    return None


def _coverage_claim_primary_entry(coverage_claim: dict[str, Any]) -> dict[str, Any]:
    entries = list(coverage_claim.get("selected_entries") or [])
    return dict(entries[0]) if entries else {}


def _coverage_harness_override_name(coverage_claim: dict[str, Any]) -> str | None:
    harness_targets = list(coverage_claim.get("selected_harness_targets") or [])
    if harness_targets:
        candidate = str(harness_targets[0] or "").strip()
        if candidate:
            return candidate
    primary = _coverage_claim_primary_entry(coverage_claim)
    candidate = str(primary.get("harness") or "").strip()
    return candidate or None


def _coverage_session_budget(round_budget_seconds: int, *, lane: str, coverage_claim: dict[str, Any]) -> tuple[int, str, float]:
    base_budget = max(60, int(round_budget_seconds))
    queue_kind = str(coverage_claim.get("coverage_queue_kind") or "").strip().lower()
    primary_entry = _coverage_claim_primary_entry(coverage_claim)
    multiplier = 1.0
    reason = "round_budget_default"
    if queue_kind == "uncovered":
        multiplier = 1.35
        reason = "extend_for_uncovered_function_pressure"
    elif queue_kind == "low_growth":
        multiplier = 1.2
        reason = "extend_for_low_growth_followup"
    elif queue_kind == "stalled":
        multiplier = 0.8
        reason = "shorten_for_stalled_rotation"
    elif queue_kind == "partial_degraded":
        multiplier = 0.9
        reason = "shorten_for_partial_coverage_recheck"
    elif queue_kind == "harness_focus":
        multiplier = 0.85
        reason = "shorten_for_harness_focus_recheck"
    if lane == "generalized" and queue_kind in {"partial_degraded", "stalled"}:
        multiplier = max(multiplier, 0.95)
        reason = f"{reason}_generalized"
    if int(primary_entry.get("priority") or 0) >= 100:
        multiplier += 0.1
        reason = f"{reason}_high_priority"
    adjusted = int(base_budget * multiplier)
    budget = max(60, min(max(base_budget + 600, int(base_budget * 1.5)), adjusted))
    return budget, reason, round(multiplier, 3)


def _coverage_queue_driven_reseed(coverage_claim: dict[str, Any], *, coverage_stalled: bool) -> tuple[bool, str | None]:
    queue_kind = str(coverage_claim.get("coverage_queue_kind") or "").strip().lower()
    if queue_kind in {"uncovered", "low_growth", "partial_degraded", "stalled", "harness_focus"}:
        return True, f"coverage_queue::{queue_kind}"
    if coverage_stalled:
        return True, "coverage_stalled"
    if coverage_claim.get("selected_target_function"):
        return True, "coverage_queue::selected_target"
    return False, None


def _coverage_exact_priority_targets(coverage_claim: dict[str, Any]) -> list[dict[str, Any]]:
    selected_targets = list(coverage_claim.get("selected_target_functions") or [])
    exact_priority: list[dict[str, Any]] = []
    for item in selected_targets:
        if not isinstance(item, dict):
            continue
        source_level = str(item.get("source_level") or "").strip().lower()
        queue_kind = str(item.get("queue_kind") or "").strip().lower()
        if source_level != "exact":
            continue
        if queue_kind not in {"uncovered", "low_growth"}:
            continue
        exact_priority.append(dict(item))
    return _dedupe_names(exact_priority, limit=8)


def _coverage_target_stall_rounds(state: dict[str, Any], selected_target_function: str | None) -> int:
    target_name = str(selected_target_function or "").strip()
    if not target_name:
        return 0
    coverage_state = dict(state.get("coverage_state") or {})
    per_target_stall_counts = dict(coverage_state.get("per_target_stall_counts") or {})
    target_state = dict(per_target_stall_counts.get(target_name) or {})
    return int(target_state.get("stall_rounds") or 0)


def _resolve_current_harness_binding(
    *,
    task_id: str | None,
    harness_name: str | None,
    project: str | None,
) -> dict[str, Any]:
    candidate_task_id = str(task_id or "").strip()
    if not candidate_task_id:
        return {}
    build_registry_path = task_root(candidate_task_id) / "build" / "build_registry.json"
    if not build_registry_path.exists():
        return {}
    requested = str(harness_name or "").strip().lower()
    try:
        candidates = load_harness_candidates(build_registry_path, project)
    except Exception:
        return {}
    if not candidates:
        return {}
    selected = None
    if requested:
        for candidate in candidates:
            if candidate.name.strip().lower() == requested:
                selected = candidate
                break
    if selected is None:
        selected = candidates[0]
    return {
        "selected_harness": selected.name,
        "selected_harness_path": str(selected.executable_path),
        "harness_source_path": str(selected.source_path) if selected.source_path else None,
    }


def _corpus_file_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for candidate in path.rglob("*") if candidate.is_file())


def _existing_file_paths(raw_paths: list[str] | None) -> list[str]:
    selected: list[str] = []
    for raw_path in raw_paths or []:
        candidate = Path(str(raw_path))
        if candidate.exists() and candidate.is_file():
            selected.append(str(candidate))
    return selected


def _runtime_compatible_corpus_group(*, lane: str, target_mode: str) -> str | None:
    normalized_lane = str(lane or "").strip().lower()
    normalized_target_mode = str(target_mode or "").strip().lower()
    if normalized_target_mode == "source" and normalized_lane in {"source", "generalized"}:
        return "source_generalized"
    return None


def _empty_corpus_stage_summary(
    *,
    decision_log_path: Path | None = None,
    index_path: Path | None = None,
    skip_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "new_files": 0,
        "new_bytes": 0,
        "merge_count": 0,
        "reject_count": 0,
        "selected_count": 0,
        "selected_imported_count": 0,
        "cross_lane_selected_count": 0,
        "cross_project_selected_count": 0,
        "cross_harness_selected_count": 0,
        "quality_gate_passed_count": 0,
        "quality_gate_rejected_count": 0,
        "quality_gate_pass_rate": 0.0,
        "selected_files": [],
        "rejected_files": [],
        "selected_origin_lane_counts": {},
        "selected_import_reason_counts": {},
        "decision_log_path": str(decision_log_path) if decision_log_path else None,
        "index_path": str(index_path) if index_path else None,
        "skip_reason": skip_reason,
    }


def _stage_generalized_reverse_corpus(
    *,
    project: str,
    lane: str,
    target_mode: str,
    selected_harness: str | None,
    round_task_id: str,
    campaign_task_id: str,
    round_corpus_root: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    decision_log_path = manifest_path.with_name("generalized_reverse_corpus_stage_manifest.json")
    index_path = manifest_path.with_name("generalized_reverse_corpus_stage_index.json")
    compatibility_group = _runtime_compatible_corpus_group(lane=lane, target_mode=target_mode)
    if lane != "source" or target_mode != "source" or not compatibility_group:
        return _empty_corpus_stage_summary(
            decision_log_path=decision_log_path,
            index_path=index_path,
            skip_reason="reverse_generalized_import_not_applicable",
        )
    compatible_root = system_compatible_shared_corpus_path(
        compatibility_group=compatibility_group,
        target_mode=target_mode,
    )
    compatible_index_path = system_compatible_shared_corpus_index_path(
        compatibility_group=compatibility_group,
        target_mode=target_mode,
    )
    compatible_index = _read_json(compatible_index_path, {})
    allowed_paths: list[str] = []
    seen_paths: set[str] = set()
    for row in list(compatible_index.get("files") or compatible_index.get("selected_files") or []):
        if not isinstance(row, dict):
            continue
        origin_lane = str(row.get("origin_lane") or row.get("lane") or "").strip().lower()
        if origin_lane != "generalized":
            continue
        candidate_path = Path(str(row.get("destination_path") or row.get("path") or ""))
        if not candidate_path.exists() or not candidate_path.is_file():
            continue
        resolved_path = str(candidate_path.resolve())
        if resolved_path in seen_paths:
            continue
        seen_paths.add(resolved_path)
        allowed_paths.append(resolved_path)
    if not allowed_paths:
        return _empty_corpus_stage_summary(
            decision_log_path=decision_log_path,
            index_path=index_path,
            skip_reason="no_generalized_entries_in_compatible_pool",
        )
    return merge_into_slot_local_corpus(
        round_corpus_root,
        [
            {
                "root": str(compatible_root),
                "allowed_paths": allowed_paths,
                "label": "system_compatible_generalized_reverse",
                "scope": "system_compatible_shared",
                "project": None,
                "lane": None,
                "target_mode": target_mode,
                "priority_weight": 4.7,
                "index_path": str(compatible_index_path),
                "import_reason": "generalized_compatible_shared_pool",
                "selection_reason": "stage_generalized_reverse_pool_into_source_round_active",
                "cross_lane_priority_bonus": 75.0,
                "cross_project_priority_bonus": 25.0,
            }
        ],
        destination_project=project,
        destination_lane=lane,
        destination_target_mode=target_mode,
        destination_harness=selected_harness,
        decision_log_path=decision_log_path,
        index_path=index_path,
        consumer_task_id=round_task_id,
        consumer_campaign_task_id=campaign_task_id,
        **corpus_policy("round_local"),
    )


def _build_compatible_corpus_export_layers(
    *,
    campaign_task_id: str,
    round_task_id: str,
    round_record: dict[str, Any],
    project: str,
    lane: str,
    target_mode: str,
    selected_harness: str | None,
    selected_target_function: str | None,
    coverage_growth: float,
    round_local_growth_hint: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if target_mode == "binary" or lane not in {"source", "generalized"}:
        return [], {
            "generalized_branch_entered": lane == "generalized",
            "export_guard_reason": "target_mode_or_lane_not_supported",
            "new_corpus_files_count": 0,
            "coverage_growth": coverage_growth,
        }
    round_root = task_root(round_task_id)
    fuzz_manifest = _read_json(fuzz_manifest_path(round_task_id), {})
    if not fuzz_manifest:
        # Backward-compatible fallback for older runs that staged this manifest under runtime/.
        fuzz_manifest = _read_json(round_root / "runtime" / "fuzz_manifest.json", {})
    suspicious_payload = _read_json(round_root / "runtime" / "suspicious_candidate_queue.json", {})
    round_corpus_root = round_root / "corpus" / "active"
    crash_root = round_root / "crashes" / "raw"
    explicit_new_corpus_files = _existing_file_paths(list(fuzz_manifest.get("new_corpus_files") or []))
    generalized_round_local_fallback_used = False
    round_local_growth_hint = int(round_local_growth_hint or 0)
    if lane == "generalized" and not explicit_new_corpus_files and round_local_growth_hint > 0:
        fallback_round_local_files = (
            _existing_file_paths([str(path) for path in round_corpus_root.rglob("*") if path.is_file()])
            if round_corpus_root.exists()
            else []
        )
        if fallback_round_local_files:
            explicit_new_corpus_files = fallback_round_local_files
            generalized_round_local_fallback_used = True
    new_corpus_files = explicit_new_corpus_files
    raw_crashes = _existing_file_paths(list(fuzz_manifest.get("raw_crashes") or []))
    suspicious_trace_worthy = int(suspicious_payload.get("trace_worthy_candidate_count") or 0) > 0
    export_layers: list[dict[str, Any]] = []
    if raw_crashes:
        export_layers.append(
            {
                "root": str(crash_root),
                "allowed_paths": raw_crashes,
                "label": "round_crash",
                "scope": "round_crash",
                "project": project,
                "lane": lane,
                "target_mode": target_mode,
                "harness": selected_harness,
                "priority_weight": 6.6,
                "task_id": round_task_id,
                "campaign_task_id": campaign_task_id,
                "selected_target_function": selected_target_function,
                "origin_signal": "raw_crash_signal",
                "origin_input_role": "raw_crash",
                "export_reason": "compatible_cross_lane_export",
                "selection_reason": "export_raw_crash_inputs_into_compatible_pool",
            }
        )
    high_value_signals: list[str] = []
    generalized_corpus_size_increased = lane == "generalized" and bool(new_corpus_files)
    if coverage_growth > 0.0 and new_corpus_files:
        high_value_signals.append("coverage_growth")
        if lane == "generalized":
            high_value_signals.append("coverage_growing_input")
    if int(round_record.get("new_traced_crash_count") or 0) > 0 and new_corpus_files:
        high_value_signals.append("trace_signal")
    if suspicious_trace_worthy and new_corpus_files:
        high_value_signals.append("suspicious_trace_candidate")
    if generalized_corpus_size_increased:
        high_value_signals.append("corpus_size_increased")
    export_trace = {
        "generalized_branch_entered": lane == "generalized",
        "generalized_round_local_fallback_used": generalized_round_local_fallback_used,
        "round_local_growth_hint": round_local_growth_hint,
        "new_corpus_files_count": len(new_corpus_files),
        "coverage_growth": coverage_growth,
        "suspicious_trace_worthy": suspicious_trace_worthy,
        "high_value_signals": list(high_value_signals),
    }
    if high_value_signals:
        export_layers.append(
            {
                "root": str(round_corpus_root),
                "allowed_paths": new_corpus_files,
                "label": "round_high_value",
                "scope": "round_local",
                "project": project,
                "lane": lane,
                "target_mode": target_mode,
                "harness": selected_harness,
                "priority_weight": 6.2,
                "task_id": round_task_id,
                "campaign_task_id": campaign_task_id,
                "selected_target_function": selected_target_function,
                "origin_signal": "+".join(high_value_signals),
                "origin_input_role": "new_corpus_high_value",
                "export_reason": "compatible_cross_lane_export",
                "selection_reason": "export_high_value_corpus_inputs_into_compatible_pool",
            }
        )
    if not export_layers:
        export_trace["export_guard_reason"] = "no_exportable_round_inputs"
    return export_layers, export_trace


def _corpus_stage_state_for_round(round_task_id: str) -> dict[str, Any]:
    payload = _read_json(campaign_corpus_stage_manifest_path(round_task_id), {})
    stages = [
        dict(payload.get("system_stage") or {}),
        dict(payload.get("compatible_reverse_stage") or {}),
        dict(payload.get("campaign_shared_stage") or {}),
        dict(payload.get("campaign_harness_stage") or {}),
    ]
    quality_gate_passed = sum(int(stage.get("quality_gate_passed_count") or 0) for stage in stages)
    quality_gate_rejected = sum(int(stage.get("quality_gate_rejected_count") or 0) for stage in stages)
    selected_imported_count = sum(int(stage.get("selected_imported_count") or 0) for stage in stages)
    cross_lane_transfer_count = sum(int(stage.get("cross_lane_selected_count") or 0) for stage in stages)
    cross_project_transfer_count = sum(int(stage.get("cross_project_selected_count") or 0) for stage in stages)
    imported_item_ids: list[str] = []
    rejected_item_ids: list[str] = []
    imported_items: list[dict[str, Any]] = []
    rejection_reason_counts: dict[str, int] = {}
    for stage_name, stage in (
        ("system_stage", dict(payload.get("system_stage") or {})),
        ("compatible_reverse_stage", dict(payload.get("compatible_reverse_stage") or {})),
        ("campaign_shared_stage", dict(payload.get("campaign_shared_stage") or {})),
        ("campaign_harness_stage", dict(payload.get("campaign_harness_stage") or {})),
    ):
        for item in list(stage.get("selected_files") or []):
            item_id = str(item.get("item_id") or "").strip()
            if not item_id or str(item.get("source_label") or "") == "existing_destination":
                continue
            imported_item_ids.append(item_id)
            imported_items.append(
                {
                    "stage": stage_name,
                    "item_id": item_id,
                    "origin_lane": item.get("origin_lane"),
                    "consumer_lane": item.get("consumer_lane"),
                    "origin_campaign_task_id": item.get("origin_campaign_task_id"),
                    "consumer_campaign_task_id": item.get("consumer_campaign_task_id"),
                    "import_reason": item.get("import_reason"),
                    "source_corpus_tier": item.get("source_corpus_tier"),
                    "consumer_corpus_tier": item.get("consumer_corpus_tier"),
                    "cross_lane_transfer": bool(item.get("cross_lane_transfer")),
                }
            )
        for item in list(stage.get("rejected_files") or []):
            item_id = str(item.get("item_id") or "").strip()
            if item_id:
                rejected_item_ids.append(item_id)
            reason = str(item.get("rejection_reason") or "").strip()
            if reason:
                rejection_reason_counts[reason] = rejection_reason_counts.get(reason, 0) + 1
    return {
        "stage_manifest_path": str(campaign_corpus_stage_manifest_path(round_task_id)),
        "selected_imported_count": selected_imported_count,
        "cross_lane_transfer_count": cross_lane_transfer_count,
        "cross_project_transfer_count": cross_project_transfer_count,
        "imported_item_ids": imported_item_ids[:512],
        "rejected_item_ids": rejected_item_ids[:512],
        "imported_items": imported_items[:128],
        "rejection_reason_counts": rejection_reason_counts,
        "quality_gate_passed_count": quality_gate_passed,
        "quality_gate_rejected_count": quality_gate_rejected,
        "quality_gate_pass_rate": round(
            quality_gate_passed / max(quality_gate_passed + quality_gate_rejected, 1),
            6,
        ),
        "system_stage_new_files": int((payload.get("system_stage") or {}).get("new_files") or 0),
        "system_stage_selected_imported_count": int((payload.get("system_stage") or {}).get("selected_imported_count") or 0),
        "system_stage_cross_lane_transfer_count": int((payload.get("system_stage") or {}).get("cross_lane_selected_count") or 0),
        "system_stage_cross_project_transfer_count": int(
            (payload.get("system_stage") or {}).get("cross_project_selected_count") or 0
        ),
    }


def _infer_campaign_lane(base_task, target_mode: str) -> str:
    lane = (
        base_task.runtime.get("fabric_lane")
        or base_task.runtime.get("campaign_lane")
        or base_task.metadata.get("fabric_lane")
        or base_task.metadata.get("campaign_lane")
    )
    normalized = str(lane or "").strip().lower()
    if normalized in {"source", "generalized", "binary"}:
        return normalized
    if base_task.runtime.get("generalized_source") or base_task.metadata.get("generalized_source"):
        return "generalized"
    if target_mode == "binary" or base_task.metadata.get("binary_mode") or base_task.runtime.get("binary_mode"):
        return "binary"
    return "source"


def _build_harness_pool(
    *,
    base_task,
    target_mode: str,
) -> list[dict[str, Any]]:
    if target_mode == "binary":
        harness_name = (
            str(base_task.runtime.get("active_harness") or "").strip()
            or str(base_task.metadata.get("binary_target_name") or "").strip()
            or "binary_target"
        )
        focus = str(base_task.runtime.get("selected_binary_slice_focus") or "").strip() or None
        return [
            {
                "harness_name": harness_name,
                "selected_harness_path": base_task.runtime.get("active_harness_path"),
                "status": "active",
                "recent_session_count": 0,
                "recent_new_crash_count": 0,
                "recent_new_trace_count": 0,
                "recent_coverage_growth": 0.0,
                "recent_corpus_growth": 0,
                "last_used_at": None,
                "cooldown_until_session": 0,
                "selection_score": 1.0,
                "binary_focus": focus,
                "reasons": ["binary_target_lane"],
            },
        ]

    build_registry_path = str(base_task.runtime.get("build_registry_path") or "").strip()
    if not build_registry_path:
        fallback = str(base_task.runtime.get("active_harness") or "default_harness")
        return [
            {
                "harness_name": fallback,
                "selected_harness_path": base_task.runtime.get("active_harness_path"),
                "status": "active",
                "recent_session_count": 0,
                "recent_new_crash_count": 0,
                "recent_new_trace_count": 0,
                "recent_coverage_growth": 0.0,
                "recent_corpus_growth": 0,
                "last_used_at": None,
                "cooldown_until_session": 0,
                "selection_score": 1.0,
                "reasons": ["task_runtime_fallback"],
            },
        ]

    candidates = load_harness_candidates(build_registry_path, base_task.metadata.get("project"))
    if not candidates:
        fallback = str(base_task.runtime.get("active_harness") or "default_harness")
        return [
            {
                "harness_name": fallback,
                "selected_harness_path": base_task.runtime.get("active_harness_path"),
                "status": "active",
                "recent_session_count": 0,
                "recent_new_crash_count": 0,
                "recent_new_trace_count": 0,
                "recent_coverage_growth": 0.0,
                "recent_corpus_growth": 0,
                "last_used_at": None,
                "cooldown_until_session": 0,
                "selection_score": 1.0,
                "reasons": ["empty_build_registry_fallback"],
            },
        ]

    pool: list[dict[str, Any]] = []
    for candidate in candidates:
        pool.append(
            {
                "harness_name": candidate.name,
                "selected_harness_path": str(candidate.executable_path),
                "status": "active",
                "recent_session_count": 0,
                "recent_new_crash_count": 0,
                "recent_new_trace_count": 0,
                "recent_coverage_growth": 0.0,
                "recent_corpus_growth": 0,
                "last_used_at": None,
                "cooldown_until_session": 0,
                "selection_score": float(candidate.score or 0),
                "reasons": list(candidate.reasons),
            },
        )
    pool.sort(key=lambda item: float(item.get("selection_score") or 0.0), reverse=True)
    return pool


def _initial_shared_corpus(
    *,
    campaign_task_id: str,
    base_task_id: str,
    project: str,
    lane: str,
    target_mode: str,
) -> dict[str, int]:
    shared_root = campaign_shared_corpus_path(campaign_task_id)
    base_root = task_root(base_task_id)
    base_active = base_root / "corpus" / "active"
    base_binary_active = base_root / "corpus" / "binary_active"
    source_root = base_binary_active if target_mode == "binary" else base_active
    if not source_root.exists():
        source_root = base_active if base_active.exists() else base_binary_active
    manifest_path = campaign_corpus_merge_manifest_path(campaign_task_id)
    return merge_into_campaign_local_corpus(
        shared_root,
        [
            {
                "root": str(source_root),
                "label": "round_local",
                "scope": "base_task_seed",
                "project": project,
                "lane": lane,
                "target_mode": target_mode,
                "priority_weight": 5.8,
                "task_id": base_task_id,
                "campaign_task_id": campaign_task_id,
            }
        ],
        destination_kind="campaign_shared",
        destination_project=project,
        destination_lane=lane,
        destination_target_mode=target_mode,
        destination_harness=None,
        decision_log_path=manifest_path,
        index_path=manifest_path.with_name("campaign_corpus_merge_index.json"),
        **corpus_policy("campaign_shared"),
    )


def load_campaign_runtime_state(task_id: str) -> dict[str, Any]:
    return _read_json(campaign_runtime_state_path(task_id), {})


def initialize_campaign_runtime_state(
    task_id: str,
    *,
    task_store: "TaskStateStore",
    base_task_id: str,
    benchmark: str,
    target_mode: str,
    duration_seconds: int,
) -> dict[str, Any]:
    existing = load_campaign_runtime_state(task_id)
    if existing:
        return existing

    campaign_task = task_store.load_task(task_id)
    base_task = task_store.load_task(base_task_id)
    _donor_campaign_task_id, donor_runtime_state = _load_donor_campaign_runtime_state(base_task)
    donor_family_diversification = dict(donor_runtime_state.get("family_diversification") or {})
    inherited_last_selected_harness = str(
        donor_runtime_state.get("last_selected_harness")
        or donor_family_diversification.get("last_selected_harness")
        or ""
    ).strip() or None
    inherited_family_stagnation_count = int(donor_family_diversification.get("stagnation_count") or 0)
    project = str(campaign_task.metadata.get("project") or base_task.metadata.get("project") or benchmark or "unknown")
    lane = _infer_campaign_lane(campaign_task, target_mode)
    shared_seed = _initial_shared_corpus(
        campaign_task_id=task_id,
        base_task_id=base_task_id,
        project=project,
        lane=lane,
        target_mode=target_mode,
    )
    shared_seed_quality_passed = int(shared_seed.get("quality_gate_passed_count") or 0)
    shared_seed_quality_rejected = int(shared_seed.get("quality_gate_rejected_count") or 0)
    shared_seed_quality_seen = shared_seed_quality_passed + shared_seed_quality_rejected
    coverage_plane_paths = initialize_campaign_coverage_plane(
        task_id,
        project=project,
        lane=lane,
        target_mode=target_mode,
        updated_at=task_store.now(),
    )
    state = {
        "task_id": task_id,
        "benchmark": benchmark,
        "project": project,
        "lane": lane,
        "target_mode": target_mode,
        "base_task_id": base_task_id,
        "created_at": task_store.now(),
        "updated_at": task_store.now(),
        "campaign_duration_seconds": duration_seconds,
        "session_count": 0,
        "last_selected_harness": inherited_last_selected_harness,
        "last_selected_target_function": None,
        "last_session_started_at": None,
        "last_session_finished_at": None,
        "last_idle_gap_started_at": task_store.now(),
        "session_continuity_mode": "fresh_round_clone",
        "active_session_task_id": None,
        "active_session_reuse_count": 0,
        "last_session_summary_path": None,
        "last_corpus_state_reference": None,
        "last_coverage_snapshot_reference": None,
        "last_stagnation_state": {},
        "active_harness_pool": _build_harness_pool(base_task=base_task, target_mode=target_mode),
        "coverage_state": {
            "exact_or_partial": "unknown",
            "coverage_control_mode": "unknown",
            "covered_function_set": [],
            "covered_function_count": 0,
            "uncovered_function_queue": [],
            "low_growth_function_queue": [],
            "partial_degraded_target_queue": [],
            "stalled_target_queue": [],
            "per_harness_recent_growth": {},
            "per_target_stall_counts": {},
            "recent_coverage_growth": 0.0,
            "last_target_stall_count": 0,
            "last_exact_coverage_time": None,
            "last_line_coverage_fraction": None,
            "coverage_stalled": False,
            "degraded_reason": None,
            "degraded_detail": None,
            "campaign_coverage_plane_state_path": coverage_plane_paths.get("campaign_coverage_plane_state_path"),
            "campaign_coverage_queue_path": coverage_plane_paths.get("campaign_coverage_queue_path"),
            "campaign_coverage_queue_consumption_path": str(campaign_coverage_queue_consumption_path(task_id)),
            "binary_coverage_proxy": {},
        },
        "family_inventory": {
            "trace_exact_signatures": [],
            "loose_vulnerable_state_clusters": [],
            "confirmed_families": [],
            "unresolved_loose_clusters": [],
            "promotion_blockers": [],
            "loose_cluster_details": {},
            "confirmed_family_details": {},
            "last_trace_family_manifest_path": None,
            "last_repro_family_manifest_path": None,
            "last_new_exact_signatures": [],
            "last_new_loose_clusters": [],
            "last_new_confirmed_families": [],
            "requires_reconfirmation_families": [],
            "requires_reconfirmation_count": 0,
            "reconfirmation_threshold_rounds": FAMILY_RECONFIRMATION_THRESHOLD_ROUNDS,
        },
        "family_diversification": {
            "stagnation_count": inherited_family_stagnation_count,
            "last_new_trace_exact_count": 0,
            "last_new_loose_cluster_count": 0,
            "last_new_confirmed_family_count": 0,
            "unresolved_loose_cluster_count": 0,
            "promotion_blocker_count": 0,
            "last_unresolved_loose_clusters": [],
            "last_promotion_blockers": [],
            "last_triggered_at": donor_family_diversification.get("last_triggered_at"),
            "last_selected_harness": inherited_last_selected_harness,
        },
        "candidate_bridge_queue": [],
        "binary_runtime": {
            "binary_feedback_bridge_path": None,
            "binary_ida_runtime_view_path": None,
            "ida_fact_source": None,
            "ida_refresh_task_id": None,
            "binary_mode": None,
            "binary_provenance": None,
            "provenance_class": None,
            "selected_target_function": None,
            "selected_binary_slice_focus": None,
            "feedback_state": None,
            "feedback_action": None,
            "informational_only": False,
            "promotion_rate": 0.0,
            "signal_category_counts": {},
            "reseed_candidate_queue": [],
            "trace_admission_candidates": [],
            "focus_candidates": [],
            "parser_candidates": [],
            "entry_candidates": [],
            "callgraph_neighbors": [],
            "contract": {},
            "coverage_proxy": {},
        },
        "distinct_pov_names": [],
        "shared_corpus": {
            "root": str(campaign_shared_corpus_path(task_id)),
            "harness_corpora_root": str(campaign_harness_corpora_root_path(task_id)),
            "file_count": _corpus_file_count(campaign_shared_corpus_path(task_id)),
            "growth_count": int(shared_seed.get("new_files", 0)),
            "last_merged_round_task_id": None,
            "last_growth_bytes": int(shared_seed.get("new_bytes", 0)),
            "last_merge_manifest_path": shared_seed.get("decision_log_path"),
            "last_merge_index_path": shared_seed.get("index_path"),
            "last_campaign_shared_index_path": shared_seed.get("index_path"),
            "last_campaign_harness_index_path": None,
            "quality_gate_passed_count": shared_seed_quality_passed,
            "quality_gate_rejected_count": shared_seed_quality_rejected,
            "quality_gate_pass_rate": round(shared_seed_quality_passed / max(shared_seed_quality_seen, 1), 6),
            "harness_index_paths": {},
        },
        "metrics": {
            "llm_request_count_total": 0,
            "llm_request_count_by_stage": {},
            "llm_success_count": 0,
            "llm_failure_count": 0,
            "api_calls_per_hour": 0.0,
            "fuzz_session_count": 0,
            "harness_switch_count": 0,
            "reseed_trigger_count": 0,
            "exact_coverage_available_ratio": 0.0,
            "coverage_partial_sessions": 0,
            "coverage_fallback_sessions": 0,
            "coverage_unknown_sessions": 0,
            "coverage_binary_signal_sessions": 0,
            "shared_corpus_growth_count": int(shared_seed.get("new_files", 0)),
            "family_diversification_trigger_count": 0,
            "generalized_candidate_bridge_count": 0,
            "trace_worthy_candidate_count": 0,
            "trace_exact_signature_count": 0,
            "loose_cluster_count": 0,
            "confirmed_family_count": 0,
            "unresolved_loose_cluster_count": 0,
            "promotion_blocker_count": 0,
            "wall_clock_utilization_ratio": 0.0,
            "idle_gap_seconds": 0.0,
            "total_raw_crash_count": 0,
            "total_traced_crash_count": 0,
            "distinct_pov_count": 0,
            "binary_signal_lift_count": 0,
            "binary_reseed_trigger_count": 0,
            "binary_fabric_reseed_count": 0,
            "binary_fabric_candidate_count": 0,
            "binary_fabric_family_count": 0,
            "campaign_coverage_queue_count": 0,
            "campaign_low_growth_queue_count": 0,
            "campaign_uncovered_queue_count": 0,
            "campaign_partial_queue_count": 0,
            "campaign_stalled_queue_count": 0,
            "system_coverage_plane_queue_count": 0,
            "corpus_quality_gate_passed_total": shared_seed_quality_passed,
            "corpus_quality_gate_rejected_total": shared_seed_quality_rejected,
            "quality_gate_pass_rate": round(shared_seed_quality_passed / max(shared_seed_quality_seen, 1), 6),
        },
        "slot": {
            "slot_start_time": task_store.now(),
            "slot_end_time": None,
            "project_sequence": [benchmark],
            "campaign_continuation_count": 0,
            "idle_gap_seconds": 0.0,
        },
        "system_fabric": register_campaign(
            campaign_task_id=task_id,
            benchmark=benchmark,
            target_mode=target_mode,
            base_task_id=base_task_id,
            deadline_at=task_store.now(),
            slot_label=str(base_task.metadata.get("slot_controller_label") or benchmark or task_id),
        ),
    }
    persist_campaign_runtime_state(task_id, state)
    return state


def persist_campaign_runtime_state(task_id: str, state: dict[str, Any]) -> str:
    state["updated_at"] = state.get("updated_at") or state.get("created_at")
    path = campaign_runtime_state_path(task_id)
    _write_json(path, state)
    return str(path)


def _score_harness_candidate(
    entry: dict[str, Any],
    *,
    current_session_count: int,
    last_selected_harness: str | None,
    coverage_stalled: bool,
    family_stalled: bool,
    multiple_candidates: bool,
    coverage_queue_boost: float = 0.0,
    family_queue_boost: float = 0.0,
) -> float:
    score = float(entry.get("selection_score") or 0.0)
    score += min(int(entry.get("recent_new_trace_count") or 0), 5) * 1.0
    score += min(int(entry.get("recent_new_crash_count") or 0), 5) * 1.2
    score += float(entry.get("recent_coverage_growth") or 0.0) * 100.0
    score += min(int(entry.get("recent_corpus_growth") or 0), 20) * 0.05
    score -= min(int(entry.get("recent_session_count") or 0), 8) * 0.25
    if entry.get("status") == "retired":
        score -= 10.0
    elif entry.get("status") == "cooldown":
        score -= 3.0
    if multiple_candidates and coverage_stalled and entry.get("harness_name") == last_selected_harness:
        score -= 2.5
    if multiple_candidates and family_stalled and entry.get("harness_name") == last_selected_harness:
        score -= 3.0
    score += min(int(entry.get("recent_new_loose_cluster_count") or 0), 4) * 1.1
    score += min(int(entry.get("recent_new_confirmed_family_count") or 0), 3) * 1.4
    cooldown_until = int(entry.get("cooldown_until_session") or 0)
    if cooldown_until and current_session_count < cooldown_until:
        score -= 3.5
    score += float(coverage_queue_boost or 0.0)
    score += float(family_queue_boost or 0.0)
    return round(score, 4)


def _family_confirmation_inputs(state: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, float]]:
    family_inventory = dict(state.get("family_inventory") or {})
    unresolved_entries = [
        dict(item)
        for item in (family_inventory.get("unresolved_loose_clusters") or [])
        if isinstance(item, dict) and str(item.get("loose_cluster_key") or "").strip()
    ]
    reconfirmation_entries = [
        dict(item)
        for item in (family_inventory.get("requires_reconfirmation_families") or [])
        if isinstance(item, dict)
        and (
            str(item.get("loose_cluster_key") or "").strip()
            or str(item.get("confirmed_family_key") or "").strip()
        )
    ]
    unresolved_map: dict[str, dict[str, Any]] = {}
    for item in unresolved_entries + reconfirmation_entries:
        cluster_key = str(item.get("loose_cluster_key") or item.get("confirmed_family_key") or "").strip()
        if not cluster_key:
            continue
        previous_entry = dict(unresolved_map.get(cluster_key) or {})
        merged_entry = {**previous_entry, **item}
        merged_entry["loose_cluster_key"] = cluster_key
        if bool(previous_entry.get("requires_reconfirmation")) or bool(item.get("requires_reconfirmation")):
            merged_entry["requires_reconfirmation"] = True
        unresolved_map[cluster_key] = merged_entry
    unresolved = list(unresolved_map.values())
    blockers = [
        dict(item)
        for item in (family_inventory.get("promotion_blockers") or [])
        if isinstance(item, dict)
    ]
    harness_pressure: dict[str, float] = {}
    for item in unresolved:
        harness_name = str(item.get("harness_name") or item.get("selected_harness") or "").strip()
        if harness_name:
            pressure = 2.0
            if bool(item.get("requires_reconfirmation")):
                pressure += 2.0
            if str(item.get("blocker_kind") or "") in {
                "stack_top_frame_mismatch",
                "stack_second_frame_mismatch",
                "source_anchor_mismatch",
                "await_exact_signature_for_first_confirmation",
            }:
                pressure += 1.5
            harness_pressure[harness_name] = harness_pressure.get(harness_name, 0.0) + pressure
    for item in blockers[-12:]:
        harness_name = str(item.get("harness_name") or item.get("selected_harness") or "").strip()
        if harness_name:
            pressure = 1.0
            if bool(item.get("requires_reconfirmation")):
                pressure += 1.5
            if str(item.get("blocker_kind") or "") in {
                "stack_top_frame_mismatch",
                "stack_second_frame_mismatch",
                "source_anchor_mismatch",
                "await_exact_signature_for_first_confirmation",
            }:
                pressure += 1.0
            harness_pressure[harness_name] = harness_pressure.get(harness_name, 0.0) + pressure
    return unresolved, blockers, harness_pressure


def _family_reconfirmation_threshold(state: dict[str, Any]) -> int:
    family_inventory = dict(state.get("family_inventory") or {})
    threshold = int(
        family_inventory.get("reconfirmation_threshold_rounds")
        or state.get("family_reconfirmation_round_threshold")
        or FAMILY_RECONFIRMATION_THRESHOLD_ROUNDS
        or 1
    )
    return max(1, threshold)


def _refresh_family_reconfirmation_state(
    family_inventory: dict[str, Any],
    *,
    current_session_index: int,
    threshold_rounds: int,
) -> dict[str, Any]:
    normalized_threshold = max(1, int(threshold_rounds or FAMILY_RECONFIRMATION_THRESHOLD_ROUNDS))
    details: dict[str, dict[str, Any]] = {}
    for family_key, raw_detail in dict(family_inventory.get("confirmed_family_details") or {}).items():
        normalized_key = str(family_key or "").strip()
        if not normalized_key or not isinstance(raw_detail, dict):
            continue
        detail = dict(raw_detail)
        detail["confirmed_family_key"] = normalized_key
        last_reconfirmed_session_index = int(
            detail.get("last_reconfirmed_session_index")
            or detail.get("last_confirmed_session_index")
            or detail.get("first_confirmed_session_index")
            or 0
        )
        reconfirmation_round_gap = max(0, int(current_session_index or 0) - last_reconfirmed_session_index)
        explicit_requires_reconfirmation = bool(detail.get("requires_reconfirmation"))
        requires_reconfirmation = bool(
            explicit_requires_reconfirmation
            or (
                last_reconfirmed_session_index > 0
                and reconfirmation_round_gap >= normalized_threshold
            )
        )
        detail["reconfirmation_threshold_rounds"] = normalized_threshold
        detail["reconfirmation_round_gap"] = reconfirmation_round_gap
        detail["requires_reconfirmation"] = requires_reconfirmation
        details[normalized_key] = detail

    reconfirmation_entries: list[dict[str, Any]] = []
    for family_key, detail in details.items():
        if not bool(detail.get("requires_reconfirmation")):
            continue
        reconfirmation_entries.append(
            {
                "loose_cluster_key": str(
                    detail.get("family_loose_cluster_key")
                    or detail.get("source_loose_cluster_key")
                    or detail.get("confirmed_family_key")
                    or family_key
                ).strip()
                or family_key,
                "confirmed_family_key": family_key,
                "harness_name": detail.get("harness_name"),
                "primary_function": detail.get("primary_function") or detail.get("family_primary_function"),
                "primary_file": detail.get("primary_file") or detail.get("family_primary_file"),
                "requires_reconfirmation": True,
                "blocker_kind": "requires_reconfirmation",
                "blocker_reason": (
                    "confirmed family has aged beyond the reconfirmation threshold "
                    f"({int(detail.get('reconfirmation_round_gap') or 0)} rounds without reconfirmation)"
                ),
                "reconfirmation_round_gap": int(detail.get("reconfirmation_round_gap") or 0),
                "reconfirmation_threshold_rounds": normalized_threshold,
                "last_reconfirmed_session_index": detail.get("last_reconfirmed_session_index"),
                "family_lineage": detail.get("family_lineage") or detail.get("lineage") or {},
            }
        )
    updated_inventory = dict(family_inventory)
    updated_inventory["confirmed_family_details"] = details
    updated_inventory["reconfirmation_threshold_rounds"] = normalized_threshold
    updated_inventory["requires_reconfirmation_families"] = sorted(
        reconfirmation_entries,
        key=lambda item: (
            -int(item.get("reconfirmation_round_gap") or 0),
            str(item.get("confirmed_family_key") or ""),
        ),
    )
    updated_inventory["requires_reconfirmation_count"] = len(reconfirmation_entries)
    return updated_inventory


def _family_focus_target_name(item: dict[str, Any]) -> str:
    primary_function = str(item.get("primary_function") or "").strip()
    if primary_function:
        return primary_function
    cluster_key = str(item.get("loose_cluster_key") or item.get("confirmed_family_key") or "").strip()
    if cluster_key:
        return f"family_cluster::{cluster_key}"
    return ""


def _family_focus_target_priority(item: dict[str, Any]) -> int:
    priority = 12
    if bool(item.get("requires_reconfirmation")):
        priority += 4
    if str(item.get("blocker_kind") or "") in {
        "stack_top_frame_mismatch",
        "stack_second_frame_mismatch",
        "source_anchor_mismatch",
    }:
        priority += 2
    if str(item.get("blocker_kind") or "") == "await_exact_signature_for_first_confirmation":
        priority += 1
    return priority


def _binary_execution_proxy_for_round(round_task_id: str) -> dict[str, Any]:
    execution_manifest = _read_json(task_root(round_task_id) / "runtime" / "binary_execution_manifest.json", {})
    run_records = list(execution_manifest.get("run_records") or [])
    execution_count = int(execution_manifest.get("run_count", len(run_records)) or 0)
    crash_signal_count = int(execution_manifest.get("crash_candidate_count") or 0)
    unique_inputs: set[str] = set()
    for item in run_records:
        if not isinstance(item, dict):
            continue
        raw_path = str(item.get("input_path") or "").strip()
        if not raw_path:
            continue
        input_path = Path(raw_path)
        digest = raw_path
        if input_path.exists() and input_path.is_file():
            try:
                digest = hashlib.sha256(input_path.read_bytes()).hexdigest()[:16]
            except OSError:
                digest = raw_path
        unique_inputs.add(digest)
    return {
        "execution_count": execution_count,
        "unique_input_count": len(unique_inputs),
        "crash_signal_rate": round(crash_signal_count / max(execution_count, 1), 6) if execution_count else 0.0,
        "execution_signal_count": int(execution_manifest.get("execution_signal_count") or 0),
        "crash_candidate_count": crash_signal_count,
        "binary_execution_manifest_path": str(task_root(round_task_id) / "runtime" / "binary_execution_manifest.json"),
    }


def _binary_runtime_state_for_round(
    round_task_id: str,
    *,
    refresh_ida: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if refresh_ida:
        try:
            build_binary_ida_runtime_view(round_task_id, generated_at=generated_at)
        except Exception:
            pass
    feedback_bridge = _read_json(binary_feedback_bridge_path(round_task_id), {})
    ida_runtime_view = _read_json(binary_ida_runtime_view_path(round_task_id), {})
    coverage_proxy = _binary_execution_proxy_for_round(round_task_id)
    trace_candidates = _dedupe_names(
        [
            {
                "name": item.get("selected_target_function"),
                "target_type": "function",
                "queue_kind": "binary_trace_admission",
                "priority": 10 if str(item.get("admission_mode") or "") == "promoted_candidate" else 8,
                "reason": item.get("reason"),
                "source_level": "binary_feedback",
            }
            for item in (feedback_bridge.get("trace_admission_candidates") or [])
            if isinstance(item, dict) and str(item.get("selected_target_function") or "").strip()
        ],
        limit=8,
    )
    focus_candidates = _dedupe_names(
        [
            {
                "name": item.get("name"),
                "target_type": "function",
                "queue_kind": "binary_focus",
                "priority": int(float(item.get("score") or 0.0) * 10) or 6,
                "reason": ",".join(item.get("reasons") or []),
                "source_level": "ida_runtime_view",
            }
            for item in (ida_runtime_view.get("focus_candidates") or [])
            if isinstance(item, dict) and str(item.get("name") or "").strip()
        ],
        limit=8,
    )
    ida_fact_source = None
    if ida_runtime_view:
        ida_fact_source = "per_round_runtime_refresh" if refresh_ida else "persisted_round_runtime_view"
    elif feedback_bridge:
        ida_fact_source = "binary_feedback_bridge_only"
    return {
        "binary_feedback_bridge_path": str(binary_feedback_bridge_path(round_task_id)) if feedback_bridge else None,
        "binary_ida_runtime_view_path": str(binary_ida_runtime_view_path(round_task_id)) if ida_runtime_view else None,
        "ida_fact_source": ida_fact_source,
        "ida_refresh_task_id": round_task_id,
        "binary_mode": feedback_bridge.get("binary_mode") or ida_runtime_view.get("binary_mode"),
        "binary_provenance": feedback_bridge.get("binary_provenance") or ida_runtime_view.get("binary_provenance"),
        "provenance_class": feedback_bridge.get("provenance_class") or ida_runtime_view.get("provenance_class"),
        "selected_target_function": feedback_bridge.get("selected_target_function") or ida_runtime_view.get("selected_target_function"),
        "selected_binary_slice_focus": feedback_bridge.get("selected_binary_slice_focus") or ida_runtime_view.get("selected_binary_slice_focus"),
        "selected_target_is_project_local": bool(feedback_bridge.get("selected_target_is_project_local")),
        "feedback_state": feedback_bridge.get("feedback_state"),
        "feedback_action": feedback_bridge.get("next_action"),
        "informational_only": bool(feedback_bridge.get("informational_only")),
        "promotion_rate": float(feedback_bridge.get("promotion_rate") or 0.0),
        "signal_lift_total": int(feedback_bridge.get("signal_lift_total") or 0),
        "signal_lift_reason": feedback_bridge.get("signal_lift_reason"),
        "signal_category_counts": dict(feedback_bridge.get("signal_category_counts") or {}),
        "reseed_candidate_queue": _dedupe_names(feedback_bridge.get("recommended_reseed_targets") or [], limit=8),
        "trace_candidate_queue_path": feedback_bridge.get("trace_candidate_queue_path"),
        "trace_candidate_count": int(feedback_bridge.get("trace_candidate_count") or 0),
        "trace_admission_candidates": trace_candidates,
        "focus_candidates": focus_candidates,
        "parser_candidates": _dedupe_names(
            [
                {
                    "name": item.get("name"),
                    "target_type": "function",
                    "queue_kind": "binary_focus",
                    "priority": 5,
                    "reason": ",".join(item.get("reasons") or []),
                    "source_level": "ida_runtime_view",
                }
                for item in (ida_runtime_view.get("parser_candidates") or [])
                if isinstance(item, dict) and str(item.get("name") or "").strip()
            ],
            limit=8,
        ),
        "entry_candidates": _dedupe_names(
            [
                {
                    "name": item.get("name"),
                    "target_type": "function",
                    "queue_kind": "binary_focus",
                    "priority": 4,
                    "reason": "entry_candidate",
                    "source_level": "ida_runtime_view",
                }
                for item in (ida_runtime_view.get("entry_candidates") or [])
                if isinstance(item, dict) and str(item.get("name") or "").strip()
            ],
            limit=8,
        ),
        "callgraph_neighbors": _dedupe_names(
            [
                {
                    "name": item.get("name"),
                    "target_type": "function",
                    "queue_kind": "binary_focus",
                    "priority": 4,
                    "reason": f"callgraph_{item.get('direction') or 'neighbor'}",
                    "source_level": "ida_runtime_view",
                }
                for item in (ida_runtime_view.get("callgraph_neighbors") or [])
                if isinstance(item, dict) and str(item.get("name") or "").strip()
            ],
            limit=8,
        ),
        "contract": dict(ida_runtime_view.get("contract") or {}),
        "coverage_proxy": coverage_proxy,
    }


def _current_binary_runtime_for_planning(state: dict[str, Any], *, now_iso: str) -> dict[str, Any]:
    cached = dict(state.get("binary_runtime") or {})
    candidate_task_ids: list[str] = []
    for raw_task_id in (
        state.get("active_session_task_id"),
        state.get("base_task_id"),
        state.get("task_id"),
    ):
        task_id = str(raw_task_id or "").strip()
        if not task_id or task_id in candidate_task_ids:
            continue
        candidate_task_ids.append(task_id)
    for task_id in candidate_task_ids:
        runtime = _binary_runtime_state_for_round(task_id, refresh_ida=True, generated_at=now_iso)
        if runtime.get("binary_ida_runtime_view_path") or runtime.get("binary_feedback_bridge_path"):
            return {**cached, **runtime}
    cached.setdefault("ida_fact_source", "campaign_state_cache")
    cached.setdefault("ida_refresh_task_id", candidate_task_ids[0] if candidate_task_ids else None)
    cached.setdefault("coverage_proxy", {})
    return cached


def _binary_session_feedback_inputs(binary_runtime: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], str | None, dict[str, Any]]:
    binary_runtime = dict(binary_runtime or {})
    feedback_targets = _dedupe_names(binary_runtime.get("reseed_candidate_queue") or [], limit=8)
    trace_targets = _dedupe_names(binary_runtime.get("trace_admission_candidates") or [], limit=8)
    focus_targets = _dedupe_names(
        (
            binary_runtime.get("focus_candidates") or []
        )
        + (
            binary_runtime.get("parser_candidates") or []
        )
        + (
            binary_runtime.get("callgraph_neighbors") or []
        )
        + (
            binary_runtime.get("entry_candidates") or []
        ),
        limit=8,
    )
    selected_focus = (
        str(binary_runtime.get("selected_binary_slice_focus") or "").strip()
        or str(binary_runtime.get("selected_target_function") or "").strip()
        or None
    )
    return feedback_targets, trace_targets, focus_targets, selected_focus, binary_runtime


def choose_next_session_plan(
    state: dict[str, Any],
    *,
    now_iso: str,
    round_budget_seconds: int,
) -> dict[str, Any]:
    session_index = int(state.get("session_count") or 0) + 1
    harness_pool = list(state.get("active_harness_pool") or [])
    coverage_state = state.get("coverage_state") or {}
    family_diversification = state.get("family_diversification") or {}
    family_inventory = _refresh_family_reconfirmation_state(
        dict(state.get("family_inventory") or {}),
        current_session_index=session_index,
        threshold_rounds=_family_reconfirmation_threshold(state),
    )
    state["family_inventory"] = family_inventory
    lane = str(state.get("lane") or "source")
    coverage_stalled = bool(coverage_state.get("coverage_stalled"))
    family_stagnation_count = int(family_diversification.get("stagnation_count") or 0)
    family_stalled = family_stagnation_count >= FAMILY_STAGNATION_TRIGGER_THRESHOLD
    unresolved_loose_clusters, promotion_blockers, family_harness_pressure = _family_confirmation_inputs(state)
    family_confirmation_pressure = bool(unresolved_loose_clusters or promotion_blockers)
    confirmed_family_count = len(family_inventory.get("confirmed_families") or [])
    requires_reconfirmation_count = int(family_inventory.get("requires_reconfirmation_count") or 0)
    family_reconfirmation_threshold = int(
        family_inventory.get("reconfirmation_threshold_rounds")
        or FAMILY_RECONFIRMATION_THRESHOLD_ROUNDS
    )
    target_mode = str(state.get("target_mode") or "source")
    active_session_task_id = str(state.get("active_session_task_id") or "").strip() or None
    reuse_existing_round_task = target_mode != "binary" and bool(active_session_task_id)
    continuity_mode = (
        "campaign_active_session_task"
        if reuse_existing_round_task
        else ("fresh_round_clone" if target_mode != "binary" else "binary_round_clone")
    )
    planning_binary_runtime = (
        _current_binary_runtime_for_planning(state, now_iso=now_iso)
        if target_mode == "binary"
        else dict(state.get("binary_runtime") or {})
    )
    (
        binary_feedback_targets,
        binary_trace_targets,
        binary_focus_targets,
        binary_selected_focus,
        binary_runtime,
    ) = _binary_session_feedback_inputs(planning_binary_runtime)
    last_selected_harness = str(state.get("last_selected_harness") or "").strip() or None
    multiple_candidates = len(harness_pool) > 1
    coverage_plane_inputs = peek_coverage_plane_inputs(
        str(state.get("task_id") or ""),
        project=str(state.get("project") or "unknown"),
        lane=str(state.get("lane") or "source"),
        target_mode=str(state.get("target_mode") or "source"),
    )
    harness_queue_pressure = dict(coverage_plane_inputs.get("harness_queue_pressure") or {})

    best_entry = None
    best_score = None
    for entry in harness_pool:
        score = _score_harness_candidate(
            entry,
            current_session_count=int(state.get("session_count") or 0),
            last_selected_harness=last_selected_harness,
            coverage_stalled=coverage_stalled,
            family_stalled=family_stalled,
            multiple_candidates=multiple_candidates,
            coverage_queue_boost=float(harness_queue_pressure.get(str(entry.get("harness_name") or ""), 0.0) or 0.0),
            family_queue_boost=float(family_harness_pressure.get(str(entry.get("harness_name") or ""), 0.0) or 0.0),
        )
        if best_entry is None or score > float(best_score):
            best_entry = entry
            best_score = score
    selected_harness = dict(best_entry or (harness_pool[0] if harness_pool else {}))
    selected_harness_name = str(selected_harness.get("harness_name") or "").strip() or None
    pre_override_selected_harness_name = selected_harness_name
    binding = _resolve_current_harness_binding(
        task_id=active_session_task_id or str(state.get("base_task_id") or "").strip() or None,
        harness_name=selected_harness_name,
        project=str(state.get("project") or "unknown"),
    )
    if binding:
        selected_harness_name = str(binding.get("selected_harness") or selected_harness_name or "").strip() or None
        selected_harness["harness_name"] = selected_harness_name
        selected_harness["selected_harness_path"] = binding.get("selected_harness_path")
        selected_harness["harness_source_path"] = binding.get("harness_source_path")
    coverage_claim = claim_coverage_targets_for_session(
        str(state.get("task_id") or ""),
        project=str(state.get("project") or "unknown"),
        lane=lane,
        target_mode=str(state.get("target_mode") or "source"),
        preferred_harness=selected_harness_name,
        session_index=session_index,
        limit=_coverage_claim_limit(lane=lane, target_mode=target_mode),
        now_iso_value=now_iso,
    )
    coverage_queue_primary_entry = _coverage_claim_primary_entry(coverage_claim)
    coverage_queue_harness_override = _coverage_harness_override_name(coverage_claim)
    coverage_exact_priority_targets = _coverage_exact_priority_targets(coverage_claim)
    system_feedback = claim_planning_feedback(
        campaign_task_id=str(state.get("task_id") or ""),
        target_mode=target_mode,
        selected_harness=selected_harness_name,
        limit=8,
    )
    binary_fabric_reseed_targets = _dedupe_names(system_feedback.get("system_binary_reseed_requests") or [], limit=8)
    binary_fabric_candidate_targets = _dedupe_names(system_feedback.get("system_binary_candidate_targets") or [], limit=8)
    binary_fabric_family_targets = _dedupe_names(system_feedback.get("system_binary_family_targets") or [], limit=8)
    binary_reseed_targets = _dedupe_names(binary_fabric_reseed_targets + binary_feedback_targets, limit=8)
    binary_candidate_targets = _dedupe_names(binary_fabric_candidate_targets + binary_trace_targets, limit=8)
    binary_family_targets = _dedupe_names(binary_fabric_family_targets, limit=8)
    binary_claimed_feedback_items = [
        dict(item)
        for item in (system_feedback.get("claimed_feedback_items") or [])
        if str(item.get("item_type") or "") in {"binary_reseed", "binary_candidate", "binary_family"}
    ]
    harness_switch_stagnation_threshold = 15
    override_attempted = bool(
        coverage_queue_harness_override
        and coverage_queue_harness_override != pre_override_selected_harness_name
    )
    override_blocked_by_stagnation_guard = bool(
        override_attempted
        and multiple_candidates
        and family_stagnation_count >= harness_switch_stagnation_threshold
        and coverage_queue_harness_override == last_selected_harness
    )
    harness_decision_reason = "score_ranked_harness_selection"
    if (
        coverage_queue_harness_override
        and coverage_queue_harness_override != selected_harness_name
        and not (
            multiple_candidates
            and family_stagnation_count >= harness_switch_stagnation_threshold
            and coverage_queue_harness_override == last_selected_harness
        )
    ):
        selected_harness = _find_harness_pool_entry(harness_pool, coverage_queue_harness_override) or {
            **selected_harness,
            "harness_name": coverage_queue_harness_override,
        }
        selected_harness_name = coverage_queue_harness_override
        harness_decision_reason = "coverage_queue_harness_override_applied"
        binding = _resolve_current_harness_binding(
            task_id=active_session_task_id or str(state.get("base_task_id") or "").strip() or None,
            harness_name=selected_harness_name,
            project=str(state.get("project") or "unknown"),
        )
        if binding:
            selected_harness_name = str(binding.get("selected_harness") or selected_harness_name or "").strip() or None
            selected_harness["harness_name"] = selected_harness_name
            selected_harness["selected_harness_path"] = binding.get("selected_harness_path")
            selected_harness["harness_source_path"] = binding.get("harness_source_path")
    elif override_blocked_by_stagnation_guard:
        harness_decision_reason = "coverage_queue_harness_override_blocked_by_stagnation_guard"
    elif coverage_queue_harness_override and coverage_queue_harness_override == pre_override_selected_harness_name:
        harness_decision_reason = "coverage_queue_harness_override_matched_scored_selection"
    elif (
        multiple_candidates
        and family_stagnation_count >= harness_switch_stagnation_threshold
        and pre_override_selected_harness_name == last_selected_harness
    ):
        harness_decision_reason = "score_ranked_selection_kept_last_harness_before_override"
    harness_decision_trace = {
        "evaluated_stagnation_count": family_stagnation_count,
        "candidate_count": len(harness_pool),
        "override_attempted": override_attempted,
        "override_blocked_by_stagnation_guard": override_blocked_by_stagnation_guard,
        "final_selected_harness": selected_harness_name,
        "decision_reason": harness_decision_reason,
        "pre_override_selected_harness": pre_override_selected_harness_name,
        "override_harness": coverage_queue_harness_override,
    }
    coverage_plane_targets = _dedupe_names(coverage_claim.get("selected_target_functions") or [])
    coverage_plane_harness_targets = _dedupe_names(coverage_claim.get("selected_harness_targets") or [])
    coverage_partial_queue = _dedupe_names(coverage_state.get("partial_degraded_target_queue") or [])
    coverage_stalled_queue = _dedupe_names(
        list(coverage_state.get("stalled_target_queue") or [])
        + list(system_feedback.get("system_stalled_targets") or [])
    )
    low_growth_queue = _dedupe_names(
        list(coverage_state.get("low_growth_function_queue") or [])
        + list(system_feedback.get("system_low_growth_functions") or [])
    )
    uncovered_queue = _dedupe_names(
        list(coverage_state.get("uncovered_function_queue") or [])
        + list(system_feedback.get("system_uncovered_functions") or [])
    )
    candidate_bridge_queue = _dedupe_names(
        list(state.get("candidate_bridge_queue") or [])
        + list(system_feedback.get("system_candidate_bridge") or [])
    )
    system_family_feedback_targets = _dedupe_names(system_feedback.get("system_family_feedback_queue") or [])
    family_focus_targets = _dedupe_names(
        [
            {
                "name": _family_focus_target_name(item),
                "target_type": "function" if str(item.get("primary_function") or "").strip() else "family_cluster",
                "queue_kind": "family_confirmation",
                "priority": _family_focus_target_priority(item),
                "reason": item.get("blocker_kind") or ("confirmed_family_signature_drift" if item.get("requires_reconfirmation") else "unresolved_loose_cluster"),
                "source_level": "family",
                "harness": item.get("harness_name"),
                "selection_scope": "campaign",
            }
            for item in unresolved_loose_clusters
            if _family_focus_target_name(item)
        ]
    )
    coverage_queue_kind = str(coverage_claim.get("coverage_queue_kind") or "").strip() or None
    coverage_plane_engaged = bool(
        coverage_plane_targets
        or coverage_plane_harness_targets
        or coverage_queue_kind
        or int(coverage_claim.get("coverage_queue_size") or 0) > 0
        or coverage_partial_queue
        or coverage_stalled_queue
    )
    if target_mode == "binary":
        preferred_targets = (
            binary_reseed_targets
            or binary_candidate_targets
            or binary_family_targets
            or binary_focus_targets
            or family_focus_targets
            or system_family_feedback_targets
            or coverage_plane_targets
            or coverage_stalled_queue
            or coverage_partial_queue
            or low_growth_queue
            or uncovered_queue
            or candidate_bridge_queue
        )
    else:
        preferred_targets = (
            coverage_exact_priority_targets
            or family_focus_targets
            or system_family_feedback_targets
            or coverage_plane_targets
            or coverage_stalled_queue
            or coverage_partial_queue
            or low_growth_queue
            or uncovered_queue
            or candidate_bridge_queue
        )
    coverage_request_plan = _build_coverage_request_plan(preferred_targets)
    selected_target_function = preferred_targets[0]["name"] if preferred_targets else (binary_selected_focus if target_mode == "binary" else None)
    selected_target_functions = preferred_targets[:5]
    selected_target_stall_rounds = _coverage_target_stall_rounds(state, selected_target_function)
    recent_coverage_growth = float((state.get("coverage_state") or {}).get("recent_coverage_growth") or 0.0)
    coverage_target_stalled = selected_target_stall_rounds >= COVERAGE_TARGET_STALL_THRESHOLD
    selected_binary_slice_focus = (
        binary_selected_focus
        or selected_target_function
        or str(selected_harness.get("binary_focus") or "").strip()
        or None
    )
    session_budget_seconds, coverage_budget_reason, coverage_budget_multiplier = _coverage_session_budget(
        round_budget_seconds,
        lane=lane,
        coverage_claim=coverage_claim,
    )
    coverage_reseed_triggered, coverage_reseed_reason = _coverage_queue_driven_reseed(
        coverage_claim,
        coverage_stalled=coverage_stalled,
    )
    seed_mode_trigger_source: str | None = None
    seed_mode_trigger_reason: str | None = None

    if session_index == 1:
        triggered_action_type = "bootstrap"
        seed_mode_override = "SEED_INIT"
    elif target_mode == "binary" and binary_reseed_targets:
        triggered_action_type = "binary_feedback_reseed"
        seed_mode_override = "SEED_EXPLORE"
    elif target_mode == "binary" and binary_candidate_targets:
        triggered_action_type = "binary_trace_watchlist_followup"
        seed_mode_override = "SEED_EXPLORE"
    elif target_mode == "binary" and binary_family_targets:
        triggered_action_type = "binary_family_followup"
        seed_mode_override = "SEED_EXPLORE"
    elif target_mode == "binary" and (binary_focus_targets or selected_binary_slice_focus):
        triggered_action_type = "binary_ida_focus_followup"
        seed_mode_override = "SEED_EXPLORE"
    elif family_confirmation_pressure:
        triggered_action_type = "family_confirmation_followup"
        seed_mode_override = "SEED_EXPLORE"
        seed_mode_trigger_source = "family_confirmation"
        seed_mode_trigger_reason = (
            "unresolved_loose_clusters_or_reconfirmation_backlog"
            if requires_reconfirmation_count > 0
            else "unresolved_loose_clusters_or_promotion_blockers"
        )
    elif family_stalled:
        triggered_action_type = "family_diversification"
        seed_mode_override = "SEED_EXPLORE"
        seed_mode_trigger_source = "family_confirmation"
        seed_mode_trigger_reason = (
            f"family_stagnation_count>={FAMILY_STAGNATION_TRIGGER_THRESHOLD}"
        )
    elif confirmed_family_count >= FAMILY_CONFIRMED_VULN_DISCOVERY_THRESHOLD:
        triggered_action_type = "family_confirmed_depth_followup"
        seed_mode_override = "VULN_DISCOVERY"
        seed_mode_trigger_source = "family_confirmation"
        seed_mode_trigger_reason = (
            f"confirmed_family_count>={FAMILY_CONFIRMED_VULN_DISCOVERY_THRESHOLD}"
        )
    elif confirmed_family_count == 1:
        triggered_action_type = "family_single_confirmed_explore"
        seed_mode_override = "SEED_EXPLORE"
        seed_mode_trigger_source = "family_confirmation"
        seed_mode_trigger_reason = "single_confirmed_family_keep_exploring"
    elif coverage_target_stalled:
        triggered_action_type = "coverage_target_stall_followup"
        seed_mode_override = "SEED_EXPLORE"
    elif target_mode != "binary" and recent_coverage_growth > 0.0:
        triggered_action_type = "coverage_growth_followup"
        seed_mode_override = "VULN_DISCOVERY"
    elif coverage_plane_engaged or selected_target_function:
        if coverage_queue_kind == "stalled":
            triggered_action_type = "coverage_plane_stalled_queue"
        elif coverage_queue_kind in {"partial_degraded", "harness_focus"}:
            triggered_action_type = "coverage_plane_degraded_queue"
        elif coverage_plane_targets or coverage_plane_harness_targets:
            triggered_action_type = "coverage_plane_queue"
        elif coverage_partial_queue:
            triggered_action_type = "coverage_plane_degraded_queue"
        else:
            triggered_action_type = (
                "candidate_bridge_explore"
                if candidate_bridge_queue and not (low_growth_queue or uncovered_queue)
                else "coverage_queue"
            )
        seed_mode_override = "SEED_EXPLORE"
    elif coverage_stalled:
        triggered_action_type = "stalled_rotation"
        seed_mode_override = "SEED_EXPLORE"
    else:
        triggered_action_type = "steady_state"
        seed_mode_override = None

    return {
        "session_index": session_index,
        "session_budget_seconds": session_budget_seconds,
        "target_mode": target_mode,
        "active_session_task_id": active_session_task_id,
        "reuse_existing_round_task": reuse_existing_round_task,
        "continuity_mode": continuity_mode,
        "previous_session_summary_path": state.get("last_session_summary_path"),
        "last_corpus_state_reference": state.get("last_corpus_state_reference"),
        "last_coverage_snapshot_reference": state.get("last_coverage_snapshot_reference"),
        "last_stagnation_state": state.get("last_stagnation_state") or {},
        "selected_harness": selected_harness_name,
        "selected_harness_path": selected_harness.get("selected_harness_path"),
        "selected_harness_source_path": selected_harness.get("harness_source_path"),
        "selected_target_function": selected_target_function,
        "selected_target_functions": selected_target_functions,
        "selected_binary_slice_focus": selected_binary_slice_focus,
        "coverage_plane_selected_entries": coverage_claim.get("selected_entries") or [],
        "coverage_plane_selected_target_functions": coverage_claim.get("selected_target_functions") or [],
        "coverage_plane_selected_harness_targets": coverage_claim.get("selected_harness_targets") or [],
        "coverage_exact_priority_targets": coverage_exact_priority_targets,
        "campaign_coverage_queue_consumption_path": coverage_claim.get("campaign_coverage_queue_consumption_path"),
        "campaign_coverage_plane_state_path": coverage_claim.get("campaign_coverage_plane_state_path"),
        "campaign_coverage_queue_path": coverage_claim.get("campaign_coverage_queue_path"),
        "system_coverage_plane_state_path": coverage_claim.get("system_coverage_plane_state_path"),
        "system_coverage_plane_queue_path": coverage_claim.get("system_coverage_plane_queue_path"),
        "campaign_exact_or_partial": coverage_claim.get("campaign_exact_or_partial"),
        "campaign_exact_coverage_available_ratio": coverage_claim.get("campaign_exact_coverage_available_ratio"),
        "campaign_degraded_reason": coverage_claim.get("campaign_degraded_reason"),
        "campaign_degraded_detail": coverage_claim.get("campaign_degraded_detail"),
        "coverage_queue_primary_entry": coverage_queue_primary_entry,
        "coverage_queue_planning_reason": coverage_budget_reason,
        "coverage_queue_harness_override": coverage_queue_harness_override,
        "coverage_queue_budget_multiplier": coverage_budget_multiplier,
        "coverage_queue_reseed_reason": coverage_reseed_reason,
        "coverage_plane_harness_queue_pressure": harness_queue_pressure,
        "coverage_recent_growth": recent_coverage_growth,
        "coverage_target_stall_rounds": selected_target_stall_rounds,
        "coverage_target_stall_threshold": COVERAGE_TARGET_STALL_THRESHOLD,
        "harness_decision_trace": harness_decision_trace,
        "seed_mode_override": seed_mode_override,
        "seed_mode_trigger_source": seed_mode_trigger_source,
        "seed_mode_trigger_reason": seed_mode_trigger_reason,
        "reseed_triggered": bool(
            binary_reseed_targets
            if target_mode == "binary"
            else coverage_reseed_triggered
        ),
        "triggered_action_type": triggered_action_type,
        "coverage_queue_kind": (
            "binary_reseed"
            if target_mode == "binary" and binary_fabric_reseed_targets
            else (
                "binary_feedback"
                if target_mode == "binary" and binary_feedback_targets
                else (
                    "binary_candidate"
                    if target_mode == "binary" and binary_fabric_candidate_targets
                    else (
                        "binary_trace_admission"
                        if target_mode == "binary" and binary_trace_targets
                        else (
                            "binary_family"
                            if target_mode == "binary" and binary_family_targets
                            else (
                                "binary_focus"
                                if target_mode == "binary" and binary_focus_targets
                                else coverage_queue_kind
                            )
                        )
                    )
                )
            )
            or (
                "campaign_partial_degraded"
                if coverage_partial_queue
                else (
                    "stalled"
                    if coverage_stalled_queue
                    else (
                        "low_growth"
                        if low_growth_queue
                        else ("uncovered" if uncovered_queue else ("candidate_bridge" if candidate_bridge_queue else None))
                    )
                )
            )
        ),
        "coverage_queue_size": int(
            len(preferred_targets)
            if target_mode == "binary" and preferred_targets
            else (coverage_claim.get("coverage_queue_size") or len(preferred_targets))
        ),
        "system_feedback_consumed": system_feedback,
        "coverage_plane_queue_counts": {
            "campaign": coverage_claim.get("campaign_queue_counts") or {},
            "system": coverage_claim.get("system_queue_counts") or {},
        },
        "coverage_request_plan": coverage_request_plan,
        "binary_feedback_bridge_path": binary_runtime.get("binary_feedback_bridge_path"),
        "binary_ida_runtime_view_path": binary_runtime.get("binary_ida_runtime_view_path"),
        "binary_feedback_queue_size": len(binary_reseed_targets),
        "binary_trace_admission_count": len(binary_candidate_targets),
        "binary_ida_candidate_count": len(binary_focus_targets),
        "binary_family_target_count": len(binary_family_targets),
        "binary_feedback_claimed_items": binary_claimed_feedback_items,
        "binary_fabric_reseed_count": len(binary_fabric_reseed_targets),
        "binary_fabric_candidate_count": len(binary_fabric_candidate_targets),
        "binary_fabric_family_count": len(binary_fabric_family_targets),
        "binary_provenance_class": binary_runtime.get("provenance_class"),
        "binary_feedback_action": binary_runtime.get("feedback_action"),
        "binary_coverage_proxy": dict(binary_runtime.get("coverage_proxy") or {}),
        "ida_fact_source": binary_runtime.get("ida_fact_source"),
        "ida_refresh_task_id": binary_runtime.get("ida_refresh_task_id"),
        "family_confirmed_count": confirmed_family_count,
        "family_requires_reconfirmation_count": requires_reconfirmation_count,
        "family_reconfirmation_threshold_rounds": family_reconfirmation_threshold,
        "family_stagnation_count": family_stagnation_count,
        "family_diversification_triggered": family_stalled,
        "family_confirmation_backlog_count": len(unresolved_loose_clusters),
        "family_confirmation_selected_clusters": [
            str(item.get("loose_cluster_key") or "").strip()
            for item in unresolved_loose_clusters[:4]
            if str(item.get("loose_cluster_key") or "").strip()
        ],
        "family_promotion_blockers": promotion_blockers[-8:],
        "candidate_bridge_queue_size": len(candidate_bridge_queue),
        "started_at": now_iso,
        "selection_score": best_score,
    }


def _extract_low_growth_functions(summary_payload: dict[str, Any], *, limit: int = 12) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    rows = summary_payload.get("per_function_summary") or []
    for item in rows:
        name = str(item.get("name") or "").strip()
        total_lines = int(item.get("total_lines", 0) or 0)
        covered_lines = int(item.get("covered_lines", 0) or 0)
        if not name or total_lines <= 0 or covered_lines <= 0:
            continue
        coverage_fraction = float(item.get("coverage_fraction", 0.0) or 0.0)
        if coverage_fraction >= 0.35:
            continue
        selected.append(
            {
                "name": name,
                "coverage_fraction": coverage_fraction,
                "total_lines": total_lines,
                "covered_lines": covered_lines,
                "function_paths": list(item.get("function_paths") or []),
            },
        )
    selected.sort(key=lambda item: (float(item.get("coverage_fraction") or 0.0), -int(item.get("total_lines") or 0)))
    return selected[:limit]


def _access_kind_from_excerpt(stderr_excerpt: str) -> str | None:
    match = ACCESS_KIND_PATTERN.search(stderr_excerpt or "")
    if match is None:
        return None
    return match.group(1).strip().lower()


def _top_stack_offsets(payload: dict[str, Any], *, limit: int = 2) -> list[str]:
    offsets: list[str] = []
    for line in payload.get("stacktrace") or []:
        match = STACK_OFFSET_PATTERN.search(str(line))
        if match is None:
            continue
        offsets.append(match.group(1).lower())
        if len(offsets) >= limit:
            break
    return offsets


def _loose_cluster_key(payload: dict[str, Any]) -> str:
    family_key = str(payload.get("family_loose_cluster_key") or "").strip()
    if family_key:
        return family_key
    crash_type = str(payload.get("crash_type") or payload.get("crash_state") or "unknown").strip().lower()
    access_kind = _access_kind_from_excerpt(str(payload.get("stderr_excerpt") or ""))
    harness_name = str(payload.get("harness_name") or "").strip().lower()
    offsets = _top_stack_offsets(payload)
    pieces = [crash_type]
    if access_kind:
        pieces.append(access_kind)
    if offsets:
        pieces.extend(offsets[:2])
    if harness_name:
        pieces.append(harness_name)
    return "|".join(pieces)


def _confirmed_family_key(payload: dict[str, Any]) -> str:
    family_key = str(payload.get("confirmed_family_key") or payload.get("family_confirmed_family_key") or "").strip().lower()
    if family_key:
        return family_key
    signature = str(payload.get("source_crash_signature") or payload.get("signature") or "").strip().lower()
    if signature:
        return signature
    repro_attempts = payload.get("repro_attempts") or []
    if repro_attempts:
        attempt = repro_attempts[0] if isinstance(repro_attempts[0], dict) else {}
        crash_type = str(payload.get("sanitizer") or "").strip().lower()
        access_kind = _access_kind_from_excerpt(str(attempt.get("stderr_excerpt") or ""))
        pieces = [crash_type or "confirmed"]
        if access_kind:
            pieces.append(access_kind)
        if payload.get("fuzzer_name"):
            pieces.append(str(payload.get("fuzzer_name")).strip().lower())
        return "|".join(pieces)
    return str(payload.get("fuzzer_name") or "confirmed_family").strip().lower()


def _round_family_inventory(round_task_id: str) -> dict[str, Any]:
    root = task_root(round_task_id)
    trace_dir = root / "trace" / "traced_crashes"
    pov_dir = root / "pov" / "confirmed"
    binary_manifest = _read_json(root / "runtime" / "binary_execution_manifest.json", {})
    trace_family_payload = _read_json(trace_family_manifest_path(round_task_id), {})
    repro_family_payload = _read_json(repro_family_manifest_path(round_task_id), {})
    exact_signatures: set[str] = set()
    loose_clusters: set[str] = set()
    confirmed_families: set[str] = set()
    loose_cluster_details: dict[str, dict[str, Any]] = {}
    confirmed_family_details: dict[str, dict[str, Any]] = {}
    unresolved_loose_clusters: list[dict[str, Any]] = []
    promotion_blockers: list[dict[str, Any]] = []
    if trace_family_payload:
        for item in trace_family_payload.get("candidates") or []:
            if not isinstance(item, dict):
                continue
            signature = str(item.get("family_exact_signature") or item.get("signature") or "").strip()
            if signature:
                exact_signatures.add(signature)
            cluster_key = str(item.get("family_loose_cluster_key") or "").strip()
            if cluster_key:
                loose_clusters.add(cluster_key)
        for cluster in trace_family_payload.get("clusters") or []:
            if not isinstance(cluster, dict):
                continue
            cluster_key = str(cluster.get("loose_cluster_key") or "").strip()
            if not cluster_key:
                continue
            loose_cluster_details[cluster_key] = {
                "loose_cluster_key": cluster_key,
                "confirmed_family_key": cluster.get("confirmed_family_key") or cluster_key,
                "harness_name": cluster.get("representative_harness_name"),
                "primary_function": (cluster.get("features") or {}).get("primary_function"),
                "primary_file": (cluster.get("features") or {}).get("primary_file"),
                "cluster_match_reason": cluster.get("cluster_match_reason"),
                "exact_signatures": cluster.get("exact_signatures") or [],
                "artifact_paths": cluster.get("artifact_paths") or [],
            }
    else:
        for path in sorted(trace_dir.glob("*.json")):
            payload = _read_json(path, {})
            signature = str(payload.get("signature") or "").strip()
            if signature:
                exact_signatures.add(signature)
            cluster_key = _loose_cluster_key(payload)
            if cluster_key:
                loose_clusters.add(cluster_key)
                features = derive_loose_cluster_features(payload)
                loose_cluster_details.setdefault(
                    cluster_key,
                    {
                        "loose_cluster_key": cluster_key,
                        "confirmed_family_key": cluster_key,
                        "harness_name": payload.get("harness_name"),
                        "primary_function": features.get("primary_function"),
                        "primary_file": features.get("primary_file"),
                        "cluster_match_reason": payload.get("family_cluster_match_reason") or "legacy_round_reconstruction",
                        "exact_signatures": [signature] if signature else [],
                        "artifact_paths": [str(path)],
                    },
                )
    if repro_family_payload:
        for item in repro_family_payload.get("confirmed_families") or []:
            if not isinstance(item, dict):
                continue
            family_key = _confirmed_family_key(item)
            if not family_key:
                continue
            confirmed_families.add(family_key)
            confirmed_family_details[family_key] = dict(item)
        unresolved_loose_clusters = [
            dict(item)
            for item in (repro_family_payload.get("unresolved_loose_clusters") or [])
            if isinstance(item, dict) and str(item.get("loose_cluster_key") or "").strip()
        ]
        promotion_blockers = [
            dict(item)
            for item in (repro_family_payload.get("promotion_blockers") or [])
            if isinstance(item, dict)
        ]
    else:
        for path in sorted(pov_dir.glob("*.json")):
            payload = _read_json(path, {})
            family_key = _confirmed_family_key(payload)
            if family_key:
                confirmed_families.add(family_key)
                confirmed_family_details[family_key] = dict(payload)
    if not unresolved_loose_clusters:
        unresolved_loose_clusters = [
            {
                "loose_cluster_key": cluster_key,
                "confirmed_family_key": detail.get("confirmed_family_key") or cluster_key,
                "harness_name": detail.get("harness_name"),
                "primary_function": detail.get("primary_function"),
                "primary_file": detail.get("primary_file"),
                "blocker_kind": "awaiting_confirmation",
                "blocker_reason": "loose cluster traced but not yet promoted to confirmed family",
            }
            for cluster_key, detail in sorted(loose_cluster_details.items())
            if cluster_key not in confirmed_families
        ]
    for item in binary_manifest.get("per_input_execution_summary") or []:
        if not isinstance(item, dict):
            continue
        signal_signature = str(item.get("signal_signature") or "").strip()
        signal_category = str(item.get("signal_category") or "").strip()
        signal_subcategory = str(item.get("signal_subcategory") or "").strip()
        selected_focus = str(item.get("selected_binary_slice_focus") or binary_manifest.get("selected_binary_slice_focus") or "").strip()
        if signal_signature and signal_category not in {"informational_runtime_output", "runtime_noise"}:
            exact_signatures.add(f"binary-signal:{signal_category}:{signal_signature}")
        if signal_category and signal_category not in {"informational_runtime_output", "runtime_noise"}:
            pieces = ["binary", signal_category]
            if signal_subcategory:
                pieces.append(signal_subcategory)
            if selected_focus:
                pieces.append(selected_focus)
            loose_clusters.add("|".join(pieces))
        if item.get("crash_candidate"):
            confirmed_families.add(
                "binary-candidate:"
                + "|".join(
                    part
                    for part in [
                        signal_category or "candidate",
                        signal_subcategory,
                        str(item.get("crash_reason") or ""),
                    ]
                    if part
                ),
            )
    return {
        "trace_exact_signatures": sorted(exact_signatures),
        "loose_vulnerable_state_clusters": sorted(loose_clusters),
        "confirmed_families": sorted(confirmed_families),
        "unresolved_loose_clusters": unresolved_loose_clusters,
        "promotion_blockers": promotion_blockers,
        "loose_cluster_details": loose_cluster_details,
        "confirmed_family_details": confirmed_family_details,
        "trace_family_manifest_path": str(trace_family_manifest_path(round_task_id)),
        "repro_family_manifest_path": str(repro_family_manifest_path(round_task_id)),
    }


def _round_confirmed_pov_names(round_task_id: str) -> list[str]:
    root = task_root(round_task_id)
    pov_dir = root / "pov" / "confirmed"
    return sorted(path.name for path in pov_dir.glob("*.json") if path.is_file())


def _llm_metrics_for_round(round_task_id: str) -> dict[str, Any]:
    runtime_root = task_root(round_task_id) / "runtime"
    audit_payload = _read_json(runtime_root / "llm_seed_audit_manifest.json", {})
    if not audit_payload:
        return {
            "request_count_total": 0,
            "request_count_by_stage": {},
            "success_count": 0,
            "failure_count": 0,
        }
    stage = "binary_seed" if str(audit_payload.get("target_mode")) == "binary" else "seed"
    request_count = int(audit_payload.get("request_count") or 0)
    success = bool(audit_payload.get("llm_real_call_verified"))
    return {
        "request_count_total": request_count,
        "request_count_by_stage": {stage: request_count},
        "success_count": 1 if success else 0,
        "failure_count": 0 if success else (1 if request_count > 0 else 0),
    }


def _coverage_state_for_round(round_task_id: str) -> dict[str, Any]:
    root = task_root(round_task_id)
    feedback_payload = _read_json(root / "coverage" / "feedback_manifest.json", {})
    summary_payload = _read_json(root / "coverage" / "coverage_summary_manifest.json", {})
    binary_manifest = _read_json(root / "runtime" / "binary_execution_manifest.json", {})
    plane_snapshot = load_round_coverage_snapshot(round_task_id)
    current_fraction = float(summary_payload.get("line_coverage_fraction", 0.0) or plane_snapshot.get("line_coverage_fraction") or 0.0)
    binary_signal_counts = binary_manifest.get("signal_category_counts") or {}
    binary_candidates = int(binary_manifest.get("crash_candidate_count") or 0)
    binary_proxy = {
        "execution_count": int(
            (feedback_payload.get("current", {}) or {}).get("execution_count")
            or binary_manifest.get("run_count")
            or 0
        ),
        "unique_input_count": int(
            (feedback_payload.get("current", {}) or {}).get("unique_input_count")
            or len({str(item.get("input_path") or "") for item in (binary_manifest.get("run_records") or []) if isinstance(item, dict) and str(item.get("input_path") or "").strip()})
        ),
        "crash_signal_rate": float(
            (feedback_payload.get("current", {}) or {}).get("crash_signal_rate")
            or (
                (
                    int(binary_manifest.get("crash_candidate_count") or 0)
                    / max(int(binary_manifest.get("run_count") or len(binary_manifest.get("run_records") or [])), 1)
                )
                if (binary_manifest.get("run_count") or len(binary_manifest.get("run_records") or []))
                else 0.0
            )
        ),
    }
    binary_signal_stalled = bool(binary_manifest) and binary_candidates <= 0 and not any(
        key not in {"informational_runtime_output", "runtime_noise"}
        for key, count in binary_signal_counts.items()
        if int(count or 0) > 0
    )
    binary_focus = str(binary_manifest.get("selected_binary_slice_focus") or "").strip()
    binary_low_growth_queue = (
        [{"name": binary_focus, "reason": "binary_signal_stalled", "coverage_fraction": 0.0}]
        if binary_signal_stalled and binary_focus
        else []
    )
    covered_function_set = sorted(
        {
            str(item.get("name") or "").strip()
            for item in (feedback_payload.get("current", {}).get("per_function_summary") or [])
            if str(item.get("name") or "").strip() and float(item.get("coverage_fraction", 0.0) or 0.0) > 0.0
        }
    )
    return {
        "exact_or_partial": str(plane_snapshot.get("exact_or_partial") or ("binary_signal" if binary_manifest else "unknown")),
        "coverage_control_mode": str(plane_snapshot.get("coverage_control_mode") or "unknown"),
        "covered_function_set": covered_function_set,
        "covered_function_count": int(plane_snapshot.get("covered_function_count") or 0),
        "uncovered_function_queue": binary_low_growth_queue or _dedupe_names(plane_snapshot.get("uncovered_function_queue") or []),
        "low_growth_function_queue": binary_low_growth_queue or _dedupe_names(plane_snapshot.get("low_growth_function_queue") or []),
        "partial_degraded_target_queue": _dedupe_names(plane_snapshot.get("degraded_target_queue") or []),
        "stalled_target_queue": _dedupe_names(plane_snapshot.get("stalled_target_queue") or []),
        "line_coverage_fraction": current_fraction,
        "coverage_stalled": bool(feedback_payload.get("coverage_stalled") or feedback_payload.get("stalled") or binary_signal_stalled),
        "current_snapshot_path": feedback_payload.get("current_snapshot_path"),
        "feedback_manifest_path": str(root / "coverage" / "feedback_manifest.json"),
        "summary_manifest_path": str(root / "coverage" / "coverage_summary_manifest.json"),
        "coverage_plane_snapshot_path": str(coverage_plane_snapshot_path(round_task_id)),
        "degraded_reason": plane_snapshot.get("degraded_reason"),
        "degraded_detail": plane_snapshot.get("degraded_detail"),
        "binary_signal_category_counts": binary_signal_counts,
        "binary_signal_stalled": binary_signal_stalled,
        "binary_coverage_proxy": binary_proxy,
    }


def apply_round_results_to_campaign(
    campaign_task_id: str,
    *,
    round_task_id: str,
    round_record: dict[str, Any],
    state: dict[str, Any],
    now_iso: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    coverage_state = _coverage_state_for_round(round_task_id)
    family_inventory = _round_family_inventory(round_task_id)
    confirmed_pov_names = _round_confirmed_pov_names(round_task_id)
    llm_metrics = _llm_metrics_for_round(round_task_id)
    round_root = task_root(round_task_id)
    project = str(state.get("project") or "unknown")
    lane = str(state.get("lane") or "source")
    target_mode = str(state.get("target_mode") or round_record.get("target_mode") or "source")
    previous_binary_runtime = dict(state.get("binary_runtime") or {})
    round_binary_runtime = _binary_runtime_state_for_round(round_task_id) if target_mode == "binary" else {}
    round_corpus_root = round_root / "corpus" / ("binary_active" if target_mode == "binary" else "active")
    shared_root = campaign_shared_corpus_path(campaign_task_id)
    harness_root = campaign_harness_corpora_root_path(campaign_task_id)
    selected_harness = str(round_record.get("selected_harness") or state.get("last_selected_harness") or "default_harness")
    selected_harness_key = _safe_harness_dir(selected_harness)
    harness_corpus_root = harness_root / selected_harness_key
    shared_before = _corpus_file_count(shared_root)
    merge_manifest_path = campaign_corpus_merge_manifest_path(round_task_id)
    corpus_stage_state = _corpus_stage_state_for_round(round_task_id)
    shared_growth = merge_into_campaign_local_corpus(
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
                "selected_target_function": round_record.get("selected_target_function") or state.get("last_selected_target_function"),
                "selection_reason": "export_round_local_into_campaign_shared_pool",
                "export_reason": "campaign_shared_export",
            }
        ],
        destination_kind="campaign_shared",
        destination_project=project,
        destination_lane=lane,
        destination_target_mode=target_mode,
        destination_harness=None,
        decision_log_path=merge_manifest_path.with_name("campaign_shared_corpus_merge_manifest.json"),
        index_path=merge_manifest_path.with_name("campaign_shared_corpus_index.json"),
        consumer_task_id=round_task_id,
        consumer_campaign_task_id=campaign_task_id,
        **corpus_policy("campaign_shared"),
    )
    harness_growth = merge_into_campaign_local_corpus(
        harness_corpus_root,
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
                "selected_target_function": round_record.get("selected_target_function") or state.get("last_selected_target_function"),
                "selection_reason": "export_round_local_into_campaign_harness_pool",
                "export_reason": "campaign_harness_export",
            }
        ],
        destination_kind="campaign_harness",
        destination_project=project,
        destination_lane=lane,
        destination_target_mode=target_mode,
        destination_harness=selected_harness,
        decision_log_path=merge_manifest_path.with_name("campaign_harness_corpus_merge_manifest.json"),
        index_path=merge_manifest_path.with_name("campaign_harness_corpus_index.json"),
        consumer_task_id=round_task_id,
        consumer_campaign_task_id=campaign_task_id,
        **corpus_policy("campaign_harness"),
    )
    shared_after = _corpus_file_count(shared_root)
    if target_mode == "binary":
        state["binary_runtime"] = {
            **previous_binary_runtime,
            **round_binary_runtime,
        }

    metrics = dict(state.get("metrics") or {})
    metrics["fuzz_session_count"] = int(metrics.get("fuzz_session_count") or 0) + 1
    metrics["reseed_trigger_count"] = int(metrics.get("reseed_trigger_count") or 0) + (
        1 if round_record.get("reseeding_triggered") else 0
    )
    if target_mode == "binary" and round_record.get("reseeding_triggered"):
        metrics["binary_reseed_trigger_count"] = int(metrics.get("binary_reseed_trigger_count") or 0) + 1
    metrics["llm_request_count_total"] = int(metrics.get("llm_request_count_total") or 0) + int(llm_metrics["request_count_total"])
    by_stage = dict(metrics.get("llm_request_count_by_stage") or {})
    for stage, count in llm_metrics["request_count_by_stage"].items():
        by_stage[stage] = int(by_stage.get(stage) or 0) + int(count or 0)
    metrics["llm_request_count_by_stage"] = by_stage
    metrics["llm_success_count"] = int(metrics.get("llm_success_count") or 0) + int(llm_metrics["success_count"] or 0)
    metrics["llm_failure_count"] = int(metrics.get("llm_failure_count") or 0) + int(llm_metrics["failure_count"] or 0)
    metrics["shared_corpus_growth_count"] = int(metrics.get("shared_corpus_growth_count") or 0) + int(shared_growth["new_files"] or 0)
    metrics["shared_corpus_import_count_total"] = int(metrics.get("shared_corpus_import_count_total") or 0) + int(
        corpus_stage_state.get("selected_imported_count") or 0
    )
    metrics["shared_corpus_stage_new_files_total"] = int(metrics.get("shared_corpus_stage_new_files_total") or 0) + int(
        corpus_stage_state.get("system_stage_new_files") or 0
    )
    metrics["cross_lane_transfer_count_total"] = int(metrics.get("cross_lane_transfer_count_total") or 0) + int(
        corpus_stage_state.get("cross_lane_transfer_count") or 0
    )
    metrics["cross_project_transfer_count_total"] = int(
        metrics.get("cross_project_transfer_count_total") or 0
    ) + int(corpus_stage_state.get("cross_project_transfer_count") or 0)
    metrics["corpus_quality_gate_passed_total"] = int(metrics.get("corpus_quality_gate_passed_total") or 0) + int(
        corpus_stage_state.get("quality_gate_passed_count") or 0
    )
    metrics["corpus_quality_gate_rejected_total"] = int(
        metrics.get("corpus_quality_gate_rejected_total") or 0
    ) + int(corpus_stage_state.get("quality_gate_rejected_count") or 0)
    total_quality_seen = int(metrics.get("corpus_quality_gate_passed_total") or 0) + int(
        metrics.get("corpus_quality_gate_rejected_total") or 0
    )
    metrics["quality_gate_pass_rate"] = round(
        int(metrics.get("corpus_quality_gate_passed_total") or 0) / max(total_quality_seen, 1),
        6,
    )
    metrics["total_raw_crash_count"] = int(metrics.get("total_raw_crash_count") or 0) + int(round_record.get("new_raw_crash_count") or 0)
    metrics["total_traced_crash_count"] = int(metrics.get("total_traced_crash_count") or 0) + int(round_record.get("new_traced_crash_count") or 0)
    distinct_pov_names = set(state.get("distinct_pov_names") or [])
    distinct_pov_names.update(confirmed_pov_names)
    state["distinct_pov_names"] = sorted(distinct_pov_names)
    metrics["distinct_pov_count"] = len(distinct_pov_names)

    state_family_inventory = dict(state.get("family_inventory") or {})
    existing_exact = set(state_family_inventory.get("trace_exact_signatures") or [])
    existing_loose = set(state_family_inventory.get("loose_vulnerable_state_clusters") or [])
    existing_confirmed = set(state_family_inventory.get("confirmed_families") or [])
    existing_unresolved_map = {
        str(item.get("loose_cluster_key") or "").strip(): dict(item)
        for item in (state_family_inventory.get("unresolved_loose_clusters") or [])
        if isinstance(item, dict) and str(item.get("loose_cluster_key") or "").strip()
    }
    existing_blockers = [
        dict(item)
        for item in (state_family_inventory.get("promotion_blockers") or [])
        if isinstance(item, dict)
    ]
    loose_cluster_details = dict(state_family_inventory.get("loose_cluster_details") or {})
    confirmed_family_details = dict(state_family_inventory.get("confirmed_family_details") or {})
    round_exact = set(family_inventory["trace_exact_signatures"])
    round_loose = set(family_inventory["loose_vulnerable_state_clusters"])
    round_confirmed = set(family_inventory["confirmed_families"])
    current_session_index = int(round_record.get("session_index") or int(state.get("session_count") or 0) + 1)
    reconfirmation_threshold_rounds = _family_reconfirmation_threshold(state)
    round_unresolved_entries = [
        dict(item)
        for item in (family_inventory.get("unresolved_loose_clusters") or [])
        if isinstance(item, dict) and str(item.get("loose_cluster_key") or "").strip()
    ]
    round_blockers = [
        {
            **dict(item),
            "round_task_id": round_task_id,
            "recorded_at": now_iso,
        }
        for item in (family_inventory.get("promotion_blockers") or [])
        if isinstance(item, dict)
    ]
    new_exact = sorted(round_exact - existing_exact)
    new_loose = sorted(round_loose - existing_loose)
    new_confirmed = sorted(round_confirmed - existing_confirmed)
    existing_exact.update(round_exact)
    existing_loose.update(round_loose)
    existing_confirmed.update(round_confirmed)
    loose_cluster_details.update(dict(family_inventory.get("loose_cluster_details") or {}))
    confirmed_family_details.update(dict(family_inventory.get("confirmed_family_details") or {}))
    for family_key in sorted(existing_confirmed):
        previous_detail = dict((state_family_inventory.get("confirmed_family_details") or {}).get(family_key) or {})
        current_detail = dict(confirmed_family_details.get(family_key) or {})
        merged_detail = {**previous_detail, **current_detail}
        merged_detail["confirmed_family_key"] = family_key
        merged_detail["first_confirmed_round_task_id"] = (
            previous_detail.get("first_confirmed_round_task_id")
            or current_detail.get("first_confirmed_round_task_id")
            or round_task_id
        )
        merged_detail["last_confirmed_round_task_id"] = (
            round_task_id
            if family_key in round_confirmed
            else (
                current_detail.get("last_confirmed_round_task_id")
                or previous_detail.get("last_confirmed_round_task_id")
            )
        )
        merged_detail["first_confirmed_at"] = (
            previous_detail.get("first_confirmed_at")
            or current_detail.get("first_confirmed_at")
            or now_iso
        )
        merged_detail["last_confirmed_at"] = (
            now_iso
            if family_key in round_confirmed
            else (
                current_detail.get("last_confirmed_at")
                or previous_detail.get("last_confirmed_at")
            )
        )
        merged_detail["first_confirmed_session_index"] = int(
            previous_detail.get("first_confirmed_session_index")
            or current_detail.get("first_confirmed_session_index")
            or current_session_index
        )
        if family_key in round_confirmed:
            merged_detail["last_confirmed_session_index"] = current_session_index
            merged_detail["last_reconfirmed_session_index"] = current_session_index
            merged_detail["confirmation_count"] = int(previous_detail.get("confirmation_count") or 0) + 1
            merged_detail["requires_reconfirmation"] = False
        else:
            merged_detail["last_confirmed_session_index"] = int(
                current_detail.get("last_confirmed_session_index")
                or previous_detail.get("last_confirmed_session_index")
                or merged_detail.get("first_confirmed_session_index")
                or 0
            )
            merged_detail["last_reconfirmed_session_index"] = int(
                current_detail.get("last_reconfirmed_session_index")
                or previous_detail.get("last_reconfirmed_session_index")
                or merged_detail.get("last_confirmed_session_index")
                or 0
            )
            merged_detail["confirmation_count"] = int(
                current_detail.get("confirmation_count")
                or previous_detail.get("confirmation_count")
                or 0
            )
        observed_signatures = {
            str(item).strip()
            for item in list(previous_detail.get("observed_signatures") or [])
            + list(current_detail.get("observed_signatures") or [])
            + list(previous_detail.get("exact_signatures") or [])
            + list(current_detail.get("exact_signatures") or [])
            if str(item).strip()
        }
        for value in [
            previous_detail.get("family_exact_signature"),
            previous_detail.get("signature"),
            current_detail.get("family_exact_signature"),
            current_detail.get("signature"),
        ]:
            candidate = str(value or "").strip()
            if candidate:
                observed_signatures.add(candidate)
        merged_detail["observed_signatures"] = sorted(observed_signatures)
        merged_detail["family_lineage"] = (
            current_detail.get("family_lineage")
            or current_detail.get("lineage")
            or previous_detail.get("family_lineage")
            or previous_detail.get("lineage")
            or {}
        )
        merged_detail["reconfirmation_threshold_rounds"] = reconfirmation_threshold_rounds
        confirmed_family_details[family_key] = merged_detail
    unresolved_map = {
        key: value
        for key, value in existing_unresolved_map.items()
        if key and key not in existing_confirmed
    }
    for entry in round_unresolved_entries:
        cluster_key = str(entry.get("loose_cluster_key") or "").strip()
        if not cluster_key or cluster_key in existing_confirmed:
            continue
        previous_entry = dict(unresolved_map.get(cluster_key) or {})
        merged_entry = {**previous_entry, **entry}
        merged_entry["loose_cluster_key"] = cluster_key
        merged_entry["confirmed_family_key"] = (
            merged_entry.get("confirmed_family_key")
            or previous_entry.get("confirmed_family_key")
            or cluster_key
        )
        merged_entry["first_seen_round_task_id"] = (
            previous_entry.get("first_seen_round_task_id")
            or round_task_id
        )
        merged_entry["last_seen_round_task_id"] = round_task_id
        merged_entry["last_seen_at"] = now_iso
        merged_entry["seen_count"] = int(previous_entry.get("seen_count") or 0) + 1
        unresolved_map[cluster_key] = merged_entry
    resolved_unresolved_clusters = sorted(set(existing_unresolved_map) - set(unresolved_map))
    promotion_blockers = (existing_blockers + round_blockers)[-64:]
    state_family_inventory.update(
        {
            "trace_exact_signatures": sorted(existing_exact),
            "loose_vulnerable_state_clusters": sorted(existing_loose),
            "confirmed_families": sorted(existing_confirmed),
            "unresolved_loose_clusters": sorted(
                unresolved_map.values(),
                key=lambda item: (
                    str(item.get("last_seen_at") or ""),
                    str(item.get("loose_cluster_key") or ""),
                ),
            ),
            "promotion_blockers": promotion_blockers,
            "loose_cluster_details": loose_cluster_details,
            "confirmed_family_details": confirmed_family_details,
            "last_trace_family_manifest_path": family_inventory.get("trace_family_manifest_path"),
            "last_repro_family_manifest_path": family_inventory.get("repro_family_manifest_path"),
            "last_new_exact_signatures": new_exact,
            "last_new_loose_clusters": new_loose,
            "last_new_confirmed_families": new_confirmed,
        }
    )
    state_family_inventory = _refresh_family_reconfirmation_state(
        state_family_inventory,
        current_session_index=current_session_index,
        threshold_rounds=reconfirmation_threshold_rounds,
    )
    state["family_inventory"] = state_family_inventory
    metrics["trace_exact_signature_count"] = len(existing_exact)
    metrics["loose_cluster_count"] = len(existing_loose)
    metrics["confirmed_family_count"] = len(existing_confirmed)
    metrics["unresolved_loose_cluster_count"] = len(unresolved_map)
    metrics["promotion_blocker_count"] = len(promotion_blockers)
    family_progress = bool(new_exact or new_loose or new_confirmed or resolved_unresolved_clusters)
    previous_family_diversification = dict(state.get("family_diversification") or {})
    family_stagnation_count = 0 if family_progress else int(previous_family_diversification.get("stagnation_count") or 0) + 1
    family_diversification_triggered = bool(round_record.get("family_diversification_triggered")) or (
        str(round_record.get("triggered_action_type") or "") == "family_diversification"
    )
    if family_diversification_triggered:
        metrics["family_diversification_trigger_count"] = int(metrics.get("family_diversification_trigger_count") or 0) + 1
    state["family_diversification"] = {
        "stagnation_count": family_stagnation_count,
        "last_new_trace_exact_count": len(new_exact),
        "last_new_loose_cluster_count": len(new_loose),
        "last_new_confirmed_family_count": len(new_confirmed),
        "unresolved_loose_cluster_count": len(unresolved_map),
        "promotion_blocker_count": len(promotion_blockers),
        "requires_reconfirmation_count": int(state_family_inventory.get("requires_reconfirmation_count") or 0),
        "last_unresolved_loose_clusters": list(unresolved_map.values())[-8:],
        "last_promotion_blockers": promotion_blockers[-8:],
        "resolved_unresolved_clusters": resolved_unresolved_clusters,
        "last_triggered_at": now_iso if family_diversification_triggered else previous_family_diversification.get("last_triggered_at"),
        "last_selected_harness": selected_harness,
        "last_selected_target_function": round_record.get("selected_target_function"),
    }
    if coverage_state.get("binary_signal_category_counts"):
        lifted = sum(
            int(count or 0)
            for category, count in (coverage_state.get("binary_signal_category_counts") or {}).items()
            if category not in {"informational_runtime_output", "runtime_noise"}
        )
        metrics["binary_signal_lift_count"] = int(metrics.get("binary_signal_lift_count") or 0) + lifted
    previous_feedback_state = str(previous_binary_runtime.get("feedback_state") or "").strip()
    current_feedback_state = str(round_binary_runtime.get("feedback_state") or "").strip()
    metrics["binary_signal_lift_count"] = int(metrics.get("binary_signal_lift_count") or 0) + int(
        round_binary_runtime.get("signal_lift_total") or 0
    )
    if (
        target_mode == "binary"
        and previous_feedback_state in {"informational_stall", "low_promotion_stall"}
        and current_feedback_state in {"watchlist_suspicious", "promoted_candidate_available"}
    ):
        metrics["binary_signal_lift_count"] = int(metrics.get("binary_signal_lift_count") or 0) + 1

    previous_fraction = state.get("coverage_state", {}).get("last_line_coverage_fraction")
    current_fraction = coverage_state.get("line_coverage_fraction")
    coverage_growth = (
        round(float(current_fraction) - float(previous_fraction), 6)
        if previous_fraction is not None and current_fraction is not None
        else 0.0
    )
    updated_coverage_state = dict(state.get("coverage_state") or {})
    updated_coverage_state.update(
        {
            "exact_or_partial": coverage_state.get("exact_or_partial"),
            "coverage_control_mode": coverage_state.get("coverage_control_mode"),
            "covered_function_set": coverage_state.get("covered_function_set"),
            "covered_function_count": int(coverage_state.get("covered_function_count") or len(coverage_state.get("covered_function_set") or [])),
            "uncovered_function_queue": coverage_state.get("uncovered_function_queue"),
            "low_growth_function_queue": coverage_state.get("low_growth_function_queue"),
            "partial_degraded_target_queue": coverage_state.get("partial_degraded_target_queue") or [],
            "stalled_target_queue": coverage_state.get("stalled_target_queue") or [],
            "last_line_coverage_fraction": current_fraction,
            "recent_coverage_growth": coverage_growth,
            "coverage_stalled": coverage_state.get("coverage_stalled"),
            "degraded_reason": coverage_state.get("degraded_reason"),
            "degraded_detail": coverage_state.get("degraded_detail"),
            "coverage_plane_snapshot_path": coverage_state.get("coverage_plane_snapshot_path"),
            "binary_signal_category_counts": coverage_state.get("binary_signal_category_counts") or {},
            "binary_signal_stalled": bool(coverage_state.get("binary_signal_stalled")),
            "binary_coverage_proxy": dict(coverage_state.get("binary_coverage_proxy") or {}),
        }
    )
    if coverage_state.get("exact_or_partial") == "exact":
        updated_coverage_state["last_exact_coverage_time"] = now_iso
    per_harness_growth = dict(updated_coverage_state.get("per_harness_recent_growth") or {})
    per_harness_growth[selected_harness] = coverage_growth
    updated_coverage_state["per_harness_recent_growth"] = per_harness_growth
    per_target_stall_counts = dict(updated_coverage_state.get("per_target_stall_counts") or {})
    selected_target_name = str(round_record.get("selected_target_function") or state.get("last_selected_target_function") or "").strip()
    current_target_stall_count = 0
    if selected_target_name:
        previous_target_state = dict(per_target_stall_counts.get(selected_target_name) or {})
        current_target_stall_count = 0 if coverage_growth > 0.0 else int(previous_target_state.get("stall_rounds") or 0) + 1
        per_target_stall_counts[selected_target_name] = {
            "stall_rounds": current_target_stall_count,
            "last_coverage_growth": coverage_growth,
            "last_updated_at": now_iso,
        }
    if len(per_target_stall_counts) > 64:
        ordered_targets = sorted(
            per_target_stall_counts.items(),
            key=lambda item: (
                str((item[1] or {}).get("last_updated_at") or ""),
                item[0],
            ),
            reverse=True,
        )
        per_target_stall_counts = {name: value for name, value in ordered_targets[:64]}
    updated_coverage_state["per_target_stall_counts"] = per_target_stall_counts
    updated_coverage_state["last_target_stall_count"] = current_target_stall_count
    state["coverage_state"] = updated_coverage_state

    plane_update = update_coverage_plane_after_round(
        campaign_task_id,
        round_task_id=round_task_id,
        project=project,
        lane=lane,
        target_mode=target_mode,
        session_index=int(round_record.get("session_index") or int(state.get("session_count") or 0) + 1),
        selected_harness=selected_harness,
        now_iso_value=now_iso,
    )
    updated_coverage_state["campaign_coverage_plane_state_path"] = plane_update.get("campaign_coverage_plane_state_path")
    updated_coverage_state["campaign_coverage_queue_path"] = plane_update.get("campaign_coverage_queue_path")
    updated_coverage_state["campaign_coverage_queue_consumption_path"] = str(campaign_coverage_queue_consumption_path(campaign_task_id))
    updated_coverage_state["exact_coverage_available_ratio"] = plane_update.get("campaign_exact_coverage_available_ratio")
    state["coverage_state"] = updated_coverage_state

    coverage_level = str(coverage_state.get("exact_or_partial") or "unknown")
    if coverage_level == "exact":
        metrics["coverage_exact_sessions"] = int(metrics.get("coverage_exact_sessions") or 0) + 1
    elif coverage_level == "partial":
        metrics["coverage_partial_sessions"] = int(metrics.get("coverage_partial_sessions") or 0) + 1
    elif coverage_level == "fallback":
        metrics["coverage_fallback_sessions"] = int(metrics.get("coverage_fallback_sessions") or 0) + 1
    elif coverage_level == "binary_signal":
        metrics["coverage_binary_signal_sessions"] = int(metrics.get("coverage_binary_signal_sessions") or 0) + 1
    else:
        metrics["coverage_unknown_sessions"] = int(metrics.get("coverage_unknown_sessions") or 0) + 1
    metrics["exact_coverage_available_ratio"] = float(plane_update.get("campaign_exact_coverage_available_ratio") or 0.0)
    metrics["campaign_coverage_queue_count"] = int(plane_update.get("campaign_coverage_queue_count") or 0)
    metrics["campaign_low_growth_queue_count"] = int(plane_update.get("campaign_low_growth_queue_count") or 0)
    metrics["campaign_uncovered_queue_count"] = int(plane_update.get("campaign_uncovered_queue_count") or 0)
    metrics["campaign_partial_queue_count"] = int(plane_update.get("campaign_partial_queue_count") or 0)
    metrics["campaign_stalled_queue_count"] = int(plane_update.get("campaign_stalled_queue_count") or 0)
    metrics["system_coverage_plane_queue_count"] = int(plane_update.get("system_coverage_queue_count") or 0)

    candidate_bridge_queue = list(state.get("candidate_bridge_queue") or [])
    candidate_bridge_triggered = False
    trace_worthy_candidate_count = 0
    if target_mode != "binary" and not family_progress:
        low_queue = updated_coverage_state.get("low_growth_function_queue") or []
        uncovered_queue = updated_coverage_state.get("uncovered_function_queue") or []
        bridge_target = (
            round_record.get("selected_target_function")
            or (low_queue[0].get("name") if low_queue and isinstance(low_queue[0], dict) else None)
            or (uncovered_queue[0].get("name") if uncovered_queue and isinstance(uncovered_queue[0], dict) else None)
            or selected_harness
        )
        should_bridge = bool(
            bridge_target
            and (
                coverage_state.get("coverage_stalled")
                or family_stagnation_count >= 2
                or int(shared_growth["new_files"] or 0) > 0
                or low_queue
                or uncovered_queue
            )
        )
        if should_bridge:
            candidate_bridge_triggered = True
            trace_worthy = bool(coverage_state.get("coverage_stalled") or family_stagnation_count >= 2 or low_queue)
            trace_worthy_candidate_count = 1 if trace_worthy else 0
            candidate_bridge_queue.append(
                {
                    "name": str(bridge_target),
                    "reason": "no_new_family_after_fuzz_session",
                    "selected_harness": selected_harness,
                    "family_stagnation_count": family_stagnation_count,
                    "coverage_stalled": bool(coverage_state.get("coverage_stalled")),
                    "coverage_growth": coverage_growth,
                    "shared_corpus_new_files": int(shared_growth["new_files"] or 0),
                    "trace_worthy": trace_worthy,
                    "created_at": now_iso,
                    "round_task_id": round_task_id,
                }
            )
            candidate_bridge_queue = candidate_bridge_queue[-24:]
            metrics["generalized_candidate_bridge_count"] = int(metrics.get("generalized_candidate_bridge_count") or 0) + 1
            metrics["trace_worthy_candidate_count"] = int(metrics.get("trace_worthy_candidate_count") or 0) + trace_worthy_candidate_count
    else:
        candidate_bridge_queue = candidate_bridge_queue[-12:]
    state["candidate_bridge_queue"] = candidate_bridge_queue

    previous_harness = str(state.get("last_selected_harness") or "").strip() or None
    if previous_harness and previous_harness != selected_harness:
        metrics["harness_switch_count"] = int(metrics.get("harness_switch_count") or 0) + 1

    harness_pool = list(state.get("active_harness_pool") or [])
    for entry in harness_pool:
        if entry.get("harness_name") != selected_harness:
            cooldown_until = int(entry.get("cooldown_until_session") or 0)
            if entry.get("status") == "cooldown" and cooldown_until <= int(state.get("session_count") or 0) + 1:
                entry["status"] = "active"
            continue
        entry["recent_session_count"] = int(entry.get("recent_session_count") or 0) + 1
        entry["recent_new_crash_count"] = int(round_record.get("new_raw_crash_count") or 0)
        entry["recent_new_trace_count"] = int(round_record.get("new_traced_crash_count") or 0)
        entry["recent_new_trace_exact_count"] = len(new_exact)
        entry["recent_new_loose_cluster_count"] = len(new_loose)
        entry["recent_new_confirmed_family_count"] = len(new_confirmed)
        entry["recent_unresolved_loose_cluster_count"] = len(unresolved_map)
        entry["recent_promotion_blocker_count"] = len(round_blockers)
        entry["recent_family_stagnation_count"] = family_stagnation_count
        entry["recent_coverage_growth"] = coverage_growth
        entry["recent_corpus_growth"] = int(shared_growth["new_files"] or 0) + int(harness_growth["new_files"] or 0)
        entry["last_used_at"] = now_iso
        if len(harness_pool) > 1 and (
            (entry["recent_new_crash_count"] == 0 and entry["recent_new_trace_count"] == 0 and coverage_growth <= 0.0)
            or family_stagnation_count >= 2
        ):
            entry["status"] = "cooldown"
            entry["cooldown_until_session"] = int(state.get("session_count") or 0) + 2
        else:
            entry["status"] = "active"
            entry["cooldown_until_session"] = 0
    state["active_harness_pool"] = harness_pool

    shared_corpus_state = dict(state.get("shared_corpus") or {})
    harness_index_paths = dict(shared_corpus_state.get("harness_index_paths") or {})
    harness_index_paths[selected_harness_key] = str(merge_manifest_path.with_name("campaign_harness_corpus_index.json"))
    shared_corpus_state.update(
        {
            "root": str(shared_root),
            "harness_corpora_root": str(harness_root),
            "file_count": shared_after,
            "growth_count": int(shared_corpus_state.get("growth_count") or 0) + int(shared_growth["new_files"] or 0),
            "last_merged_round_task_id": round_task_id,
            "last_growth_bytes": int(shared_growth["new_bytes"] or 0),
            "last_merge_manifest_path": str(merge_manifest_path),
            "last_campaign_shared_merge_manifest_path": str(merge_manifest_path.with_name("campaign_shared_corpus_merge_manifest.json")),
            "last_campaign_harness_merge_manifest_path": str(merge_manifest_path.with_name("campaign_harness_corpus_merge_manifest.json")),
            "last_campaign_shared_index_path": str(merge_manifest_path.with_name("campaign_shared_corpus_index.json")),
            "last_campaign_harness_index_path": str(merge_manifest_path.with_name("campaign_harness_corpus_index.json")),
            "last_campaign_harness_key": selected_harness_key,
            "import_count_per_campaign": int(shared_corpus_state.get("import_count_per_campaign") or 0)
            + int(corpus_stage_state.get("selected_imported_count") or 0),
            "cross_lane_transfer_count": int(shared_corpus_state.get("cross_lane_transfer_count") or 0)
            + int(corpus_stage_state.get("cross_lane_transfer_count") or 0),
            "cross_project_transfer_count": int(shared_corpus_state.get("cross_project_transfer_count") or 0)
            + int(corpus_stage_state.get("cross_project_transfer_count") or 0),
            "quality_gate_passed_count": int(shared_corpus_state.get("quality_gate_passed_count") or 0)
            + int(corpus_stage_state.get("quality_gate_passed_count") or 0),
            "quality_gate_rejected_count": int(shared_corpus_state.get("quality_gate_rejected_count") or 0)
            + int(corpus_stage_state.get("quality_gate_rejected_count") or 0),
            "quality_gate_pass_rate": metrics.get("quality_gate_pass_rate"),
            "last_stage_manifest_path": corpus_stage_state.get("stage_manifest_path"),
            "harness_index_paths": harness_index_paths,
        }
    )
    state["shared_corpus"] = shared_corpus_state

    compatible_export_layers, compatible_export_trace = _build_compatible_corpus_export_layers(
        campaign_task_id=campaign_task_id,
        round_task_id=round_task_id,
        round_record=round_record,
        project=project,
        lane=lane,
        target_mode=target_mode,
        selected_harness=selected_harness,
        selected_target_function=round_record.get("selected_target_function") or state.get("last_selected_target_function"),
        coverage_growth=coverage_growth,
        round_local_growth_hint=int(shared_growth["new_files"] or 0) + int(harness_growth["new_files"] or 0),
    )
    system_updates = update_after_round(
        campaign_task_id=campaign_task_id,
        round_task_id=round_task_id,
        project=project,
        lane=lane,
        target_mode=target_mode,
        selected_harness=selected_harness,
        selected_target_function=round_record.get("selected_target_function") or state.get("last_selected_target_function"),
        round_corpus_root=round_corpus_root,
        coverage_state=updated_coverage_state,
        family_inventory=state_family_inventory,
        round_record=round_record,
        now_iso=now_iso,
        compatible_export_layers=compatible_export_layers,
    )
    metrics["shared_corpus_growth_count"] = int(metrics.get("shared_corpus_growth_count") or 0) + int(
        system_updates.get("system_shared_corpus_new_files") or 0
    )
    metrics["shared_corpus_export_count_total"] = int(metrics.get("shared_corpus_export_count_total") or 0) + int(
        system_updates.get("system_compatible_shared_new_files") or 0
    )
    metrics["corpus_quality_gate_passed_total"] = int(metrics.get("corpus_quality_gate_passed_total") or 0) + int(
        system_updates.get("system_compatible_selected_count") or 0
    )
    metrics["corpus_quality_gate_rejected_total"] = int(
        metrics.get("corpus_quality_gate_rejected_total") or 0
    ) + int(system_updates.get("system_compatible_quality_gate_rejected_count") or 0)
    total_quality_seen = int(metrics.get("corpus_quality_gate_passed_total") or 0) + int(
        metrics.get("corpus_quality_gate_rejected_total") or 0
    )
    metrics["quality_gate_pass_rate"] = round(
        int(metrics.get("corpus_quality_gate_passed_total") or 0) / max(total_quality_seen, 1),
        6,
    )
    metrics["generalized_candidate_bridge_count"] = int(metrics.get("generalized_candidate_bridge_count") or 0) + int(
        system_updates.get("system_candidate_bridge_new_count") or 0
    )
    metrics["trace_worthy_candidate_count"] = int(metrics.get("trace_worthy_candidate_count") or 0) + int(
        system_updates.get("system_trace_worthy_new_count") or 0
    )
    metrics["system_candidate_bridge_count"] = int(metrics.get("system_candidate_bridge_count") or 0) + int(
        system_updates.get("system_candidate_bridge_new_count") or 0
    )
    metrics["system_trace_worthy_candidate_count"] = int(metrics.get("system_trace_worthy_candidate_count") or 0) + int(
        system_updates.get("system_trace_worthy_new_count") or 0
    )
    metrics["binary_fabric_reseed_count"] = int(metrics.get("binary_fabric_reseed_count") or 0) + int(
        system_updates.get("system_binary_reseed_new_count") or 0
    )
    metrics["binary_fabric_candidate_count"] = int(metrics.get("binary_fabric_candidate_count") or 0) + int(
        system_updates.get("system_binary_candidate_new_count") or 0
    )
    metrics["binary_fabric_family_count"] = int(metrics.get("binary_fabric_family_count") or 0) + int(
        system_updates.get("system_binary_family_new_count") or 0
    )
    metrics["system_low_growth_queue_count"] = int(system_updates.get("system_low_growth_queue_count") or 0)
    metrics["system_uncovered_queue_count"] = int(system_updates.get("system_uncovered_queue_count") or 0)
    metrics["system_stalled_target_count"] = int(system_updates.get("system_stalled_target_count") or 0)
    metrics["system_compatible_selected_count"] = int(system_updates.get("system_compatible_selected_count") or 0)
    metrics["system_compatible_cross_lane_selected_count"] = int(
        system_updates.get("system_compatible_cross_lane_selected_count") or 0
    )
    metrics["system_compatible_cross_project_selected_count"] = int(
        system_updates.get("system_compatible_cross_project_selected_count") or 0
    )
    shared_corpus_state = dict(state.get("shared_corpus") or {})
    shared_corpus_state["export_count_per_campaign"] = int(shared_corpus_state.get("export_count_per_campaign") or 0) + int(
        system_updates.get("system_compatible_shared_new_files") or 0
    )
    shared_corpus_state["last_system_compatible_export_manifest_path"] = system_updates.get(
        "system_compatible_shared_corpus_merge_manifest_path"
    )
    shared_corpus_state["last_system_compatible_export_index_path"] = system_updates.get(
        "system_compatible_shared_corpus_index_path"
    )
    shared_corpus_state["last_system_compatible_selected_count"] = int(
        system_updates.get("system_compatible_selected_count") or 0
    )
    shared_corpus_state["last_system_compatible_cross_lane_selected_count"] = int(
        system_updates.get("system_compatible_cross_lane_selected_count") or 0
    )
    shared_corpus_state["last_system_compatible_cross_project_selected_count"] = int(
        system_updates.get("system_compatible_cross_project_selected_count") or 0
    )
    shared_corpus_state["quality_gate_pass_rate"] = metrics.get("quality_gate_pass_rate")
    state["shared_corpus"] = shared_corpus_state
    state["system_fabric"] = {
        **dict(state.get("system_fabric") or {}),
        **system_updates,
    }
    _write_json(
        merge_manifest_path,
        {
            "generated_at": now_iso,
            "campaign_task_id": campaign_task_id,
            "round_task_id": round_task_id,
            "project": project,
            "lane": lane,
            "target_mode": target_mode,
            "selected_harness": selected_harness,
            "round_corpus_root": str(round_corpus_root),
            "corpus_stage_state": corpus_stage_state,
            "compatible_export_layer_count": len(compatible_export_layers),
            "compatible_export_trace": compatible_export_trace,
            "compatible_export_layers": [
                {
                    "label": str(layer.get("label") or "unknown"),
                    "root": str(layer.get("root") or ""),
                    "allowed_path_count": len(layer.get("allowed_paths") or []),
                    "origin_signal": layer.get("origin_signal"),
                    "origin_input_role": layer.get("origin_input_role"),
                    "export_reason": layer.get("export_reason"),
                }
                for layer in compatible_export_layers
            ],
            "campaign_shared_merge": shared_growth,
            "campaign_harness_merge": harness_growth,
            "system_merge": system_updates,
        },
    )

    if target_mode != "binary":
        if bool(round_record.get("session_workspace_reused")):
            state["active_session_reuse_count"] = int(state.get("active_session_reuse_count") or 0) + 1
            metrics["continuous_workspace_reuse_count"] = int(metrics.get("continuous_workspace_reuse_count") or 0) + 1
        state["active_session_task_id"] = round_task_id
        state["session_continuity_mode"] = (
            round_record.get("session_continuity_mode")
            or ("campaign_active_session_task" if int(state.get("session_count") or 0) >= 1 else "fresh_round_clone")
        )
        state["last_session_summary_path"] = round_record.get("session_summary_path")
        state["last_corpus_state_reference"] = (
            round_record.get("session_corpus_state_reference") or str(round_corpus_root)
        )
        state["last_coverage_snapshot_reference"] = (
            round_record.get("session_coverage_snapshot_reference")
            or coverage_state.get("current_snapshot_path")
            or round_record.get("coverage_snapshot_path")
        )
        state["last_stagnation_state"] = {
            "coverage_stalled": bool(updated_coverage_state.get("coverage_stalled")),
            "coverage_growth": coverage_growth,
            "coverage_target_stall_count": current_target_stall_count,
            "family_stagnation_count": family_stagnation_count,
            "triggered_action_type": round_record.get("triggered_action_type"),
            "selected_harness": selected_harness,
            "selected_target_function": round_record.get("selected_target_function"),
            "updated_at": now_iso,
        }

    state["session_count"] = int(state.get("session_count") or 0) + 1
    state["last_selected_harness"] = selected_harness
    state["last_selected_target_function"] = round_record.get("selected_target_function")
    state["last_session_finished_at"] = now_iso
    state["updated_at"] = now_iso
    state["metrics"] = metrics

    round_updates = {
        "shared_corpus_count_before": shared_before,
        "shared_corpus_count_after": shared_after,
        "shared_corpus_new_files": int(shared_growth["new_files"] or 0),
        "selected_harness": selected_harness,
        "selected_target_function": round_record.get("selected_target_function") or state.get("last_selected_target_function"),
        "low_growth_function_count": len(updated_coverage_state.get("low_growth_function_queue") or []),
        "trace_exact_signature_count": len(existing_exact),
        "loose_cluster_count": len(existing_loose),
        "confirmed_family_count": len(existing_confirmed),
        "unresolved_loose_cluster_count": len(unresolved_map),
        "promotion_blocker_count": len(promotion_blockers),
        "family_diversification_triggered": family_diversification_triggered,
        "family_stagnation_count": family_stagnation_count,
        "candidate_bridge_triggered": candidate_bridge_triggered,
        "candidate_bridge_count": len(candidate_bridge_queue),
        "trace_worthy_candidate_count": trace_worthy_candidate_count,
        "trace_family_manifest_path": family_inventory.get("trace_family_manifest_path"),
        "repro_family_manifest_path": family_inventory.get("repro_family_manifest_path"),
        "system_candidate_bridge_new_count": int(system_updates.get("system_candidate_bridge_new_count") or 0),
        "system_trace_worthy_new_count": int(system_updates.get("system_trace_worthy_new_count") or 0),
        "system_binary_reseed_new_count": int(system_updates.get("system_binary_reseed_new_count") or 0),
        "system_binary_candidate_new_count": int(system_updates.get("system_binary_candidate_new_count") or 0),
        "system_binary_family_new_count": int(system_updates.get("system_binary_family_new_count") or 0),
        "system_low_growth_queue_count": int(system_updates.get("system_low_growth_queue_count") or 0),
        "system_uncovered_queue_count": int(system_updates.get("system_uncovered_queue_count") or 0),
        "system_stalled_target_count": int(system_updates.get("system_stalled_target_count") or 0),
        "system_shared_corpus_new_files": int(system_updates.get("system_shared_corpus_new_files") or 0),
        "system_fabric_root": system_updates.get("system_fabric_root"),
        "campaign_exact_or_partial": plane_update.get("campaign_exact_or_partial"),
        "campaign_degraded_reason": plane_update.get("campaign_degraded_reason"),
        "campaign_coverage_queue_count": int(plane_update.get("campaign_coverage_queue_count") or 0),
        "campaign_low_growth_queue_count": int(plane_update.get("campaign_low_growth_queue_count") or 0),
        "campaign_uncovered_queue_count": int(plane_update.get("campaign_uncovered_queue_count") or 0),
        "campaign_partial_queue_count": int(plane_update.get("campaign_partial_queue_count") or 0),
        "campaign_stalled_queue_count": int(plane_update.get("campaign_stalled_queue_count") or 0),
        "system_coverage_plane_queue_count": int(plane_update.get("system_coverage_queue_count") or 0),
        "compatible_export_trace": compatible_export_trace,
        "compatible_export_layer_count": len(compatible_export_layers),
        "binary_feedback_queue_count": len(round_binary_runtime.get("reseed_candidate_queue") or []),
        "binary_trace_admission_count": len(round_binary_runtime.get("trace_admission_candidates") or []),
        "binary_trace_candidate_count": int(round_binary_runtime.get("trace_candidate_count") or 0),
        "binary_ida_focus_count": len(round_binary_runtime.get("focus_candidates") or []),
        "binary_provenance_class": round_binary_runtime.get("provenance_class"),
        "binary_feedback_action": round_binary_runtime.get("feedback_action"),
        "binary_feedback_bridge_path": round_binary_runtime.get("binary_feedback_bridge_path"),
        "binary_ida_runtime_view_path": round_binary_runtime.get("binary_ida_runtime_view_path"),
        "ida_fact_source": round_binary_runtime.get("ida_fact_source"),
        "ida_refresh_task_id": round_binary_runtime.get("ida_refresh_task_id"),
        "binary_trace_candidate_queue_path": round_binary_runtime.get("trace_candidate_queue_path"),
        "binary_signal_lift_total": int(round_binary_runtime.get("signal_lift_total") or 0),
        "binary_signal_lift_reason": round_binary_runtime.get("signal_lift_reason"),
        "binary_coverage_proxy": round_binary_runtime.get("coverage_proxy") or updated_coverage_state.get("binary_coverage_proxy") or {},
        "llm_request_count_total": int(llm_metrics["request_count_total"] or 0),
        "llm_success_count": int(llm_metrics["success_count"] or 0),
        "llm_failure_count": int(llm_metrics["failure_count"] or 0),
    }
    return state, round_updates


def prepare_session_round_task(
    campaign_task_id: str,
    *,
    round_task_id: str,
    session_plan: dict[str, Any],
    task_store: "TaskStateStore",
) -> dict[str, Any]:
    round_root = task_root(round_task_id)
    campaign_state = load_campaign_runtime_state(campaign_task_id)
    project = str(campaign_state.get("project") or "unknown")
    lane = str(campaign_state.get("lane") or "source")
    shared_corpus_state = dict(campaign_state.get("shared_corpus") or {})
    campaign_shared_root = campaign_shared_corpus_path(campaign_task_id)
    selected_harness = str(session_plan.get("selected_harness") or "").strip() or None
    selected_harness_key = _safe_harness_dir(selected_harness) if selected_harness else None
    harness_corpus_root = (
        campaign_harness_corpora_root_path(campaign_task_id) / _safe_harness_dir(selected_harness)
        if selected_harness
        else None
    )
    campaign_shared_index_path = (
        shared_corpus_state.get("last_campaign_shared_index_path") or shared_corpus_state.get("last_merge_index_path")
    )
    harness_index_path = (
        (shared_corpus_state.get("harness_index_paths") or {}).get(selected_harness_key)
        if selected_harness_key
        else None
    )
    target_mode = str(session_plan.get("target_mode") or "source")
    round_corpus_root = round_root / "corpus" / ("binary_active" if target_mode == "binary" else "active")
    stage_manifest_path = campaign_corpus_stage_manifest_path(round_task_id)
    staged_from_system = stage_system_corpus(
        project=project,
        lane=lane,
        target_mode=target_mode,
        selected_harness=selected_harness,
        round_corpus_root=round_corpus_root,
        manifest_path=stage_manifest_path.with_name("system_corpus_stage_manifest.json"),
    )
    generalized_from_system = int((staged_from_system.get("selected_origin_lane_counts") or {}).get("generalized") or 0)
    staged_from_compatible_reverse = (
        _stage_generalized_reverse_corpus(
            project=project,
            lane=lane,
            target_mode=target_mode,
            selected_harness=selected_harness,
            round_task_id=round_task_id,
            campaign_task_id=campaign_task_id,
            round_corpus_root=round_corpus_root,
            manifest_path=stage_manifest_path,
        )
        if lane == "source" and target_mode == "source" and generalized_from_system == 0
        else _empty_corpus_stage_summary(skip_reason="system_stage_already_imported_generalized_inputs")
    )
    staged_from_shared = merge_into_slot_local_corpus(
        round_corpus_root,
        [
            {
                "root": str(campaign_shared_root),
                "label": "campaign_shared",
                "scope": "campaign_shared",
                "project": project,
                "lane": lane,
                "target_mode": target_mode,
                "priority_weight": 4.8,
                "campaign_task_id": campaign_task_id,
                "index_path": campaign_shared_index_path,
                "import_reason": "campaign_shared_pool",
                "selection_reason": "stage_campaign_shared_pool_into_round_active",
            }
        ],
        destination_project=project,
        destination_lane=lane,
        destination_target_mode=target_mode,
        destination_harness=selected_harness,
        decision_log_path=stage_manifest_path.with_name("campaign_shared_corpus_stage_manifest.json"),
        index_path=stage_manifest_path.with_name("campaign_shared_corpus_stage_index.json"),
        consumer_task_id=round_task_id,
        consumer_campaign_task_id=campaign_task_id,
        **corpus_policy("round_local"),
    )
    staged_from_harness = (
        merge_into_slot_local_corpus(
            round_corpus_root,
            [
                {
                    "root": str(harness_corpus_root),
                    "label": "campaign_harness",
                    "scope": "campaign_harness",
                    "project": project,
                    "lane": lane,
                    "target_mode": target_mode,
                    "harness": selected_harness,
                    "priority_weight": 5.2,
                    "campaign_task_id": campaign_task_id,
                    "index_path": harness_index_path,
                    "import_reason": "campaign_harness_pool",
                    "selection_reason": "stage_campaign_harness_pool_into_round_active",
                }
            ],
            destination_project=project,
            destination_lane=lane,
            destination_target_mode=target_mode,
            destination_harness=selected_harness,
            decision_log_path=stage_manifest_path.with_name("campaign_harness_corpus_stage_manifest.json"),
            index_path=stage_manifest_path.with_name("campaign_harness_corpus_stage_index.json"),
            consumer_task_id=round_task_id,
            consumer_campaign_task_id=campaign_task_id,
            **corpus_policy("round_local"),
        )
        if harness_corpus_root
        else {"new_files": 0, "new_bytes": 0, "cross_harness_selected_count": 0, "selected_files": [], "rejected_files": []}
    )
    stage_summaries = [staged_from_system, staged_from_compatible_reverse, staged_from_shared, staged_from_harness]
    shared_to_session_import_count = sum(int(stage.get("selected_imported_count") or 0) for stage in stage_summaries)
    shared_to_session_reject_count = sum(int(stage.get("quality_gate_rejected_count") or 0) for stage in stage_summaries)
    shared_to_session_imported_items: list[dict[str, Any]] = []
    shared_to_session_imported_item_ids: list[str] = []
    shared_to_session_rejected_item_ids: list[str] = []
    shared_to_session_cross_lane_import_count = 0
    generalized_to_source_import_count = 0
    for stage_name, stage in (
        ("system_stage", staged_from_system),
        ("compatible_reverse_stage", staged_from_compatible_reverse),
        ("campaign_shared_stage", staged_from_shared),
        ("campaign_harness_stage", staged_from_harness),
    ):
        for item in list(stage.get("selected_files") or []):
            item_id = str(item.get("item_id") or "").strip()
            if not item_id or str(item.get("source_label") or "") == "existing_destination":
                continue
            shared_to_session_imported_item_ids.append(item_id)
            cross_lane_transfer = bool(item.get("cross_lane_transfer"))
            if cross_lane_transfer:
                shared_to_session_cross_lane_import_count += 1
            if str(item.get("origin_lane") or "").strip() == "generalized" and str(item.get("consumer_lane") or "").strip() == "source":
                generalized_to_source_import_count += 1
            shared_to_session_imported_items.append(
                {
                    "stage": stage_name,
                    "item_id": item_id,
                    "origin_lane": item.get("origin_lane"),
                    "consumer_lane": item.get("consumer_lane"),
                    "origin_campaign_task_id": item.get("origin_campaign_task_id"),
                    "consumer_campaign_task_id": item.get("consumer_campaign_task_id"),
                    "import_reason": item.get("import_reason"),
                    "source_corpus_tier": item.get("source_corpus_tier"),
                    "consumer_corpus_tier": item.get("consumer_corpus_tier"),
                    "cross_lane_transfer": cross_lane_transfer,
                }
            )
        for item in list(stage.get("rejected_files") or []):
            item_id = str(item.get("item_id") or "").strip()
            if item_id:
                shared_to_session_rejected_item_ids.append(item_id)
    _write_json(
        stage_manifest_path,
        {
            "generated_at": task_store.now(),
            "campaign_task_id": campaign_task_id,
            "round_task_id": round_task_id,
            "project": project,
            "lane": lane,
            "target_mode": target_mode,
            "selected_harness": selected_harness,
            "round_corpus_root": str(round_corpus_root),
            "corpus_layers": {
                "slot_local": str(round_corpus_root),
                "campaign_local_shared": str(campaign_shared_root),
                "campaign_local_harness": str(harness_corpus_root) if harness_corpus_root else None,
                "system_shared_stage_manifest_path": staged_from_system.get("decision_log_path"),
                "compatible_reverse_stage_manifest_path": staged_from_compatible_reverse.get("decision_log_path"),
            },
            "system_stage": staged_from_system,
            "compatible_reverse_stage": staged_from_compatible_reverse,
            "campaign_shared_stage": staged_from_shared,
            "campaign_harness_stage": staged_from_harness,
            "shared_to_session_import_count": shared_to_session_import_count,
            "shared_to_session_reject_count": shared_to_session_reject_count,
            "shared_to_session_cross_lane_import_count": shared_to_session_cross_lane_import_count,
            "generalized_to_source_import_count": generalized_to_source_import_count,
            "shared_to_session_imported_item_ids": shared_to_session_imported_item_ids[:512],
            "shared_to_session_rejected_item_ids": shared_to_session_rejected_item_ids[:512],
            "shared_to_session_imported_items": shared_to_session_imported_items[:128],
        },
    )
    coverage_selected_entries = list(session_plan.get("coverage_plane_selected_entries") or [])
    coverage_selected_targets = list(session_plan.get("coverage_plane_selected_target_functions") or session_plan.get("selected_target_functions") or [])
    coverage_low_growth_targets = [
        item for item in coverage_selected_targets if str(item.get("queue_kind") or "") == "low_growth"
    ]
    coverage_uncovered_targets = [
        item for item in coverage_selected_targets if str(item.get("queue_kind") or "") == "uncovered"
    ]
    coverage_partial_targets = [
        item
        for item in coverage_selected_targets
        if str(item.get("source_level") or "") != "exact" or str(item.get("queue_kind") or "") == "partial_degraded"
    ]
    coverage_stalled_targets = [
        item for item in coverage_selected_targets if str(item.get("queue_kind") or "") == "stalled"
    ]
    rebound_harness = _resolve_current_harness_binding(
        task_id=round_task_id,
        harness_name=selected_harness,
        project=project,
    )
    selected_harness_path = rebound_harness.get("selected_harness_path") or session_plan.get("selected_harness_path")
    harness_source_path = rebound_harness.get("harness_source_path")
    runtime_patch = {
        "campaign_runtime_state_path": str(campaign_runtime_state_path(campaign_task_id)),
        "campaign_session_index": int(session_plan.get("session_index") or 0),
        "campaign_session_budget_seconds": int(session_plan.get("session_budget_seconds") or 0),
        "campaign_active_session_task_id": session_plan.get("active_session_task_id") or round_task_id,
        "campaign_session_continuity_mode": session_plan.get("continuity_mode"),
        "campaign_session_workspace_reused": bool(session_plan.get("reuse_existing_round_task")),
        "campaign_previous_session_summary_path": session_plan.get("previous_session_summary_path"),
        "campaign_last_corpus_state_reference": session_plan.get("last_corpus_state_reference"),
        "campaign_last_coverage_snapshot_reference": session_plan.get("last_coverage_snapshot_reference"),
        "campaign_last_stagnation_state": session_plan.get("last_stagnation_state") or {},
        "campaign_triggered_action_type": session_plan.get("triggered_action_type"),
        "campaign_coverage_queue_kind": session_plan.get("coverage_queue_kind"),
        "campaign_coverage_queue_size": int(session_plan.get("coverage_queue_size") or 0),
        "campaign_coverage_plane_state_path": session_plan.get("campaign_coverage_plane_state_path"),
        "campaign_coverage_queue_path": session_plan.get("campaign_coverage_queue_path"),
        "campaign_coverage_queue_consumption_path": session_plan.get("campaign_coverage_queue_consumption_path"),
        "system_coverage_plane_state_path": session_plan.get("system_coverage_plane_state_path"),
        "system_coverage_plane_queue_path": session_plan.get("system_coverage_plane_queue_path"),
        "campaign_coverage_selected_entries": coverage_selected_entries,
        "campaign_coverage_queue_selected_entries": coverage_selected_entries,
        "campaign_exact_or_partial": session_plan.get("campaign_exact_or_partial"),
        "campaign_exact_coverage_available_ratio": session_plan.get("campaign_exact_coverage_available_ratio"),
        "campaign_degraded_reason": session_plan.get("campaign_degraded_reason"),
        "campaign_degraded_detail": session_plan.get("campaign_degraded_detail"),
        "campaign_coverage_queue_primary_entry": session_plan.get("coverage_queue_primary_entry") or {},
        "campaign_coverage_queue_planning_reason": session_plan.get("coverage_queue_planning_reason"),
        "campaign_coverage_queue_harness_override": session_plan.get("coverage_queue_harness_override"),
        "campaign_coverage_queue_budget_multiplier": session_plan.get("coverage_queue_budget_multiplier"),
        "campaign_coverage_queue_reseed_reason": session_plan.get("coverage_queue_reseed_reason"),
        "campaign_system_feedback_consumed": session_plan.get("system_feedback_consumed") or {},
        "campaign_family_diversification_triggered": bool(session_plan.get("family_diversification_triggered")),
        "campaign_family_stagnation_count": int(session_plan.get("family_stagnation_count") or 0),
        "campaign_seed_mode_trigger_source": session_plan.get("seed_mode_trigger_source"),
        "campaign_seed_mode_trigger_reason": session_plan.get("seed_mode_trigger_reason"),
        "campaign_family_confirmed_count": int(session_plan.get("family_confirmed_count") or 0),
        "campaign_family_requires_reconfirmation_count": int(
            session_plan.get("family_requires_reconfirmation_count") or 0
        ),
        "campaign_family_reconfirmation_threshold_rounds": int(
            session_plan.get("family_reconfirmation_threshold_rounds") or 0
        ),
        "campaign_family_confirmation_backlog_count": int(session_plan.get("family_confirmation_backlog_count") or 0),
        "campaign_family_confirmation_selected_clusters": session_plan.get("family_confirmation_selected_clusters") or [],
        "campaign_family_promotion_blockers": session_plan.get("family_promotion_blockers") or [],
        "campaign_candidate_bridge_queue_size": int(session_plan.get("candidate_bridge_queue_size") or 0),
        "harness_decision_trace": session_plan.get("harness_decision_trace") or {},
        "selected_harness": selected_harness,
        "selected_target": selected_harness,
        "active_harness": selected_harness,
        "selected_harness_path": selected_harness_path,
        "active_harness_path": selected_harness_path,
        "harness_source_path": harness_source_path,
        "seed_task_mode_override": session_plan.get("seed_mode_override"),
        "selected_binary_slice_focus": session_plan.get("selected_binary_slice_focus"),
        "selected_target_function": session_plan.get("selected_target_function"),
        "selected_target_functions": session_plan.get("selected_target_functions") or [],
        "binary_feedback_bridge_path": session_plan.get("binary_feedback_bridge_path"),
        "binary_ida_runtime_view_path": session_plan.get("binary_ida_runtime_view_path"),
        "ida_fact_source": session_plan.get("ida_fact_source"),
        "ida_refresh_task_id": session_plan.get("ida_refresh_task_id"),
        "binary_feedback_queue_size": int(session_plan.get("binary_feedback_queue_size") or 0),
        "binary_trace_admission_count": int(session_plan.get("binary_trace_admission_count") or 0),
        "binary_ida_candidate_count": int(session_plan.get("binary_ida_candidate_count") or 0),
        "binary_family_target_count": int(session_plan.get("binary_family_target_count") or 0),
        "binary_feedback_claimed_items": session_plan.get("binary_feedback_claimed_items") or [],
        "binary_fabric_reseed_count": int(session_plan.get("binary_fabric_reseed_count") or 0),
        "binary_fabric_candidate_count": int(session_plan.get("binary_fabric_candidate_count") or 0),
        "binary_fabric_family_count": int(session_plan.get("binary_fabric_family_count") or 0),
        "binary_provenance_class": session_plan.get("binary_provenance_class"),
        "binary_feedback_action": session_plan.get("binary_feedback_action"),
        "binary_coverage_proxy": session_plan.get("binary_coverage_proxy") or {},
        "campaign_coverage_target_queue": coverage_selected_targets,
        "campaign_coverage_request_plan": session_plan.get("coverage_request_plan") or {},
        "campaign_low_growth_functions": coverage_low_growth_targets,
        "campaign_uncovered_functions": coverage_uncovered_targets,
        "campaign_partial_degraded_targets": coverage_partial_targets,
        "campaign_stalled_targets": coverage_stalled_targets,
        "campaign_reseed_target_functions": coverage_selected_targets,
        "campaign_binary_reseed_targets": session_plan.get("system_feedback_consumed", {}).get("system_binary_reseed_requests") or [],
        "campaign_binary_candidate_targets": session_plan.get("system_feedback_consumed", {}).get("system_binary_candidate_targets") or [],
        "campaign_binary_family_targets": session_plan.get("system_feedback_consumed", {}).get("system_binary_family_targets") or [],
        "campaign_candidate_bridge_targets": (
            session_plan.get("selected_target_functions") or []
            if session_plan.get("coverage_queue_kind") == "candidate_bridge"
            else []
        ),
        "campaign_stage_shared_corpus_new_files": int(staged_from_shared["new_files"] or 0),
        "campaign_stage_harness_corpus_new_files": int(staged_from_harness["new_files"] or 0),
        "campaign_stage_system_corpus_new_files": int(staged_from_system["new_files"] or 0),
        "campaign_stage_system_corpus_selected_imported_count": int(staged_from_system.get("selected_imported_count") or 0),
        "campaign_stage_system_corpus_cross_lane_transfer_count": int(
            staged_from_system.get("cross_lane_selected_count") or 0
        ),
        "campaign_stage_compatible_reverse_corpus_new_files": int(staged_from_compatible_reverse.get("new_files") or 0),
        "campaign_stage_compatible_reverse_selected_imported_count": int(
            staged_from_compatible_reverse.get("selected_imported_count") or 0
        ),
        "campaign_stage_compatible_reverse_cross_lane_transfer_count": int(
            staged_from_compatible_reverse.get("cross_lane_selected_count") or 0
        ),
        "campaign_stage_system_corpus_cross_project_transfer_count": int(
            staged_from_system.get("cross_project_selected_count") or 0
        ),
        "campaign_stage_quality_gate_pass_rate": float(staged_from_system.get("quality_gate_pass_rate") or 0.0),
        "campaign_stage_quality_gate_rejected_count": int(staged_from_system.get("quality_gate_rejected_count") or 0),
        "campaign_shared_to_session_import_count": shared_to_session_import_count,
        "campaign_shared_to_session_reject_count": shared_to_session_reject_count,
        "campaign_shared_to_session_cross_lane_import_count": shared_to_session_cross_lane_import_count,
        "campaign_generalized_to_source_import_count": generalized_to_source_import_count,
        "campaign_shared_to_session_imported_item_ids": shared_to_session_imported_item_ids[:128],
        "campaign_stage_cross_harness_selected_count": int(
            staged_from_system.get("cross_harness_selected_count") or 0
        )
        + int(staged_from_compatible_reverse.get("cross_harness_selected_count") or 0)
        + int(staged_from_shared.get("cross_harness_selected_count") or 0)
        + int(staged_from_harness.get("cross_harness_selected_count") or 0),
        "campaign_system_corpus_stage_manifest_path": staged_from_system.get("decision_log_path"),
        "campaign_compatible_reverse_corpus_stage_manifest_path": staged_from_compatible_reverse.get("decision_log_path"),
        "campaign_shared_corpus_stage_manifest_path": staged_from_shared.get("decision_log_path"),
        "campaign_harness_corpus_stage_manifest_path": staged_from_harness.get("decision_log_path"),
        "campaign_shared_corpus_path": str(campaign_shared_root),
        "campaign_shared_corpus_target_path": str(round_corpus_root),
        "campaign_corpus_stage_manifest_path": str(stage_manifest_path),
        "campaign_corpus_merge_manifest_path": str(campaign_corpus_merge_manifest_path(round_task_id)),
        "system_fabric_root": str(system_fabric_root()),
        "system_orchestrator_state_path": str(system_orchestrator_state_path()),
        "system_coverage_queue_path": str(system_coverage_queue_path()),
        "system_family_inventory_path": str(system_family_inventory_path()),
        "system_candidate_queue_path": str(system_candidate_queue_path()),
    }
    task_store.update_runtime(round_task_id, runtime_patch)
    return runtime_patch


def write_campaign_runtime_artifacts(
    campaign_task_id: str,
    *,
    state: dict[str, Any],
    started_at: str,
    deadline_at: str,
    finished_at: str | None,
) -> dict[str, str]:
    runtime_state_path = campaign_runtime_state_path(campaign_task_id)
    strength_report_path = campaign_strength_report_path(campaign_task_id)
    slot_manifest_path = campaign_slot_manifest_path(campaign_task_id)
    slot_payload = {
        "task_id": campaign_task_id,
        "slot_start_time": state.get("slot", {}).get("slot_start_time") or started_at,
        "slot_end_time": finished_at or deadline_at,
        "project_sequence": state.get("slot", {}).get("project_sequence") or [],
        "campaign_continuation_count": int(state.get("slot", {}).get("campaign_continuation_count") or 0),
        "idle_gap_seconds": float(state.get("slot", {}).get("idle_gap_seconds") or 0.0),
    }
    strength_payload = {
        "task_id": campaign_task_id,
        "generated_at": state.get("updated_at"),
        "benchmark": state.get("benchmark"),
        "target_mode": state.get("target_mode"),
        "session_count": int(state.get("session_count") or 0),
        "metrics": state.get("metrics") or {},
        "coverage_state": {
            "exact_or_partial": (state.get("coverage_state") or {}).get("exact_or_partial"),
            "coverage_control_mode": (state.get("coverage_state") or {}).get("coverage_control_mode"),
            "covered_function_count": (state.get("coverage_state") or {}).get("covered_function_count"),
            "uncovered_function_count": len((state.get("coverage_state") or {}).get("uncovered_function_queue") or []),
            "low_growth_function_count": len((state.get("coverage_state") or {}).get("low_growth_function_queue") or []),
            "partial_degraded_target_count": len((state.get("coverage_state") or {}).get("partial_degraded_target_queue") or []),
            "last_exact_coverage_time": (state.get("coverage_state") or {}).get("last_exact_coverage_time"),
            "degraded_reason": (state.get("coverage_state") or {}).get("degraded_reason"),
            "exact_coverage_available_ratio": (state.get("coverage_state") or {}).get("exact_coverage_available_ratio"),
            "campaign_coverage_plane_state_path": (state.get("coverage_state") or {}).get("campaign_coverage_plane_state_path"),
            "campaign_coverage_queue_path": (state.get("coverage_state") or {}).get("campaign_coverage_queue_path"),
        },
        "family_inventory": {
            "trace_exact_signature_count": len((state.get("family_inventory") or {}).get("trace_exact_signatures") or []),
            "loose_cluster_count": len((state.get("family_inventory") or {}).get("loose_vulnerable_state_clusters") or []),
            "confirmed_family_count": len((state.get("family_inventory") or {}).get("confirmed_families") or []),
            "unresolved_loose_cluster_count": len((state.get("family_inventory") or {}).get("unresolved_loose_clusters") or []),
            "requires_reconfirmation_count": int((state.get("family_inventory") or {}).get("requires_reconfirmation_count") or 0),
            "reconfirmation_threshold_rounds": int((state.get("family_inventory") or {}).get("reconfirmation_threshold_rounds") or 0),
            "promotion_blocker_count": len((state.get("family_inventory") or {}).get("promotion_blockers") or []),
            "last_trace_family_manifest_path": (state.get("family_inventory") or {}).get("last_trace_family_manifest_path"),
            "last_repro_family_manifest_path": (state.get("family_inventory") or {}).get("last_repro_family_manifest_path"),
        },
        "family_diversification": state.get("family_diversification") or {},
        "candidate_bridge_queue": state.get("candidate_bridge_queue") or [],
        "continuous_fuzzing": {
            "continuity_mode": state.get("session_continuity_mode"),
            "active_session_task_id": state.get("active_session_task_id"),
            "active_session_reuse_count": int(state.get("active_session_reuse_count") or 0),
            "last_session_summary_path": state.get("last_session_summary_path"),
            "last_corpus_state_reference": state.get("last_corpus_state_reference"),
            "last_coverage_snapshot_reference": state.get("last_coverage_snapshot_reference"),
            "last_stagnation_state": state.get("last_stagnation_state") or {},
        },
        "binary_runtime": state.get("binary_runtime") or {},
        "shared_corpus": state.get("shared_corpus") or {},
        "active_harness_pool": state.get("active_harness_pool") or [],
        "system_fabric": state.get("system_fabric") or {},
    }
    _write_json(runtime_state_path, state)
    _write_json(slot_manifest_path, slot_payload)
    _write_json(strength_report_path, strength_payload)
    return {
        "campaign_runtime_state_path": str(runtime_state_path),
        "campaign_slot_manifest_path": str(slot_manifest_path),
        "campaign_strength_report_path": str(strength_report_path),
    }

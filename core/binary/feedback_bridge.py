from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from core.analysis.suspicious_candidate import (
    GENERALIZED_CANDIDATE_QUEUE_VERSION,
    suspicious_candidate_queue_path,
    suspicious_candidate_trace_results_dir,
    write_suspicious_candidate_queue,
)
from core.storage.layout import (
    binary_candidate_promotion_report_path,
    binary_execution_manifest_path,
    binary_feedback_bridge_path,
    binary_ida_runtime_view_path,
    binary_observation_gap_report_path,
    binary_signal_promotion_analysis_path,
    binary_trace_eligibility_manifest_path,
    task_json_path,
)
from core.utils.settings import settings

INFORMATIONAL_SIGNAL_CATEGORIES = {"informational_runtime_output", "runtime_noise", "clean_exit"}
TRACE_CANDIDATE_ITEM_LIMIT = 5


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _normalize_binary_provenance_class(binary_mode: str | None, binary_provenance: str | None) -> str:
    raw = " ".join(part for part in [str(binary_mode or ""), str(binary_provenance or "")] if part).lower()
    if "source_derived" in raw or "source-derived" in raw:
        return "source-derived"
    if "opaque" in raw:
        return "opaque"
    if raw:
        return "native"
    return "unknown"


def _signal_categories_only(signal_counts: dict[str, Any], allowed: set[str]) -> bool:
    active = {
        str(name).strip()
        for name, count in (signal_counts or {}).items()
        if int(count or 0) > 0 and str(name).strip()
    }
    return bool(active) and active.issubset(allowed)


def _candidate_name(candidate: dict[str, Any], fallback: str | None) -> str | None:
    for key in ("selected_target_function", "name", "selected_binary_slice_focus"):
        name = str(candidate.get(key) or "").strip()
        if name:
            return name
    return fallback


def _task_dir(task_id: str) -> Path:
    return task_json_path(task_id).parent


def _clear_generalized_candidate_queue(task_id: str) -> None:
    queue_path = suspicious_candidate_queue_path(_task_dir(task_id))
    if queue_path.exists():
        queue_path.unlink()


def _canonicalize_testcase_path(task_id: str, raw_path: str | None) -> Path:
    candidate = Path(str(raw_path or "").strip())
    if candidate.exists():
        return candidate
    parts = list(candidate.parts)
    if "tasks" not in parts:
        return candidate
    index = parts.index("tasks")
    if index + 1 >= len(parts):
        return candidate
    source_task_id = parts[index + 1]
    relative = Path(*parts[index + 2 :]) if index + 2 < len(parts) else Path()
    roots = [
        Path(settings.data_root),
        _task_dir(task_id).parent,
    ]
    seen: set[str] = set()
    for root in roots:
        root_path = Path(root)
        key = str(root_path)
        if key in seen:
            continue
        seen.add(key)
        remapped = root_path / source_task_id / relative
        if remapped.exists():
            return remapped
    return candidate


def _candidate_target_names(
    *,
    selected_target_function: str | None,
    selected_binary_slice_focus: str | None,
    recommended_reseed_targets: list[dict[str, Any]],
    ida_runtime_view: dict[str, Any],
) -> list[str]:
    names: list[str] = []

    def add(value: str | None) -> None:
        normalized = str(value or "").strip()
        if normalized and normalized not in names:
            names.append(normalized)

    add(selected_target_function)
    add(selected_binary_slice_focus)
    for item in recommended_reseed_targets:
        if isinstance(item, dict):
            add(item.get("name"))
        else:
            add(str(item))
    for item in (ida_runtime_view.get("focus_candidates") or [])[:6]:
        if isinstance(item, dict):
            add(item.get("name"))
    for item in (ida_runtime_view.get("callgraph_neighbors") or [])[:6]:
        if isinstance(item, dict):
            add(item.get("name"))
    return names[:8]


def _selected_target_is_project_local(
    candidate_promotion_payload: dict[str, Any],
    ida_runtime_view: dict[str, Any],
) -> bool:
    if bool(candidate_promotion_payload.get("selected_target_is_project_local")):
        return True
    for item in (ida_runtime_view.get("focus_candidates") or [])[:4]:
        if isinstance(item, dict) and bool(item.get("project_local_match")):
            return True
    return False


def _queue_examples_from_watchlist(
    watchlist_candidates: list[dict[str, Any]],
    selected_target_function: str | None,
) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for item in watchlist_candidates:
        if not isinstance(item, dict):
            continue
        input_path = str(item.get("input_path") or "").strip()
        if not input_path or input_path in seen_paths:
            continue
        examples.append(
            {
                "testcase_path": input_path,
                "selected_target_function": _candidate_name(item, selected_target_function),
                "signal_category": str(item.get("signal_category") or "suspicious_semantic_signal"),
                "signal_subcategory": str(item.get("signal_subcategory") or "watchlist_followup"),
                "source_kind": "binary_watchlist",
            }
        )
        seen_paths.add(input_path)
        if len(examples) >= TRACE_CANDIDATE_ITEM_LIMIT:
            break
    return examples


def _queue_examples_from_execution_summary(
    *,
    top_signal_examples: list[dict[str, Any]],
    selected_target_function: str | None,
) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for item in top_signal_examples:
        if not isinstance(item, dict):
            continue
        input_path = str(item.get("input_path") or "").strip()
        signal_category = str(item.get("signal_category") or "").strip()
        if not input_path or input_path in seen_paths:
            continue
        if signal_category not in INFORMATIONAL_SIGNAL_CATEGORIES and signal_category != "suspicious_semantic_signal":
            continue
        examples.append(
            {
                "testcase_path": input_path,
                "selected_target_function": _candidate_name(item, selected_target_function),
                "signal_category": signal_category or "informational_runtime_output",
                "signal_subcategory": str(item.get("signal_subcategory") or "fixed_input_execution_info"),
                "source_kind": str(item.get("source_kind") or "binary_execution_input"),
            }
        )
        seen_paths.add(input_path)
        if len(examples) >= TRACE_CANDIDATE_ITEM_LIMIT:
            break
    return examples


def _build_generalized_candidate_queue(
    *,
    task_id: str,
    generated_at: str | None,
    task_payload: dict[str, Any],
    feedback_state: str,
    informational_only: bool,
    crash_candidate_count: int,
    watchlist_candidates: list[dict[str, Any]],
    selected_target_function: str | None,
    selected_binary_slice_focus: str | None,
    selected_target_is_project_local: bool,
    recommended_reseed_targets: list[dict[str, Any]],
    top_signal_examples: list[dict[str, Any]],
    ida_runtime_view: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    if crash_candidate_count > 0:
        return None, None

    queue_policy_name: str | None = None
    candidate_reason: str | None = None
    candidate_confidence = 0.0
    candidate_priority = 0
    queue_examples: list[dict[str, Any]] = []
    if watchlist_candidates and selected_target_is_project_local:
        queue_policy_name = "binary_watchlist_trace_candidate"
        candidate_reason = "binary_watchlist_semantic_signal"
        candidate_confidence = 0.82
        candidate_priority = 820
        queue_examples = _queue_examples_from_watchlist(watchlist_candidates, selected_target_function)
    elif (
        feedback_state in {"informational_stall", "low_promotion_stall"}
        and informational_only
        and selected_target_is_project_local
        and str(selected_target_function or "").strip()
        and (
            ida_runtime_view.get("focus_candidates")
            or ida_runtime_view.get("callgraph_neighbors")
            or ida_runtime_view.get("parser_candidates")
        )
    ):
        queue_policy_name = "binary_project_local_informational_trace_candidate"
        candidate_reason = (
            "binary_informational_project_local_focus"
            if feedback_state == "informational_stall"
            else "binary_low_promotion_project_local_focus"
        )
        candidate_confidence = 0.63 if feedback_state == "informational_stall" else 0.58
        candidate_priority = 630 if feedback_state == "informational_stall" else 580
        queue_examples = _queue_examples_from_execution_summary(
            top_signal_examples=top_signal_examples,
            selected_target_function=selected_target_function,
        )

    if not queue_policy_name or not queue_examples:
        return None, None

    metadata = dict(task_payload.get("metadata") or {})
    runtime = dict(task_payload.get("runtime") or {})
    candidate_targets = _candidate_target_names(
        selected_target_function=selected_target_function,
        selected_binary_slice_focus=selected_binary_slice_focus,
        recommended_reseed_targets=recommended_reseed_targets,
        ida_runtime_view=ida_runtime_view,
    )
    selected_harness = (
        str(metadata.get("binary_target_name") or "").strip()
        or str(runtime.get("active_harness") or "").strip()
        or str(selected_binary_slice_focus or "").strip()
        or str(selected_target_function or "").strip()
    )
    source_campaign_task_id = (
        str(metadata.get("campaign_parent_task_id") or runtime.get("campaign_parent_task_id") or "").strip() or None
    )
    campaign_round = metadata.get("campaign_round") or runtime.get("campaign_round")
    campaign_session_index = runtime.get("campaign_session_index")
    project = str(metadata.get("project") or "").strip() or None
    benchmark = str(metadata.get("benchmark") or "").strip() or None
    trace_results_dir = suspicious_candidate_trace_results_dir(_task_dir(task_id))

    items: list[dict[str, Any]] = []
    for example in queue_examples:
        testcase_path = _canonicalize_testcase_path(task_id, str(example.get("testcase_path") or ""))
        if not testcase_path.exists() or not testcase_path.is_file():
            continue
        selected_target = (
            str(example.get("selected_target_function") or "").strip()
            or str(selected_target_function or "").strip()
            or str(selected_binary_slice_focus or "").strip()
        )
        signal_category = str(example.get("signal_category") or "").strip() or "informational_runtime_output"
        signal_subcategory = str(example.get("signal_subcategory") or "").strip() or "binary_trace_followup"
        digest = hashlib.sha256(
            f"{testcase_path.resolve()}|{candidate_reason}|{selected_target}".encode("utf-8", errors="ignore")
        ).hexdigest()
        candidate_reasons = [
            str(candidate_reason),
            f"feedback_state:{feedback_state}",
            f"signal_category:{signal_category}",
            f"signal_subcategory:{signal_subcategory}",
            "selected_target_is_project_local",
            "ida_runtime_view_backed",
        ]
        items.append(
            {
                "candidate_id": f"binary-suspicious-{digest[:12]}",
                "candidate_origin_kind": "suspicious_candidate",
                "candidate_kind": "binary_feedback_candidate",
                "candidate_reason": candidate_reason,
                "candidate_reasons": candidate_reasons,
                "candidate_confidence": candidate_confidence,
                "candidate_priority": candidate_priority,
                "testcase_path": str(testcase_path),
                "testcase_name": testcase_path.name,
                "candidate_source_kind": str(example.get("source_kind") or "binary_execution_input"),
                "selected_harness": selected_harness or None,
                "selected_target_function": selected_target or None,
                "candidate_targets": candidate_targets,
                "trace_worthy": True,
                "replayable": True,
                "trace_admission_eligibility": "eligible",
                "trace_admission_block_reason": None,
                "repro_admission_eligibility": "defer_until_trace_result",
                "repro_admission_reason": "await_trace_result",
                "admission_state": "pending_trace",
                "sha256": digest,
                "size_bytes": testcase_path.stat().st_size,
                "created_at": generated_at,
                "source_task_id": task_id,
                "originating_task_id": task_id,
                "originating_round_task_id": task_id,
                "source_campaign_task_id": source_campaign_task_id,
                "campaign_round": int(campaign_round) if str(campaign_round or "").isdigit() else campaign_round,
                "campaign_session_index": int(campaign_session_index) if str(campaign_session_index or "").isdigit() else campaign_session_index,
                "project": project,
                "benchmark": benchmark,
                "target_mode": "binary",
                "trace_claim_token": None,
                "trace_claimed_at": None,
                "trace_claimed_by": None,
                "trace_result_path": None,
                "trace_artifact_path": None,
                "trace_rejection_reason": None,
                "trace_result_classification": None,
                "trace_completed_at": None,
                "repro_gate_decision": None,
                "repro_gate_reason": None,
                "repro_attempt_path": None,
                "pov_path": None,
            }
        )

    if not items:
        return None, None

    payload = {
        "queue_version": GENERALIZED_CANDIDATE_QUEUE_VERSION,
        "task_id": task_id,
        "generated_at": generated_at,
        "candidate_origin_kind": "suspicious_candidate",
        "selected_harness": selected_harness or None,
        "selected_target_function": selected_target_function,
        "candidate_targets": candidate_targets,
        "project": project,
        "benchmark": benchmark,
        "target_mode": "binary",
        "source_campaign_task_id": source_campaign_task_id,
        "campaign_round": int(campaign_round) if str(campaign_round or "").isdigit() else campaign_round,
        "campaign_session_index": int(campaign_session_index) if str(campaign_session_index or "").isdigit() else campaign_session_index,
        "candidate_selection_policy": {
            "policy_name": queue_policy_name,
            "feedback_state": feedback_state,
            "selected_target_is_project_local": selected_target_is_project_local,
            "selected_target_function": selected_target_function,
            "selected_binary_slice_focus": selected_binary_slice_focus,
            "candidate_targets": candidate_targets,
        },
        "reason_tokens": [candidate_reason, f"feedback_state:{feedback_state}", "ida_runtime_view_backed"],
        "reason_summary": [candidate_reason, f"feedback_state:{feedback_state}"],
        "candidate_count": len(items),
        "replayable_candidate_count": len(items),
        "trace_worthy_candidate_count": len(items),
        "trace_eligible_candidate_count": len(items),
        "candidate_claim_count": 0,
        "candidate_trace_result_count": 0,
        "candidate_trace_artifact_count": 0,
        "candidate_rejected_count": 0,
        "candidate_repro_eligible_count": 0,
        "candidate_results_dir": str(trace_results_dir),
        "queue_blocked_reason": None,
        "items": items[:TRACE_CANDIDATE_ITEM_LIMIT],
    }
    return payload, queue_policy_name


def _recommended_reseed_targets(
    *,
    feedback_state: str,
    selected_target_function: str | None,
    selected_binary_slice_focus: str | None,
    watchlist_candidates: list[dict[str, Any]],
    ida_runtime_view: dict[str, Any],
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(name: str | None, *, priority: int, reason: str, source_level: str) -> None:
        normalized = str(name or "").strip()
        if not normalized or normalized in seen:
            return
        selected.append(
            {
                "name": normalized,
                "target_type": "function",
                "queue_kind": "binary_feedback",
                "priority": priority,
                "reason": reason,
                "source_level": source_level,
            }
        )
        seen.add(normalized)

    primary_reason = {
        "watchlist_suspicious": "binary_watchlist_suspicious_signal",
        "informational_stall": "binary_informational_only_stall",
        "low_promotion_stall": "binary_low_promotion_stall",
    }.get(feedback_state, "binary_feedback_followup")
    add(selected_target_function, priority=14, reason=primary_reason, source_level="binary_feedback")
    add(selected_binary_slice_focus, priority=13, reason=primary_reason, source_level="binary_feedback")
    for item in watchlist_candidates[:4]:
        add(
            _candidate_name(item, selected_target_function),
            priority=12,
            reason=str(item.get("signal_subcategory") or item.get("signal_category") or "watchlist_candidate"),
            source_level="binary_feedback_watchlist",
        )
    for item in (ida_runtime_view.get("focus_candidates") or [])[:4]:
        add(
            str(item.get("name") or ""),
            priority=9,
            reason="ida_focus_candidate",
            source_level="ida_runtime_view",
        )
    for item in (ida_runtime_view.get("callgraph_neighbors") or [])[:4]:
        add(
            str(item.get("name") or ""),
            priority=7,
            reason=f"callgraph_{item.get('direction') or 'neighbor'}",
            source_level="ida_runtime_view",
        )
    return selected[:8]


def _trace_admission_candidates(
    *,
    crash_candidate_count: int,
    promoted_candidates: list[dict[str, Any]],
    watchlist_candidates: list[dict[str, Any]],
    selected_target_function: str | None,
    selected_target_is_project_local: bool,
    generalized_candidate_queue: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if crash_candidate_count > 0:
        return [
            {
                "candidate_path": item.get("candidate_path"),
                "reason": item.get("reason"),
                "selected_target_function": selected_target_function,
                "admission_mode": "promoted_candidate",
            }
            for item in promoted_candidates[:8]
            if isinstance(item, dict)
        ]
    queue_items = list((generalized_candidate_queue or {}).get("items") or [])
    if queue_items:
        return [
            {
                "candidate_id": item.get("candidate_id"),
                "candidate_path": item.get("testcase_path"),
                "reason": item.get("candidate_reason"),
                "selected_target_function": item.get("selected_target_function") or selected_target_function,
                "admission_mode": "binary_generalized_candidate",
                "candidate_priority": item.get("candidate_priority"),
                "candidate_confidence": item.get("candidate_confidence"),
            }
            for item in queue_items[:TRACE_CANDIDATE_ITEM_LIMIT]
            if isinstance(item, dict)
        ]
    if not selected_target_is_project_local:
        return []
    return [
        {
            "candidate_path": item.get("input_path"),
            "reason": item.get("signal_subcategory") or item.get("signal_category"),
            "selected_target_function": _candidate_name(item, selected_target_function),
            "admission_mode": "watchlist_followup",
        }
        for item in watchlist_candidates[:6]
        if isinstance(item, dict)
    ]


def build_binary_feedback_bridge(
    task_id: str,
    *,
    generated_at: str | None = None,
    execution_manifest: dict[str, Any] | None = None,
    trace_eligibility_payload: dict[str, Any] | None = None,
    candidate_promotion_payload: dict[str, Any] | None = None,
    signal_promotion_payload: dict[str, Any] | None = None,
    observation_gap_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    task_payload = _read_json(task_json_path(task_id), {})
    metadata = dict(task_payload.get("metadata") or {})
    runtime = dict(task_payload.get("runtime") or {})
    execution_manifest = execution_manifest or _read_json(binary_execution_manifest_path(task_id), {})
    trace_eligibility_payload = trace_eligibility_payload or _read_json(binary_trace_eligibility_manifest_path(task_id), {})
    candidate_promotion_payload = candidate_promotion_payload or _read_json(binary_candidate_promotion_report_path(task_id), {})
    signal_promotion_payload = signal_promotion_payload or _read_json(binary_signal_promotion_analysis_path(task_id), {})
    observation_gap_payload = observation_gap_payload or _read_json(binary_observation_gap_report_path(task_id), {})
    ida_runtime_view = _read_json(binary_ida_runtime_view_path(task_id), {})

    binary_mode = str(execution_manifest.get("binary_mode") or metadata.get("binary_mode") or runtime.get("binary_mode") or "").strip() or None
    binary_provenance = str(
        execution_manifest.get("binary_provenance")
        or metadata.get("binary_provenance")
        or runtime.get("binary_provenance")
        or ""
    ).strip() or None
    provenance_class = _normalize_binary_provenance_class(binary_mode, binary_provenance)
    selected_target_function = (
        str(candidate_promotion_payload.get("selected_target_function") or "").strip()
        or str(ida_runtime_view.get("selected_target_function") or "").strip()
        or str(runtime.get("selected_target_function") or "").strip()
        or None
    )
    selected_binary_slice_focus = (
        str(execution_manifest.get("selected_binary_slice_focus") or "").strip()
        or str(ida_runtime_view.get("selected_binary_slice_focus") or "").strip()
        or str(runtime.get("selected_binary_slice_focus") or "").strip()
        or selected_target_function
    )
    signal_category_counts = dict(execution_manifest.get("signal_category_counts") or {})
    promotion_rate = float(
        candidate_promotion_payload.get("promotion_rate")
        or signal_promotion_payload.get("promotion_rate")
        or execution_manifest.get("promotion_rate")
        or 0.0
    )
    crash_candidate_count = int(
        execution_manifest.get("crash_candidate_count")
        or trace_eligibility_payload.get("candidate_count")
        or 0
    )
    promoted_candidates = [
        dict(item)
        for item in (candidate_promotion_payload.get("promoted_candidates") or [])
        if isinstance(item, dict)
    ]
    watchlist_candidates = [
        dict(item)
        for item in (candidate_promotion_payload.get("watchlist_candidates") or [])
        if isinstance(item, dict)
    ]
    selected_target_is_project_local = _selected_target_is_project_local(candidate_promotion_payload, ida_runtime_view)
    watchlist_candidate_count = len(watchlist_candidates)
    informational_only = crash_candidate_count <= 0 and watchlist_candidate_count <= 0 and _signal_categories_only(
        signal_category_counts,
        INFORMATIONAL_SIGNAL_CATEGORIES,
    )
    if crash_candidate_count > 0:
        feedback_state = "promoted_candidate_available"
    elif watchlist_candidate_count > 0:
        feedback_state = "watchlist_suspicious"
    elif informational_only:
        feedback_state = "informational_stall"
    elif promotion_rate <= 0.0:
        feedback_state = "low_promotion_stall"
    else:
        feedback_state = "observe"
    needs_reseed = feedback_state in {"watchlist_suspicious", "informational_stall", "low_promotion_stall"}
    top_signal_examples = list(
        signal_promotion_payload.get("top_signal_examples")
        or execution_manifest.get("per_input_execution_summary")
        or []
    )[:6]
    reseed_targets = (
        _recommended_reseed_targets(
            feedback_state=feedback_state,
            selected_target_function=selected_target_function,
            selected_binary_slice_focus=selected_binary_slice_focus,
            watchlist_candidates=watchlist_candidates,
            ida_runtime_view=ida_runtime_view,
        )
        if needs_reseed
        else []
    )
    generalized_candidate_queue, signal_lift_reason = _build_generalized_candidate_queue(
        task_id=task_id,
        generated_at=generated_at or runtime.get("binary_execution_completed_at"),
        task_payload=task_payload,
        feedback_state=feedback_state,
        informational_only=informational_only,
        crash_candidate_count=crash_candidate_count,
        watchlist_candidates=watchlist_candidates,
        selected_target_function=selected_target_function,
        selected_binary_slice_focus=selected_binary_slice_focus,
        selected_target_is_project_local=selected_target_is_project_local,
        recommended_reseed_targets=reseed_targets,
        top_signal_examples=top_signal_examples,
        ida_runtime_view=ida_runtime_view,
    )
    trace_candidate_queue_path = None
    if generalized_candidate_queue:
        trace_candidate_queue_path = write_suspicious_candidate_queue(_task_dir(task_id), generalized_candidate_queue)
    else:
        _clear_generalized_candidate_queue(task_id)
    trace_admission_candidates = _trace_admission_candidates(
        crash_candidate_count=crash_candidate_count,
        promoted_candidates=promoted_candidates,
        watchlist_candidates=watchlist_candidates,
        selected_target_function=selected_target_function,
        selected_target_is_project_local=selected_target_is_project_local,
        generalized_candidate_queue=generalized_candidate_queue,
    )
    signal_lift_total = 0
    if crash_candidate_count <= 0 and trace_admission_candidates:
        signal_lift_total = len(trace_admission_candidates)
    payload = {
        "task_id": task_id,
        "generated_at": generated_at or runtime.get("binary_execution_completed_at"),
        "binary_mode": binary_mode,
        "binary_provenance": binary_provenance,
        "provenance_class": provenance_class,
        "selected_target_function": selected_target_function,
        "selected_binary_slice_focus": selected_binary_slice_focus,
        "selected_target_is_project_local": selected_target_is_project_local,
        "feedback_state": feedback_state,
        "needs_reseed": needs_reseed,
        "next_action": (
            "trace_promoted_candidates"
            if crash_candidate_count > 0
            else "trace_generalized_candidates"
            if signal_lift_total > 0
            else "binary_feedback_reseed"
            if needs_reseed
            else "observe"
        ),
        "informational_only": informational_only,
        "promotion_rate": promotion_rate,
        "signal_lift_total": signal_lift_total,
        "signal_lift_reason": signal_lift_reason,
        "signal_category_counts": signal_category_counts,
        "crash_candidate_count": crash_candidate_count,
        "watchlist_candidate_count": watchlist_candidate_count,
        "trace_admission_candidates": trace_admission_candidates,
        "trace_candidate_queue_path": trace_candidate_queue_path,
        "trace_candidate_count": len((generalized_candidate_queue or {}).get("items") or []),
        "recommended_reseed_targets": reseed_targets,
        "watchlist_candidates": watchlist_candidates[:6],
        "top_signal_examples": top_signal_examples,
        "promotion_blockers": [
            {
                "kind": feedback_state,
                "reason": observation_gap_payload.get("observation_gap_summary") or observation_gap_payload.get("next_required_layer"),
                "selected_target_function": selected_target_function,
            }
        ]
        if needs_reseed
        else [],
        "generalized_candidate_queue_summary": {
            "policy_name": signal_lift_reason,
            "candidate_count": len((generalized_candidate_queue or {}).get("items") or []),
            "candidate_queue_path": trace_candidate_queue_path,
            "candidate_results_dir": str(suspicious_candidate_trace_results_dir(_task_dir(task_id))),
        }
        if generalized_candidate_queue
        else None,
        "feedback_inputs": {
            "binary_execution_manifest_path": str(binary_execution_manifest_path(task_id)),
            "binary_trace_eligibility_manifest_path": str(binary_trace_eligibility_manifest_path(task_id)),
            "binary_candidate_promotion_report_path": str(binary_candidate_promotion_report_path(task_id)),
            "binary_signal_promotion_analysis_path": str(binary_signal_promotion_analysis_path(task_id)),
            "binary_observation_gap_report_path": str(binary_observation_gap_report_path(task_id)),
            "binary_ida_runtime_view_path": str(binary_ida_runtime_view_path(task_id)),
        },
    }
    _write_json(binary_feedback_bridge_path(task_id), payload)
    return payload

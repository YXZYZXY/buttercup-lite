from __future__ import annotations

import fcntl
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from core.campaign.coverage_queue import (
    build_queue_item,
    mark_queue_items_consumed,
    merge_queue_items,
    now_iso,
    queue_counts,
    select_queue_items,
)
from core.storage.layout import (
    campaign_coverage_plane_state_path,
    campaign_coverage_queue_consumption_path,
    campaign_coverage_queue_path,
    coverage_artifact_manifest_path,
    coverage_feedback_manifest_path,
    coverage_plane_snapshot_path,
    coverage_summary_manifest_path,
    task_json_path,
    tasks_root,
)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _normalize_level(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"exact", "partial", "fallback", "binary_signal", "unknown"}:
        return normalized
    return "unknown"


def _clean_name(value: Any) -> str:
    return str(value or "").strip()


def _normalize_degraded_detail(detail: Any) -> dict[str, Any] | None:
    if not isinstance(detail, dict):
        return None
    normalized: dict[str, Any] = {}
    for key in (
        "failure_reason",
        "coverage_artifacts_level",
        "sampled_input_count",
        "profraw_count",
        "coverage_binary_path",
        "llvm_profdata_path",
        "llvm_cov_path",
        "merged_profdata_path",
        "coverage_json_path",
        "selected_harness",
        "stderr_signal_present",
        "retryable",
    ):
        value = detail.get(key)
        if value not in (None, "", [], {}):
            normalized[key] = value
    replay_results = detail.get("replay_results")
    if isinstance(replay_results, list):
        normalized["replay_results"] = replay_results[:4]
    return normalized or None


def _coverage_failure_detail(
    *,
    level: str,
    degraded_reason: str | None,
    artifact: dict[str, Any],
    feedback: dict[str, Any],
    runtime: dict[str, Any],
    selected_harness: str | None,
) -> dict[str, Any] | None:
    raw_detail = _normalize_degraded_detail(
        artifact.get("coverage_failure_detail")
        or (feedback.get("current") or {}).get("coverage_failure_detail")
        or runtime.get("coverage_failure_detail")
    )
    if not degraded_reason and level == "exact" and not raw_detail:
        return None
    detail = raw_detail or {}
    if degraded_reason:
        detail.setdefault("failure_reason", degraded_reason)
    detail.setdefault("coverage_artifacts_level", level)
    detail.setdefault("sampled_input_count", int(artifact.get("sampled_input_count") or 0))
    detail.setdefault("profraw_count", len(artifact.get("profraw_files") or []))
    if artifact.get("coverage_binary_path"):
        detail.setdefault("coverage_binary_path", artifact.get("coverage_binary_path"))
    if artifact.get("llvm_profdata_path"):
        detail.setdefault("llvm_profdata_path", artifact.get("llvm_profdata_path"))
    if artifact.get("llvm_cov_path"):
        detail.setdefault("llvm_cov_path", artifact.get("llvm_cov_path"))
    if artifact.get("merged_profdata_path"):
        detail.setdefault("merged_profdata_path", artifact.get("merged_profdata_path"))
    if artifact.get("coverage_json_path"):
        detail.setdefault("coverage_json_path", artifact.get("coverage_json_path"))
    if selected_harness:
        detail.setdefault("selected_harness", selected_harness)
    replay_results = artifact.get("replay_results")
    if isinstance(replay_results, list) and replay_results:
        detail.setdefault("replay_results", replay_results[:4])
        detail.setdefault(
            "stderr_signal_present",
            any(_clean_name(item.get("stderr_excerpt")) for item in replay_results if isinstance(item, dict)),
        )
    if degraded_reason:
        detail.setdefault(
            "retryable",
            degraded_reason in {"UNKNOWN", "PROFRAW_NOT_EMITTED", "no_corpus_samples_available", "no_profraw_emitted"},
        )
    return detail or None


def _load_task_payload(task_id: str) -> dict[str, Any]:
    return _read_json(task_json_path(task_id), {})


def _extract_exact_uncovered_functions(rows: list[dict[str, Any]], *, limit: int = 16) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in rows:
        name = _clean_name(item.get("name") or item.get("function_name"))
        total_lines = int(item.get("total_lines", 0) or 0)
        covered_lines = int(item.get("covered_lines", 0) or 0)
        if (
            not name
            or name in seen
            or total_lines <= 0
            or covered_lines > 0
            or name == "LLVMFuzzerTestOneInput"
            or name.startswith("<")
        ):
            continue
        seen.add(name)
        selected.append(
            {
                "name": name,
                "coverage_fraction": float(item.get("coverage_fraction", 0.0) or 0.0),
                "total_lines": total_lines,
                "covered_lines": covered_lines,
                "function_paths": list(item.get("function_paths") or []),
                "target_type": "function",
            }
        )
    selected.sort(key=lambda item: (-int(item.get("total_lines") or 0), item["name"]))
    return selected[:limit]


def _extract_exact_low_growth_functions(rows: list[dict[str, Any]], *, limit: int = 16) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in rows:
        name = _clean_name(item.get("name") or item.get("function_name"))
        total_lines = int(item.get("total_lines", 0) or 0)
        covered_lines = int(item.get("covered_lines", 0) or 0)
        coverage_fraction = float(item.get("coverage_fraction", 0.0) or 0.0)
        if not name or name in seen or total_lines <= 0 or covered_lines <= 0 or coverage_fraction >= 0.35:
            continue
        seen.add(name)
        selected.append(
            {
                "name": name,
                "coverage_fraction": coverage_fraction,
                "total_lines": total_lines,
                "covered_lines": covered_lines,
                "function_paths": list(item.get("function_paths") or []),
                "target_type": "function",
            }
        )
    selected.sort(key=lambda item: (float(item.get("coverage_fraction") or 0.0), -int(item.get("total_lines") or 0), item["name"]))
    return selected[:limit]


def _selected_runtime_targets(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    raw_groups = [
        runtime.get("campaign_coverage_selected_entries"),
        runtime.get("campaign_coverage_queue_selected_entries"),
        runtime.get("campaign_coverage_target_queue"),
        runtime.get("campaign_partial_degraded_targets"),
        runtime.get("campaign_stalled_targets"),
        runtime.get("campaign_uncovered_functions"),
        runtime.get("campaign_low_growth_functions"),
        runtime.get("campaign_reseed_target_functions"),
    ]
    queue_kind = _clean_name(runtime.get("campaign_coverage_queue_kind")).lower()
    if queue_kind in {
        "low_growth",
        "uncovered",
        "partial_degraded",
        "stalled",
        "harness_focus",
        "campaign_partial_degraded",
        "coverage_plane_queue",
    }:
        selected_target_function = _clean_name(runtime.get("selected_target_function"))
        if selected_target_function:
            raw_groups.append([selected_target_function])
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_targets in raw_groups:
        if not isinstance(raw_targets, list):
            continue
        for item in raw_targets:
            if isinstance(item, dict):
                name = _clean_name(item.get("name"))
                payload = {
                    "name": name,
                    "target_type": _clean_name(item.get("target_type")) or "function",
                    "coverage_fraction": item.get("coverage_fraction"),
                    "total_lines": int(item.get("total_lines", 0) or 0),
                    "covered_lines": int(item.get("covered_lines", 0) or 0),
                    "function_paths": list(item.get("function_paths") or []),
                }
            else:
                name = _clean_name(item)
                payload = {"name": name, "target_type": "function"}
            if not name or name in seen:
                continue
            seen.add(name)
            selected.append(payload)
    return selected[:8]


def _build_degraded_targets(
    *,
    runtime: dict[str, Any],
    project: str,
    lane: str,
    target_mode: str,
    selected_harness: str | None,
    source_level: str,
    degraded_reason: str | None,
    degraded_detail: dict[str, Any] | None,
    source_campaign_task_id: str | None,
    source_round_task_id: str,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    selected_targets = _selected_runtime_targets(runtime)
    for item in selected_targets:
        queue_item = build_queue_item(
            raw=item,
            queue_kind="partial_degraded",
            target_mode=target_mode,
            selected_harness=selected_harness,
            source_level=source_level,
            project=project,
            lane=lane,
            reason="coverage_exact_unavailable",
            target_type=_clean_name(item.get("target_type")) or "function",
            source_campaign_task_id=source_campaign_task_id,
            source_round_task_id=source_round_task_id,
            degraded_reason=degraded_reason,
            degraded_detail=degraded_detail,
        )
        if queue_item is not None:
            entries.append(queue_item)
    if not entries and selected_harness:
        queue_item = build_queue_item(
            raw={"name": selected_harness, "target_type": "harness"},
            queue_kind="harness_focus",
            target_mode=target_mode,
            selected_harness=selected_harness,
            source_level=source_level,
            project=project,
            lane=lane,
            reason="coverage_exact_unavailable_harness_fallback",
            target_type="harness",
            source_campaign_task_id=source_campaign_task_id,
            source_round_task_id=source_round_task_id,
            degraded_reason=degraded_reason,
            degraded_detail=degraded_detail,
        )
        if queue_item is not None:
            entries.append(queue_item)
    return entries


def _build_stalled_targets(
    *,
    runtime: dict[str, Any],
    feedback: dict[str, Any],
    project: str,
    lane: str,
    target_mode: str,
    selected_harness: str | None,
    source_level: str,
    degraded_reason: str | None,
    degraded_detail: dict[str, Any] | None,
    source_campaign_task_id: str | None,
    source_round_task_id: str,
) -> list[dict[str, Any]]:
    if not (
        bool(feedback.get("stalled"))
        or bool(feedback.get("coverage_stalled"))
        or bool(feedback.get("proxy_stalled"))
        or bool(runtime.get("coverage_stalled"))
    ):
        return []
    stalled_reason_parts = [
        name
        for name, active in (
            ("feedback_stalled", bool(feedback.get("stalled"))),
            ("coverage_stalled", bool(feedback.get("coverage_stalled")) or bool(runtime.get("coverage_stalled"))),
            ("proxy_stalled", bool(feedback.get("proxy_stalled"))),
        )
        if active
    ]
    stalled_reason = "+".join(stalled_reason_parts) or "coverage_stalled"
    entries: list[dict[str, Any]] = []
    for item in _selected_runtime_targets(runtime)[:4]:
        queue_item = build_queue_item(
            raw=item,
            queue_kind="stalled",
            target_mode=target_mode,
            selected_harness=selected_harness,
            source_level=source_level,
            project=project,
            lane=lane,
            reason=stalled_reason,
            target_type=_clean_name(item.get("target_type")) or "function",
            source_campaign_task_id=source_campaign_task_id,
            source_round_task_id=source_round_task_id,
            degraded_reason=degraded_reason,
            degraded_detail=degraded_detail,
        )
        if queue_item is not None:
            entries.append(queue_item)
    if selected_harness:
        queue_item = build_queue_item(
            raw={"name": selected_harness, "target_type": "harness"},
            queue_kind="stalled",
            target_mode=target_mode,
            selected_harness=selected_harness,
            source_level=source_level,
            project=project,
            lane=lane,
            reason=f"{stalled_reason}_harness_focus",
            target_type="harness",
            source_campaign_task_id=source_campaign_task_id,
            source_round_task_id=source_round_task_id,
            degraded_reason=degraded_reason,
            degraded_detail=degraded_detail,
        )
        if queue_item is not None:
            entries.append(queue_item)
    return entries


def build_round_coverage_snapshot(task_id: str) -> dict[str, Any]:
    task_payload = _load_task_payload(task_id)
    runtime = task_payload.get("runtime") or {}
    metadata = task_payload.get("metadata") or {}
    feedback = _read_json(coverage_feedback_manifest_path(task_id), {})
    summary = _read_json(coverage_summary_manifest_path(task_id), {})
    artifact = _read_json(coverage_artifact_manifest_path(task_id), {})
    level = _normalize_level(
        summary.get("coverage_level")
        or (feedback.get("current") or {}).get("coverage_artifacts_level")
        or artifact.get("coverage_artifacts_level")
        or runtime.get("coverage_artifacts_level")
    )
    degraded_reason = (
        artifact.get("failure_reason")
        or (feedback.get("current") or {}).get("failure_reason")
        or runtime.get("coverage_failure_reason")
        or ("coverage_not_recorded" if level == "unknown" else None)
    )
    if level == "unknown" and degraded_reason:
        level = "fallback"

    current = feedback.get("current") or {}
    function_rows = list(current.get("per_function_summary") or summary.get("per_function_summary") or artifact.get("per_function_summary") or [])
    project = _clean_name(metadata.get("project") or task_payload.get("project") or runtime.get("project") or "unknown")
    generalized_source = bool(runtime.get("generalized_source")) or bool(metadata.get("generalized_source"))
    lane = _clean_name(
        runtime.get("fabric_lane")
        or metadata.get("fabric_lane")
        or runtime.get("campaign_lane")
        or metadata.get("campaign_lane")
        or ("generalized" if generalized_source else "source")
    )
    target_mode = _clean_name(runtime.get("target_mode") or metadata.get("target_mode") or "source")
    selected_harness = _clean_name(runtime.get("selected_harness") or runtime.get("active_harness")) or None
    degraded_detail = _coverage_failure_detail(
        level=level,
        degraded_reason=_clean_name(degraded_reason) or None,
        artifact=artifact,
        feedback=feedback,
        runtime=runtime,
        selected_harness=selected_harness,
    )
    exact_uncovered = _extract_exact_uncovered_functions(function_rows) if level == "exact" else []
    low_growth = _extract_exact_low_growth_functions(function_rows) if level == "exact" else []
    degraded_targets = (
        _build_degraded_targets(
            runtime=runtime,
            project=project,
            lane=lane,
            target_mode=target_mode,
            selected_harness=selected_harness,
            source_level=level,
            degraded_reason=_clean_name(degraded_reason) or None,
            degraded_detail=degraded_detail,
            source_campaign_task_id=_clean_name(metadata.get("campaign_parent_task_id")) or None,
            source_round_task_id=task_id,
        )
        if level != "exact"
        else []
    )
    stalled_targets = _build_stalled_targets(
        runtime=runtime,
        feedback=feedback,
        project=project,
        lane=lane,
        target_mode=target_mode,
        selected_harness=selected_harness,
        source_level=level,
        degraded_reason=_clean_name(degraded_reason) or None,
        degraded_detail=degraded_detail,
        source_campaign_task_id=_clean_name(metadata.get("campaign_parent_task_id")) or None,
        source_round_task_id=task_id,
    )
    payload = {
        "schema_version": 1,
        "generated_at": now_iso(),
        "task_id": task_id,
        "project": project,
        "lane": lane,
        "target_mode": target_mode,
        "selected_harness": selected_harness,
        "selected_target_function": _clean_name(runtime.get("selected_target_function")) or None,
        "selected_target_functions": _selected_runtime_targets(runtime),
        "exact_or_partial": level,
        "coverage_control_mode": "exact" if level == "exact" else "degraded",
        "exact_available": level == "exact",
        "partial_degraded": level != "exact",
        "degraded_reason": _clean_name(degraded_reason) or None,
        "exact_coverage_failure_reason": _clean_name(degraded_reason) or None,
        "degraded_detail": degraded_detail,
        "coverage_step": artifact.get("coverage_step") or current.get("coverage_step"),
        "line_coverage_fraction": summary.get("line_coverage_fraction"),
        "function_coverage_fraction": summary.get("function_coverage_fraction"),
        "covered_function_count": len(
            [
                item
                for item in function_rows
                if float(item.get("coverage_fraction", 0.0) or 0.0) > 0.0 and _clean_name(item.get("name"))
            ]
        ),
        "uncovered_function_queue": exact_uncovered,
        "low_growth_function_queue": low_growth,
        "degraded_target_queue": degraded_targets,
        "stalled_target_queue": stalled_targets,
        "feedback_stalled": bool(feedback.get("stalled")),
        "coverage_stalled": bool(feedback.get("coverage_stalled")),
        "proxy_stalled": bool(feedback.get("proxy_stalled")),
        "feedback_manifest_path": str(coverage_feedback_manifest_path(task_id)),
        "coverage_summary_manifest_path": str(coverage_summary_manifest_path(task_id)),
        "coverage_artifact_manifest_path": str(coverage_artifact_manifest_path(task_id)),
    }
    _write_json(coverage_plane_snapshot_path(task_id), payload)
    return payload


def load_round_coverage_snapshot(task_id: str) -> dict[str, Any]:
    path = coverage_plane_snapshot_path(task_id)
    snapshot = _read_json(path, {})
    if snapshot:
        return snapshot
    return build_round_coverage_snapshot(task_id)


def system_coverage_plane_root() -> Path:
    root = tasks_root() / "_system_fabric" / "coverage_plane"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_component(value: str | None) -> str:
    candidate = _clean_name(value).lower() or "default"
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in candidate)


def _system_namespace_root(*, project: str, lane: str, target_mode: str) -> Path:
    root = system_coverage_plane_root() / _safe_component(project) / _safe_component(lane) / _safe_component(target_mode)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _selectable_system_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for item in items:
        source_level = _normalize_level(item.get("source_level"))
        queue_kind = _clean_name(item.get("queue_kind")).lower()
        if source_level == "unknown":
            continue
        if source_level == "binary_signal":
            continue
        if source_level != "exact" and queue_kind not in {"partial_degraded", "stalled", "harness_focus"}:
            continue
        selected.append(item)
    return selected


def system_coverage_plane_state_path(*, project: str, lane: str, target_mode: str) -> Path:
    return _system_namespace_root(project=project, lane=lane, target_mode=target_mode) / "state.json"


def system_coverage_plane_queue_path(*, project: str, lane: str, target_mode: str) -> Path:
    return _system_namespace_root(project=project, lane=lane, target_mode=target_mode) / "queue.json"


@contextmanager
def _system_plane_lock():
    lock_path = system_coverage_plane_root() / ".lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _initial_campaign_state(*, campaign_task_id: str, project: str, lane: str, target_mode: str, updated_at: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "campaign_task_id": campaign_task_id,
        "project": project,
        "lane": lane,
        "target_mode": target_mode,
        "created_at": updated_at,
        "updated_at": updated_at,
        "exact_or_partial": "unknown",
        "coverage_control_mode": "unknown",
        "current_degraded_reason": None,
        "current_degraded_state": None,
        "exact_sessions": 0,
        "partial_sessions": 0,
        "fallback_sessions": 0,
        "binary_signal_sessions": 0,
        "unknown_sessions": 0,
        "total_sessions": 0,
        "exact_coverage_available_ratio": 0.0,
        "last_exact_coverage_time": None,
        "last_round_task_id": None,
        "last_selected_harness": None,
        "last_selected_target_function": None,
        "covered_function_count": 0,
        "uncovered_function_count": 0,
        "low_growth_function_count": 0,
        "degraded_target_count": 0,
        "stalled_target_count": 0,
        "current_degraded_detail": None,
        "queue_counts": {},
        "queue_path": str(campaign_coverage_queue_path(campaign_task_id)),
    }


def _initial_queue(*, owner_kind: str, owner_id: str, project: str, lane: str, target_mode: str, updated_at: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "owner_kind": owner_kind,
        "owner_id": owner_id,
        "project": project,
        "lane": lane,
        "target_mode": target_mode,
        "updated_at": updated_at,
        "items": [],
        "counts": {},
    }


def initialize_campaign_coverage_plane(
    campaign_task_id: str,
    *,
    project: str,
    lane: str,
    target_mode: str,
    updated_at: str,
) -> dict[str, Any]:
    state_path = campaign_coverage_plane_state_path(campaign_task_id)
    queue_path = campaign_coverage_queue_path(campaign_task_id)
    state = _read_json(state_path, {})
    queue = _read_json(queue_path, {})
    if not state:
        state = _initial_campaign_state(
            campaign_task_id=campaign_task_id,
            project=project,
            lane=lane,
            target_mode=target_mode,
            updated_at=updated_at,
        )
        _write_json(state_path, state)
    if not queue:
        queue = _initial_queue(
            owner_kind="campaign",
            owner_id=campaign_task_id,
            project=project,
            lane=lane,
            target_mode=target_mode,
            updated_at=updated_at,
        )
        _write_json(queue_path, queue)
    return {
        "campaign_coverage_plane_state_path": str(state_path),
        "campaign_coverage_queue_path": str(queue_path),
    }


def _merge_snapshot_into_queue(
    *,
    snapshot: dict[str, Any],
    project: str,
    lane: str,
    target_mode: str,
    selected_harness: str | None,
    source_campaign_task_id: str,
    source_round_task_id: str,
) -> list[dict[str, Any]]:
    incoming: list[dict[str, Any]] = []
    source_level = _normalize_level(snapshot.get("exact_or_partial"))
    degraded_reason = _clean_name(snapshot.get("degraded_reason")) or None
    for item in snapshot.get("uncovered_function_queue") or []:
        queue_item = build_queue_item(
            raw=item,
            queue_kind="uncovered",
            target_mode=target_mode,
            selected_harness=selected_harness,
            source_level=source_level,
            project=project,
            lane=lane,
            reason="exact_uncovered_function",
            target_type="function",
            source_campaign_task_id=source_campaign_task_id,
            source_round_task_id=source_round_task_id,
            degraded_reason=degraded_reason,
        )
        if queue_item is not None:
            incoming.append(queue_item)
    for item in snapshot.get("low_growth_function_queue") or []:
        queue_item = build_queue_item(
            raw=item,
            queue_kind="low_growth",
            target_mode=target_mode,
            selected_harness=selected_harness,
            source_level=source_level,
            project=project,
            lane=lane,
            reason="exact_low_growth_function",
            target_type="function",
            source_campaign_task_id=source_campaign_task_id,
            source_round_task_id=source_round_task_id,
            degraded_reason=degraded_reason,
        )
        if queue_item is not None:
            incoming.append(queue_item)
    incoming.extend(snapshot.get("degraded_target_queue") or [])
    incoming.extend(snapshot.get("stalled_target_queue") or [])
    return incoming


def update_coverage_plane_after_round(
    campaign_task_id: str,
    *,
    round_task_id: str,
    project: str,
    lane: str,
    target_mode: str,
    session_index: int,
    selected_harness: str | None,
    now_iso_value: str,
) -> dict[str, Any]:
    initialize_campaign_coverage_plane(
        campaign_task_id,
        project=project,
        lane=lane,
        target_mode=target_mode,
        updated_at=now_iso_value,
    )
    snapshot = load_round_coverage_snapshot(round_task_id)
    state_path = campaign_coverage_plane_state_path(campaign_task_id)
    queue_path = campaign_coverage_queue_path(campaign_task_id)
    state = _read_json(
        state_path,
        _initial_campaign_state(
            campaign_task_id=campaign_task_id,
            project=project,
            lane=lane,
            target_mode=target_mode,
            updated_at=now_iso_value,
        ),
    )
    queue = _read_json(
        queue_path,
        _initial_queue(
            owner_kind="campaign",
            owner_id=campaign_task_id,
            project=project,
            lane=lane,
            target_mode=target_mode,
            updated_at=now_iso_value,
        ),
    )
    incoming = _merge_snapshot_into_queue(
        snapshot=snapshot,
        project=project,
        lane=lane,
        target_mode=target_mode,
        selected_harness=selected_harness,
        source_campaign_task_id=campaign_task_id,
        source_round_task_id=round_task_id,
    )
    queue["items"] = merge_queue_items(list(queue.get("items") or []), incoming, updated_at=now_iso_value)
    queue["updated_at"] = now_iso_value
    queue["counts"] = queue_counts(queue["items"])
    _write_json(queue_path, queue)

    state["updated_at"] = now_iso_value
    state["last_round_task_id"] = round_task_id
    state["last_selected_harness"] = selected_harness
    state["last_selected_target_function"] = snapshot.get("selected_target_function")
    state["exact_or_partial"] = snapshot.get("exact_or_partial")
    state["coverage_control_mode"] = snapshot.get("coverage_control_mode")
    state["current_degraded_reason"] = snapshot.get("degraded_reason")
    state["current_degraded_detail"] = snapshot.get("degraded_detail")
    state["current_degraded_state"] = snapshot.get("exact_or_partial")
    state["covered_function_count"] = int(snapshot.get("covered_function_count") or 0)
    state["uncovered_function_count"] = len(snapshot.get("uncovered_function_queue") or [])
    state["low_growth_function_count"] = len(snapshot.get("low_growth_function_queue") or [])
    state["degraded_target_count"] = len(snapshot.get("degraded_target_queue") or [])
    state["stalled_target_count"] = len(snapshot.get("stalled_target_queue") or [])
    state["total_sessions"] = max(int(state.get("total_sessions") or 0), int(session_index or 0))
    level = _normalize_level(snapshot.get("exact_or_partial"))
    state[f"{level}_sessions"] = int(state.get(f"{level}_sessions") or 0) + 1
    if level == "exact":
        state["last_exact_coverage_time"] = now_iso_value
    total_sessions = max(int(state.get("total_sessions") or 0), 1)
    state["exact_coverage_available_ratio"] = round(int(state.get("exact_sessions") or 0) / total_sessions, 4)
    state["queue_counts"] = queue.get("counts") or {}
    state["last_round_snapshot_path"] = str(coverage_plane_snapshot_path(round_task_id))
    _write_json(state_path, state)

    with _system_plane_lock():
        system_state_path = system_coverage_plane_state_path(project=project, lane=lane, target_mode=target_mode)
        system_queue_path = system_coverage_plane_queue_path(project=project, lane=lane, target_mode=target_mode)
        system_state = _read_json(
            system_state_path,
            {
                "schema_version": 1,
                "project": project,
                "lane": lane,
                "target_mode": target_mode,
                "created_at": now_iso_value,
                "updated_at": now_iso_value,
                "exact_sessions": 0,
                "partial_sessions": 0,
                "fallback_sessions": 0,
                "binary_signal_sessions": 0,
                "unknown_sessions": 0,
                "total_sessions": 0,
                "exact_coverage_available_ratio": 0.0,
                "covered_function_count": 0,
                "uncovered_function_count": 0,
                "low_growth_function_count": 0,
                "degraded_target_count": 0,
                "stalled_target_count": 0,
                "queue_counts": {},
            },
        )
        system_queue = _read_json(
            system_queue_path,
            _initial_queue(
                owner_kind="system",
                owner_id=f"{project}:{lane}:{target_mode}",
                project=project,
                lane=lane,
                target_mode=target_mode,
                updated_at=now_iso_value,
            ),
        )
        system_queue["items"] = merge_queue_items(
            _selectable_system_items(list(system_queue.get("items") or [])),
            _selectable_system_items(incoming),
            updated_at=now_iso_value,
        )
        system_queue["updated_at"] = now_iso_value
        system_queue["counts"] = queue_counts(system_queue["items"])
        _write_json(system_queue_path, system_queue)
        system_state["updated_at"] = now_iso_value
        system_state["last_round_task_id"] = round_task_id
        system_state["last_campaign_task_id"] = campaign_task_id
        system_state["last_selected_harness"] = selected_harness
        system_state["last_exact_or_partial"] = level
        system_state["current_degraded_reason"] = snapshot.get("degraded_reason")
        system_state["current_degraded_detail"] = snapshot.get("degraded_detail")
        system_state["total_sessions"] = int(system_state.get("total_sessions") or 0) + 1
        system_state[f"{level}_sessions"] = int(system_state.get(f"{level}_sessions") or 0) + 1
        total_system_sessions = max(int(system_state.get("total_sessions") or 0), 1)
        system_state["exact_coverage_available_ratio"] = round(
            int(system_state.get("exact_sessions") or 0) / total_system_sessions,
            4,
        )
        system_state["covered_function_count"] = int(snapshot.get("covered_function_count") or 0)
        system_state["uncovered_function_count"] = len(snapshot.get("uncovered_function_queue") or [])
        system_state["low_growth_function_count"] = len(snapshot.get("low_growth_function_queue") or [])
        system_state["degraded_target_count"] = len(snapshot.get("degraded_target_queue") or [])
        system_state["stalled_target_count"] = len(snapshot.get("stalled_target_queue") or [])
        system_state["queue_counts"] = system_queue.get("counts") or {}
        _write_json(system_state_path, system_state)

    return {
        "campaign_coverage_plane_state_path": str(state_path),
        "campaign_coverage_queue_path": str(queue_path),
        "campaign_coverage_snapshot_path": str(coverage_plane_snapshot_path(round_task_id)),
        "campaign_coverage_queue_count": int((queue.get("counts") or {}).get("total") or 0),
        "campaign_low_growth_queue_count": int(((queue.get("counts") or {}).get("by_kind") or {}).get("low_growth") or 0),
        "campaign_uncovered_queue_count": int(((queue.get("counts") or {}).get("by_kind") or {}).get("uncovered") or 0),
        "campaign_partial_queue_count": int(
            ((queue.get("counts") or {}).get("by_kind") or {}).get("partial_degraded", 0)
            + ((queue.get("counts") or {}).get("by_kind") or {}).get("harness_focus", 0)
        ),
        "campaign_stalled_queue_count": int(((queue.get("counts") or {}).get("by_kind") or {}).get("stalled") or 0),
        "campaign_exact_coverage_available_ratio": state.get("exact_coverage_available_ratio"),
        "campaign_exact_or_partial": state.get("exact_or_partial"),
        "campaign_degraded_reason": state.get("current_degraded_reason"),
        "campaign_degraded_detail": state.get("current_degraded_detail"),
        "system_coverage_plane_state_path": str(system_coverage_plane_state_path(project=project, lane=lane, target_mode=target_mode)),
        "system_coverage_plane_queue_path": str(system_coverage_plane_queue_path(project=project, lane=lane, target_mode=target_mode)),
        "system_coverage_queue_count": int((system_queue.get("counts") or {}).get("total") or 0),
        "system_low_growth_queue_count": int(((system_queue.get("counts") or {}).get("by_kind") or {}).get("low_growth") or 0),
        "system_uncovered_queue_count": int(((system_queue.get("counts") or {}).get("by_kind") or {}).get("uncovered") or 0),
        "system_stalled_target_count": int(((system_queue.get("counts") or {}).get("by_kind") or {}).get("stalled") or 0),
    }


def peek_coverage_plane_inputs(
    campaign_task_id: str,
    *,
    project: str,
    lane: str,
    target_mode: str,
) -> dict[str, Any]:
    campaign_state = _read_json(campaign_coverage_plane_state_path(campaign_task_id), {})
    campaign_queue = _read_json(campaign_coverage_queue_path(campaign_task_id), {})
    system_state = _read_json(system_coverage_plane_state_path(project=project, lane=lane, target_mode=target_mode), {})
    system_queue = _read_json(system_coverage_plane_queue_path(project=project, lane=lane, target_mode=target_mode), {})
    campaign_items = list(campaign_queue.get("items") or [])
    system_items = _selectable_system_items(list(system_queue.get("items") or []))
    all_items = campaign_items + system_items
    harness_pressure: dict[str, float] = {}
    for item in all_items:
        harness = _clean_name(item.get("harness"))
        if not harness:
            continue
        level = _normalize_level(item.get("source_level"))
        queue_kind = _clean_name(item.get("queue_kind")).lower()
        score = 2.2 if level == "exact" else 1.4 if level == "partial" else 0.9
        if _clean_name(item.get("target_type")) == "harness":
            score += 1.6
        if queue_kind == "low_growth":
            score += 0.9
        elif queue_kind == "uncovered":
            score += 1.1
        elif queue_kind == "stalled":
            score += 1.3
        elif queue_kind == "partial_degraded":
            score += 0.7
        harness_pressure[harness] = round(harness_pressure.get(harness, 0.0) + score, 3)
    return {
        "campaign_state": campaign_state,
        "campaign_queue": campaign_queue,
        "system_state": system_state,
        "system_queue": system_queue,
        "campaign_queue_counts": campaign_queue.get("counts") or queue_counts(campaign_items),
        "system_queue_counts": system_queue.get("counts") or queue_counts(list(system_queue.get("items") or [])),
        "harness_queue_pressure": harness_pressure,
    }


def claim_coverage_targets_for_session(
    campaign_task_id: str,
    *,
    project: str,
    lane: str,
    target_mode: str,
    preferred_harness: str | None,
    session_index: int,
    limit: int,
    now_iso_value: str,
) -> dict[str, Any]:
    peek = peek_coverage_plane_inputs(
        campaign_task_id,
        project=project,
        lane=lane,
        target_mode=target_mode,
    )
    campaign_queue_path = campaign_coverage_queue_path(campaign_task_id)
    campaign_queue = dict(peek.get("campaign_queue") or {})
    campaign_items = list(campaign_queue.get("items") or [])
    system_queue_path = system_coverage_plane_queue_path(project=project, lane=lane, target_mode=target_mode)
    system_queue = dict(peek.get("system_queue") or {})
    system_items = list(system_queue.get("items") or [])
    selectable_system_items = _selectable_system_items(system_items)
    selected: list[dict[str, Any]] = []
    selected_keys: set[tuple[str, str]] = set()
    for scope, items in (("campaign", campaign_items), ("system", selectable_system_items)):
        for item in select_queue_items(
            items,
            preferred_harness=preferred_harness,
            limit=limit,
            session_index=session_index,
        ):
            key = (_clean_name(item.get("target_type")) or "function", _clean_name(item.get("name")))
            if not key[1] or key in selected_keys:
                continue
            payload = dict(item)
            payload["selection_scope"] = scope
            selected.append(payload)
            selected_keys.add(key)
            if len(selected) >= limit:
                break
        if len(selected) >= limit:
            break

    updated_campaign_items = mark_queue_items_consumed(
        campaign_items,
        [item for item in selected if item.get("selection_scope") == "campaign"],
        consumed_at=now_iso_value,
        session_index=session_index,
    )
    updated_system_items = mark_queue_items_consumed(
        system_items,
        [item for item in selected if item.get("selection_scope") == "system"],
        consumed_at=now_iso_value,
        session_index=session_index,
    )
    if campaign_queue:
        campaign_queue["items"] = updated_campaign_items
        campaign_queue["updated_at"] = now_iso_value
        campaign_queue["counts"] = queue_counts(updated_campaign_items)
        _write_json(campaign_queue_path, campaign_queue)
    if system_queue:
        system_queue["items"] = updated_system_items
        system_queue["updated_at"] = now_iso_value
        system_queue["counts"] = queue_counts(updated_system_items)
        with _system_plane_lock():
            _write_json(system_queue_path, system_queue)

    selected_function_entries = [item for item in selected if _clean_name(item.get("target_type")) == "function"]
    selected_harness_entries = [item for item in selected if _clean_name(item.get("target_type")) == "harness"]
    selected_target_functions = [
        {
            key: value
            for key, value in item.items()
            if key
            in {
                "name",
                "target_type",
                "queue_kind",
                "source_level",
                "coverage_fraction",
                "total_lines",
                "covered_lines",
                "function_paths",
                "reason",
                "degraded_reason",
                "degraded_detail",
                "selection_scope",
                "harness",
                "priority",
                "activation_state",
                "consume_count",
                "hit_count",
                "source_campaign_task_id",
                "source_round_task_id",
            }
        }
        for item in selected_function_entries
    ]
    selected_harness_names: list[str] = []
    for item in selected:
        harness_name = (
            _clean_name(item.get("name"))
            if _clean_name(item.get("target_type")) == "harness"
            else _clean_name(item.get("harness"))
        )
        if harness_name and harness_name not in selected_harness_names:
            selected_harness_names.append(harness_name)
    queue_kind = _clean_name(selected[0].get("queue_kind")) if selected else None
    consumption_path = campaign_coverage_queue_consumption_path(campaign_task_id)
    consumption_payload = {
        "generated_at": now_iso_value,
        "campaign_task_id": campaign_task_id,
        "project": project,
        "lane": lane,
        "target_mode": target_mode,
        "preferred_harness": preferred_harness,
        "session_index": session_index,
        "selected_entries": selected,
        "selected_target_functions": selected_target_functions,
        "selected_harness_targets": selected_harness_names,
        "coverage_queue_kind": queue_kind,
        "campaign_coverage_plane_state_path": str(campaign_coverage_plane_state_path(campaign_task_id)),
        "campaign_coverage_queue_path": str(campaign_queue_path),
        "system_coverage_plane_state_path": str(system_coverage_plane_state_path(project=project, lane=lane, target_mode=target_mode)),
        "system_coverage_plane_queue_path": str(system_queue_path),
        "campaign_queue_counts": campaign_queue.get("counts") or {},
        "system_queue_counts": system_queue.get("counts") or {},
        "campaign_exact_or_partial": (peek.get("campaign_state") or {}).get("exact_or_partial"),
        "campaign_exact_coverage_available_ratio": (peek.get("campaign_state") or {}).get("exact_coverage_available_ratio"),
        "campaign_degraded_reason": (peek.get("campaign_state") or {}).get("current_degraded_reason"),
        "campaign_degraded_detail": (peek.get("campaign_state") or {}).get("current_degraded_detail"),
        "coverage_queue_primary_entry": selected[0] if selected else None,
    }
    _write_json(consumption_path, consumption_payload)
    return {
        **consumption_payload,
        "campaign_coverage_queue_consumption_path": str(consumption_path),
        "harness_queue_pressure": peek.get("harness_queue_pressure") or {},
        "selected_target_function": selected_target_functions[0]["name"] if selected_target_functions else None,
        "selected_target_functions": selected_target_functions,
        "selected_harness_targets": selected_harness_names,
        "coverage_queue_size": len(selected),
    }

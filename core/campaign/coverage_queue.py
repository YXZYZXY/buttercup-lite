from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

MAX_QUEUE_ITEMS = 160

QUEUE_COOLDOWN_SESSIONS = {
    "uncovered": 2,
    "low_growth": 3,
    "partial_degraded": 2,
    "stalled": 1,
    "harness_focus": 1,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clean_name(value: Any) -> str:
    return str(value or "").strip()


def _queue_item_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        _clean_name(item.get("queue_kind")),
        _clean_name(item.get("target_type")) or "function",
        _clean_name(item.get("target_mode")) or "source",
        _clean_name(item.get("name")),
    )


def _source_rank(level: str) -> int:
    normalized = _clean_name(level).lower()
    if normalized == "exact":
        return 4
    if normalized == "partial":
        return 3
    if normalized == "fallback":
        return 2
    if normalized == "binary_signal":
        return 1
    return 0


def _queue_cooldown_sessions(queue_kind: str) -> int:
    return QUEUE_COOLDOWN_SESSIONS.get(_clean_name(queue_kind).lower(), 1)


def _activation_rank(item: dict[str, Any], *, session_index: int | None = None) -> int:
    activation_state = _clean_name(item.get("activation_state")).lower() or "active"
    reactivate_after = _int(item.get("reactivate_after_session_index"))
    if activation_state == "active":
        return 2
    if session_index is not None and reactivate_after and session_index >= reactivate_after:
        return 1
    return 0


def _effective_priority(item: dict[str, Any], *, session_index: int | None = None) -> int:
    base_priority = _int(item.get("priority"))
    penalty = min(_int(item.get("consume_count")) * 4, 24)
    if _activation_rank(item, session_index=session_index) <= 0:
        penalty += 12
    return max(1, base_priority - penalty)


def build_queue_item(
    *,
    raw: dict[str, Any] | str,
    queue_kind: str,
    target_mode: str,
    selected_harness: str | None,
    source_level: str,
    project: str,
    lane: str,
    reason: str,
    target_type: str = "function",
    source_campaign_task_id: str | None = None,
    source_round_task_id: str | None = None,
    degraded_reason: str | None = None,
    degraded_detail: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        name = _clean_name(raw.get("name"))
        coverage_fraction = raw.get("coverage_fraction")
        total_lines = _int(raw.get("total_lines"))
        covered_lines = _int(raw.get("covered_lines"))
        function_paths = list(raw.get("function_paths") or [])
        target_type = _clean_name(raw.get("target_type")) or target_type
    else:
        name = _clean_name(raw)
        coverage_fraction = None
        total_lines = 0
        covered_lines = 0
        function_paths = []
    if not name:
        return None

    base_priority = {
        "low_growth": 95,
        "uncovered": 90,
        "partial_degraded": 70,
        "stalled": 65,
        "harness_focus": 55,
    }.get(queue_kind, 50)
    if coverage_fraction is not None:
        base_priority += max(0, int((1.0 - max(0.0, min(_float(coverage_fraction), 1.0))) * 20.0))
    if total_lines > 0:
        base_priority += min(total_lines // 12, 12)
    if source_level != "exact":
        base_priority = max(40, base_priority - 10)

    return {
        "name": name,
        "queue_kind": queue_kind,
        "target_type": target_type,
        "project": project,
        "lane": lane,
        "target_mode": target_mode,
        "harness": _clean_name(selected_harness) or None,
        "source_level": source_level,
        "priority": base_priority,
        "coverage_fraction": None if coverage_fraction is None else round(_float(coverage_fraction), 4),
        "total_lines": total_lines,
        "covered_lines": covered_lines,
        "function_paths": function_paths,
        "reason": reason,
        "degraded_reason": degraded_reason,
        "degraded_detail": degraded_detail or None,
        "source_campaign_task_id": source_campaign_task_id,
        "source_round_task_id": source_round_task_id,
        "activation_state": "active",
        "cooldown_sessions": _queue_cooldown_sessions(queue_kind),
        "reactivate_after_session_index": None,
    }


def merge_queue_items(
    existing_items: list[dict[str, Any]],
    incoming_items: list[dict[str, Any]],
    *,
    updated_at: str | None = None,
    max_items: int = MAX_QUEUE_ITEMS,
) -> list[dict[str, Any]]:
    now = updated_at or now_iso()
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {
        _queue_item_key(item): dict(item)
        for item in existing_items
        if _clean_name(item.get("name"))
    }

    for item in incoming_items:
        if not _clean_name(item.get("name")):
            continue
        key = _queue_item_key(item)
        if key in merged:
            current = merged[key]
            current.update({k: v for k, v in item.items() if v not in (None, "", [], {})})
            current["priority"] = max(_int(current.get("priority")), _int(item.get("priority")))
            current["hit_count"] = _int(current.get("hit_count"), 1) + 1
            current["last_seen_at"] = now
            current["activation_state"] = "active"
            current["reactivate_after_session_index"] = None
            current["cooldown_sessions"] = _queue_cooldown_sessions(current.get("queue_kind"))
        else:
            payload = dict(item)
            payload["first_seen_at"] = now
            payload["last_seen_at"] = now
            payload["hit_count"] = 1
            payload.setdefault("consume_count", 0)
            payload.setdefault("last_consumed_at", None)
            payload.setdefault("last_consumed_session_index", None)
            payload.setdefault("activation_state", "active")
            payload.setdefault("cooldown_sessions", _queue_cooldown_sessions(payload.get("queue_kind")))
            payload.setdefault("reactivate_after_session_index", None)
            merged[key] = payload

    def _sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        coverage_fraction = item.get("coverage_fraction")
        coverage_value = 2.0 if coverage_fraction is None else _float(coverage_fraction, 2.0)
        return (
            -_activation_rank(item),
            -_source_rank(_clean_name(item.get("source_level"))),
            -_effective_priority(item),
            coverage_value,
            _int(item.get("consume_count")),
            -_int(item.get("hit_count"), 1),
            _clean_name(item.get("last_seen_at")),
            _clean_name(item.get("name")),
        )

    items = sorted(merged.values(), key=_sort_key)
    return items[:max_items]


def select_queue_items(
    items: list[dict[str, Any]],
    *,
    preferred_harness: str | None,
    limit: int,
    session_index: int | None = None,
) -> list[dict[str, Any]]:
    preferred = _clean_name(preferred_harness)

    def _sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        coverage_fraction = item.get("coverage_fraction")
        coverage_value = 2.0 if coverage_fraction is None else _float(coverage_fraction, 2.0)
        harness_match = 1 if preferred and _clean_name(item.get("harness")) == preferred else 0
        target_type = _clean_name(item.get("target_type")) or "function"
        return (
            -_activation_rank(item, session_index=session_index),
            -_source_rank(_clean_name(item.get("source_level"))),
            -harness_match,
            0 if target_type == "function" else 1,
            -_effective_priority(item, session_index=session_index),
            coverage_value,
            _int(item.get("consume_count")),
            -_int(item.get("hit_count"), 1),
            _clean_name(item.get("name")),
        )

    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in sorted(items, key=_sort_key):
        name = _clean_name(item.get("name"))
        if not name or name in seen or _activation_rank(item, session_index=session_index) <= 0:
            continue
        selected.append(dict(item))
        seen.add(name)
        if len(selected) >= limit:
            break
    return selected


def mark_queue_items_consumed(
    items: list[dict[str, Any]],
    selected_items: list[dict[str, Any]],
    *,
    consumed_at: str,
    session_index: int,
) -> list[dict[str, Any]]:
    selected_keys = {_queue_item_key(item) for item in selected_items}
    updated: list[dict[str, Any]] = []
    for item in items:
        payload = dict(item)
        if _queue_item_key(item) in selected_keys:
            payload["consume_count"] = _int(payload.get("consume_count")) + 1
            payload["last_consumed_at"] = consumed_at
            payload["last_consumed_session_index"] = session_index
            payload["activation_state"] = "cooldown"
            payload["reactivate_after_session_index"] = session_index + _queue_cooldown_sessions(payload.get("queue_kind"))
        updated.append(payload)
    return updated


def queue_counts(items: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {
        "total": 0,
        "exact_items": 0,
        "partial_items": 0,
        "fallback_items": 0,
        "binary_signal_items": 0,
        "function_items": 0,
        "harness_items": 0,
        "active_items": 0,
        "cooldown_items": 0,
    }
    by_kind: dict[str, int] = {}
    by_harness: dict[str, int] = {}
    for item in items:
        counts["total"] += 1
        level = _clean_name(item.get("source_level")).lower()
        if level == "exact":
            counts["exact_items"] += 1
        elif level == "partial":
            counts["partial_items"] += 1
        elif level == "fallback":
            counts["fallback_items"] += 1
        elif level == "binary_signal":
            counts["binary_signal_items"] += 1
        target_type = _clean_name(item.get("target_type")) or "function"
        if target_type == "function":
            counts["function_items"] += 1
        else:
            counts["harness_items"] += 1
        if _clean_name(item.get("activation_state")).lower() == "cooldown":
            counts["cooldown_items"] += 1
        else:
            counts["active_items"] += 1
        kind = _clean_name(item.get("queue_kind")) or "unknown"
        by_kind[kind] = by_kind.get(kind, 0) + 1
        harness = _clean_name(item.get("harness"))
        if harness:
            by_harness[harness] = by_harness.get(harness, 0) + 1
    counts["by_kind"] = by_kind
    counts["by_harness"] = by_harness
    return counts

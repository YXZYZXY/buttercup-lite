from __future__ import annotations

from typing import Any


_MIN_SESSION_SECONDS = 60


def derive_child_launch_plan(
    *,
    remaining_seconds: int,
    child_campaign_duration_seconds: int,
    round_seconds: int,
    min_continuation_seconds: int,
) -> dict[str, int] | None:
    minimum_launch_seconds = max(_MIN_SESSION_SECONDS, int(min_continuation_seconds or 0))
    remaining = int(remaining_seconds or 0)
    if remaining < minimum_launch_seconds:
        return None
    child_duration = max(
        minimum_launch_seconds,
        min(int(child_campaign_duration_seconds or minimum_launch_seconds), remaining),
    )
    effective_round_seconds = max(
        _MIN_SESSION_SECONDS,
        min(int(round_seconds or child_duration), child_duration),
    )
    return {
        "child_campaign_duration_seconds": child_duration,
        "round_seconds": effective_round_seconds,
        "minimum_launch_seconds": minimum_launch_seconds,
    }


def classify_claimed_work_item(work_item: dict[str, Any]) -> dict[str, Any]:
    continuation = dict(work_item.get("continuation") or {})
    metadata = dict(work_item.get("metadata") or {})
    continuation_index = int(continuation.get("continuation_index") or 0)
    retry_of_work_item_id = str(continuation.get("retry_of_work_item_id") or "").strip() or None
    replacement_reason = (
        str(metadata.get("replacement_reason") or "").strip()
        or str(metadata.get("slot_replacement_reason") or "").strip()
        or None
    )
    if retry_of_work_item_id or replacement_reason:
        kind = "replacement"
    elif continuation_index > 0:
        kind = "continuation"
    else:
        kind = "bootstrap"
    return {
        "kind": kind,
        "continuation_index": continuation_index,
        "requested_reason": str(continuation.get("requested_reason") or "").strip() or None,
        "retry_of_work_item_id": retry_of_work_item_id,
        "source_status": str(continuation.get("source_status") or "").strip() or None,
        "replacement_reason": replacement_reason,
    }


def derive_campaign_exit_resolution(snapshot: dict[str, Any], *, return_code: int | None) -> dict[str, Any]:
    status = str(snapshot.get("status") or "").strip()
    lifecycle_state = str(snapshot.get("campaign_lifecycle_state") or "").strip()
    completed_reason = (
        str(snapshot.get("campaign_completed_reason") or "").strip()
        or str(snapshot.get("campaign_local_completion_reason") or "").strip()
        or None
    )
    if status == "CAMPAIGN_COMPLETED" or (lifecycle_state == "finished" and completed_reason):
        return {
            "kind": "complete",
            "reason": completed_reason or "campaign_completed",
        }
    failure_reason = (
        str(snapshot.get("campaign_error") or "").strip()
        or f"slot_controller_process_exit_{return_code}:{status or lifecycle_state or 'unknown'}"
    )
    return {
        "kind": "replace",
        "reason": failure_reason,
    }

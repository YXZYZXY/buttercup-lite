from __future__ import annotations

from datetime import datetime, timedelta, timezone


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def compute_deadline(started_at: datetime, duration_seconds: int) -> datetime:
    return started_at + timedelta(seconds=duration_seconds)


def should_continue(deadline_at: datetime, current_time: datetime | None = None) -> bool:
    current = current_time or now_utc()
    return current < deadline_at


def remaining_seconds(deadline_at: datetime, current_time: datetime | None = None) -> int:
    current = current_time or now_utc()
    remaining = int((deadline_at - current).total_seconds())
    return max(0, remaining)


from __future__ import annotations

import fcntl
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.campaign.fabric_models import (
    FabricClaimRecord,
    FabricContinuation,
    FabricSlotState,
    FabricWorkItem,
)
from core.storage.layout import tasks_root


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def fabric_root() -> Path:
    root = tasks_root() / "_system_fabric"
    root.mkdir(parents=True, exist_ok=True)
    return root


def fabric_state_path() -> Path:
    return fabric_root() / "fabric_state.json"


def fabric_events_path() -> Path:
    return fabric_root() / "fabric_events.json"


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


@contextmanager
def _fabric_lock():
    root = fabric_root()
    lock_path = root / ".fabric.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _initial_state() -> dict[str, Any]:
    now = _now()
    return {
        "schema_version": 1,
        "created_at": now,
        "updated_at": now,
        "queues": {
            "pending": [],
            "claimed": [],
            "completed": [],
            "failed": [],
            "requeue": []
        },
        "work_items": {},
        "claims": {},
        "campaign_bindings": {},
        "slots": {},
        "metrics": {
            "claims_total": 0,
            "completed_total": 0,
            "failed_total": 0,
            "requeued_total": 0,
            "continuations_total": 0
        }
    }


def _initial_events() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "created_at": _now(),
        "updated_at": _now(),
        "events": []
    }


class FabricStore:
    def __init__(self) -> None:
        self.root = fabric_root()
        self.state_path = fabric_state_path()
        self.events_path = fabric_events_path()

    def _load_state(self) -> dict[str, Any]:
        return _read_json(self.state_path, _initial_state())

    def _save_state(self, state: dict[str, Any]) -> None:
        state["updated_at"] = _now()
        _write_json(self.state_path, state)

    def _append_event(
        self,
        *,
        event_type: str,
        work_item_id: str | None = None,
        slot_id: str | None = None,
        claim_token: str | None = None,
        campaign_task_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = _read_json(self.events_path, _initial_events())
        event = {
            "event_id": str(uuid4()),
            "event_type": event_type,
            "created_at": _now(),
            "work_item_id": work_item_id,
            "slot_id": slot_id,
            "claim_token": claim_token,
            "campaign_task_id": campaign_task_id,
            "details": details or {},
        }
        payload.setdefault("events", []).append(event)
        payload["updated_at"] = event["created_at"]
        _write_json(self.events_path, payload)
        return event

    def _queue_remove(self, queue: list[str], item_id: str) -> None:
        while item_id in queue:
            queue.remove(item_id)

    def _queue_append_unique(self, queue: list[str], item_id: str) -> None:
        if item_id not in queue:
            queue.append(item_id)

    def _queue_sort_pending(self, state: dict[str, Any]) -> None:
        def _sort_key(item_id: str) -> tuple[Any, ...]:
            item = state.setdefault("work_items", {}).get(item_id, {})
            continuation = item.get("continuation") or {}
            return (
                -int(item.get("priority") or 0),
                -int(continuation.get("continuation_index") or 0),
                str(item.get("created_at") or ""),
                item_id,
            )

        state.setdefault("queues", {}).setdefault("pending", []).sort(key=_sort_key)

    def _lane_matches(self, item: dict[str, Any], filters: dict[str, Any]) -> bool:
        namespaces = set(str(v) for v in (filters.get("namespaces") or []) if str(v).strip())
        if namespaces and str(item.get("namespace") or "") not in namespaces:
            return False
        lanes = set(str(v) for v in (filters.get("lanes") or []) if str(v).strip())
        if lanes and str(item.get("lane") or "") not in lanes:
            return False
        projects = set(str(v) for v in (filters.get("projects") or []) if str(v).strip())
        if projects and str(item.get("project") or "") not in projects:
            return False
        benchmarks = set(str(v) for v in (filters.get("benchmarks") or []) if str(v).strip())
        if benchmarks and str(item.get("benchmark") or "") not in benchmarks:
            return False
        return True

    def _claim_record(self, *, claim_token: str, work_item_id: str, slot_id: str, lease_expires_at: str) -> dict[str, Any]:
        now = _now()
        return FabricClaimRecord(
            claim_token=claim_token,
            work_item_id=work_item_id,
            slot_id=slot_id,
            status="claimed",
            claimed_at=now,
            last_heartbeat_at=now,
            lease_expires_at=lease_expires_at,
            created_at=now,
            updated_at=now,
        ).to_dict()

    def _spawn_continuation_locked(
        self,
        state: dict[str, Any],
        *,
        source_item: dict[str, Any],
        next_base_task_id: str,
        remaining_seconds: int,
        requested_reason: str,
        completion_source: str,
        retry_of_work_item_id: str | None = None,
    ) -> dict[str, Any]:
        continuation = dict(source_item.get("continuation") or {})
        continuation_index = int(continuation.get("continuation_index") or 0) + 1
        item = FabricWorkItem(
            work_item_id=str(uuid4()),
            kind=str(source_item.get("kind") or "campaign"),
            status="pending",
            lane=str(source_item.get("lane") or "source"),
            target_mode=str(source_item.get("target_mode") or "source"),
            project=str(source_item.get("project") or ""),
            benchmark=source_item.get("benchmark"),
            namespace=source_item.get("namespace"),
            slot_label=source_item.get("slot_label"),
            base_task_id=next_base_task_id,
            donor_task_id=next_base_task_id,
            priority=int(source_item.get("priority") or 100),
            metadata=dict(source_item.get("metadata") or {}),
            continuation=FabricContinuation(
                continuation_of_work_item_id=str(source_item.get("work_item_id") or ""),
                continuation_index=continuation_index,
                requested_by_campaign_task_id=str(source_item.get("campaign_task_id") or "") or None,
                requested_reason=requested_reason,
                remaining_seconds=int(remaining_seconds),
                recommended_base_task_id=next_base_task_id,
                retry_of_work_item_id=retry_of_work_item_id,
                donor_task_id=next_base_task_id,
                source_status=completion_source,
            ),
            created_at=_now(),
            updated_at=_now(),
        ).to_dict()
        state.setdefault("work_items", {})[item["work_item_id"]] = item
        self._queue_append_unique(state.setdefault("queues", {}).setdefault("pending", []), item["work_item_id"])
        state.setdefault("metrics", {})["continuations_total"] = int(state["metrics"].get("continuations_total") or 0) + 1
        self._queue_sort_pending(state)
        self._append_event(
            event_type="work_item_enqueued",
            work_item_id=item["work_item_id"],
            details={
                "reason": requested_reason,
                "lane": item["lane"],
                "project": item["project"],
                "namespace": item["namespace"],
                "continuation_index": continuation_index,
                "retry_of_work_item_id": retry_of_work_item_id,
            },
        )
        return item

    def _existing_continuation_locked(self, state: dict[str, Any], *, source_work_item_id: str) -> dict[str, Any] | None:
        for item in state.setdefault("work_items", {}).values():
            continuation = item.get("continuation") or {}
            if str(continuation.get("continuation_of_work_item_id") or "") == source_work_item_id:
                return item
        return None

    def scavenge_expired_claims(self) -> dict[str, Any]:
        with _fabric_lock():
            state = self._load_state()
            changed = False
            now = _now()
            now_dt = _parse_iso(now)
            expired: list[dict[str, Any]] = []
            for claim_token, claim in list(state.setdefault("claims", {}).items()):
                if str(claim.get("status") or "") != "claimed":
                    continue
                lease_dt = _parse_iso(claim.get("lease_expires_at"))
                if lease_dt is None or now_dt is None or lease_dt >= now_dt:
                    continue
                work_item_id = str(claim.get("work_item_id") or "")
                slot_id = str(claim.get("slot_id") or "")
                item = state.setdefault("work_items", {}).get(work_item_id)
                if not item:
                    continue
                item["status"] = "pending"
                item["claim_token"] = None
                item["claimed_by_slot"] = None
                item["claimed_at"] = None
                item["lease_expires_at"] = None
                item["last_status"] = "claim_expired_requeued"
                item["requeue_count"] = int(item.get("requeue_count") or 0) + 1
                item["updated_at"] = now
                self._queue_remove(state.setdefault("queues", {}).setdefault("claimed", []), work_item_id)
                self._queue_append_unique(state["queues"].setdefault("pending", []), work_item_id)
                self._queue_append_unique(state["queues"].setdefault("requeue", []), work_item_id)
                slot = state.setdefault("slots", {}).get(slot_id)
                if slot:
                    slot["status"] = "idle"
                    slot["current_work_item_id"] = None
                    slot["current_claim_token"] = None
                    slot["current_campaign_task_id"] = None
                    slot["requeues_total"] = int(slot.get("requeues_total") or 0) + 1
                    slot["updated_at"] = now
                claim["status"] = "expired"
                claim["updated_at"] = now
                changed = True
                expired.append(
                    {
                        "work_item_id": work_item_id,
                        "slot_id": slot_id,
                        "claim_token": claim_token,
                    }
                )
                self._append_event(
                    event_type="claim_expired_requeued",
                    work_item_id=work_item_id,
                    slot_id=slot_id,
                    claim_token=claim_token,
                    details={"lease_expires_at": claim.get("lease_expires_at")},
                )
            if changed:
                state.setdefault("metrics", {})["requeued_total"] = int(state["metrics"].get("requeued_total") or 0) + len(expired)
                self._queue_sort_pending(state)
                self._save_state(state)
            return {"requeued": expired, "state_path": str(self.state_path), "events_path": str(self.events_path)}

    def register_slot(
        self,
        *,
        slot_id: str,
        label: str,
        lane: str,
        project: str | None,
        namespace: str | None,
        claim_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with _fabric_lock():
            state = self._load_state()
            now = _now()
            slot = FabricSlotState(
                slot_id=slot_id,
                label=label,
                lane=lane,
                project=project,
                namespace=namespace,
                claim_filters=dict(claim_filters or {}),
                last_heartbeat_at=now,
                created_at=now,
                updated_at=now,
            ).to_dict()
            existing = state.setdefault("slots", {}).get(slot_id)
            if existing:
                slot = {
                    **existing,
                    "label": label,
                    "lane": lane,
                    "project": project,
                    "namespace": namespace,
                    "claim_filters": dict(claim_filters or existing.get("claim_filters") or {}),
                    "last_heartbeat_at": now,
                    "updated_at": now,
                }
            state["slots"][slot_id] = slot
            self._save_state(state)
            self._append_event(
                event_type="slot_registered",
                slot_id=slot_id,
                details={
                    "label": label,
                    "lane": lane,
                    "project": project,
                    "namespace": namespace,
                    "claim_filters": slot.get("claim_filters") or {},
                },
            )
            return slot

    def heartbeat_slot(
        self,
        *,
        slot_id: str,
        status: str,
        current_work_item_id: str | None = None,
        current_campaign_task_id: str | None = None,
    ) -> dict[str, Any]:
        with _fabric_lock():
            state = self._load_state()
            now = _now()
            slot = state.setdefault("slots", {}).get(slot_id)
            if not slot:
                slot = FabricSlotState(
                    slot_id=slot_id,
                    label=slot_id,
                    lane="unknown",
                    created_at=now,
                    updated_at=now,
                ).to_dict()
            slot["status"] = status
            slot["last_heartbeat_at"] = now
            slot["current_work_item_id"] = current_work_item_id
            slot["current_campaign_task_id"] = current_campaign_task_id
            slot["updated_at"] = now
            state.setdefault("slots", {})[slot_id] = slot
            self._save_state(state)
            self._append_event(
                event_type="slot_heartbeat",
                slot_id=slot_id,
                work_item_id=current_work_item_id,
                campaign_task_id=current_campaign_task_id,
                details={"status": status},
            )
            return slot

    def enqueue_work_item(
        self,
        *,
        lane: str,
        target_mode: str,
        project: str,
        benchmark: str | None,
        namespace: str | None,
        slot_label: str | None,
        base_task_id: str | None,
        donor_task_id: str | None,
        priority: int = 100,
        dedupe_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with _fabric_lock():
            state = self._load_state()
            if dedupe_key:
                for item in state.setdefault("work_items", {}).values():
                    if item.get("dedupe_key") != dedupe_key:
                        continue
                    if str(item.get("status") or "") in {"pending", "claimed"}:
                        return item
            now = _now()
            item = FabricWorkItem(
                work_item_id=str(uuid4()),
                kind="campaign",
                status="pending",
                lane=lane,
                target_mode=target_mode,
                project=project,
                benchmark=benchmark,
                namespace=namespace,
                slot_label=slot_label,
                base_task_id=base_task_id,
                donor_task_id=donor_task_id or base_task_id,
                priority=int(priority),
                dedupe_key=dedupe_key,
                metadata=dict(metadata or {}),
                created_at=now,
                updated_at=now,
            ).to_dict()
            state.setdefault("work_items", {})[item["work_item_id"]] = item
            self._queue_append_unique(state.setdefault("queues", {}).setdefault("pending", []), item["work_item_id"])
            self._queue_sort_pending(state)
            self._save_state(state)
            self._append_event(
                event_type="work_item_enqueued",
                work_item_id=item["work_item_id"],
                details={
                    "lane": lane,
                    "target_mode": target_mode,
                    "project": project,
                    "benchmark": benchmark,
                    "namespace": namespace,
                    "base_task_id": base_task_id,
                },
            )
            return item

    def claim_next_work_item(
        self,
        *,
        slot_id: str,
        lease_seconds: int,
        claim_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        self.scavenge_expired_claims()
        with _fabric_lock():
            state = self._load_state()
            slot = state.setdefault("slots", {}).get(slot_id)
            if not slot:
                return None
            filters = dict(slot.get("claim_filters") or {})
            if claim_filters:
                filters.update(claim_filters)
            for item_id in list(state.setdefault("queues", {}).setdefault("pending", [])):
                item = state.setdefault("work_items", {}).get(item_id)
                if not item or str(item.get("status") or "") != "pending":
                    self._queue_remove(state["queues"]["pending"], item_id)
                    continue
                if not self._lane_matches(item, filters):
                    continue
                now = _now()
                lease_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=max(60, int(lease_seconds)))).isoformat()
                claim_token = str(uuid4())
                item["status"] = "claimed"
                item["claim_token"] = claim_token
                item["claimed_by_slot"] = slot_id
                item["claimed_at"] = now
                item["last_heartbeat_at"] = now
                item["lease_duration_seconds"] = max(60, int(lease_seconds))
                item["lease_expires_at"] = lease_expires_at
                item["attempt_count"] = int(item.get("attempt_count") or 0) + 1
                item["updated_at"] = now
                self._queue_remove(state["queues"]["pending"], item_id)
                self._queue_append_unique(state["queues"].setdefault("claimed", []), item_id)
                state.setdefault("claims", {})[claim_token] = self._claim_record(
                    claim_token=claim_token,
                    work_item_id=item_id,
                    slot_id=slot_id,
                    lease_expires_at=lease_expires_at,
                )
                slot["status"] = "claimed"
                slot["current_work_item_id"] = item_id
                slot["current_claim_token"] = claim_token
                slot["last_claimed_at"] = now
                slot["last_heartbeat_at"] = now
                slot["claims_total"] = int(slot.get("claims_total") or 0) + 1
                slot["updated_at"] = now
                state.setdefault("metrics", {})["claims_total"] = int(state["metrics"].get("claims_total") or 0) + 1
                self._save_state(state)
                self._append_event(
                    event_type="work_item_claimed",
                    work_item_id=item_id,
                    slot_id=slot_id,
                    claim_token=claim_token,
                    details={
                        "lane": item.get("lane"),
                        "project": item.get("project"),
                        "namespace": item.get("namespace"),
                        "lease_seconds": item.get("lease_duration_seconds"),
                    },
                )
                return item
            return None

    def bind_claim_to_campaign(
        self,
        *,
        work_item_id: str,
        claim_token: str,
        slot_id: str,
        campaign_task_id: str,
        base_task_id: str | None = None,
        donor_task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        with _fabric_lock():
            state = self._load_state()
            item = state.setdefault("work_items", {}).get(work_item_id)
            claim = state.setdefault("claims", {}).get(claim_token)
            if not item or not claim or str(item.get("claim_token") or "") != claim_token:
                return None
            now = _now()
            item["campaign_task_id"] = campaign_task_id
            if base_task_id:
                item["base_task_id"] = base_task_id
            if donor_task_id:
                item["donor_task_id"] = donor_task_id
            if metadata:
                item.setdefault("metadata", {}).update(metadata)
            item["last_status"] = "campaign_bound"
            item["updated_at"] = now
            claim["campaign_task_id"] = campaign_task_id
            claim["updated_at"] = now
            claim["last_heartbeat_at"] = now
            slot = state.setdefault("slots", {}).get(slot_id)
            if slot:
                slot["status"] = "running"
                slot["current_work_item_id"] = work_item_id
                slot["current_claim_token"] = claim_token
                slot["current_campaign_task_id"] = campaign_task_id
                slot["last_heartbeat_at"] = now
                slot["updated_at"] = now
            state.setdefault("campaign_bindings", {})[campaign_task_id] = {
                "work_item_id": work_item_id,
                "claim_token": claim_token,
                "slot_id": slot_id,
                "status": "running",
                "updated_at": now,
            }
            self._save_state(state)
            self._append_event(
                event_type="campaign_bound_to_claim",
                work_item_id=work_item_id,
                slot_id=slot_id,
                claim_token=claim_token,
                campaign_task_id=campaign_task_id,
                details={"base_task_id": base_task_id, "donor_task_id": donor_task_id},
            )
            return item

    def observe_campaign_registration(
        self,
        *,
        campaign_task_id: str,
        benchmark: str,
        lane: str,
        target_mode: str,
        base_task_id: str | None,
        slot_label: str | None,
    ) -> dict[str, Any] | None:
        with _fabric_lock():
            state = self._load_state()
            binding = state.setdefault("campaign_bindings", {}).get(campaign_task_id)
            if not binding:
                return None
            work_item_id = str(binding.get("work_item_id") or "")
            item = state.setdefault("work_items", {}).get(work_item_id)
            if not item:
                return None
            now = _now()
            item["benchmark"] = benchmark or item.get("benchmark")
            item["lane"] = lane or item.get("lane")
            item["target_mode"] = target_mode or item.get("target_mode")
            item["base_task_id"] = base_task_id or item.get("base_task_id")
            item["slot_label"] = slot_label or item.get("slot_label")
            item["last_status"] = "campaign_registered"
            item["updated_at"] = now
            binding["status"] = "registered"
            binding["updated_at"] = now
            self._save_state(state)
            self._append_event(
                event_type="campaign_registered",
                work_item_id=work_item_id,
                slot_id=binding.get("slot_id"),
                claim_token=binding.get("claim_token"),
                campaign_task_id=campaign_task_id,
                details={"benchmark": benchmark, "lane": lane, "target_mode": target_mode},
            )
            return item

    def _resolve_binding(self, state: dict[str, Any], *, campaign_task_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
        binding = state.setdefault("campaign_bindings", {}).get(campaign_task_id)
        if not binding:
            return None, None, None
        item = state.setdefault("work_items", {}).get(str(binding.get("work_item_id") or ""))
        claim = state.setdefault("claims", {}).get(str(binding.get("claim_token") or ""))
        return binding, item, claim

    def heartbeat_by_campaign(
        self,
        *,
        campaign_task_id: str,
        status: str,
        round_count: int,
        metrics: dict[str, Any] | None = None,
        heartbeat_source: str = "campaign",
    ) -> dict[str, Any] | None:
        with _fabric_lock():
            state = self._load_state()
            binding, item, claim = self._resolve_binding(state, campaign_task_id=campaign_task_id)
            if not binding or not item or not claim:
                return None
            now = _now()
            lease_seconds = max(60, int(item.get("lease_duration_seconds") or 300))
            lease_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()
            item["last_status"] = status
            item["campaign_round_count"] = int(round_count)
            item["last_heartbeat_at"] = now
            item["lease_expires_at"] = lease_expires_at
            if metrics:
                item.setdefault("metadata", {})["last_metrics"] = dict(metrics)
            item["updated_at"] = now
            claim["status"] = "running"
            claim["campaign_task_id"] = campaign_task_id
            claim["last_heartbeat_at"] = now
            claim["lease_expires_at"] = lease_expires_at
            claim["updated_at"] = now
            binding["status"] = status
            binding["updated_at"] = now
            slot = state.setdefault("slots", {}).get(str(binding.get("slot_id") or ""))
            if slot:
                slot["status"] = status
                slot["current_work_item_id"] = item.get("work_item_id")
                slot["current_claim_token"] = claim.get("claim_token")
                slot["current_campaign_task_id"] = campaign_task_id
                slot["last_heartbeat_at"] = now
                slot["updated_at"] = now
            self._save_state(state)
            self._append_event(
                event_type="campaign_heartbeat",
                work_item_id=item.get("work_item_id"),
                slot_id=binding.get("slot_id"),
                claim_token=claim.get("claim_token"),
                campaign_task_id=campaign_task_id,
                details={
                    "status": status,
                    "round_count": round_count,
                    "heartbeat_source": heartbeat_source,
                },
            )
            return item

    def complete_by_campaign(
        self,
        *,
        campaign_task_id: str,
        completed_reason: str,
        next_base_task_id: str | None,
        remaining_seconds: int,
        min_continuation_seconds: int = 90,
        completion_source: str = "campaign",
    ) -> dict[str, Any] | None:
        with _fabric_lock():
            state = self._load_state()
            binding, item, claim = self._resolve_binding(state, campaign_task_id=campaign_task_id)
            if not binding or not item:
                return None
            work_item_id = str(item.get("work_item_id") or binding.get("work_item_id") or "")
            existing_continuation = self._existing_continuation_locked(state, source_work_item_id=work_item_id)
            if str(item.get("status") or "") == "completed":
                if int(remaining_seconds) >= int(min_continuation_seconds) and next_base_task_id and not existing_continuation:
                    continuation_item = self._spawn_continuation_locked(
                        state,
                        source_item=item,
                        next_base_task_id=next_base_task_id,
                        remaining_seconds=remaining_seconds,
                        requested_reason=completed_reason,
                        completion_source=completion_source,
                    )
                    item["updated_at"] = _now()
                    self._save_state(state)
                    self._append_event(
                        event_type="continuation_requested",
                        work_item_id=continuation_item.get("work_item_id"),
                        slot_id=binding.get("slot_id"),
                        campaign_task_id=campaign_task_id,
                        details={
                            "from_work_item_id": work_item_id,
                            "remaining_seconds": remaining_seconds,
                            "next_base_task_id": next_base_task_id,
                            "late_after_completion": True,
                        },
                    )
                    return {
                        **item,
                        "continuation_work_item_id": continuation_item.get("work_item_id"),
                    }
                return {
                    **item,
                    "continuation_work_item_id": (existing_continuation or {}).get("work_item_id"),
                }
            now = _now()
            item["status"] = "completed"
            item["last_status"] = "completed"
            item["completion_reason"] = completed_reason
            item["completed_at"] = now
            item["updated_at"] = now
            self._queue_remove(state.setdefault("queues", {}).setdefault("claimed", []), work_item_id)
            self._queue_append_unique(state["queues"].setdefault("completed", []), work_item_id)
            slot_id = str(binding.get("slot_id") or "")
            slot = state.setdefault("slots", {}).get(slot_id)
            if slot:
                slot["status"] = "idle"
                slot["current_work_item_id"] = None
                slot["current_claim_token"] = None
                slot["current_campaign_task_id"] = None
                slot["last_completed_at"] = now
                slot["last_heartbeat_at"] = now
                slot["completions_total"] = int(slot.get("completions_total") or 0) + 1
                slot["updated_at"] = now
            if claim:
                claim["status"] = "completed"
                claim["updated_at"] = now
            binding["status"] = "completed"
            binding["updated_at"] = now
            continuation_item = None
            if int(remaining_seconds) >= int(min_continuation_seconds) and next_base_task_id:
                continuation_item = self._spawn_continuation_locked(
                    state,
                    source_item=item,
                    next_base_task_id=next_base_task_id,
                    remaining_seconds=remaining_seconds,
                    requested_reason=completed_reason,
                    completion_source=completion_source,
                )
            state.setdefault("metrics", {})["completed_total"] = int(state["metrics"].get("completed_total") or 0) + 1
            self._save_state(state)
            self._append_event(
                event_type="work_item_completed",
                work_item_id=work_item_id,
                slot_id=slot_id or None,
                claim_token=(claim or {}).get("claim_token"),
                campaign_task_id=campaign_task_id,
                details={
                    "completed_reason": completed_reason,
                    "remaining_seconds": remaining_seconds,
                    "next_base_task_id": next_base_task_id,
                    "continuation_work_item_id": (continuation_item or {}).get("work_item_id"),
                },
            )
            if continuation_item:
                self._append_event(
                    event_type="continuation_requested",
                    work_item_id=continuation_item.get("work_item_id"),
                    slot_id=slot_id or None,
                    campaign_task_id=campaign_task_id,
                    details={
                        "from_work_item_id": work_item_id,
                        "remaining_seconds": remaining_seconds,
                        "next_base_task_id": next_base_task_id,
                    },
                )
            return {
                **item,
                "continuation_work_item_id": (continuation_item or {}).get("work_item_id"),
            }

    def fail_by_campaign(
        self,
        *,
        campaign_task_id: str,
        failure_reason: str,
        remaining_seconds: int,
        next_base_task_id: str | None = None,
        requeue_on_failure: bool = True,
        min_continuation_seconds: int = 90,
        completion_source: str = "campaign_failure",
    ) -> dict[str, Any] | None:
        with _fabric_lock():
            state = self._load_state()
            binding, item, claim = self._resolve_binding(state, campaign_task_id=campaign_task_id)
            if not binding or not item:
                return None
            if str(item.get("status") or "") in {"completed", "failed"}:
                return item
            now = _now()
            work_item_id = str(item.get("work_item_id") or binding.get("work_item_id") or "")
            item["status"] = "failed"
            item["failure_reason"] = failure_reason
            item["last_status"] = "failed"
            item["updated_at"] = now
            self._queue_remove(state.setdefault("queues", {}).setdefault("claimed", []), work_item_id)
            self._queue_append_unique(state["queues"].setdefault("failed", []), work_item_id)
            slot_id = str(binding.get("slot_id") or "")
            slot = state.setdefault("slots", {}).get(slot_id)
            if slot:
                slot["status"] = "idle"
                slot["current_work_item_id"] = None
                slot["current_claim_token"] = None
                slot["current_campaign_task_id"] = None
                slot["last_heartbeat_at"] = now
                slot["failures_total"] = int(slot.get("failures_total") or 0) + 1
                slot["updated_at"] = now
            if claim:
                claim["status"] = "failed"
                claim["updated_at"] = now
            binding["status"] = "failed"
            binding["updated_at"] = now
            requeued_item = None
            target_base = next_base_task_id or item.get("base_task_id") or item.get("donor_task_id")
            if requeue_on_failure and int(remaining_seconds) >= int(min_continuation_seconds) and target_base:
                self._queue_append_unique(state["queues"].setdefault("requeue", []), work_item_id)
                requeued_item = self._spawn_continuation_locked(
                    state,
                    source_item=item,
                    next_base_task_id=str(target_base),
                    remaining_seconds=remaining_seconds,
                    requested_reason=failure_reason,
                    completion_source=completion_source,
                    retry_of_work_item_id=work_item_id,
                )
                item["requeue_count"] = int(item.get("requeue_count") or 0) + 1
            state.setdefault("metrics", {})["failed_total"] = int(state["metrics"].get("failed_total") or 0) + 1
            if requeued_item:
                state["metrics"]["requeued_total"] = int(state["metrics"].get("requeued_total") or 0) + 1
            self._save_state(state)
            self._append_event(
                event_type="work_item_failed",
                work_item_id=work_item_id,
                slot_id=slot_id or None,
                claim_token=(claim or {}).get("claim_token"),
                campaign_task_id=campaign_task_id,
                details={
                    "failure_reason": failure_reason,
                    "remaining_seconds": remaining_seconds,
                    "requeue_on_failure": requeue_on_failure,
                    "requeued_work_item_id": (requeued_item or {}).get("work_item_id"),
                },
            )
            if requeued_item:
                self._append_event(
                    event_type="work_item_requeued",
                    work_item_id=requeued_item.get("work_item_id"),
                    slot_id=slot_id or None,
                    campaign_task_id=campaign_task_id,
                    details={
                        "from_failed_work_item_id": work_item_id,
                        "failure_reason": failure_reason,
                    },
                )
            return {
                **item,
                "requeued_work_item_id": (requeued_item or {}).get("work_item_id"),
            }

    def snapshot(self, *, namespace: str | None = None) -> dict[str, Any]:
        with _fabric_lock():
            state = self._load_state()
            if not namespace:
                return {
                    "state_path": str(self.state_path),
                    "events_path": str(self.events_path),
                    "state": state,
                }
            filtered_work_items = {
                item_id: item
                for item_id, item in (state.get("work_items") or {}).items()
                if str(item.get("namespace") or "") == namespace
            }
            queue_payload: dict[str, list[str]] = {}
            for queue_name, queue in (state.get("queues") or {}).items():
                queue_payload[queue_name] = [item_id for item_id in queue if item_id in filtered_work_items]
            filtered_slots = {
                slot_id: slot
                for slot_id, slot in (state.get("slots") or {}).items()
                if str(slot.get("namespace") or "") == namespace
            }
            return {
                "state_path": str(self.state_path),
                "events_path": str(self.events_path),
                "state": {
                    **state,
                    "work_items": filtered_work_items,
                    "queues": queue_payload,
                    "slots": filtered_slots,
                },
            }

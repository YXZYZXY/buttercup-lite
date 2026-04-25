from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FabricContinuation:
    continuation_of_work_item_id: str | None = None
    continuation_index: int = 0
    requested_by_campaign_task_id: str | None = None
    requested_reason: str | None = None
    remaining_seconds: int = 0
    recommended_base_task_id: str | None = None
    retry_of_work_item_id: str | None = None
    donor_task_id: str | None = None
    source_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FabricWorkItem:
    work_item_id: str
    kind: str
    status: str
    lane: str
    target_mode: str
    project: str
    item_id: str | None = None
    item_type: str | None = None
    benchmark: str | None = None
    namespace: str | None = None
    slot_label: str | None = None
    base_task_id: str | None = None
    donor_task_id: str | None = None
    priority: int = 100
    dedupe_key: str | None = None
    claim_token: str | None = None
    claimed_by_slot: str | None = None
    claimed_at: str | None = None
    last_heartbeat_at: str | None = None
    lease_duration_seconds: int = 0
    lease_expires_at: str | None = None
    queue_name: str | None = None
    lease_owner: str | None = None
    lease_until: str | None = None
    ack_state: str = "pending"
    retry_count: int = 0
    attempt_count: int = 0
    requeue_count: int = 0
    campaign_task_id: str | None = None
    campaign_round_count: int = 0
    last_status: str | None = None
    completion_reason: str | None = None
    failure_reason: str | None = None
    completed_at: str | None = None
    acked_at: str | None = None
    nacked_at: str | None = None
    dead_lettered_at: str | None = None
    source_campaign: str | None = None
    source_round: str | None = None
    source_slot: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    continuation: FabricContinuation = field(default_factory=FabricContinuation)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str | None = None
    updated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["item_id"] = payload.get("item_id") or payload.get("work_item_id")
        payload["item_type"] = payload.get("item_type") or payload.get("kind")
        payload["queue_name"] = payload.get("queue_name")
        payload["lease_owner"] = payload.get("lease_owner") or payload.get("claimed_by_slot")
        payload["lease_until"] = payload.get("lease_until") or payload.get("lease_expires_at")
        payload["ack_state"] = payload.get("ack_state") or payload.get("status") or "pending"
        payload["retry_count"] = int(payload.get("retry_count") or payload.get("requeue_count") or 0)
        payload["continuation"] = self.continuation.to_dict()
        return payload


@dataclass
class FabricClaimRecord:
    claim_token: str
    work_item_id: str
    slot_id: str
    status: str
    campaign_task_id: str | None = None
    claimed_at: str | None = None
    last_heartbeat_at: str | None = None
    lease_expires_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FabricSlotState:
    slot_id: str
    label: str
    lane: str
    project: str | None = None
    namespace: str | None = None
    claim_filters: dict[str, Any] = field(default_factory=dict)
    status: str = "idle"
    current_work_item_id: str | None = None
    current_claim_token: str | None = None
    current_campaign_task_id: str | None = None
    last_heartbeat_at: str | None = None
    last_claimed_at: str | None = None
    last_completed_at: str | None = None
    claims_total: int = 0
    completions_total: int = 0
    failures_total: int = 0
    requeues_total: int = 0
    created_at: str | None = None
    updated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

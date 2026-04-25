from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.campaign.continuation_policy import (
    classify_claimed_work_item,
    derive_campaign_exit_resolution,
    derive_child_launch_plan,
)
from core.campaign.fabric_store import FabricStore, fabric_events_path, fabric_state_path
from core.campaign.system_fabric import complete_campaign, fail_campaign, heartbeat_campaign, register_campaign
from core.models.task import AdapterType, ExecutionMode, TaskSource, TaskSpec, TaskStatus
from core.state.task_state import TaskStateStore
from core.storage.layout import campaign_manifest_path, task_json_path


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


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


def _redact_env(env: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in env.items():
        if "KEY" in key or "TOKEN" in key or "SECRET" in key:
            redacted[key] = f"***{value[-6:]}" if value else ""
        elif key in {"DEEPSEEK_API_KEY", "OPENAI_API_KEY"}:
            redacted[key] = f"***{value[-6:]}" if value else ""
        else:
            redacted[key] = value
    return redacted


def _task_snapshot(task_id: str) -> dict[str, Any]:
    payload = _read_json(task_json_path(task_id), {})
    manifest = _read_json(campaign_manifest_path(task_id), {})
    runtime = payload.get("runtime") or {}
    return {
        "task_id": task_id,
        "status": payload.get("status"),
        "campaign_lifecycle_state": runtime.get("campaign_lifecycle_state") or manifest.get("lifecycle_state"),
        "campaign_completed_reason": runtime.get("campaign_completed_reason"),
        "campaign_local_completion_reason": runtime.get("campaign_local_completion_reason"),
        "campaign_resolution_owner": runtime.get("campaign_resolution_owner"),
        "campaign_slot_resolution_deferred": runtime.get("campaign_slot_resolution_deferred"),
        "campaign_iterations_total": runtime.get("campaign_iterations_total") or manifest.get("iterations_total"),
        "campaign_manifest_path": runtime.get("campaign_manifest_path") or (str(campaign_manifest_path(task_id)) if campaign_manifest_path(task_id).exists() else None),
        "campaign_runtime_state_path": runtime.get("campaign_runtime_state_path"),
        "campaign_strength_report_path": runtime.get("campaign_strength_report_path"),
        "campaign_origin_task_ids": runtime.get("campaign_origin_task_ids") or manifest.get("origin_task_ids") or [],
        "campaign_last_round_finished_at": runtime.get("campaign_last_round_finished_at"),
        "campaign_finished_at": runtime.get("campaign_finished_at") or manifest.get("campaign_finished_at"),
        "campaign_error": runtime.get("campaign_error"),
        "campaign_failed_at": runtime.get("campaign_failed_at"),
        "fabric_work_item_id": runtime.get("fabric_work_item_id"),
        "fabric_claim_token": runtime.get("fabric_claim_token"),
        "fabric_slot_id": runtime.get("fabric_slot_id"),
        "fabric_lane": runtime.get("fabric_lane") or runtime.get("campaign_lane"),
        "llm_request_count_total": manifest.get("llm_request_count_total"),
        "llm_success_count": manifest.get("llm_success_count"),
        "llm_failure_count": manifest.get("llm_failure_count"),
        "api_calls_per_hour": manifest.get("api_calls_per_hour"),
        "fuzz_session_count": manifest.get("fuzz_session_count"),
        "harness_switch_count": manifest.get("harness_switch_count"),
        "reseed_trigger_count": manifest.get("reseed_trigger_count"),
        "shared_corpus_growth_count": manifest.get("shared_corpus_growth_count"),
        "family_diversification_trigger_count": manifest.get("family_diversification_trigger_count"),
        "generalized_candidate_bridge_count": manifest.get("generalized_candidate_bridge_count"),
        "trace_worthy_candidate_count": manifest.get("trace_worthy_candidate_count"),
        "trace_exact_signature_count": manifest.get("trace_exact_signature_count"),
        "loose_cluster_count": manifest.get("loose_cluster_count"),
        "confirmed_family_count": manifest.get("confirmed_family_count"),
    }


def _latest_donor_from_campaign(task_id: str, fallback_task_id: str) -> str:
    snapshot = _task_snapshot(task_id)
    origins = [str(item) for item in snapshot.get("campaign_origin_task_ids") or [] if str(item).strip()]
    return origins[-1] if origins else fallback_task_id


def _normalized_lane(payload: dict[str, Any]) -> str:
    raw = str(payload.get("lane") or "").strip().lower()
    if raw in {"source", "generalized", "binary"}:
        return raw
    metadata = dict(payload.get("metadata") or {})
    target_mode = str(payload.get("target_mode") or "source")
    if bool(payload.get("generalized_source")) or bool(metadata.get("generalized_source")):
        return "generalized"
    if target_mode == "binary":
        return "binary"
    return "source"


@dataclass
class SlotSpec:
    label: str
    base_task_id: str
    target_mode: str
    lane: str
    project: str
    slot_duration_seconds: int
    child_campaign_duration_seconds: int
    round_seconds: int
    priority: int = 100
    adapter_type: str = "ossfuzz"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: dict[str, Any], default_slot_seconds: int) -> "SlotSpec":
        metadata = dict(payload.get("metadata") or {})
        target_mode = str(payload.get("target_mode") or "source")
        lane = _normalized_lane({**payload, "metadata": metadata})
        project = str(payload.get("project") or metadata.get("project") or payload["label"])
        adapter_type = str(payload.get("adapter_type") or ("binary" if target_mode == "binary" else "ossfuzz"))
        return cls(
            label=str(payload["label"]),
            base_task_id=str(payload["base_task_id"]),
            target_mode=target_mode,
            lane=lane,
            project=project,
            slot_duration_seconds=int(payload.get("slot_duration_seconds") or default_slot_seconds),
            child_campaign_duration_seconds=int(payload.get("child_campaign_duration_seconds") or min(default_slot_seconds, 900)),
            round_seconds=int(payload.get("round_seconds") or 300),
            priority=int(payload.get("priority") or metadata.get("priority") or 100),
            adapter_type=adapter_type,
            metadata=metadata,
        )


@dataclass
class RunningCampaign:
    spec: SlotSpec
    launch_sequence: int
    continuation_index: int
    task_id: str
    base_task_id: str
    work_item_id: str
    claim_token: str
    slot_id: str
    process: subprocess.Popen
    log_path: Path
    log_handle: Any
    launch_manifest_path: Path
    started_at: str
    child_duration_seconds: int
    round_seconds: int


@dataclass
class PreparedLaunch:
    spec: SlotSpec
    task_id: str
    prepared_at: str
    prelaunched_at: str
    source_campaign_task_id: str
    predicted_base_task_id: str
    child_duration_seconds: int
    round_seconds: int
    expected_launch_sequence: int
    predicted_continuation_index: int
    process: subprocess.Popen
    log_path: Path
    log_handle: Any
    launch_manifest_path: Path


@dataclass
class AsyncTeardown:
    label: str
    campaign_task_id: str
    launch_manifest_path: Path
    started_at: str
    timeout_seconds: int
    thread: threading.Thread


class SlotController:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.repo_root = Path(config.get("repo_root") or Path.cwd()).resolve()
        self.run_root = Path(config["run_root"]).resolve()
        self.data_root = Path(config.get("data_root") or self.repo_root / "data" / "tasks").resolve()
        self.python_bin = str(config.get("python_bin") or sys.executable)
        self.poll_seconds = float(config.get("poll_seconds") or 3)
        self.slot_duration_seconds = int(config.get("slot_duration_seconds") or 3600)
        self.fabric_lease_seconds = int(config.get("fabric_lease_seconds") or 900)
        self.min_continuation_seconds = int(config.get("min_continuation_seconds") or 60)
        self.binary_min_continuation_seconds = int(config.get("binary_min_continuation_seconds") or 600)
        self.warmup_seconds = int(config.get("warmup_seconds") or 45)
        self.async_teardown_timeout_seconds = int(config.get("async_teardown_timeout_seconds") or 30)
        self.started_at = _now()
        self.deadline_at = self.started_at.timestamp() + self.slot_duration_seconds
        self.fabric_namespace = str(
            config.get("fabric_namespace")
            or f"slot-controller::{self.run_root.name}"
        )
        self.task_store = TaskStateStore()
        self.fabric = FabricStore()
        self.state_path = self.run_root / "slot_controller_state.json"
        self.dashboard_path = self.run_root / "slot_controller_dashboard.json"
        self.summary_path = self.run_root / "slot_controller_summary.json"
        self.fabric_snapshot_path = self.run_root / "fabric_snapshot.json"
        self.project_specs = [
            SlotSpec.from_payload(item, self.slot_duration_seconds)
            for item in (config.get("projects") or [])
        ]
        self.running: dict[str, RunningCampaign] = {}
        self.prepared_launches: dict[str, PreparedLaunch] = {}
        self.async_teardowns: dict[str, AsyncTeardown] = {}
        self.completed_campaigns: list[dict[str, Any]] = []
        self.project_state: dict[str, dict[str, Any]] = {
            spec.label: {
                "label": spec.label,
                "lane": spec.lane,
                "project": spec.project,
                "base_task_id": spec.base_task_id,
                "current_base_task_id": spec.base_task_id,
                "launch_count": 0,
                "continuation_count": 0,
                "replacement_count": 0,
                "campaign_task_ids": [],
                "idle_gap_seconds": 0.0,
                "idle_started_at": _iso(self.started_at),
                "active_seconds": 0.0,
                "last_exit_at": None,
                "last_start_at": None,
                "last_status": "pending",
                "last_completed_reason": None,
                "last_resolution_kind": None,
                "last_claimed_work_item_id": None,
                "last_claim_token": None,
                "last_continuation_work_item_id": None,
                "claim_history": [],
                "completed_reason_history": [],
                "normal_completion_count": 0,
                "abnormal_exit_count": 0,
                "warmup_prepared_count": 0,
                "warmup_utilized_count": 0,
                "warmup_discarded_count": 0,
                "last_warmup_prepared_at": None,
                "last_warmup_task_id": None,
                "last_warmup_source_campaign_task_id": None,
                "last_switch_latency_seconds": None,
                "slot_switch_latency_count": 0,
                "slot_switch_latency_seconds_total": 0.0,
                "slot_switch_latency_history": [],
            }
            for spec in self.project_specs
        }

    def _update_manifest(self, path: Path, updates: dict[str, Any]) -> None:
        payload = _read_json(path, {})
        payload.update(updates)
        _write_json(path, payload)

    def _activate_slot_window(self) -> None:
        self.started_at = _now()
        self.deadline_at = self.started_at.timestamp() + self.slot_duration_seconds
        activated_at = _iso(self.started_at)
        deadline_at = self._deadline_iso()
        for label, campaign in self.running.items():
            self.task_store.update_runtime(
                campaign.task_id,
                {
                    "slot_controller_started_at": activated_at,
                    "slot_controller_deadline_at": deadline_at,
                },
            )
            launch_manifest = _read_json(campaign.launch_manifest_path, {})
            if launch_manifest:
                launch_manifest["slot_started_at"] = activated_at
                launch_manifest["slot_deadline_at"] = deadline_at
                launch_manifest["prestart_phase_completed_at"] = activated_at
                _write_json(campaign.launch_manifest_path, launch_manifest)
        for state in self.project_state.values():
            state["idle_gap_seconds"] = 0.0
            state["idle_started_at"] = None
            state["last_switch_latency_seconds"] = None
            state["slot_switch_latency_count"] = 0
            state["slot_switch_latency_seconds_total"] = 0.0
            state["slot_switch_latency_history"] = []

    def _remaining_seconds(self) -> int:
        return max(0, int(self.deadline_at - _now().timestamp()))

    def _min_continuation_seconds_for_spec(self, spec: SlotSpec) -> int:
        if spec.lane == "binary" or spec.target_mode == "binary":
            return max(self.min_continuation_seconds, self.binary_min_continuation_seconds)
        return self.min_continuation_seconds

    def _deadline_iso(self) -> str:
        return datetime.fromtimestamp(self.deadline_at, timezone.utc).isoformat()

    def _claim_filters(self, spec: SlotSpec) -> dict[str, Any]:
        return {
            "lanes": [spec.lane],
            "projects": [spec.project],
            "benchmarks": [spec.label],
            "namespaces": [self.fabric_namespace],
        }

    def _bootstrap_fabric(self) -> None:
        bootstrap_manifest = {
            "generated_at": _iso(),
            "fabric_namespace": self.fabric_namespace,
            "slots": [],
        }
        for spec in self.project_specs:
            slot_record = self.fabric.register_slot(
                slot_id=spec.label,
                label=spec.label,
                lane=spec.lane,
                project=spec.project,
                namespace=self.fabric_namespace,
                claim_filters=self._claim_filters(spec),
            )
            item = self.fabric.enqueue_work_item(
                lane=spec.lane,
                target_mode=spec.target_mode,
                project=spec.project,
                benchmark=spec.label,
                namespace=self.fabric_namespace,
                slot_label=spec.label,
                base_task_id=spec.base_task_id,
                donor_task_id=spec.base_task_id,
                priority=spec.priority,
                dedupe_key=f"{self.fabric_namespace}::{spec.label}::seed",
                metadata={
                    **spec.metadata,
                    "slot_controller_label": spec.label,
                    "slot_controller_run_root": str(self.run_root),
                    "campaign_lane": spec.lane,
                    "fabric_namespace": self.fabric_namespace,
                },
            )
            bootstrap_manifest["slots"].append(
                {
                    "slot_id": spec.label,
                    "slot_record": slot_record,
                    "seed_work_item_id": item.get("work_item_id"),
                }
            )
        _write_json(self.run_root / "fabric_bootstrap_manifest.json", bootstrap_manifest)

    def _campaign_metadata(
        self,
        spec: SlotSpec,
        work_item: dict[str, Any],
        child_duration: int,
        *,
        round_seconds: int,
    ) -> dict[str, Any]:
        base_task_id = str(work_item.get("base_task_id") or spec.base_task_id)
        metadata = {
            **spec.metadata,
            **dict(work_item.get("metadata") or {}),
            "benchmark": str(work_item.get("benchmark") or spec.label),
            "project": str(work_item.get("project") or spec.project),
            "base_task_id": base_task_id,
            "target_mode": str(work_item.get("target_mode") or spec.target_mode),
            "campaign_duration_seconds": child_duration,
            "campaign_enable_seed_tasks": True,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": int(round_seconds),
            "slot_controller_round_seconds": int(round_seconds),
            "slot_controller_child_campaign_duration_seconds": int(child_duration),
            "SEED_GENERATION_BACKEND": spec.metadata.get("SEED_GENERATION_BACKEND", "llm"),
            "task_partition": spec.metadata.get("task_partition", "official_main"),
            "ENABLE_PATCH_ATTEMPT": False,
            "PATCH_DISABLED": True,
            "slot_controller_label": spec.label,
            "campaign_lane": str(work_item.get("lane") or spec.lane),
            "fabric_lane": str(work_item.get("lane") or spec.lane),
            "fabric_namespace": self.fabric_namespace,
        }
        if metadata.get("campaign_lane") == "generalized":
            metadata["generalized_source"] = True
        if spec.target_mode == "binary":
            base_payload = _read_json(task_json_path(base_task_id), {})
            base_metadata = base_payload.get("metadata") or {}
            base_runtime = base_payload.get("runtime") or {}
            for key in (
                "binary_mode",
                "binary_provenance",
                "binary_input_contract",
                "binary_input_contract_source",
                "binary_target_name",
            ):
                if key not in metadata and (base_metadata.get(key) or base_runtime.get(key)):
                    metadata[key] = base_metadata.get(key) or base_runtime.get(key)
        return metadata

    def _create_campaign_task(
        self,
        spec: SlotSpec,
        work_item: dict[str, Any],
        *,
        child_duration: int,
        round_seconds: int,
        continuation_index: int,
    ) -> str:
        adapter = AdapterType.BINARY if spec.target_mode == "binary" or spec.adapter_type == "binary" else AdapterType.OSSFUZZ
        work_item_ref = str(work_item.get("work_item_id") or f"warmup-{spec.label}")
        record = self.task_store.create_task(
            TaskSpec(
                source=TaskSource(
                    adapter_type=adapter,
                    uri=f"fabric://{spec.label}",
                    ref=f"work-item-{work_item_ref}",
                ),
                execution_mode=ExecutionMode.HYBRID,
                metadata=self._campaign_metadata(
                    spec,
                    work_item,
                    child_duration,
                    round_seconds=round_seconds,
                ),
            ),
            status=TaskStatus.CAMPAIGN_QUEUED,
        )
        self.task_store.update_runtime(
            record.task_id,
            {
                "campaign_duration_seconds": child_duration,
                "slot_controller_label": spec.label,
                "slot_controller_run_root": str(self.run_root),
                "slot_controller_started_at": _iso(self.started_at),
                "slot_controller_deadline_at": self._deadline_iso(),
                "slot_controller_continuation_index": continuation_index,
                "fabric_namespace": self.fabric_namespace,
                "fabric_work_item_id": work_item.get("work_item_id"),
                "fabric_claim_token": work_item.get("claim_token"),
                "fabric_slot_id": spec.label,
                "fabric_lane": work_item.get("lane") or spec.lane,
                "campaign_lane": work_item.get("lane") or spec.lane,
                "fabric_priority": int(work_item.get("priority") or spec.priority),
                "fabric_state_path": str(fabric_state_path()),
                "fabric_events_path": str(fabric_events_path()),
                "generalized_source": bool((work_item.get("lane") or spec.lane) == "generalized"),
                "slot_controller_round_seconds": int(round_seconds),
                "slot_controller_child_campaign_duration_seconds": int(child_duration),
                "slot_controller_warmup_prepared": bool(work_item.get("_warmup_prepared")),
            },
        )
        return record.task_id

    def _update_campaign_task_for_launch(
        self,
        *,
        task_id: str,
        spec: SlotSpec,
        work_item: dict[str, Any],
        child_duration: int,
        round_seconds: int,
        continuation_index: int,
    ) -> None:
        metadata_patch = self._campaign_metadata(
            spec,
            work_item,
            child_duration,
            round_seconds=round_seconds,
        )
        self.task_store.update_task(
            task_id,
            status=TaskStatus.CAMPAIGN_QUEUED,
            metadata=metadata_patch,
            runtime={
                "campaign_duration_seconds": child_duration,
                "slot_controller_label": spec.label,
                "slot_controller_run_root": str(self.run_root),
                "slot_controller_started_at": _iso(self.started_at),
                "slot_controller_deadline_at": self._deadline_iso(),
                "slot_controller_continuation_index": continuation_index,
                "fabric_namespace": self.fabric_namespace,
                "fabric_work_item_id": work_item.get("work_item_id"),
                "fabric_claim_token": work_item.get("claim_token"),
                "fabric_slot_id": spec.label,
                "fabric_lane": work_item.get("lane") or spec.lane,
                "campaign_lane": work_item.get("lane") or spec.lane,
                "fabric_priority": int(work_item.get("priority") or spec.priority),
                "fabric_state_path": str(fabric_state_path()),
                "fabric_events_path": str(fabric_events_path()),
                "generalized_source": bool((work_item.get("lane") or spec.lane) == "generalized"),
                "slot_controller_round_seconds": int(round_seconds),
                "slot_controller_child_campaign_duration_seconds": int(child_duration),
                "slot_controller_warmup_prepared": False,
                "slot_controller_warmup_prepared_at": None,
            },
        )

    def _consume_idle_gap_on_launch(
        self,
        label: str,
        started_at: str,
        *,
        launch_sequence: int,
        launch_kind: str | None,
        warmup_utilized: bool,
    ) -> float | None:
        project = self.project_state[label]
        exit_at = _parse_iso(project.get("idle_started_at"))
        start_dt = _parse_iso(started_at)
        if exit_at is None or start_dt is None:
            project["idle_started_at"] = None
            return None
        latency_seconds = max(0.0, (start_dt - exit_at).total_seconds())
        project["idle_gap_seconds"] = round(float(project.get("idle_gap_seconds") or 0.0) + latency_seconds, 3)
        project["last_switch_latency_seconds"] = round(latency_seconds, 3)
        project["slot_switch_latency_count"] = int(project.get("slot_switch_latency_count") or 0) + 1
        project["slot_switch_latency_seconds_total"] = round(
            float(project.get("slot_switch_latency_seconds_total") or 0.0) + latency_seconds,
            3,
        )
        project.setdefault("slot_switch_latency_history", []).append(
            {
                "launch_sequence": int(launch_sequence),
                "launch_kind": launch_kind,
                "started_at": started_at,
                "switch_latency_seconds": round(latency_seconds, 3),
                "warmup_utilized": bool(warmup_utilized),
            }
        )
        project["slot_switch_latency_history"] = list(project.get("slot_switch_latency_history") or [])[-128:]
        project["idle_started_at"] = None
        return round(latency_seconds, 3)

    def _effective_idle_gap_seconds(self, label: str, *, now: datetime | None = None) -> float:
        project = self.project_state[label]
        idle_gap = float(project.get("idle_gap_seconds") or 0.0)
        idle_started_at = _parse_iso(project.get("idle_started_at"))
        if idle_started_at is None:
            return round(idle_gap, 3)
        current = now or _now()
        idle_gap += max(0.0, (current - idle_started_at).total_seconds())
        return round(idle_gap, 3)

    def _enqueue_slot_replacement(self, spec: SlotSpec) -> dict[str, Any] | None:
        project = self.project_state[spec.label]
        base_task_id = str(project.get("current_base_task_id") or spec.base_task_id)
        fabric_state = self.fabric.snapshot(namespace=self.fabric_namespace).get("state") or {}
        slot_state = dict((fabric_state.get("slots") or {}).get(spec.label) or {})
        if slot_state.get("current_work_item_id") or slot_state.get("current_campaign_task_id"):
            return None
        return self.fabric.enqueue_work_item(
            lane=spec.lane,
            target_mode=spec.target_mode,
            project=spec.project,
            benchmark=spec.label,
            namespace=self.fabric_namespace,
            slot_label=spec.label,
            base_task_id=base_task_id,
            donor_task_id=base_task_id,
            priority=spec.priority,
            dedupe_key=f"{self.fabric_namespace}::{spec.label}::replacement::{base_task_id}",
            metadata={
                **spec.metadata,
                "slot_controller_label": spec.label,
                "slot_controller_run_root": str(self.run_root),
                "campaign_lane": spec.lane,
                "fabric_namespace": self.fabric_namespace,
                "replacement_reason": "slot_empty_replacement",
                "slot_replacement_reason": "slot_empty_replacement",
            },
        )

    def _campaign_remaining_seconds(self, campaign: RunningCampaign) -> int:
        started_at = _parse_iso(campaign.started_at)
        if started_at is None:
            return 0
        elapsed = max(0.0, (_now() - started_at).total_seconds())
        return max(0, int(campaign.child_duration_seconds - elapsed))

    def _prepare_warmup_launch(self, spec: SlotSpec, campaign: RunningCampaign) -> None:
        if spec.label in self.prepared_launches:
            return
        min_continuation_seconds = self._min_continuation_seconds_for_spec(spec)
        if self._remaining_seconds() < min_continuation_seconds:
            return
        campaign_remaining = self._campaign_remaining_seconds(campaign)
        if campaign_remaining > self.warmup_seconds:
            return
        projected_remaining = max(min_continuation_seconds, self._remaining_seconds() - max(campaign_remaining, 0))
        launch_plan = derive_child_launch_plan(
            remaining_seconds=projected_remaining,
            child_campaign_duration_seconds=spec.child_campaign_duration_seconds,
            round_seconds=spec.round_seconds,
            min_continuation_seconds=min_continuation_seconds,
        )
        if not launch_plan:
            return
        predicted_base_task_id = _latest_donor_from_campaign(campaign.task_id, campaign.base_task_id)
        predicted_launch_sequence = int(self.project_state[spec.label].get("launch_count") or 0) + 1
        predicted_continuation_index = int(self.project_state[spec.label].get("continuation_count") or 0) + 1
        warmup_work_item = {
            "benchmark": spec.label,
            "project": spec.project,
            "target_mode": spec.target_mode,
            "lane": spec.lane,
            "base_task_id": predicted_base_task_id,
            "metadata": {
                **spec.metadata,
                "slot_controller_label": spec.label,
                "slot_controller_run_root": str(self.run_root),
                "campaign_lane": spec.lane,
                "fabric_namespace": self.fabric_namespace,
                "slot_controller_warmup": True,
            },
            "_warmup_prepared": True,
        }
        task_id = self._create_campaign_task(
            spec,
            warmup_work_item,
            child_duration=int(launch_plan["child_campaign_duration_seconds"]),
            round_seconds=int(launch_plan["round_seconds"]),
            continuation_index=predicted_continuation_index,
        )
        prepared_at = _iso()
        project_dir = self.run_root / spec.label / f"continuation_{predicted_launch_sequence:03d}"
        project_dir.mkdir(parents=True, exist_ok=True)
        log_path = project_dir / "stdout.log"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.repo_root)
        env["DATA_ROOT"] = str(self.data_root)
        env["CAMPAIGN_TASK_ID"] = task_id
        env["CAMPAIGN_POLL_SECONDS"] = str(self.config.get("campaign_poll_seconds", 5))
        env["PYTHONUNBUFFERED"] = "1"
        cmd = [self.python_bin, "-m", "apps.workers.campaign.main"]
        log_handle = log_path.open("a", encoding="utf-8", buffering=1)
        process = subprocess.Popen(
            cmd,
            cwd=str(self.repo_root),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            text=True,
        )
        prelaunched_at = _iso()
        launch_manifest_path = project_dir / "launch_manifest.json"
        self.task_store.update_runtime(
            task_id,
            {
                "campaign_started_at": None,
                "campaign_deadline_at": None,
                "slot_controller_warmup_prepared": True,
                "slot_controller_warmup_hold": True,
                "slot_controller_warmup_state": "prepared",
                "slot_controller_warmup_prepared_at": prepared_at,
                "slot_controller_warmup_for_task_id": campaign.task_id,
            },
        )
        _write_json(
            launch_manifest_path,
            {
                "label": spec.label,
                "project": spec.project,
                "lane": spec.lane,
                "target_mode": spec.target_mode,
                "task_id": task_id,
                "launch_sequence": predicted_launch_sequence,
                "continuation_index": predicted_continuation_index,
                "warmup_prepared": True,
                "warmup_utilized": False,
                "prepared_at": prepared_at,
                "prelaunched_at": prelaunched_at,
                "source_campaign_task_id": campaign.task_id,
                "predicted_base_task_id": predicted_base_task_id,
                "planned_child_campaign_duration_seconds": int(launch_plan["child_campaign_duration_seconds"]),
                "effective_round_seconds": int(launch_plan["round_seconds"]),
                "slot_deadline_at": self._deadline_iso(),
                "pid": process.pid,
                "command": cmd,
                "cwd": str(self.repo_root),
                "log_path": str(log_path),
                "fabric_namespace": self.fabric_namespace,
                "env": _redact_env(
                    {
                        key: env.get(key, "")
                        for key in (
                            "PYTHONPATH",
                            "DATA_ROOT",
                            "CAMPAIGN_TASK_ID",
                            "CAMPAIGN_POLL_SECONDS",
                            "PYTHONUNBUFFERED",
                            "DEEPSEEK_BASE_URL",
                            "OPENAI_BASE_URL",
                            "DEEPSEEK_API_KEY",
                            "OPENAI_API_KEY",
                            "SEED_GENERATION_BACKEND",
                        )
                    }
                ),
            },
        )
        self.prepared_launches[spec.label] = PreparedLaunch(
            spec=spec,
            task_id=task_id,
            prepared_at=prepared_at,
            prelaunched_at=prelaunched_at,
            source_campaign_task_id=campaign.task_id,
            predicted_base_task_id=predicted_base_task_id,
            child_duration_seconds=int(launch_plan["child_campaign_duration_seconds"]),
            round_seconds=int(launch_plan["round_seconds"]),
            expected_launch_sequence=predicted_launch_sequence,
            predicted_continuation_index=predicted_continuation_index,
            process=process,
            log_path=log_path,
            log_handle=log_handle,
            launch_manifest_path=launch_manifest_path,
        )
        project = self.project_state[spec.label]
        project["warmup_prepared_count"] = int(project.get("warmup_prepared_count") or 0) + 1
        project["last_warmup_prepared_at"] = prepared_at
        project["last_warmup_task_id"] = task_id
        project["last_warmup_source_campaign_task_id"] = campaign.task_id

    def _discard_prepared_launch(self, label: str) -> None:
        prepared = self.prepared_launches.pop(label, None)
        if not prepared:
            return
        try:
            if prepared.process.poll() is None:
                os.killpg(prepared.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            prepared.log_handle.close()
        except Exception:
            pass
        self.project_state[label]["warmup_discarded_count"] = int(
            self.project_state[label].get("warmup_discarded_count") or 0
        ) + 1
        self.task_store.update_runtime(
            prepared.task_id,
            {
                "slot_controller_warmup_prepared": False,
                "slot_controller_warmup_discarded_at": _iso(),
            },
        )

    def _start_async_teardown(self, label: str, campaign: RunningCampaign, *, released_at: str) -> None:
        timeout_seconds = max(1, int(self.async_teardown_timeout_seconds))
        self._update_manifest(
            campaign.launch_manifest_path,
            {
                "async_teardown": True,
                "async_teardown_started_at": released_at,
                "async_teardown_timeout_seconds": timeout_seconds,
            },
        )

        def _background_teardown() -> None:
            completed_at = _iso()
            return_code = campaign.process.poll()
            timed_out = False
            forced_signal = None
            try:
                if return_code is None:
                    try:
                        return_code = campaign.process.wait(timeout=timeout_seconds)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        forced_signal = "SIGKILL"
                        try:
                            os.killpg(campaign.process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            return_code = campaign.process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            return_code = campaign.process.poll()
                completed_at = _iso()
            finally:
                try:
                    campaign.log_handle.flush()
                except Exception:
                    pass
                try:
                    campaign.log_handle.close()
                except Exception:
                    pass
                self._update_manifest(
                    campaign.launch_manifest_path,
                    {
                        "async_teardown_completed_at": completed_at,
                        "async_teardown_return_code": return_code,
                        "async_teardown_timed_out": timed_out,
                        "async_teardown_forced_signal": forced_signal,
                    },
                )
                self.async_teardowns.pop(label, None)

        worker = threading.Thread(
            target=_background_teardown,
            name=f"slot-teardown-{label}",
            daemon=True,
        )
        self.async_teardowns[label] = AsyncTeardown(
            label=label,
            campaign_task_id=campaign.task_id,
            launch_manifest_path=campaign.launch_manifest_path,
            started_at=released_at,
            timeout_seconds=timeout_seconds,
            thread=worker,
        )
        worker.start()

    def _try_manifest_safe_handoff(self, label: str, campaign: RunningCampaign) -> bool:
        if campaign.process.poll() is not None:
            return False
        snapshot = _task_snapshot(campaign.task_id)
        resolution_policy = derive_campaign_exit_resolution(snapshot, return_code=None)
        manifest_safe = resolution_policy.get("kind") == "complete" and bool(
            snapshot.get("campaign_manifest_path")
            and (snapshot.get("campaign_finished_at") or snapshot.get("campaign_completed_reason"))
        )
        if not manifest_safe:
            return False
        released_at = _iso()
        next_base = _latest_donor_from_campaign(campaign.task_id, campaign.base_task_id)
        project = self.project_state[label]
        project["current_base_task_id"] = next_base
        project["last_exit_at"] = released_at
        project["last_status"] = str(snapshot.get("status") or snapshot.get("campaign_lifecycle_state") or "manifest_safe_handoff")
        project["last_completed_reason"] = resolution_policy.get("reason")
        project["last_resolution_kind"] = resolution_policy.get("kind")
        try:
            start_dt = datetime.fromisoformat(str(campaign.started_at))
            release_dt = datetime.fromisoformat(released_at)
            project["active_seconds"] = float(project.get("active_seconds") or 0.0) + max(
                0.0, (release_dt - start_dt).total_seconds()
            )
        except ValueError:
            project["active_seconds"] = float(project.get("active_seconds") or 0.0)
        project["normal_completion_count"] = int(project.get("normal_completion_count") or 0) + 1
        completed = {
            "label": label,
            "lane": campaign.spec.lane,
            "project": campaign.spec.project,
            "task_id": campaign.task_id,
            "base_task_id": campaign.base_task_id,
            "next_base_task_id": next_base,
            "launch_sequence": campaign.launch_sequence,
            "continuation_index": campaign.continuation_index,
            "work_item_id": campaign.work_item_id,
            "claim_token": campaign.claim_token,
            "started_at": campaign.started_at,
            "exited_at": released_at,
            "return_code": None,
            "log_path": str(campaign.log_path),
            "launch_manifest_path": str(campaign.launch_manifest_path),
            "completed_reason": resolution_policy.get("reason"),
            "resolution_kind": resolution_policy.get("kind"),
            "manifest_safe_handoff": True,
            "process_alive_at_handoff": True,
            "snapshot": snapshot,
        }
        completed["fabric_resolution"] = complete_campaign(
            campaign_task_id=campaign.task_id,
            completed_reason=str(resolution_policy.get("reason") or "campaign_completed"),
            next_base_task_id=next_base,
            remaining_seconds=self._remaining_seconds(),
            min_continuation_seconds=self.min_continuation_seconds,
        )
        resolution = dict(completed.get("fabric_resolution") or {})
        project["last_continuation_work_item_id"] = resolution.get("fabric_continuation_work_item_id")
        project.setdefault("completed_reason_history", []).append(
            {
                "campaign_task_id": campaign.task_id,
                "exited_at": released_at,
                "return_code": None,
                "resolution_kind": resolution_policy.get("kind"),
                "completed_reason": resolution_policy.get("reason"),
                "next_base_task_id": next_base,
                "continuation_work_item_id": project.get("last_continuation_work_item_id"),
                "manifest_safe_handoff": True,
            }
        )
        project["completed_reason_history"] = list(project.get("completed_reason_history") or [])[-128:]
        if self._remaining_seconds() > 0:
            project["idle_started_at"] = released_at
        self.completed_campaigns.append(completed)
        _write_json(campaign.launch_manifest_path.parent / "exit_snapshot.json", completed)
        self._update_manifest(
            campaign.launch_manifest_path,
            {
                "handoff_release_at": released_at,
                "handoff_release_kind": "manifest_safe_async_teardown",
                "handoff_release_reason": resolution_policy.get("reason"),
                "process_alive_at_handoff": True,
            },
        )
        self.running.pop(label, None)
        self._start_async_teardown(label, campaign, released_at=released_at)
        return True

    def _launch_campaign(self, spec: SlotSpec) -> None:
        remaining = self._remaining_seconds()
        min_continuation_seconds = self._min_continuation_seconds_for_spec(spec)
        launch_plan = derive_child_launch_plan(
            remaining_seconds=remaining,
            child_campaign_duration_seconds=spec.child_campaign_duration_seconds,
            round_seconds=spec.round_seconds,
            min_continuation_seconds=min_continuation_seconds,
        )
        if not launch_plan:
            self._discard_prepared_launch(spec.label)
            return
        child_duration = int(launch_plan["child_campaign_duration_seconds"])
        round_seconds = int(launch_plan["round_seconds"])
        work_item = self.fabric.claim_next_work_item(
            slot_id=spec.label,
            lease_seconds=max(self.fabric_lease_seconds, child_duration + 120),
        )
        if not work_item:
            self._enqueue_slot_replacement(spec)
            work_item = self.fabric.claim_next_work_item(
                slot_id=spec.label,
                lease_seconds=max(self.fabric_lease_seconds, child_duration + 120),
            )
        if not work_item:
            self.fabric.heartbeat_slot(slot_id=spec.label, status="idle")
            self.project_state[spec.label]["idle_started_at"] = self.project_state[spec.label].get("idle_started_at") or _iso()
            return
        launch_policy = classify_claimed_work_item(work_item)
        continuation_index = int(launch_policy.get("continuation_index") or 0)
        prepared = self.prepared_launches.pop(spec.label, None)
        warmup_utilized = prepared is not None and prepared.process.poll() is None
        if prepared is not None and prepared.process.poll() is None:
            task_id = prepared.task_id
            self._update_campaign_task_for_launch(
                task_id=task_id,
                spec=spec,
                work_item=work_item,
                child_duration=child_duration,
                round_seconds=round_seconds,
                continuation_index=continuation_index,
            )
            process = prepared.process
            log_path = prepared.log_path
            log_handle = prepared.log_handle
            launch_manifest_path = prepared.launch_manifest_path
            project_dir = launch_manifest_path.parent
        else:
            if prepared is not None:
                try:
                    prepared.log_handle.close()
                except Exception:
                    pass
            task_id = self._create_campaign_task(
                spec,
                work_item,
                child_duration=child_duration,
                round_seconds=round_seconds,
                continuation_index=continuation_index,
            )
            project = self.project_state[spec.label]
            launch_sequence = int(project.get("launch_count") or 0) + 1
            project_dir = self.run_root / spec.label / f"continuation_{launch_sequence:03d}"
            project_dir.mkdir(parents=True, exist_ok=True)
            log_path = project_dir / "stdout.log"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.repo_root)
            env["DATA_ROOT"] = str(self.data_root)
            env["CAMPAIGN_TASK_ID"] = task_id
            env["CAMPAIGN_POLL_SECONDS"] = str(self.config.get("campaign_poll_seconds", 5))
            env["PYTHONUNBUFFERED"] = "1"
            cmd = [self.python_bin, "-m", "apps.workers.campaign.main"]
            log_handle = log_path.open("a", encoding="utf-8", buffering=1)
            process = subprocess.Popen(
                cmd,
                cwd=str(self.repo_root),
                env=env,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                text=True,
            )
            launch_manifest_path = project_dir / "launch_manifest.json"
        base_task_id = str(work_item.get("base_task_id") or spec.base_task_id)
        donor_task_id = str(work_item.get("donor_task_id") or base_task_id)
        self.fabric.bind_claim_to_campaign(
            work_item_id=str(work_item.get("work_item_id") or ""),
            claim_token=str(work_item.get("claim_token") or ""),
            slot_id=spec.label,
            campaign_task_id=task_id,
            base_task_id=base_task_id,
            donor_task_id=donor_task_id,
            metadata={
                "slot_controller_run_root": str(self.run_root),
                "slot_controller_label": spec.label,
            },
        )
        register_campaign(
            campaign_task_id=task_id,
            benchmark=str(work_item.get("benchmark") or spec.label),
            target_mode=str(work_item.get("target_mode") or spec.target_mode),
            base_task_id=base_task_id,
            deadline_at=self._deadline_iso(),
            slot_label=spec.label,
        )
        if warmup_utilized:
            self.task_store.update_runtime(
                task_id,
                {
                    "slot_controller_warmup_hold": False,
                    "slot_controller_warmup_state": "released",
                    "slot_controller_warmup_released_at": _iso(),
                },
            )
        project = self.project_state[spec.label]
        launch_sequence = int(project.get("launch_count") or 0) + 1
        started_at = _iso()
        launch_manifest = {
            "label": spec.label,
            "project": spec.project,
            "lane": spec.lane,
            "target_mode": spec.target_mode,
            "base_task_id": base_task_id,
            "donor_task_id": donor_task_id,
            "task_id": task_id,
            "launch_sequence": launch_sequence,
            "continuation_index": continuation_index,
            "started_at": started_at,
            "planned_child_campaign_duration_seconds": child_duration,
            "effective_round_seconds": round_seconds,
            "slot_deadline_at": self._deadline_iso(),
            "pid": process.pid,
            "command": [self.python_bin, "-m", "apps.workers.campaign.main"],
            "cwd": str(self.repo_root),
            "log_path": str(log_path),
            "fabric_namespace": self.fabric_namespace,
            "fabric_work_item_id": work_item.get("work_item_id"),
            "fabric_claim_token": work_item.get("claim_token"),
            "launch_kind": launch_policy.get("kind"),
            "requested_reason": launch_policy.get("requested_reason"),
            "retry_of_work_item_id": launch_policy.get("retry_of_work_item_id"),
            "source_status": launch_policy.get("source_status"),
            "replacement_reason": launch_policy.get("replacement_reason"),
            "fabric_state_path": str(fabric_state_path()),
            "fabric_events_path": str(fabric_events_path()),
            "warmup_prepared": warmup_utilized or prepared is not None,
            "warmup_prepared_at": prepared.prepared_at if prepared is not None else None,
            "warmup_process_started_at": prepared.prelaunched_at if prepared is not None else None,
        }
        switch_latency_seconds = self._consume_idle_gap_on_launch(
            spec.label,
            started_at,
            launch_sequence=launch_sequence,
            launch_kind=str(launch_policy.get("kind") or ""),
            warmup_utilized=warmup_utilized,
        )
        launch_manifest["warmup_utilized"] = warmup_utilized
        launch_manifest["switch_latency_seconds"] = switch_latency_seconds
        launch_manifest["prepared_task_id"] = prepared.task_id if prepared is not None else None
        _write_json(launch_manifest_path, launch_manifest)
        project["launch_count"] = launch_sequence
        if launch_policy.get("kind") == "continuation":
            project["continuation_count"] = int(project.get("continuation_count") or 0) + 1
        elif launch_policy.get("kind") == "replacement":
            project["replacement_count"] = int(project.get("replacement_count") or 0) + 1
        if warmup_utilized:
            project["warmup_utilized_count"] = int(project.get("warmup_utilized_count") or 0) + 1
        project["campaign_task_ids"].append(task_id)
        project["last_start_at"] = started_at
        project["last_status"] = "running"
        project["last_claimed_work_item_id"] = work_item.get("work_item_id")
        project["last_claim_token"] = work_item.get("claim_token")
        project.setdefault("claim_history", []).append(
            {
                "launched_at": started_at,
                "launch_sequence": launch_sequence,
                "launch_kind": launch_policy.get("kind"),
                "continuation_index": continuation_index,
                "requested_reason": launch_policy.get("requested_reason"),
                "retry_of_work_item_id": launch_policy.get("retry_of_work_item_id"),
                "replacement_reason": launch_policy.get("replacement_reason"),
                "source_status": launch_policy.get("source_status"),
                "warmup_utilized": warmup_utilized,
                "switch_latency_seconds": switch_latency_seconds,
                "work_item_id": work_item.get("work_item_id"),
                "claim_token": work_item.get("claim_token"),
                "campaign_task_id": task_id,
                "base_task_id": base_task_id,
                "donor_task_id": donor_task_id,
            }
        )
        project["claim_history"] = list(project.get("claim_history") or [])[-128:]
        self.running[spec.label] = RunningCampaign(
            spec=spec,
            launch_sequence=launch_sequence,
            continuation_index=continuation_index,
            task_id=task_id,
            base_task_id=base_task_id,
            work_item_id=str(work_item.get("work_item_id") or ""),
            claim_token=str(work_item.get("claim_token") or ""),
            slot_id=spec.label,
            process=process,
            log_path=log_path,
            log_handle=log_handle,
            launch_manifest_path=launch_manifest_path,
            started_at=started_at,
            child_duration_seconds=child_duration,
            round_seconds=round_seconds,
        )
        self.fabric.heartbeat_slot(
            slot_id=spec.label,
            status="running",
            current_work_item_id=str(work_item.get("work_item_id") or ""),
            current_campaign_task_id=task_id,
        )
        heartbeat_campaign(
            campaign_task_id=task_id,
            status="launched_by_slot_controller",
            round_count=0,
            metrics={
                "slot_controller_label": spec.label,
                "continuation_index": continuation_index,
                "fabric_work_item_id": work_item.get("work_item_id"),
                "warmup_utilized": warmup_utilized,
                "switch_latency_seconds": switch_latency_seconds,
            },
        )

    def _heartbeat_running_campaigns(self) -> None:
        for label, campaign in list(self.running.items()):
            snapshot = _task_snapshot(campaign.task_id)
            self.fabric.heartbeat_slot(
                slot_id=label,
                status="running",
                current_work_item_id=campaign.work_item_id,
                current_campaign_task_id=campaign.task_id,
            )
            self.fabric.heartbeat_by_campaign(
                campaign_task_id=campaign.task_id,
                status=str(snapshot.get("campaign_lifecycle_state") or snapshot.get("status") or "running"),
                round_count=int(snapshot.get("campaign_iterations_total") or 0),
                metrics={"heartbeat_source": "slot_controller", "slot_label": label},
                heartbeat_source="slot_controller",
            )

    def _handle_exit(self, label: str, campaign: RunningCampaign) -> None:
        exit_at = _iso()
        return_code = campaign.process.poll()
        snapshot = _task_snapshot(campaign.task_id)
        next_base = _latest_donor_from_campaign(campaign.task_id, campaign.base_task_id)
        resolution_policy = derive_campaign_exit_resolution(snapshot, return_code=return_code)
        project = self.project_state[label]
        project["current_base_task_id"] = next_base
        project["last_exit_at"] = exit_at
        project["last_status"] = snapshot.get("status") or f"process_exit_{return_code}"
        project["last_completed_reason"] = resolution_policy.get("reason")
        project["last_resolution_kind"] = resolution_policy.get("kind")
        try:
            start_dt = datetime.fromisoformat(str(campaign.started_at))
            exit_dt = datetime.fromisoformat(exit_at)
            project["active_seconds"] = float(project.get("active_seconds") or 0.0) + max(
                0.0, (exit_dt - start_dt).total_seconds()
            )
        except ValueError:
            project["active_seconds"] = float(project.get("active_seconds") or 0.0)
        completed = {
            "label": label,
            "lane": campaign.spec.lane,
            "project": campaign.spec.project,
            "task_id": campaign.task_id,
            "base_task_id": campaign.base_task_id,
            "next_base_task_id": next_base,
            "launch_sequence": campaign.launch_sequence,
            "continuation_index": campaign.continuation_index,
            "work_item_id": campaign.work_item_id,
            "claim_token": campaign.claim_token,
            "started_at": campaign.started_at,
            "exited_at": exit_at,
            "return_code": return_code,
            "log_path": str(campaign.log_path),
            "launch_manifest_path": str(campaign.launch_manifest_path),
            "completed_reason": resolution_policy.get("reason"),
            "resolution_kind": resolution_policy.get("kind"),
            "snapshot": snapshot,
        }
        success = resolution_policy.get("kind") == "complete"
        if success:
            project["normal_completion_count"] = int(project.get("normal_completion_count") or 0) + 1
            min_continuation_seconds = self._min_continuation_seconds_for_spec(campaign.spec)
            completed["fabric_resolution"] = complete_campaign(
                campaign_task_id=campaign.task_id,
                completed_reason=str(resolution_policy.get("reason") or "campaign_completed"),
                next_base_task_id=next_base,
                remaining_seconds=self._remaining_seconds(),
                min_continuation_seconds=min_continuation_seconds,
            )
        else:
            project["abnormal_exit_count"] = int(project.get("abnormal_exit_count") or 0) + 1
            min_continuation_seconds = self._min_continuation_seconds_for_spec(campaign.spec)
            completed["fabric_resolution"] = fail_campaign(
                campaign_task_id=campaign.task_id,
                failure_reason=str(resolution_policy.get("reason") or f"slot_controller_process_exit_{return_code}:unknown"),
                remaining_seconds=self._remaining_seconds(),
                next_base_task_id=next_base,
                requeue_on_failure=self._remaining_seconds() >= min_continuation_seconds,
                min_continuation_seconds=min_continuation_seconds,
            )
        resolution = dict(completed.get("fabric_resolution") or {})
        project["last_continuation_work_item_id"] = (
            resolution.get("fabric_continuation_work_item_id")
            or resolution.get("fabric_requeued_work_item_id")
        )
        project.setdefault("completed_reason_history", []).append(
            {
                "campaign_task_id": campaign.task_id,
                "exited_at": exit_at,
                "return_code": return_code,
                "resolution_kind": resolution_policy.get("kind"),
                "completed_reason": resolution_policy.get("reason"),
                "next_base_task_id": next_base,
                "continuation_work_item_id": project.get("last_continuation_work_item_id"),
            }
        )
        project["completed_reason_history"] = list(project.get("completed_reason_history") or [])[-128:]
        if self._remaining_seconds() > 0:
            project["idle_started_at"] = exit_at
        self.completed_campaigns.append(completed)
        _write_json(campaign.launch_manifest_path.parent / "exit_snapshot.json", completed)
        try:
            campaign.log_handle.close()
        except Exception:
            pass
        self.running.pop(label, None)

    def _snapshot(self) -> dict[str, Any]:
        running = {}
        for label, campaign in self.running.items():
            running[label] = {
                "pid": campaign.process.pid,
                "alive": campaign.process.poll() is None,
                "task_id": campaign.task_id,
                "work_item_id": campaign.work_item_id,
                "claim_token": campaign.claim_token,
                "log_path": str(campaign.log_path),
                "launch_manifest_path": str(campaign.launch_manifest_path),
                "snapshot": _task_snapshot(campaign.task_id),
            }
        now = _now()
        totals = {
            "llm_request_count_total": 0,
            "llm_success_count": 0,
            "llm_failure_count": 0,
            "fuzz_session_count": 0,
            "harness_switch_count": 0,
            "reseed_trigger_count": 0,
            "shared_corpus_growth_count": 0,
            "family_diversification_trigger_count": 0,
            "generalized_candidate_bridge_count": 0,
            "trace_worthy_candidate_count": 0,
            "trace_exact_signature_count": 0,
            "loose_cluster_count": 0,
            "confirmed_family_count": 0,
            "warmup_prepared_count": 0,
            "warmup_utilized_count": 0,
            "slot_switch_latency_count": 0,
            "slot_switch_latency_seconds_total": 0.0,
        }
        for item in self.completed_campaigns:
            snapshot = item.get("snapshot") or {}
            for key in totals:
                totals[key] += int(snapshot.get(key) or 0)
        for item in running.values():
            snapshot = item.get("snapshot") or {}
            for key in totals:
                totals[key] += int(snapshot.get(key) or 0)
        elapsed = max(1.0, (now - self.started_at).total_seconds())
        totals["api_calls_per_hour"] = round(totals["llm_request_count_total"] / (elapsed / 3600.0), 3)
        configured_window = max(1.0, self.deadline_at - self.started_at.timestamp())
        active_seconds = 0.0
        idle_gap_seconds = 0.0
        project_state_snapshot: dict[str, dict[str, Any]] = {}
        for label, state in self.project_state.items():
            state_snapshot = dict(state)
            project_active = float(state.get("active_seconds") or 0.0)
            effective_idle_gap = self._effective_idle_gap_seconds(label, now=now)
            idle_gap_seconds += effective_idle_gap
            running_item = self.running.get(label)
            if running_item and running_item.process.poll() is None:
                try:
                    start_dt = datetime.fromisoformat(str(running_item.started_at))
                    project_active += max(0.0, (now - start_dt).total_seconds())
                except ValueError:
                    project_active += min(elapsed, configured_window)
            active_seconds += min(project_active, configured_window)
            state_snapshot["idle_gap_seconds"] = effective_idle_gap
            state_snapshot["slot_started_at"] = _iso(self.started_at)
            state_snapshot["slot_deadline_at"] = self._deadline_iso()
            state_snapshot["slot_runtime_state_path"] = str(self.state_path)
            totals["warmup_prepared_count"] += int(state_snapshot.get("warmup_prepared_count") or 0)
            totals["warmup_utilized_count"] += int(state_snapshot.get("warmup_utilized_count") or 0)
            totals["slot_switch_latency_count"] += int(state_snapshot.get("slot_switch_latency_count") or 0)
            totals["slot_switch_latency_seconds_total"] += float(state_snapshot.get("slot_switch_latency_seconds_total") or 0.0)
            project_state_snapshot[label] = state_snapshot
        totals["wall_clock_utilization_ratio"] = round(
            min(1.0, active_seconds / (configured_window * max(len(self.project_specs), 1))),
            4,
        )
        totals["idle_gap_seconds"] = round(idle_gap_seconds, 3)
        totals["idle_gap_total_seconds"] = round(idle_gap_seconds, 3)
        totals["slot_switch_latency_seconds_avg"] = round(
            float(totals["slot_switch_latency_seconds_total"]) / max(int(totals["slot_switch_latency_count"]), 1),
            3,
        )
        fabric_snapshot = self.fabric.snapshot(namespace=self.fabric_namespace)
        state = fabric_snapshot.get("state") or {}
        fabric_summary = {
            "namespace": self.fabric_namespace,
            "state_path": fabric_snapshot.get("state_path"),
            "events_path": fabric_snapshot.get("events_path"),
            "pending_count": len((state.get("queues") or {}).get("pending") or []),
            "claimed_count": len((state.get("queues") or {}).get("claimed") or []),
            "completed_count": len((state.get("queues") or {}).get("completed") or []),
            "failed_count": len((state.get("queues") or {}).get("failed") or []),
            "requeue_count": len((state.get("queues") or {}).get("requeue") or []),
            "dead_count": len((state.get("queues") or {}).get("dead") or []),
            "slot_count": len(state.get("slots") or {}),
            "metrics": state.get("metrics") or {},
        }
        return {
            "generated_at": _iso(),
            "run_root": str(self.run_root),
            "slot_started_at": _iso(self.started_at),
            "slot_deadline_at": self._deadline_iso(),
            "remaining_seconds": self._remaining_seconds(),
            "fabric_namespace": self.fabric_namespace,
            "fabric_summary": fabric_summary,
            "project_state": project_state_snapshot,
            "prepared_launches": {
                label: {
                    "task_id": prepared.task_id,
                    "prepared_at": prepared.prepared_at,
                    "source_campaign_task_id": prepared.source_campaign_task_id,
                    "predicted_base_task_id": prepared.predicted_base_task_id,
                    "child_duration_seconds": prepared.child_duration_seconds,
                    "round_seconds": prepared.round_seconds,
                    "expected_launch_sequence": prepared.expected_launch_sequence,
                    "predicted_continuation_index": prepared.predicted_continuation_index,
                }
                for label, prepared in self.prepared_launches.items()
            },
            "running": running,
            "completed_campaigns": self.completed_campaigns,
            "totals": totals,
        }

    def _persist_state(self) -> None:
        payload = self._snapshot()
        _write_json(self.state_path, payload)
        _write_json(self.dashboard_path, payload)
        fabric_snapshot = self.fabric.snapshot(namespace=self.fabric_namespace)
        _write_json(self.fabric_snapshot_path, fabric_snapshot)
        heartbeat = self.run_root / "slot_controller_heartbeat.txt"
        heartbeat.write_text(f"{payload['generated_at']} remaining_seconds={payload['remaining_seconds']}\n", encoding="utf-8")

    def run(self) -> dict[str, Any]:
        self.run_root.mkdir(parents=True, exist_ok=True)
        self._bootstrap_fabric()
        for spec in self.project_specs:
            self._launch_campaign(spec)
        self._activate_slot_window()
        self._persist_state()
        try:
            while self._remaining_seconds() > 0:
                self.fabric.scavenge_expired_claims()
                for label, campaign in list(self.running.items()):
                    self._prepare_warmup_launch(campaign.spec, campaign)
                for label, campaign in list(self.running.items()):
                    if self._try_manifest_safe_handoff(label, campaign):
                        continue
                    if campaign.process.poll() is not None:
                        self._handle_exit(label, campaign)
                self._heartbeat_running_campaigns()
                for spec in self.project_specs:
                    if spec.label not in self.running:
                        self._launch_campaign(spec)
                self._persist_state()
                time.sleep(min(self.poll_seconds, max(1, self._remaining_seconds())))
        finally:
            for label in list(self.prepared_launches):
                self._discard_prepared_launch(label)
            for label, campaign in list(self.running.items()):
                if campaign.process.poll() is None:
                    try:
                        os.killpg(campaign.process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    deadline = time.time() + 20
                    while campaign.process.poll() is None and time.time() < deadline:
                        time.sleep(1)
                    if campaign.process.poll() is None:
                        try:
                            os.killpg(campaign.process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    self._handle_exit(label, campaign)
            self._persist_state()
            summary = self._snapshot()
            summary["finished_at"] = _iso()
            _write_json(self.summary_path, summary)
        return _read_json(self.summary_path, {})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run campaign slots until a wall-clock deadline.")
    parser.add_argument("--config", required=True, help="Path to slot controller JSON config.")
    args = parser.parse_args(argv)
    config_path = Path(args.config)
    config = _read_json(config_path, {})
    if not config:
        raise SystemExit(f"empty or unreadable slot controller config: {config_path}")
    controller = SlotController(config)
    summary = controller.run()
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

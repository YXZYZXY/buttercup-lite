from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Any

from core.campaign.budgeting import arbitrate_workloads
from core.campaign.deadline_loop import compute_deadline, now_utc, remaining_seconds, should_continue
from core.campaign.executor import execute_campaign_iteration
from core.campaign.manifest import write_campaign_manifest
from core.campaign.models import CampaignManifest, CampaignRound, filter_campaign_round_payload
from core.campaign.runtime_state import (
    apply_round_results_to_campaign,
    choose_next_session_plan,
    initialize_campaign_runtime_state,
    persist_campaign_runtime_state,
    write_campaign_runtime_artifacts,
)
from core.campaign.system_fabric import complete_campaign, heartbeat_campaign, register_campaign
from core.patch_priority import consume_patch_priority_manifest, consume_patch_reflection_manifest
from core.state.task_state import TaskStateStore
from core.storage.layout import campaign_checkpoint_path
from core.storage.layout import global_arbitration_manifest_path
from core.utils.settings import settings


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _campaign_duration_seconds(task_metadata: dict[str, Any], task_runtime: dict[str, Any]) -> int:
    raw = (
        task_runtime.get("campaign_duration_seconds")
        or task_metadata.get("campaign_duration_seconds")
        or task_metadata.get("campaign_duration")
    )
    if raw is not None:
        return int(raw)
    rounds = int(task_metadata.get("campaign_rounds", 1))
    fuzz_duration = int(task_metadata.get("FUZZ_MAX_TOTAL_TIME_SECONDS", 30))
    return max(rounds * fuzz_duration, fuzz_duration)


def _session_budget_target_seconds(*, lane: str, target_mode: str, configured_budget: int) -> int:
    if target_mode == "binary":
        return configured_budget
    lane_defaults = {
        "source": 90,
        "generalized": 105,
    }
    return max(60, min(configured_budget, lane_defaults.get(lane, 90)))


def _collect_signature_set(origin_task_ids: list[str], data_root: Path) -> set[str]:
    signatures: set[str] = set()
    for origin_task_id in origin_task_ids:
        trace_dir = data_root / origin_task_id / "trace" / "traced_crashes"
        if not trace_dir.exists():
            continue
        for traced_path in trace_dir.glob("*.json"):
            try:
                import json

                payload = json.loads(traced_path.read_text(encoding="utf-8"))
            except (FileNotFoundError, ValueError):
                continue
            signature = payload.get("signature")
            if signature:
                signatures.add(signature)
    return signatures


def _empty_campaign_reports() -> dict[str, Any]:
    return {
        "pov_inventory": {
            "distinct_signature_count": 0,
        },
        "vuln_coverage": {
            "found_vuln_count": 0,
            "found_vuln_ids": [],
            "missing_vuln_ids": [],
        },
        "pov_inventory_path": None,
        "vuln_coverage_path": None,
        "signature_index_path": None,
        "pov_lineage_path": None,
    }


def _build_offline_campaign_reports_if_requested(
    *,
    metadata: dict[str, Any],
    campaign_task_id: str,
    origin_task_ids: list[str],
    data_root: Path,
) -> dict[str, Any]:
    if not metadata.get("ENABLE_OFFLINE_CAMPAIGN_REPORTS"):
        return _empty_campaign_reports()
    ground_truth_path = metadata.get("ground_truth_path")
    if not ground_truth_path:
        return _empty_campaign_reports()
    from offline_eval.campaign_reports import build_offline_campaign_reports

    return build_offline_campaign_reports(
        campaign_task_id=campaign_task_id,
        origin_task_ids=origin_task_ids,
        ground_truth_path=ground_truth_path,
        data_root=data_root,
    )


def _load_task_payload(task_id: str, data_root: Path) -> dict[str, Any]:
    task_path = data_root / task_id / "task.json"
    if not task_path.exists():
        return {}
    import json

    return json.loads(task_path.read_text(encoding="utf-8"))


def _load_optional_json(path_str: str | None) -> dict[str, Any]:
    if not path_str:
        return {}
    path = Path(path_str)
    if not path.exists():
        return {}
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def _slot_controller_managed(task_payload) -> bool:
    metadata = dict(getattr(task_payload, "metadata", {}) or {})
    runtime = dict(getattr(task_payload, "runtime", {}) or {})
    return bool(
        runtime.get("slot_controller_label")
        or runtime.get("slot_controller_deadline_at")
        or runtime.get("fabric_slot_id")
        or metadata.get("slot_controller_label")
        or metadata.get("slot_controller_deadline_at")
    )


def _extract_round_signatures(round_record: dict[str, Any], data_root: Path) -> set[str]:
    signatures = {
        str(signature).strip()
        for signature in (round_record.get("traced_crash_signatures") or [])
        if str(signature).strip()
    }
    if signatures:
        return signatures
    task_id = str(round_record.get("origin_task_id") or "").strip()
    if not task_id:
        return set()
    dedup_index = _load_optional_json(str(data_root / task_id / "trace" / "dedup_index.json"))
    if isinstance(dedup_index, dict) and dedup_index:
        return {str(signature).strip() for signature in dedup_index if str(signature).strip()}
    trace_dir = data_root / task_id / "trace" / "traced_crashes"
    if not trace_dir.exists():
        return set()
    import json

    discovered: set[str] = set()
    for traced_path in trace_dir.glob("*.json"):
        try:
            payload = json.loads(traced_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            continue
        signature = str(payload.get("signature") or "").strip()
        if signature:
            discovered.add(signature)
    return discovered


def _extract_round_pov_names(round_record: dict[str, Any], data_root: Path) -> set[str]:
    from_record = {
        str(name).strip()
        for name in (round_record.get("confirmed_pov_names") or [])
        if str(name).strip()
    }
    if from_record:
        return from_record
    task_id = str(round_record.get("origin_task_id") or "").strip()
    if not task_id:
        return set()
    pov_dir = data_root / task_id / "pov" / "confirmed"
    if not pov_dir.exists():
        return set()
    return {candidate.name for candidate in pov_dir.glob("*.json") if candidate.is_file()}


def _build_workload_candidates(workload_task_ids: list[str], data_root: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for task_id in workload_task_ids:
        payload = _load_task_payload(task_id, data_root)
        if not payload:
            continue
        runtime = payload.get("runtime", {})
        adapter = runtime.get("adapter_resolution") or payload.get("source", {}).get("adapter_type") or "source"
        adapter = "binary" if adapter == "binary" else ("protocol" if adapter == "protocol" else "source")
        execution_plan = _load_optional_json(runtime.get("execution_plan_path"))
        feedback = _load_optional_json(runtime.get("coverage_feedback_manifest_path"))
        priority_payload = _load_optional_json(runtime.get("patch_priority_manifest_path"))
        reflection_payload = _load_optional_json(runtime.get("patch_reflection_manifest_path"))
        target_name = runtime.get("selected_target") or runtime.get("active_harness") or runtime.get("selected_binary_slice_focus") or task_id
        target_priority = runtime.get("target_priority") or execution_plan.get("target_priority") or "normal"
        target_weight = float(runtime.get("target_weight") or execution_plan.get("target_weight") or 1.0)
        stalled = bool(feedback.get("stalled"))
        crash_count = int(runtime.get("crash_count_live_raw") or runtime.get("binary_execution_crash_candidate_count") or runtime.get("raw_crash_count") or 0)
        pov_count = 1 if runtime.get("pov_path") else 0

        seed_stage = execution_plan.get("stages", {}).get("binary_seed" if adapter == "binary" else "seed", {})
        if seed_stage.get("execute", True):
            candidates.append(
                {
                    "candidate_id": f"{task_id}:seed:{target_name}",
                    "task_id": task_id,
                    "adapter": adapter,
                    "workload_type": "seed",
                    "selected_target": target_name,
                    "priority": seed_stage.get("priority") or target_priority,
                    "weight": target_weight,
                    "budget_before": float(seed_stage.get("budget_multiplier") or 1.0),
                    "stalled": stalled,
                    "crash_count": crash_count,
                    "pov_count": pov_count,
                    "seed_mode": seed_stage.get("task_mode_default") or runtime.get("seed_task_mode") or "SEED_INIT",
                    "patch_priority_action": priority_payload.get("priority_decision", {}).get("action"),
                    "reflection_action": reflection_payload.get("reflection_action"),
                    "evidence_refs": [
                        runtime.get("coverage_manifest_path"),
                        runtime.get("coverage_feedback_manifest_path"),
                        runtime.get("scheduler_feedback_consumption_path"),
                    ],
                },
            )

        workload_type = "binary_execution" if adapter == "binary" else "fuzz"
        candidates.append(
            {
                "candidate_id": f"{task_id}:{workload_type}:{target_name}",
                "task_id": task_id,
                "adapter": adapter,
                "workload_type": workload_type,
                "selected_target": target_name,
                "priority": target_priority,
                "weight": target_weight,
                "budget_before": 1.0,
                "stalled": stalled,
                "crash_count": crash_count,
                "pov_count": pov_count,
                "patch_priority_action": priority_payload.get("priority_decision", {}).get("action"),
                "reflection_action": reflection_payload.get("reflection_action"),
                "evidence_refs": [
                    runtime.get("fuzz_manifest_path") or runtime.get("binary_execution_manifest_path"),
                    runtime.get("coverage_manifest_path"),
                ],
            },
        )

        if priority_payload or reflection_payload or runtime.get("patch_priority_manifest_path"):
            candidates.append(
                {
                    "candidate_id": f"{task_id}:patch:{target_name}",
                    "task_id": task_id,
                    "adapter": adapter,
                    "workload_type": "patch",
                    "selected_target": target_name,
                    "priority": "high" if priority_payload.get("priority_decision", {}).get("action") == "escalate" else "normal",
                    "weight": 1.0,
                    "budget_before": 1.0,
                    "stalled": stalled,
                    "crash_count": crash_count,
                    "pov_count": pov_count,
                    "patch_priority_action": priority_payload.get("priority_decision", {}).get("action"),
                    "reflection_action": reflection_payload.get("reflection_action"),
                    "evidence_refs": [
                        runtime.get("patch_priority_manifest_path"),
                        runtime.get("patch_reflection_manifest_path"),
                    ],
                },
            )
    return candidates


def _write_global_arbitration_manifest(
    *,
    task_id: str,
    now: str,
    workload_task_ids: list[str],
    arbitration: dict[str, Any],
) -> str:
    path = global_arbitration_manifest_path(task_id)
    payload = {
        "task_id": task_id,
        "generated_at": now,
        "workload_task_ids": workload_task_ids,
        "policy": {
            "objective": "rebalance budgets across source, pure-binary, and patch workloads using live coverage/crash/priority signals",
            "dimensions": ["adapter", "workload_type", "target", "priority", "stalled", "crash_count", "patch_priority_action"],
        },
        **arbitration,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    import json

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _apply_global_arbitration_side_effects(
    *,
    task_store: TaskStateStore,
    arbitration: dict[str, Any],
) -> None:
    for candidate in arbitration.get("candidates_after", []):
        task_id = candidate.get("task_id")
        if not task_id:
            continue
        runtime_patch = {
            "global_arbitration_decision": candidate.get("decision"),
            "global_arbitration_budget_after": candidate.get("budget_after"),
            "global_arbitration_score": candidate.get("score"),
            "global_arbitration_workload_type": candidate.get("workload_type"),
            "global_arbitration_target": candidate.get("selected_target"),
        }
        if candidate.get("workload_type") == "seed":
            runtime_patch["campaign_budget_state"] = (
                "exploit"
                if candidate.get("decision") == "boost" and candidate.get("seed_mode") == "VULN_DISCOVERY"
                else ("explore" if candidate.get("decision") in {"boost", "support"} else "hold")
            )
        task_store.update_runtime(task_id, runtime_patch)


def _consume_patch_priority_inputs(
    *,
    campaign_task_id: str,
    origin_task_ids: list[str],
    task_store: TaskStateStore,
    data_root: Path,
) -> list[dict[str, Any]]:
    consumed: list[dict[str, Any]] = []
    for origin_task_id in origin_task_ids:
        task_path = data_root / origin_task_id / "task.json"
        if not task_path.exists():
            continue
        import json

        task_payload = json.loads(task_path.read_text(encoding="utf-8"))
        manifest_path = task_payload.get("runtime", {}).get("patch_priority_manifest_path")
        if not manifest_path:
            candidate = data_root / origin_task_id / "runtime" / "patch_priority_manifest.json"
            manifest_path = str(candidate) if candidate.exists() else None
        if not manifest_path:
            continue
        consumption_path = consume_patch_priority_manifest(
            campaign_task_id,
            consumer="campaign",
            now=task_store.now(),
            manifest_path=manifest_path,
        )
        consumed.append(
            {
                "origin_task_id": origin_task_id,
                "patch_priority_manifest_path": manifest_path,
                "patch_priority_consumption_path": str(consumption_path),
            },
        )
    return consumed


def _consume_patch_reflection_inputs(
    *,
    campaign_task_id: str,
    origin_task_ids: list[str],
    task_store: TaskStateStore,
    data_root: Path,
) -> list[dict[str, Any]]:
    consumed: list[dict[str, Any]] = []
    for origin_task_id in origin_task_ids:
        task_path = data_root / origin_task_id / "task.json"
        if not task_path.exists():
            continue
        import json

        task_payload = json.loads(task_path.read_text(encoding="utf-8"))
        manifest_path = task_payload.get("runtime", {}).get("patch_reflection_manifest_path")
        if not manifest_path:
            candidate = data_root / origin_task_id / "patch" / "reflection_manifest.json"
            manifest_path = str(candidate) if candidate.exists() else None
        if not manifest_path:
            continue
        consumption_path = consume_patch_reflection_manifest(
            campaign_task_id,
            consumer="campaign",
            now=task_store.now(),
            manifest_path=manifest_path,
        )
        consumed.append(
            {
                "origin_task_id": origin_task_id,
                "patch_reflection_manifest_path": manifest_path,
                "patch_reflection_consumption_path": str(consumption_path),
            },
        )
    return consumed


def _initialize_campaign_runtime(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    runtime = dict(task.runtime)
    now = now_utc()
    started_at = _parse_time(runtime.get("campaign_started_at")) or now
    duration_seconds = _campaign_duration_seconds(task.metadata, runtime)
    deadline_at = _parse_time(runtime.get("campaign_deadline_at")) or compute_deadline(started_at, duration_seconds)
    task_store.update_runtime(
        task_id,
        {
            "campaign_duration_seconds": duration_seconds,
            "campaign_started_at": started_at.isoformat(),
            "campaign_deadline_at": deadline_at.isoformat(),
            "campaign_heartbeat_at": now.isoformat(),
            "campaign_origin_task_ids": runtime.get("campaign_origin_task_ids") or list(task.metadata.get("origin_task_ids", [])),
            "campaign_round_records": runtime.get("campaign_round_records") or [],
            "campaign_iterations_total": int(runtime.get("campaign_iterations_total", 0)),
            "campaign_lifecycle_state": runtime.get("campaign_lifecycle_state") or "executing",
        },
    )
    return {
        "task": task_store.load_task(task_id),
        "started_at": started_at,
        "deadline_at": deadline_at,
        "duration_seconds": duration_seconds,
    }


def _wait_for_slot_warmup_release(task_id: str, task_store: TaskStateStore) -> None:
    task = task_store.load_task(task_id)
    runtime = dict(task.runtime)
    if not bool(runtime.get("slot_controller_warmup_hold")):
        return
    while True:
        task = task_store.load_task(task_id)
        runtime = dict(task.runtime)
        if not bool(runtime.get("slot_controller_warmup_hold")):
            released_at = now_utc()
            duration_seconds = _campaign_duration_seconds(task.metadata, runtime)
            task_store.update_runtime(
                task_id,
                {
                    "campaign_started_at": released_at.isoformat(),
                    "campaign_deadline_at": compute_deadline(released_at, duration_seconds).isoformat(),
                    "campaign_heartbeat_at": released_at.isoformat(),
                    "slot_controller_warmup_state": "released",
                    "slot_controller_warmup_released_at": released_at.isoformat(),
                },
            )
            return
        task_store.update_runtime(
            task_id,
            {
                "slot_controller_warmup_state": "prepared",
                "slot_controller_warmup_heartbeat_at": now_utc().isoformat(),
            },
        )
        time.sleep(0.5)


def _write_checkpoint(
    *,
    task_id: str,
    lifecycle_state: str,
    started_at: str,
    deadline_at: str,
    heartbeat_at: str,
    finished_at: str | None,
    iterations_total: int,
    last_round_finished_at: str | None,
    patch_priority_consumed: list[dict[str, Any]],
    patch_reflection_consumed: list[dict[str, Any]],
) -> str:
    import json

    path = campaign_checkpoint_path(task_id)
    payload = {
        "task_id": task_id,
        "generated_at": heartbeat_at,
        "lifecycle_state": lifecycle_state,
        "campaign_started_at": started_at,
        "campaign_deadline_at": deadline_at,
        "campaign_heartbeat_at": heartbeat_at,
        "campaign_last_round_finished_at": last_round_finished_at,
        "campaign_finished_at": finished_at,
        "iterations_total": iterations_total,
        "next_action": "stop" if finished_at else "continue",
        "patch_priority_consumed_inputs": patch_priority_consumed,
        "patch_reflection_consumed_inputs": patch_reflection_consumed,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _build_and_write_manifest(
    *,
    task_id: str,
    task_store: TaskStateStore,
    reports: dict[str, Any],
    origin_task_ids: list[str],
    round_records: list[dict[str, Any]],
    data_root: Path,
    duration_seconds: int,
    started_at: str,
    deadline_at: str,
    heartbeat_at: str,
    finished_at: str | None,
    lifecycle_state: str,
    checkpoint_path: str,
    campaign_state: dict[str, Any],
) -> str:
    task = task_store.load_task(task_id)
    coverage = reports.get("vuln_coverage") or {}
    all_signatures: set[str] = set()
    all_pov_names: set[str] = set()
    for round_record in round_records:
        all_signatures.update(_extract_round_signatures(round_record, data_root))
        all_pov_names.update(_extract_round_pov_names(round_record, data_root))
    metrics = dict(campaign_state.get("metrics") or {})
    family_inventory = dict(campaign_state.get("family_inventory") or {})
    coverage_state = dict(campaign_state.get("coverage_state") or {})
    started_dt = datetime.fromisoformat(started_at)
    current_dt = datetime.fromisoformat(finished_at or heartbeat_at)
    elapsed_seconds = max(0.0, (current_dt - started_dt).total_seconds())
    if elapsed_seconds > 0:
        metrics["api_calls_per_hour"] = round(
            float(metrics.get("llm_request_count_total") or 0) / max(elapsed_seconds / 3600.0, 1e-9),
            3,
        )
    metrics["wall_clock_utilization_ratio"] = round(elapsed_seconds / max(duration_seconds, 1), 4)
    campaign_state.setdefault("metrics", {}).update(metrics)
    campaign_state.setdefault("slot", {})["slot_end_time"] = finished_at or heartbeat_at
    manifest = CampaignManifest(
        campaign_task_id=task_id,
        benchmark=str(task.metadata.get("benchmark", "")),
        origin_task_ids=origin_task_ids,
        campaign_duration_seconds=duration_seconds,
        campaign_started_at=started_at,
        campaign_deadline_at=deadline_at,
        campaign_heartbeat_at=heartbeat_at,
        campaign_last_round_finished_at=task.runtime.get("campaign_last_round_finished_at"),
        campaign_finished_at=finished_at,
        iterations_total=len(round_records),
        fuzz_time_total_seconds=round(sum(item.get("duration_seconds", 0.0) for item in round_records), 3),
        new_corpus_files_total=sum(int(item.get("new_corpus_files", 0)) for item in round_records),
        total_raw_crash_count=int(metrics.get("total_raw_crash_count") or sum(int(item.get("new_raw_crash_count", 0)) for item in round_records)),
        total_traced_crash_count=int(metrics.get("total_traced_crash_count") or sum(int(item.get("new_traced_crash_count", 0)) for item in round_records)),
        distinct_pov_count=max(int(metrics.get("distinct_pov_count") or 0), len(all_pov_names)),
        distinct_signature_count=len(family_inventory.get("trace_exact_signatures") or all_signatures),
        trace_exact_signature_count=len(family_inventory.get("trace_exact_signatures") or all_signatures),
        loose_cluster_count=len(family_inventory.get("loose_vulnerable_state_clusters") or []),
        confirmed_family_count=len(family_inventory.get("confirmed_families") or []),
        distinct_vuln_count=int(coverage.get("found_vuln_count", 0)),
        llm_request_count_total=int(metrics.get("llm_request_count_total") or 0),
        llm_request_count_by_stage=dict(metrics.get("llm_request_count_by_stage") or {}),
        llm_success_count=int(metrics.get("llm_success_count") or 0),
        llm_failure_count=int(metrics.get("llm_failure_count") or 0),
        api_calls_per_hour=float(metrics.get("api_calls_per_hour") or 0.0),
        fuzz_session_count=int(metrics.get("fuzz_session_count") or len(round_records)),
        harness_switch_count=int(metrics.get("harness_switch_count") or 0),
        reseed_trigger_count=int(metrics.get("reseed_trigger_count") or 0),
        exact_coverage_available_ratio=float(metrics.get("exact_coverage_available_ratio") or 0.0),
        shared_corpus_growth_count=int(metrics.get("shared_corpus_growth_count") or 0),
        family_diversification_trigger_count=int(metrics.get("family_diversification_trigger_count") or 0),
        generalized_candidate_bridge_count=int(metrics.get("generalized_candidate_bridge_count") or 0),
        trace_worthy_candidate_count=int(metrics.get("trace_worthy_candidate_count") or 0),
        system_candidate_bridge_count=int(metrics.get("system_candidate_bridge_count") or metrics.get("generalized_candidate_bridge_count") or 0),
        system_trace_worthy_candidate_count=int(metrics.get("system_trace_worthy_candidate_count") or metrics.get("trace_worthy_candidate_count") or 0),
        system_low_growth_queue_count=int(metrics.get("system_low_growth_queue_count") or 0),
        system_uncovered_queue_count=int(metrics.get("system_uncovered_queue_count") or 0),
        system_stalled_target_count=int(metrics.get("system_stalled_target_count") or 0),
        binary_signal_lift_count=int(metrics.get("binary_signal_lift_count") or 0),
        binary_reseed_trigger_count=int(metrics.get("binary_reseed_trigger_count") or 0),
        wall_clock_utilization_ratio=float(metrics.get("wall_clock_utilization_ratio") or 0.0),
        idle_gap_seconds=float((campaign_state.get("slot") or {}).get("idle_gap_seconds") or metrics.get("idle_gap_seconds") or 0.0),
        slot_start_time=(campaign_state.get("slot") or {}).get("slot_start_time"),
        slot_end_time=(campaign_state.get("slot") or {}).get("slot_end_time") or finished_at or heartbeat_at,
        project_sequence=list((campaign_state.get("slot") or {}).get("project_sequence") or []),
        campaign_continuation_count=int((campaign_state.get("slot") or {}).get("campaign_continuation_count") or 0),
        campaign_runtime_state_path=str(persist_campaign_runtime_state(task_id, campaign_state)),
        rounds=[
            CampaignRound(**filter_campaign_round_payload(round_record))
            for round_record in round_records
        ],
        pov_inventory_path=reports.get("pov_inventory_path"),
        vuln_coverage_path=reports.get("vuln_coverage_path"),
        signature_index_path=reports.get("signature_index_path"),
        pov_lineage_path=reports.get("pov_lineage_path"),
        found_vuln_ids=coverage.get("found_vuln_ids", []),
        missing_vuln_ids=coverage.get("missing_vuln_ids", []),
        lifecycle_state=lifecycle_state,
        checkpoint_path=checkpoint_path,
    )
    manifest_path = write_campaign_manifest(task_id, manifest.to_dict())
    return str(manifest_path)


def run_campaign(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    _wait_for_slot_warmup_release(task_id, task_store)
    context = _initialize_campaign_runtime(task_id, task_store)
    task = context["task"]
    metadata = task.metadata
    runtime = task.runtime

    duration_seconds = int(context["duration_seconds"])
    deadline_at = context["deadline_at"]
    started_at = context["started_at"]
    target_mode = str(metadata.get("target_mode", "source"))
    data_root = Path(settings.data_root)
    origin_task_ids = list(runtime.get("campaign_origin_task_ids") or [])
    round_records = list(runtime.get("campaign_round_records") or [])
    base_task_id = str(metadata.get("base_task_id") or "").strip()
    completed = False

    workload_task_ids = list(metadata.get("workload_task_ids") or [])
    if workload_task_ids:
        now = now_utc()
        candidates = _build_workload_candidates(workload_task_ids, data_root)
        arbitration = arbitrate_workloads(candidates)
        _apply_global_arbitration_side_effects(task_store=task_store, arbitration=arbitration)
        manifest_path = _write_global_arbitration_manifest(
            task_id=task_id,
            now=now.isoformat(),
            workload_task_ids=workload_task_ids,
            arbitration=arbitration,
        )
        checkpoint_path = _write_checkpoint(
            task_id=task_id,
            lifecycle_state="finished",
            started_at=started_at.isoformat(),
            deadline_at=deadline_at.isoformat(),
            heartbeat_at=now.isoformat(),
            finished_at=now.isoformat(),
            iterations_total=0,
            last_round_finished_at=None,
            patch_priority_consumed=[],
            patch_reflection_consumed=[],
        )
        task_store.update_runtime(
            task_id,
            {
                "campaign_heartbeat_at": now.isoformat(),
                "campaign_checkpoint_path": checkpoint_path,
                "global_arbitration_manifest_path": manifest_path,
                "global_arbitration_selected_candidates": arbitration.get("selected_candidates", []),
                "campaign_lifecycle_state": "finished",
            },
        )
        return {
            "completed": True,
            "found_vuln_ids": [],
            "missing_vuln_ids": [],
            "round_records": [],
            "campaign_deadline_at": deadline_at.isoformat(),
            "campaign_manifest_path": None,
            "campaign_checkpoint_path": checkpoint_path,
            "global_arbitration_manifest_path": manifest_path,
            "selected_candidates": arbitration.get("selected_candidates", []),
        }

    now = now_utc()
    campaign_state = (
        initialize_campaign_runtime_state(
            task_id,
            task_store=task_store,
            base_task_id=base_task_id,
            benchmark=str(metadata.get("benchmark", "")),
            target_mode=target_mode,
            duration_seconds=duration_seconds,
        )
        if base_task_id
        else {}
    )
    if campaign_state:
        system_paths = register_campaign(
            campaign_task_id=task_id,
            benchmark=str(metadata.get("benchmark", "")),
            target_mode=target_mode,
            base_task_id=base_task_id,
            deadline_at=deadline_at.isoformat(),
            slot_label=str(metadata.get("slot_controller_label") or metadata.get("benchmark") or task_id),
        )
        campaign_state["system_fabric"] = {**dict(campaign_state.get("system_fabric") or {}), **system_paths}
        persist_campaign_runtime_state(task_id, campaign_state)
    lane = str(
        (campaign_state.get("lane") if campaign_state else None)
        or runtime.get("fabric_lane")
        or runtime.get("campaign_lane")
        or metadata.get("fabric_lane")
        or metadata.get("campaign_lane")
        or ("generalized" if metadata.get("generalized_source") else ("binary" if target_mode == "binary" else "source"))
    )
    session_budget_default = int(metadata.get("FUZZ_MAX_TOTAL_TIME_SECONDS", 30))
    session_budget_target = int(
        metadata.get("FUZZ_SESSION_TARGET_SECONDS")
        or _session_budget_target_seconds(
            lane=lane,
            target_mode=target_mode,
            configured_budget=session_budget_default,
        )
    )
    slot_controller_managed = _slot_controller_managed(task)
    minimum_session_seconds = 60 if target_mode != "binary" else max(60, min(session_budget_default, 300))
    if slot_controller_managed and target_mode != "binary":
        # Allow a final short bounded round so slot-controlled campaigns can
        # stay occupied closer to the slot deadline instead of idling for the
        # last sub-minute tail.
        minimum_session_seconds = max(15, min(minimum_session_seconds, session_budget_default))

    if base_task_id:
        while should_continue(deadline_at, now):
            remaining = remaining_seconds(deadline_at, now)
            if remaining < minimum_session_seconds:
                break
            idle_started = str(campaign_state.get("last_idle_gap_started_at") or "").strip()
            if idle_started:
                idle_dt = datetime.fromisoformat(idle_started)
                idle_gap = max(0.0, (now - idle_dt).total_seconds())
                campaign_state.setdefault("slot", {})
                campaign_state["slot"]["idle_gap_seconds"] = round(
                    float((campaign_state.get("slot") or {}).get("idle_gap_seconds") or 0.0) + idle_gap,
                    3,
                )
                campaign_state.setdefault("metrics", {})
                campaign_state["metrics"]["idle_gap_seconds"] = float((campaign_state.get("slot") or {}).get("idle_gap_seconds") or 0.0)
            session_budget = max(
                minimum_session_seconds,
                min(
                    session_budget_default,
                    session_budget_target,
                    remaining,
                ),
            )
            session_plan = choose_next_session_plan(
                campaign_state,
                now_iso=now.isoformat(),
                round_budget_seconds=session_budget,
            )
            round_number = len(round_records) + 1
            active_session_task_id = str(campaign_state.get("active_session_task_id") or "").strip() or None
            donor_task_id = active_session_task_id or (origin_task_ids[-1] if origin_task_ids else base_task_id)
            cumulative_signatures = set((campaign_state.get("family_inventory") or {}).get("trace_exact_signatures") or [])
            round_task_id, round_record, _ = execute_campaign_iteration(
                base_task_id=base_task_id,
                donor_task_id=donor_task_id,
                target_mode=target_mode,
                round_number=round_number,
                task_store=task_store,
                data_root=data_root,
                cumulative_signatures=cumulative_signatures,
                duration_seconds=session_budget,
                campaign_task_id=task_id,
                session_plan=session_plan,
                reusable_round_task_id=active_session_task_id if target_mode != "binary" else None,
            )
            round_record.update(
                {
                    "session_index": int(session_plan.get("session_index") or 0),
                    "session_budget_seconds": int(session_plan.get("session_budget_seconds") or 0),
                    "selected_harness": session_plan.get("selected_harness") or round_record.get("selected_harness"),
                    "selected_target_function": session_plan.get("selected_target_function") or round_record.get("selected_target_function"),
                    "triggered_action_type": session_plan.get("triggered_action_type"),
                    "reseeding_triggered": bool(session_plan.get("reseed_triggered")) or bool(round_record.get("reseeding_triggered")),
                    "uncovered_function_count": int(session_plan.get("coverage_queue_size") or round_record.get("uncovered_function_count") or 0),
                    "family_diversification_triggered": bool(session_plan.get("family_diversification_triggered")),
                    "family_stagnation_count": int(session_plan.get("family_stagnation_count") or 0),
                    "family_confirmation_backlog_count": int(session_plan.get("family_confirmation_backlog_count") or 0),
                    "family_confirmation_selected_clusters": session_plan.get("family_confirmation_selected_clusters") or [],
                    "candidate_bridge_count": int(session_plan.get("candidate_bridge_queue_size") or round_record.get("candidate_bridge_count") or 0),
                }
            )
            now = now_utc()
            campaign_state, round_updates = apply_round_results_to_campaign(
                task_id,
                round_task_id=round_task_id,
                round_record=round_record,
                state=campaign_state,
                now_iso=now.isoformat(),
            )
            round_record.update(round_updates)
            if round_task_id not in origin_task_ids:
                origin_task_ids.append(round_task_id)
            round_records.append(round_record)
            campaign_state["last_idle_gap_started_at"] = now.isoformat()
            persist_campaign_runtime_state(task_id, campaign_state)
            task_store.update_runtime(
                task_id,
                {
                    "campaign_heartbeat_at": now.isoformat(),
                    "campaign_last_round_finished_at": now.isoformat(),
                    "campaign_origin_task_ids": origin_task_ids,
                    "campaign_round_records": round_records,
                    "campaign_iterations_total": len(round_records),
                    "campaign_runtime_state_path": str(persist_campaign_runtime_state(task_id, campaign_state)),
                },
            )
            heartbeat_campaign(
                campaign_task_id=task_id,
                status="running",
                round_count=len(round_records),
                metrics=dict(campaign_state.get("metrics") or {}),
            )
            if remaining_seconds(deadline_at, now) < minimum_session_seconds:
                break

    task = task_store.load_task(task_id)
    runtime = task.runtime
    origin_task_ids = list(runtime.get("campaign_origin_task_ids") or origin_task_ids)
    round_records = list(runtime.get("campaign_round_records") or round_records)
    reports = _build_offline_campaign_reports_if_requested(
        metadata=metadata,
        campaign_task_id=task_id,
        origin_task_ids=origin_task_ids,
        data_root=data_root,
    )
    patch_priority_consumed = _consume_patch_priority_inputs(
        campaign_task_id=task_id,
        origin_task_ids=origin_task_ids,
        task_store=task_store,
        data_root=data_root,
    )
    patch_reflection_consumed = _consume_patch_reflection_inputs(
        campaign_task_id=task_id,
        origin_task_ids=origin_task_ids,
        task_store=task_store,
        data_root=data_root,
    )
    now = now_utc()
    local_completion_reason = "deadline_exhausted"
    local_remaining_seconds = max(0, remaining_seconds(deadline_at, now))
    slot_controller_managed = _slot_controller_managed(task)
    if (base_task_id and remaining_seconds(deadline_at, now) < minimum_session_seconds) or not should_continue(deadline_at, now):
        completed = True
    finished_at = now.isoformat() if completed else None
    lifecycle_state = "finished" if completed else "executing"
    if campaign_state:
        campaign_state.setdefault("slot", {})
        campaign_state["slot"]["slot_end_time"] = finished_at or now.isoformat()
        campaign_state.setdefault("metrics", {})
        if completed:
            next_base_task_id = (
                str(campaign_state.get("active_session_task_id") or "").strip()
                or (origin_task_ids[-1] if origin_task_ids else base_task_id)
            )
            if slot_controller_managed:
                completion_record = {
                    "campaign_task_id": task_id,
                    "completed_reason": local_completion_reason,
                    "next_base_task_id": next_base_task_id,
                    "remaining_seconds": local_remaining_seconds,
                    "slot_level_resolution_deferred": True,
                    "resolution_owner": "slot_controller",
                    "local_campaign_deadline_at": deadline_at.isoformat(),
                    "slot_controller_deadline_at": (
                        task.runtime.get("slot_controller_deadline_at")
                        or task.metadata.get("slot_controller_deadline_at")
                    ),
                }
            else:
                completion_record = complete_campaign(
                    campaign_task_id=task_id,
                    completed_reason=local_completion_reason,
                    next_base_task_id=next_base_task_id,
                    remaining_seconds=local_remaining_seconds,
                )
            campaign_state["system_fabric"] = {
                **dict(campaign_state.get("system_fabric") or {}),
                "last_completion_record": completion_record,
            }
        else:
            heartbeat_campaign(
                campaign_task_id=task_id,
                status="executing",
                round_count=len(round_records),
                metrics=dict(campaign_state.get("metrics") or {}),
            )
    checkpoint_path = _write_checkpoint(
        task_id=task_id,
        lifecycle_state=lifecycle_state,
        started_at=started_at.isoformat(),
        deadline_at=deadline_at.isoformat(),
        heartbeat_at=now.isoformat(),
        finished_at=finished_at,
        iterations_total=len(round_records),
        last_round_finished_at=task_store.load_task(task_id).runtime.get("campaign_last_round_finished_at"),
        patch_priority_consumed=patch_priority_consumed,
        patch_reflection_consumed=patch_reflection_consumed,
    )
    runtime_artifacts = (
        write_campaign_runtime_artifacts(
            task_id,
            state=campaign_state,
            started_at=started_at.isoformat(),
            deadline_at=deadline_at.isoformat(),
            finished_at=finished_at,
        )
        if campaign_state
        else {}
    )
    manifest_path = _build_and_write_manifest(
        task_id=task_id,
        task_store=task_store,
        reports=reports,
        origin_task_ids=origin_task_ids,
        round_records=round_records,
        data_root=data_root,
        duration_seconds=duration_seconds,
        started_at=started_at.isoformat(),
        deadline_at=deadline_at.isoformat(),
        heartbeat_at=now.isoformat(),
        finished_at=finished_at,
        lifecycle_state=lifecycle_state,
        checkpoint_path=checkpoint_path,
        campaign_state=campaign_state,
    )

    task_store.update_runtime(
        task_id,
        {
            "campaign_heartbeat_at": now.isoformat(),
            "campaign_manifest_path": manifest_path,
            "campaign_checkpoint_path": checkpoint_path,
            "campaign_lifecycle_state": lifecycle_state,
            "campaign_local_completion_reason": local_completion_reason if completed else None,
            "campaign_completed_reason": local_completion_reason if completed else None,
            "campaign_local_remaining_seconds_at_finish": local_remaining_seconds if completed else None,
            "campaign_slot_resolution_deferred": bool(completed and slot_controller_managed),
            "campaign_resolution_owner": "slot_controller" if completed and slot_controller_managed else ("campaign" if completed else None),
            **runtime_artifacts,
            "pov_inventory_path": reports.get("pov_inventory_path"),
            "vuln_coverage_path": reports.get("vuln_coverage_path"),
            "signature_index_path": reports.get("signature_index_path"),
            "pov_lineage_path": reports.get("pov_lineage_path"),
            "found_vuln_ids": (reports.get("vuln_coverage") or {}).get("found_vuln_ids", []),
            "missing_vuln_ids": (reports.get("vuln_coverage") or {}).get("missing_vuln_ids", []),
            "campaign_origin_task_ids": origin_task_ids,
            "campaign_round_records": round_records,
            "campaign_iterations_total": len(round_records),
            "patch_priority_consumed": bool(patch_priority_consumed),
            "patch_priority_consumed_inputs": patch_priority_consumed,
            "patch_reflection_consumed": bool(patch_reflection_consumed),
            "patch_reflection_consumed_inputs": patch_reflection_consumed,
            **({"campaign_finished_at": finished_at} if finished_at else {}),
        },
    )

    return {
        "campaign_manifest_path": manifest_path,
        "campaign_checkpoint_path": checkpoint_path,
        "campaign_lifecycle_state": lifecycle_state,
        **runtime_artifacts,
        "pov_inventory_path": reports.get("pov_inventory_path"),
        "vuln_coverage_path": reports.get("vuln_coverage_path"),
        "signature_index_path": reports.get("signature_index_path"),
        "pov_lineage_path": reports.get("pov_lineage_path"),
        "found_vuln_ids": (reports.get("vuln_coverage") or {}).get("found_vuln_ids", []),
        "missing_vuln_ids": (reports.get("vuln_coverage") or {}).get("missing_vuln_ids", []),
        "round_records": round_records,
        "origin_task_ids": origin_task_ids,
        "completed": completed,
        "campaign_duration_seconds": duration_seconds,
        "campaign_started_at": started_at.isoformat(),
        "campaign_deadline_at": deadline_at.isoformat(),
        "campaign_heartbeat_at": now.isoformat(),
        "campaign_completed_reason": local_completion_reason if completed else None,
        "campaign_slot_resolution_deferred": bool(completed and slot_controller_managed),
        "campaign_resolution_owner": "slot_controller" if completed and slot_controller_managed else ("campaign" if completed else None),
        "campaign_last_round_finished_at": task_store.load_task(task_id).runtime.get("campaign_last_round_finished_at"),
        "patch_priority_consumed_inputs": patch_priority_consumed,
        "patch_reflection_consumed_inputs": patch_reflection_consumed,
    }

from __future__ import annotations

import json
from pathlib import Path

from core.analysis.suspicious_candidate import (
    load_candidate_trace_results,
    record_suspicious_candidate_repro_status,
)
from core.models.task import TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.utils.settings import settings


def _load_json(path_str: str | None) -> dict:
    if not path_str:
        return {}
    path = Path(path_str)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def maybe_enqueue_repro(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> bool:
    with task_store.task_lock(task_id):
        task = task_store._load_task_unlocked(task_id)
        if task.status in {TaskStatus.QUEUED_REPRO, TaskStatus.REPRODUCING, TaskStatus.POV_CONFIRMED}:
            return False

        plan = _load_json(task.runtime.get("execution_plan_path"))
        is_binary = task.runtime.get("adapter_resolution") == "binary" or task.runtime.get("target_mode") == "binary"
        task_dir = Path(task.task_dir)
        candidate_trace_results = load_candidate_trace_results(task_dir)
        generalized_candidate_results = [
            item for item in candidate_trace_results if item.get("candidate_origin_kind") == "suspicious_candidate"
        ]
        generalized_repro_eligible = [
            item
            for item in generalized_candidate_results
            if item.get("repro_admission_eligibility") == "eligible" and item.get("trace_artifact_path")
        ]
        if not is_binary and not plan.get("stages", {}).get("repro", {}).get("execute"):
            task.runtime.update(
                {
                    "repro_gate_decision": "blocked",
                    "repro_gate_reason": "repro_stage_disabled_by_execution_plan",
                    "generalized_candidate_trace_result_count": len(generalized_candidate_results),
                },
            )
            task_store._save_task_unlocked(task)
            return False
        traced_dir = Path(task.layout.get("trace_traced_crashes", Path(task.layout["trace"]) / "traced_crashes"))
        if not traced_dir.exists():
            reason = (
                "generalized_candidate_trace_results_present_but_no_trace_artifact_directory"
                if generalized_candidate_results
                else "traced_crash_directory_missing"
            )
            task.runtime.update(
                {
                    "repro_gate_decision": "blocked",
                    "repro_gate_reason": reason,
                    "generalized_candidate_trace_result_count": len(generalized_candidate_results),
                    "generalized_candidate_repro_eligible_count": len(generalized_repro_eligible),
                },
            )
            for item in generalized_candidate_results:
                record_suspicious_candidate_repro_status(
                    task_dir,
                    candidate_id=str(item.get("candidate_id")),
                    repro_gate_decision="blocked",
                    repro_gate_reason=reason,
                )
            task_store._save_task_unlocked(task)
            return False
        traced_files = list(traced_dir.glob("*.json"))
        if not traced_files:
            reason = (
                "no_repro_eligible_generalized_candidate_trace_results"
                if generalized_candidate_results
                else "no_traced_candidates_available"
            )
            task.runtime.update(
                {
                    "repro_gate_decision": "blocked",
                    "repro_gate_reason": reason,
                    "generalized_candidate_trace_result_count": len(generalized_candidate_results),
                    "generalized_candidate_repro_eligible_count": len(generalized_repro_eligible),
                },
            )
            for item in generalized_candidate_results:
                record_suspicious_candidate_repro_status(
                    task_dir,
                    candidate_id=str(item.get("candidate_id")),
                    repro_gate_decision="blocked",
                    repro_gate_reason=reason,
                )
            task_store._save_task_unlocked(task)
            return False
        traced_payloads = [json.loads(path.read_text(encoding="utf-8")) for path in traced_files]
        live_raw_candidates = [
            payload for payload in traced_payloads if payload.get("crash_source") == "live_raw"
        ]
        generalized_candidate_ids = {
            str(item.get("candidate_id"))
            for item in generalized_repro_eligible
            if str(item.get("candidate_id") or "").strip()
        }
        suspicious_recommended = [
            payload
            for payload in traced_payloads
            if payload.get("candidate_origin_kind") == "suspicious_candidate"
            and (
                payload.get("repro_admission_recommended") is True
                or str(payload.get("candidate_id") or "") in generalized_candidate_ids
            )
        ]
        if settings.crash_source_policy == "live_raw_only":
            if not live_raw_candidates and not suspicious_recommended:
                reason = (
                    "no_live_raw_or_generalized_repro_candidate_after_policy_filter"
                    if generalized_candidate_results
                    else "no_live_raw_traced_candidate_after_policy_filter"
                )
                task.runtime.update(
                    {
                        "repro_gate_decision": "blocked",
                        "repro_gate_reason": reason,
                        "generalized_candidate_trace_result_count": len(generalized_candidate_results),
                        "generalized_candidate_repro_eligible_count": len(generalized_repro_eligible),
                    },
                )
                for item in generalized_candidate_results:
                    record_suspicious_candidate_repro_status(
                        task_dir,
                        candidate_id=str(item.get("candidate_id")),
                        repro_gate_decision="blocked",
                        repro_gate_reason=reason,
                    )
                task_store._save_task_unlocked(task)
                return False

        if not live_raw_candidates and not suspicious_recommended and generalized_candidate_results:
            reason = "generalized_candidate_trace_results_present_but_not_repro_eligible"
            task.runtime.update(
                {
                    "repro_gate_decision": "blocked",
                    "repro_gate_reason": reason,
                    "generalized_candidate_trace_result_count": len(generalized_candidate_results),
                    "generalized_candidate_repro_eligible_count": len(generalized_repro_eligible),
                },
            )
            for item in generalized_candidate_results:
                record_suspicious_candidate_repro_status(
                    task_dir,
                    candidate_id=str(item.get("candidate_id")),
                    repro_gate_decision="blocked",
                    repro_gate_reason=reason,
                )
            task_store._save_task_unlocked(task)
            return False

        now = task_store.now()
        task.status = TaskStatus.QUEUED_REPRO
        task.runtime.update(
            {
                "repro_queue_name": QueueNames.REPRO,
                "repro_queued_at": now,
                "repro_gate_decision": "queued",
                "repro_gate_reason": (
                    "recommended_suspicious_candidate_available"
                    if suspicious_recommended and not live_raw_candidates
                    else "stable_traced_candidate_available"
                ),
                "repro_gate_candidate_count": (
                    len(live_raw_candidates)
                    if live_raw_candidates
                    else len(suspicious_recommended)
                ),
                "repro_gate_candidate_origin_kind": (
                    "suspicious_candidate_trace_result"
                    if suspicious_recommended and not live_raw_candidates
                    else "raw_crash"
                ),
                "generalized_candidate_trace_result_count": len(generalized_candidate_results),
                "generalized_candidate_repro_eligible_count": len(generalized_repro_eligible),
            },
        )
        if suspicious_recommended and not live_raw_candidates:
            queued_ids = {
                str(payload.get("candidate_id") or "")
                for payload in suspicious_recommended
                if str(payload.get("candidate_id") or "").strip()
            }
            for item in generalized_candidate_results:
                record_suspicious_candidate_repro_status(
                    task_dir,
                    candidate_id=str(item.get("candidate_id")),
                    repro_gate_decision="queued" if str(item.get("candidate_id") or "") in queued_ids else "blocked",
                    repro_gate_reason=(
                        "recommended_suspicious_candidate_trace_result_available"
                        if str(item.get("candidate_id") or "") in queued_ids
                        else "not_selected_for_repro_queue"
                    ),
                )
        task_store._save_task_unlocked(task)

    queue.push(QueueNames.REPRO, task_id)
    return True

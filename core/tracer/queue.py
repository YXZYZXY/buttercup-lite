from __future__ import annotations

import json
from pathlib import Path

from core.analysis.suspicious_candidate import (
    replayable_suspicious_candidates,
    suspicious_candidate_queue_path,
)
from core.binary.trace_bridge import binary_candidate_dir
from core.fuzz.harness_binding import classify_crash_source
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


def maybe_enqueue_trace(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> bool:
    with task_store.task_lock(task_id):
        task = task_store._load_task_unlocked(task_id)
        if task.status in {TaskStatus.QUEUED_TRACE, TaskStatus.TRACING, TaskStatus.TRACED, TaskStatus.POV_CONFIRMED}:
            return False

        plan = _load_json(task.runtime.get("execution_plan_path"))
        is_binary = task.runtime.get("adapter_resolution") == "binary" or task.runtime.get("target_mode") == "binary"
        task_dir = Path(task.task_dir)
        if not is_binary and not plan.get("stages", {}).get("trace", {}).get("execute"):
            task.runtime.update(
                {
                    "trace_gate_decision": "blocked",
                    "trace_gate_reason": "trace_stage_disabled_by_execution_plan",
                },
            )
            task_store._save_task_unlocked(task)
            return False
        crash_dir = binary_candidate_dir(task_dir) if is_binary else Path(task.layout.get("crashes_raw", Path(task.layout["crashes"]) / "raw"))
        raw_candidates_before_policy = [path for path in crash_dir.iterdir() if path.is_file()] if crash_dir.exists() else []
        raw_candidates = list(raw_candidates_before_policy)
        if settings.crash_source_policy == "live_raw_only":
            raw_candidates = [path for path in raw_candidates if classify_crash_source(path) == "live_raw"]
        suspicious_candidates = (
            replayable_suspicious_candidates(task_dir, require_trace_worthy=True)
            if not is_binary
            else []
        )
        using_suspicious_candidates = False
        trace_gate_reason = None
        blocked_reason = None
        candidates: list[Path] | list[dict] = raw_candidates
        if raw_candidates:
            trace_gate_reason = (
                "semantic_crash_candidate_available"
                if is_binary
                else "source_live_raw_candidate_available"
            )
        elif suspicious_candidates:
            candidates = suspicious_candidates
            using_suspicious_candidates = True
            trace_gate_reason = "generalized_candidate_trace_admission_available"
        else:
            if not crash_dir.exists():
                blocked_reason = "candidate_directory_missing"
            elif not raw_candidates_before_policy:
                blocked_reason = "no_candidate_files_present"
            elif settings.crash_source_policy == "live_raw_only":
                blocked_reason = "no_live_raw_candidates_after_policy_filter"
            else:
                blocked_reason = "no_candidate_files_present"
            if not is_binary and suspicious_candidate_queue_path(task_dir).exists():
                blocked_reason = "generalized_candidate_queue_present_but_no_trace_eligible_inputs"
            task.runtime.update(
                {
                    "trace_gate_decision": "blocked",
                    "trace_gate_reason": blocked_reason,
                    "trace_gate_candidate_origin_kind": (
                        "suspicious_candidate"
                        if suspicious_candidate_queue_path(task_dir).exists()
                        else "raw_crash"
                    ),
                    "suspicious_candidate_queue_path": (
                        str(suspicious_candidate_queue_path(task_dir))
                        if suspicious_candidate_queue_path(task_dir).exists()
                        else task.runtime.get("suspicious_candidate_queue_path")
                    ),
                    "suspicious_candidate_count_available": len(suspicious_candidates),
                },
            )
            task_store._save_task_unlocked(task)
            return False

        now = task_store.now()
        task.status = TaskStatus.QUEUED_TRACE
        task.runtime.update(
            {
                "trace_queue_name": QueueNames.TRACE,
                "trace_queued_at": now,
                "trace_gate_decision": "queued",
                "trace_gate_reason": trace_gate_reason,
                "trace_gate_candidate_count": len(candidates),
                "trace_gate_candidate_origin_kind": (
                    "suspicious_candidate" if using_suspicious_candidates else "raw_crash"
                ),
                "suspicious_candidate_queue_path": (
                    str(suspicious_candidate_queue_path(task_dir))
                    if using_suspicious_candidates
                    else task.runtime.get("suspicious_candidate_queue_path")
                ),
                "suspicious_candidate_count_available": len(suspicious_candidates),
            },
        )
        task_store._save_task_unlocked(task)

    queue.push(QueueNames.TRACE, task_id)
    return True

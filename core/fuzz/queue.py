from __future__ import annotations

import json
from pathlib import Path

from core.models.task import TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore


def _load_json(path_str: str | None) -> dict:
    if not path_str:
        return {}
    path = Path(path_str)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def maybe_enqueue_fuzz(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> bool:
    with task_store.task_lock(task_id):
        task = task_store._load_task_unlocked(task_id)
        if task.status in {
            TaskStatus.QUEUED_FUZZ,
            TaskStatus.FUZZING,
            TaskStatus.QUEUED_TRACE,
            TaskStatus.TRACING,
            TaskStatus.TRACED,
            TaskStatus.POV_CONFIRMED,
        }:
            return False

        plan = _load_json(task.runtime.get("execution_plan_path"))
        if not plan.get("stages", {}).get("fuzz", {}).get("execute"):
            return False
        if not task.runtime.get("seed_manifest_path"):
            return False
        if task.runtime.get("build_status") != TaskStatus.BUILT.value:
            return False
        build_registry_path = task.runtime.get("build_registry_path")
        if not build_registry_path or not Path(build_registry_path).exists():
            return False

        now = task_store.now()
        task.status = TaskStatus.QUEUED_FUZZ
        task.runtime.update(
            {
                "fuzz_queue_name": QueueNames.FUZZ,
                "fuzz_queued_at": now,
            },
        )
        task_store._save_task_unlocked(task)

    queue.push(QueueNames.FUZZ, task_id)
    return True

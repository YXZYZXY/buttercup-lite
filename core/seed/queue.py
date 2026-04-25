from __future__ import annotations

import json
import logging
from pathlib import Path

from core.models.task import TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore

logger = logging.getLogger(__name__)


def _load_json(path_str: str | None) -> dict:
    if not path_str:
        return {}
    path = Path(path_str)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def maybe_enqueue_seed(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> bool:
    with task_store.task_lock(task_id):
        task = task_store._load_task_unlocked(task_id)
        if task.status in {TaskStatus.QUEUED_SEED, TaskStatus.SEEDING, TaskStatus.SEEDED}:
            return False

        plan = _load_json(task.runtime.get("execution_plan_path"))
        seed_stage = plan.get("stages", {}).get("seed", {})
        if not seed_stage.get("execute"):
            logger.warning("[%s] seed 入队跳过：execution_plan 中 seed.execute=False", task_id)
            return False

        index_manifest_path = task.runtime.get("index_manifest_path")
        if not index_manifest_path:
            logger.warning("[%s] seed 入队等待：index_manifest 尚未就绪，路径=%s", task_id, index_manifest_path)
            return False
        build_status = task.runtime.get("build_status")
        if build_status != TaskStatus.BUILT.value:
            logger.warning("[%s] seed 入队等待：build_status=%s，需要 BUILT", task_id, build_status)
            return False
        build_registry_path = task.runtime.get("build_registry_path")
        if not build_registry_path or not Path(build_registry_path).exists():
            logger.warning("[%s] seed 入队等待：build_registry 尚未就绪，路径=%s", task_id, build_registry_path)
            return False

        build_registry = _load_json(build_registry_path)
        if not build_registry.get("harnesses"):
            logger.warning("[%s] seed 入队被阻塞：build_registry.harnesses 为空，无法启动 seed", task_id)
            now = task_store.now()
            task.status = TaskStatus.SEED_FAILED
            task.runtime.update(
                {
                    "seed_blocked_at": now,
                    "seed_blocked_reason": "no_harness",
                    "seed_blocked_build_registry_path": build_registry_path,
                },
            )
            task_store._save_task_unlocked(task)
            return False

        now = task_store.now()
        task.status = TaskStatus.QUEUED_SEED
        task.runtime.update(
            {
                "seed_queue_name": QueueNames.SEED,
                "seed_queued_at": now,
            },
        )
        task_store._save_task_unlocked(task)

    queue.push(QueueNames.SEED, task_id)
    return True

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

from core.campaign import run_campaign
from core.campaign.system_fabric import fail_campaign
from core.models.task import TaskStatus
from core.campaign.executor import InMemoryQueue
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("campaign-worker")


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue | InMemoryQueue, *, requeue: bool = True) -> bool:
    logger.info("campaign received task %s", task_id)
    task = task_store.load_task(task_id)
    if task.status != TaskStatus.CAMPAIGN_RUNNING:
        task_store.update_status(
            task_id,
            TaskStatus.CAMPAIGN_RUNNING,
            runtime_patch={"campaign_started_at": task.runtime.get("campaign_started_at") or task_store.now()},
        )
    result = run_campaign(task_id, task_store)
    if result["completed"]:
        task_store.update_status(
            task_id,
            TaskStatus.CAMPAIGN_COMPLETED,
            runtime_patch={
                "campaign_completed_at": task_store.now(),
                **result,
            },
        )
        logger.info("campaign completed task %s found=%s", task_id, result["found_vuln_ids"])
        queue.ack(QueueNames.CAMPAIGN, task_id)
        return True

    task_store.update_runtime(
        task_id,
        {
            **result,
        },
    )
    if requeue:
        queue.push(QueueNames.CAMPAIGN, task_id)
    queue.ack(QueueNames.CAMPAIGN, task_id)
    logger.info(
        "campaign heartbeat task %s iterations=%s deadline=%s",
        task_id,
        len(result["round_records"]),
        result["campaign_deadline_at"],
    )
    return False


def _run_single_task_daemon(task_id: str) -> None:
    queue = InMemoryQueue()
    task_store = TaskStateStore()
    sleep_seconds = float(os.environ.get("CAMPAIGN_POLL_SECONDS", "60"))
    logger.info("campaign daemon started for task %s", task_id)
    while True:
        completed = process_task(task_id, task_store, queue, requeue=False)
        if completed:
            break
        time.sleep(max(1.0, sleep_seconds))


def main() -> None:
    single_task_id = os.environ.get("CAMPAIGN_TASK_ID")
    if single_task_id:
        _run_single_task_daemon(single_task_id)
        return
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("campaign worker started")
    while True:
        task_id = queue.pop(QueueNames.CAMPAIGN, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("campaign failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.CAMPAIGN_FAILED,
                runtime_patch={"campaign_error": str(exc), "campaign_failed_at": task_store.now()},
            )
            task = task_store.load_task(task_id)
            deadline_raw = (
                task.runtime.get("slot_controller_deadline_at")
                or task.runtime.get("campaign_deadline_at")
                or task.metadata.get("slot_controller_deadline_at")
            )
            remaining_seconds = 0
            if deadline_raw:
                try:
                    deadline_at = datetime.fromisoformat(str(deadline_raw).replace("Z", "+00:00"))
                    remaining_seconds = max(
                        0,
                        int((deadline_at - datetime.now(timezone.utc)).total_seconds()),
                    )
                except ValueError:
                    remaining_seconds = 0
            next_base_task_id = (
                task.runtime.get("campaign_origin_task_ids", [])[-1]
                if task.runtime.get("campaign_origin_task_ids")
                else task.metadata.get("base_task_id")
            )
            fail_campaign(
                campaign_task_id=task_id,
                failure_reason=str(exc),
                remaining_seconds=remaining_seconds,
                next_base_task_id=next_base_task_id,
                requeue_on_failure=bool(task.runtime.get("fabric_work_item_id")),
            )
            queue.ack(QueueNames.CAMPAIGN, task_id)


if __name__ == "__main__":
    main()

import logging
import json
import time

from core.models.task import TaskStatus
from core.protocol import write_protocol_adapter_manifest, write_protocol_execution_manifest
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.storage.layout import protocol_checkpoint_path
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("protocol-execution-worker")


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("protocol placeholder received task %s", task_id)
    started_at = task_store.now()
    task_store.update_status(
        task_id,
        TaskStatus.PROTOCOL_EXECUTING,
        runtime_patch={
            "protocol_execution_started_at": started_at,
            "protocol_execution_heartbeat_at": started_at,
            "protocol_lifecycle_state": "executing",
        },
    )
    task = task_store.load_task(task_id)
    adapter_path = write_protocol_adapter_manifest(task_id, generated_at=task_store.now(), metadata=task.metadata)
    heartbeat_at = task_store.now()
    execution_path = write_protocol_execution_manifest(task_id, generated_at=heartbeat_at, metadata=task.metadata)
    finished_at = task_store.now()
    checkpoint_path = protocol_checkpoint_path(task_id)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path.write_text(
        json.dumps(
            {
                "task_id": task_id,
                "generated_at": finished_at,
                "state": "protocol_not_implemented",
                "started_at": started_at,
                "heartbeat_at": heartbeat_at,
                "finished_at": finished_at,
                "next_action": "stop",
                "worker_slot": "protocol-execution-worker",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    task_store.update_status(
        task_id,
        TaskStatus.PROTOCOL_NOT_IMPLEMENTED,
        runtime_patch={
            "protocol_adapter_manifest_path": str(adapter_path),
            "protocol_execution_manifest_path": str(execution_path),
            "protocol_execution_status": "NOT_IMPLEMENTED",
            "protocol_execution_completed_at": finished_at,
            "protocol_execution_heartbeat_at": heartbeat_at,
            "protocol_checkpoint_path": str(checkpoint_path),
            "protocol_lifecycle_state": "stopped",
            "protocol_worker_slot": "protocol-execution-worker",
        },
    )
    queue.ack(QueueNames.PROTOCOL_EXECUTION, task_id)
    logger.info("task %s protocol placeholder wrote manifest=%s", task_id, execution_path)


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("protocol execution worker started")
    while True:
        task_id = queue.pop(QueueNames.PROTOCOL_EXECUTION, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("protocol execution failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.PROTOCOL_EXECUTION_FAILED,
                runtime_patch={"protocol_execution_error": str(exc), "protocol_execution_failed_at": task_store.now()},
            )
            queue.ack(QueueNames.PROTOCOL_EXECUTION, task_id)


if __name__ == "__main__":
    main()

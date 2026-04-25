import json
import logging
import time

from core.buttercup_compat.scheduler import write_scheduler_fanout_manifest
from core.campaign.coverage_feedback import consume_coverage_feedback_for_scheduler
from core.models.task import ExecutionMode, TaskStatus
from core.planning.execution import build_execution_plan
from core.planning.imports import stage_task_imports
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.storage.layout import (
    adapter_manifest_path,
    execution_plan_path,
    import_manifest_path,
    protocol_adapter_manifest_path,
    protocol_execution_manifest_path,
)
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("scheduler-worker")


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("scheduler received ready task %s", task_id)
    now = task_store.now()
    task = task_store.load_task(task_id)
    import_manifest = stage_task_imports(task, now)
    task = task_store.load_task(task_id)
    plan, adapter_manifest = build_execution_plan(task, now, import_manifest)
    plan, scheduler_feedback = consume_coverage_feedback_for_scheduler(task=task, plan=plan, now=now)
    execution_plan_path(task_id).write_text(json.dumps(plan, indent=2), encoding="utf-8")
    fanout_manifest = write_scheduler_fanout_manifest(task, plan, import_manifest, now)

    runtime_patch = {
        "scheduler_seen_at": now,
        "scheduler_note": "original-buttercup-compatible execution planning",
        "resolved_imports": import_manifest["resolved_paths"],
        "import_manifest_path": str(import_manifest_path(task_id)),
        "asset_import_manifest_path": import_manifest.get("asset_import_manifest_path"),
        "asset_import_mode": import_manifest.get("asset_import_mode"),
        "imported_asset_count": import_manifest.get("imported_asset_count"),
        "execution_plan_path": str(execution_plan_path(task_id)),
        "adapter_manifest_path": str(adapter_manifest_path(task_id)),
        "scheduler_fanout_manifest_path": fanout_manifest["scheduler_fanout_manifest_path"],
        "scheduler_ready_fanout_requests": [
            request["request_type"]
            for request in fanout_manifest.get("requests", [])
            if request.get("execute") or request.get("request_type") == "PatchReservedRequest"
        ],
        "adapter_resolution": plan["adapter_resolution"],
        "adapter_name": plan.get("adapter_name"),
        "planned_execution_mode": plan["execution_mode"],
        "scheduler_consumed_feedback": bool(scheduler_feedback),
    }
    if scheduler_feedback:
        runtime_patch.update(
            {
                "scheduler_feedback_consumption_path": scheduler_feedback["scheduler_feedback_consumption_path"],
                "scheduler_feedback_reason": scheduler_feedback["reason"],
                "scheduler_feedback_before": scheduler_feedback["before"],
                "scheduler_feedback_after": scheduler_feedback["after"],
            },
        )
    binary_stage = plan["stages"].get("binary_analysis", {})
    build_stage = plan["stages"].get("build", {})
    protocol_stage = plan["stages"].get("protocol_execution", {})
    if binary_stage.get("execute"):
        runtime_patch["binary_analysis_backend"] = binary_stage.get("backend")
        runtime_patch["binary_analysis_backend_reason"] = binary_stage.get("backend_selection_reason")
    if build_stage.get("contract"):
        runtime_patch["build_contract"] = build_stage["contract"]
    if protocol_stage.get("execute"):
        runtime_patch["protocol_adapter_manifest_path"] = str(protocol_adapter_manifest_path(task_id))
        runtime_patch["protocol_execution_manifest_path"] = str(protocol_execution_manifest_path(task_id))
    task_store.update_task(
        task_id,
        execution_mode=ExecutionMode(plan["execution_mode"]),
        runtime=runtime_patch,
    )
    if settings.scheduler_ready_hold_seconds > 0:
        logger.info("holding task %s in READY for %s seconds", task_id, settings.scheduler_ready_hold_seconds)
        time.sleep(settings.scheduler_ready_hold_seconds)
    runtime_update = {
        "scheduled_at": task_store.now(),
    }
    if binary_stage.get("execute"):
        queue.push(QueueNames.BINARY_ANALYSIS, task_id)
        runtime_update.update(
            {
                "binary_analysis_queue_name": QueueNames.BINARY_ANALYSIS,
                "binary_analysis_queued_at": task_store.now(),
            },
        )
    if protocol_stage.get("execute"):
        queue.push(QueueNames.PROTOCOL_EXECUTION, task_id)
        runtime_update.update(
            {
                "protocol_execution_queue_name": QueueNames.PROTOCOL_EXECUTION,
                "protocol_execution_queued_at": task_store.now(),
            },
        )
    if plan["stages"]["index"]["execute"]:
        queue.push(QueueNames.INDEX, task_id)
        runtime_update.update(
            {
                "index_queue_name": QueueNames.INDEX,
                "index_queued_at": task_store.now(),
            },
        )
    if plan["stages"]["build"]["execute"]:
        queue.push(QueueNames.BUILD, task_id)
        runtime_update.update(
            {
                "build_queue_name": QueueNames.BUILD,
                "build_queued_at": task_store.now(),
                "build_status": TaskStatus.QUEUED_BUILD.value,
            },
        )
    seed_stage = plan["stages"].get("seed", {})
    if seed_stage.get("task_mode_default"):
        runtime_update["seed_task_mode_default"] = seed_stage["task_mode_default"]
    task_store.update_task(
        task_id,
        status=(
            TaskStatus.QUEUED_BINARY_ANALYSIS
            if binary_stage.get("execute")
            else (
                TaskStatus.QUEUED_PROTOCOL_EXECUTION
                if protocol_stage.get("execute")
                else (TaskStatus.QUEUED_INDEX if plan["stages"]["index"]["execute"] else TaskStatus.SCHEDULED)
            )
        ),
        execution_mode=ExecutionMode(plan["execution_mode"]),
        runtime=runtime_update,
    )
    queue.ack(QueueNames.READY, task_id)
    logger.info(
        "task %s planned adapter=%s mode=%s workers=%s",
        task_id,
        adapter_manifest["adapter_resolution"],
        plan["execution_mode"],
        ",".join(plan["workers_to_run"]),
    )


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("scheduler worker started")
    while True:
        task_id = queue.pop(QueueNames.READY, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("scheduler failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.FAILED,
                runtime_patch={"error": str(exc), "failed_at": task_store.now()},
            )


if __name__ == "__main__":
    main()

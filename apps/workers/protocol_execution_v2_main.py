from __future__ import annotations

import importlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from core.models.task import TaskStatus
from core.protocol_registry import protocol_artifact_runtime_patch
from core.protocol_runtime import DEFAULT_PROTOCOL_TASK_JSON_NAME, canonical_protocol_metadata
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.storage.layout import (
    adapter_manifest_path,
    execution_plan_path,
    import_manifest_path,
    protocol_adapter_manifest_path,
    protocol_backend_task_path,
    protocol_checkpoint_path,
    protocol_execution_manifest_path,
    protocol_heartbeat_path,
    protocol_stage_state_path,
)
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("protocol-execution-worker-v2")


def _configure_proto_environment() -> None:
    os.environ["PROTO_TASKS_ROOT"] = settings.data_root
    os.environ["PROTO_TASK_JSON_NAME"] = settings.protocol_backend_task_json_name or DEFAULT_PROTOCOL_TASK_JSON_NAME
    backend_root = Path(settings.protocol_backend_root).resolve()
    if str(backend_root) not in sys.path:
        sys.path.insert(0, str(backend_root))


def _load_proto_symbols() -> dict[str, Any]:
    _configure_proto_environment()
    runner = importlib.import_module("protofuzz.runner")
    tasking = importlib.import_module("protofuzz.tasking")
    models = importlib.import_module("shared.schemas.models")
    return {
        "run_task": runner.run_task,
        "save_task_record": tasking.save_task_record,
        "ProtoTaskRecord": models.TaskRecord,
        "ProtoTaskSource": models.TaskSource,
    }


def _sync_protocol_backend_task(task_id: str, task_store: TaskStateStore) -> Path:
    task = task_store.load_task(task_id)
    proto = _load_proto_symbols()
    ProtoTaskRecord = proto["ProtoTaskRecord"]
    ProtoTaskSource = proto["ProtoTaskSource"]
    save_task_record = proto["save_task_record"]
    canonical = canonical_protocol_metadata(task.metadata)

    runtime = {
        "localized_inputs": dict(task.runtime.get("localized_inputs") or {}),
        "execution_plan_path": str(execution_plan_path(task_id)),
        "import_manifest_path": str(import_manifest_path(task_id)),
        "adapter_manifest_path": str(adapter_manifest_path(task_id)),
        "network_fuzz_manifest_path": str(protocol_execution_manifest_path(task_id)),
        "protocol_stage_state_path": str(protocol_stage_state_path(task_id)),
        "protocol_checkpoint_path": str(protocol_checkpoint_path(task_id)),
        "protocol_heartbeat_path": str(protocol_heartbeat_path(task_id)),
    }
    proto_record = ProtoTaskRecord(
        task_id=task.task_id,
        source=ProtoTaskSource(adapter_type="protocol", uri=canonical["pcap_path"]),
        status="CREATED",
        metadata={
            "project": task.metadata.get("project") or canonical["protocol"],
            "protocol": canonical["protocol"],
            "pcap_path": canonical["pcap_path"],
            "target_host": canonical["target_host"],
            "target_port": canonical["target_port"],
            "target_service_name": canonical["target_service_name"],
            "prompt_template_path": canonical["prompt_template_path"],
            "connect_timeout_ms": canonical["connect_timeout_ms"],
            "replay_timeout_ms": canonical["replay_timeout_ms"],
            "replay_mode": canonical["replay_mode"],
            "replay_backend": canonical["replay_backend"],
            "start_target": canonical["start_target"],
            "existing_corpus_path": canonical["existing_corpus_path"],
        },
        task_dir=task.task_dir,
        created_at=task.created_at,
        updated_at=task.updated_at,
        layout=task.layout,
        runtime=runtime,
    )
    save_task_record(proto_record)
    return protocol_backend_task_path(task_id)


def _summarize_failure(task_id: str, exc: Exception) -> dict[str, Any]:
    checkpoint = protocol_checkpoint_path(task_id)
    if checkpoint.exists():
        payload = json.loads(checkpoint.read_text(encoding="utf-8"))
        return {
            "error": str(exc),
            "current_stage": payload.get("current_stage"),
            "last_completed_stage": payload.get("last_completed_stage"),
            "next_stage": payload.get("next_stage"),
        }
    return {"error": str(exc)}


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    started_at = task_store.now()
    task_store.update_status(
        task_id,
        TaskStatus.PROTOCOL_EXECUTING,
        runtime_patch={
            "protocol_execution_started_at": started_at,
            "protocol_execution_heartbeat_at": started_at,
            "protocol_lifecycle_state": "executing",
            "protocol_backend_root": settings.protocol_backend_root,
        },
    )
    backend_task_path = _sync_protocol_backend_task(task_id, task_store)
    proto = _load_proto_symbols()
    run_task = proto["run_task"]
    run_task(task_id, resume=False)
    runtime_patch = {
        "protocol_backend_task_path": str(backend_task_path),
        "protocol_stage_state_path": str(protocol_stage_state_path(task_id)),
        "protocol_checkpoint_path": str(protocol_checkpoint_path(task_id)),
        "protocol_heartbeat_path": str(protocol_heartbeat_path(task_id)),
        "protocol_execution_completed_at": task_store.now(),
        "protocol_execution_heartbeat_at": task_store.now(),
        "protocol_lifecycle_state": "completed",
    }
    runtime_patch.update(protocol_artifact_runtime_patch(task_id))
    task_store.update_status(task_id, TaskStatus.PROTOCOL_EXECUTED, runtime_patch=runtime_patch)
    queue.ack(QueueNames.PROTOCOL_EXECUTION, task_id)
    logger.info("protocol task %s executed via proto backend", task_id)


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("protocol execution worker v2 started")
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
                runtime_patch={
                    "protocol_execution_failed_at": task_store.now(),
                    "protocol_execution_error": _summarize_failure(task_id, exc),
                    "protocol_lifecycle_state": "failed",
                },
            )
            queue.ack(QueueNames.PROTOCOL_EXECUTION, task_id)


if __name__ == "__main__":
    main()

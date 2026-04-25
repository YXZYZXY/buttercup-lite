from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path
from urllib.parse import urlparse

from apps.workers.downloader.main import process_task as legacy_process_task
from core.models.task import AdapterType, TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.storage.layout import create_task_layout
from core.utils.settings import expand_local_path, is_remote_uri, settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("downloader-worker-v2")


def _file_uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    return expand_local_path(parsed.path)


def _protocol_input_source(raw_value: str) -> Path:
    if raw_value.startswith("file://"):
        return _file_uri_to_path(raw_value)
    if is_remote_uri(raw_value):
        raise RuntimeError(f"protocol task does not support remote input uri: {raw_value!r}")
    return expand_local_path(raw_value)


def _copy_input(source_path: Path, destination_path: Path) -> Path:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if source_path.is_dir():
        if destination_path.exists():
            shutil.rmtree(destination_path)
        shutil.copytree(source_path, destination_path)
        return destination_path
    shutil.copy2(source_path, destination_path)
    return destination_path


def _process_protocol_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    task_store.update_status(
        task_id,
        TaskStatus.DOWNLOADING,
        runtime_patch={"download_started_at": task_store.now()},
    )
    layout = create_task_layout(task_id)
    task = task_store.load_task(task_id)

    pcap_source = _protocol_input_source(task.source.uri)
    if not pcap_source.exists() or not pcap_source.is_file():
        raise RuntimeError(f"protocol source.uri must point to an existing capture file: {task.source.uri!r}")
    prompt_raw = str(task.metadata.get("prompt_template_path") or "").strip()
    if not prompt_raw:
        raise RuntimeError("protocol tasks require metadata.prompt_template_path")
    prompt_source = _protocol_input_source(prompt_raw)
    if not prompt_source.exists() or not prompt_source.is_file():
        raise RuntimeError(f"protocol prompt_template_path must point to an existing file: {prompt_raw!r}")

    inputs_root = Path(layout["inputs"])
    _copy_input(pcap_source, inputs_root / "sample.pcapng")
    _copy_input(prompt_source, inputs_root / "prompt_template.txt")

    localized_inputs: dict[str, str | None] = {
        "pcap_path": "inputs/sample.pcapng",
        "prompt_template_path": "inputs/prompt_template.txt",
        "existing_corpus_path": None,
    }
    existing_corpus = task.metadata.get("existing_corpus_path")
    if existing_corpus:
        corpus_source = _protocol_input_source(str(existing_corpus))
        if not corpus_source.exists():
            raise RuntimeError(f"protocol existing_corpus_path does not exist: {existing_corpus!r}")
        corpus_name = "existing_corpus"
        if corpus_source.is_file() and corpus_source.suffix:
            corpus_name = f"{corpus_name}{corpus_source.suffix}"
        _copy_input(corpus_source, inputs_root / corpus_name)
        localized_inputs["existing_corpus_path"] = f"inputs/{corpus_name}"

    protocol_name = str(task.metadata.get("protocol") or task.metadata.get("protocol_name") or "unknown_protocol")
    metadata_patch = {
        "protocol": protocol_name,
        "protocol_name": protocol_name,
        "protocol_input_contract": {
            "capture_path": localized_inputs["pcap_path"],
            "prompt_template_path": localized_inputs["prompt_template_path"],
            "existing_corpus_path": localized_inputs["existing_corpus_path"],
            "target": {
                "host": task.metadata.get("target_host"),
                "port": task.metadata.get("target_port"),
                "service_name": task.metadata.get("target_service_name"),
            },
        },
        "pcap_path": localized_inputs["pcap_path"],
        "prompt_template_path": localized_inputs["prompt_template_path"],
        "existing_corpus_path": localized_inputs["existing_corpus_path"],
        "replay_backend": task.metadata.get("replay_backend", "tcp_replay"),
        "replay_mode": task.metadata.get("replay_mode", "application_payload_first"),
        "connect_timeout_ms": task.metadata.get("connect_timeout_ms", 1000),
        "replay_timeout_ms": task.metadata.get("replay_timeout_ms", 3000),
    }
    runtime_patch = {
        "ready_at": task_store.now(),
        "ready_queue_name": QueueNames.READY,
        "source_contract_kind": "protocol_local_files",
        "protocol_localized_at": task_store.now(),
        "localized_inputs": localized_inputs,
        "protocol_capture_path": localized_inputs["pcap_path"],
        "protocol_prompt_template_path": localized_inputs["prompt_template_path"],
    }
    record = task_store.update_task(
        task_id,
        status=TaskStatus.READY,
        layout=layout,
        runtime=runtime_patch,
        metadata=metadata_patch,
    )
    queue.push(QueueNames.READY, task_id)
    queue.ack(QueueNames.DOWNLOAD, task_id)
    logger.info("protocol task %s is %s and pushed to %s", task_id, record.status, QueueNames.READY)


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    task = task_store.load_task(task_id)
    if task.source.adapter_type == AdapterType.PROTOCOL:
        _process_protocol_task(task_id, task_store, queue)
        return
    legacy_process_task(task_id, task_store, queue)


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("downloader worker v2 started")
    while True:
        task_id = queue.pop(QueueNames.DOWNLOAD, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("downloader failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.FAILED,
                runtime_patch={
                    "download_error": str(exc),
                    "failed_at": task_store.now(),
                },
            )


if __name__ == "__main__":
    main()

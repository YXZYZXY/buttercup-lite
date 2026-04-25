from __future__ import annotations

import json
from pathlib import Path

from apps.workers.downloader_v2_main import process_task as download_task
from apps.workers.protocol_execution_v2_main import process_task as protocol_execute_task
from core.models.task import AdapterType, TaskSource, TaskSpec, TaskStatus
from core.planning.execution import build_execution_plan
from core.planning.imports import stage_task_imports
from core.protocol_registry import protocol_artifact_runtime_patch
from core.state.task_state import TaskStateStore
from core.storage.layout import (
    create_task_layout,
    protocol_feedback_path,
    protocol_registry_path,
    protocol_trace_path,
    task_root,
)
from core.utils.settings import settings


class LocalQueue:
    def __init__(self) -> None:
        self.pushed: list[tuple[str, str]] = []
        self.acked: list[tuple[str, str]] = []

    def push(self, queue_name: str, payload: str) -> int:
        self.pushed.append((queue_name, payload))
        return len(self.pushed)

    def ack(self, queue_name: str, payload: str) -> None:
        self.acked.append((queue_name, payload))


def _protocol_spec(tmp_path: Path, *, adapter_type: str = "protocol") -> TaskSpec:
    capture = tmp_path / "sample.pcapng"
    prompt = tmp_path / "prompt.txt"
    capture.write_bytes(b"pcap")
    prompt.write_text("prompt", encoding="utf-8")
    return TaskSpec(
        source=TaskSource(adapter_type=adapter_type, uri=str(capture)),
        metadata={
            "protocol": "http",
            "prompt_template_path": str(prompt),
            "target_host": "127.0.0.1",
            "target_port": 8080,
            "replay_backend": "tcp_replay",
            "replay_mode": "application_payload_first",
        },
    )


def test_protocol_task_creation_accepts_legacy_network_protocol(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "data_root", str(tmp_path / "tasks"))
    store = TaskStateStore()
    record = store.create_task(_protocol_spec(tmp_path, adapter_type="network_protocol"), status=TaskStatus.QUEUED_DOWNLOAD)
    assert record.source.adapter_type == AdapterType.PROTOCOL


def test_protocol_downloader_localizes_inputs_and_skips_source_workspace(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "data_root", str(tmp_path / "tasks"))
    store = TaskStateStore()
    queue = LocalQueue()
    record = store.create_task(_protocol_spec(tmp_path), status=TaskStatus.QUEUED_DOWNLOAD)

    download_task(record.task_id, store, queue)
    updated = store.load_task(record.task_id)

    assert updated.status == TaskStatus.READY
    assert updated.runtime["localized_inputs"]["pcap_path"] == "inputs/sample.pcapng"
    assert updated.runtime["localized_inputs"]["prompt_template_path"] == "inputs/prompt_template.txt"
    assert "source_root" not in updated.runtime
    assert "source_task_normalization_manifest_path" not in updated.runtime
    assert (task_root(record.task_id) / "inputs" / "sample.pcapng").exists()
    assert queue.pushed[-1][0] == "q.tasks.ready"


def test_protocol_scheduler_plan_disables_source_index_build_assumptions(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "data_root", str(tmp_path / "tasks"))
    store = TaskStateStore()
    queue = LocalQueue()
    record = store.create_task(_protocol_spec(tmp_path), status=TaskStatus.QUEUED_DOWNLOAD)
    download_task(record.task_id, store, queue)
    task = store.load_task(record.task_id)
    import_manifest = stage_task_imports(task, store.now())
    plan, adapter_manifest = build_execution_plan(task, store.now(), import_manifest)

    assert plan["adapter_resolution"] == "protocol"
    assert plan["stages"]["protocol_execution"]["execute"] is True
    assert plan["stages"]["index"]["execute"] is False
    assert plan["stages"]["build"]["execute"] is False
    assert plan["stages"]["seed"]["execute"] is False
    assert plan["stages"]["fuzz"]["execute"] is False
    assert adapter_manifest["protocol_name"] == "http"
    assert adapter_manifest["resolved_inputs"]["pcap_path"] == "inputs/sample.pcapng"


def test_protocol_registry_consumer_reads_protocol_assets(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "data_root", str(tmp_path / "tasks"))
    task_id = "protocol-assets"
    layout = create_task_layout(task_id)
    registry_path = protocol_registry_path(task_id)
    feedback_path = protocol_feedback_path(task_id)
    trace_path = protocol_trace_path(task_id)
    trace_path.write_text("{}", encoding="utf-8")
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(
            {
                "task_id": task_id,
                "adapter_type": "protocol",
                "protocol": "http",
                "replay_backend": "tcp_replay",
                "artifacts": {
                    "reports": [{"path": "build/out/reports/replay_results.json"}],
                    "metadata_files": [{"path": "build/out/metadata/protocol_registry.json"}],
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    feedback_path.parent.mkdir(parents=True, exist_ok=True)
    feedback_path.write_text(
        json.dumps({"task_id": task_id, "status_counts": {"http_2xx": 1}}, indent=2),
        encoding="utf-8",
    )

    patch = protocol_artifact_runtime_patch(task_id)
    assert patch["protocol_adapter_type"] == "protocol"
    assert patch["protocol_name"] == "http"
    assert patch["protocol_replay_backend"] == "tcp_replay"
    assert patch["protocol_report_paths"] == ["build/out/reports/replay_results.json"]


def test_protocol_worker_calls_proto_backend_and_updates_task(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "data_root", str(tmp_path / "tasks"))
    monkeypatch.setattr(settings, "protocol_backend_root", str(tmp_path / "proto-backend"))
    store = TaskStateStore()
    queue = LocalQueue()
    record = store.create_task(_protocol_spec(tmp_path), status=TaskStatus.QUEUED_DOWNLOAD)
    download_task(record.task_id, store, queue)
    store.update_task(record.task_id, status=TaskStatus.QUEUED_PROTOCOL_EXECUTION)
    create_task_layout(record.task_id)

    calls: list[tuple[str, bool]] = []

    def fake_sync(task_id: str, task_store: TaskStateStore) -> Path:
        path = task_root(task_id) / "protocol" / "task.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
        return path

    def fake_run_task(task_id: str, resume: bool = False, **_: object) -> dict[str, object]:
        calls.append((task_id, resume))
        protocol_registry_path(task_id).parent.mkdir(parents=True, exist_ok=True)
        protocol_registry_path(task_id).write_text(
            json.dumps(
                {
                    "task_id": task_id,
                    "adapter_type": "protocol",
                    "protocol": "http",
                    "replay_backend": "tcp_replay",
                    "artifacts": {
                        "reports": [{"path": "build/out/reports/replay_results.json"}],
                        "metadata_files": [{"path": "build/out/metadata/protocol_registry.json"}],
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        protocol_feedback_path(task_id).parent.mkdir(parents=True, exist_ok=True)
        protocol_feedback_path(task_id).write_text(
            json.dumps({"task_id": task_id, "status_counts": {"http_2xx": 1}}, indent=2),
            encoding="utf-8",
        )
        protocol_trace_path(task_id).parent.mkdir(parents=True, exist_ok=True)
        protocol_trace_path(task_id).write_text("{}", encoding="utf-8")
        return {"write_feedback": {"status_counts": {"http_2xx": 1}}}

    monkeypatch.setattr("apps.workers.protocol_execution_v2_main._sync_protocol_backend_task", fake_sync)
    monkeypatch.setattr("apps.workers.protocol_execution_v2_main._load_proto_symbols", lambda: {"run_task": fake_run_task})

    protocol_execute_task(record.task_id, store, queue)
    updated = store.load_task(record.task_id)

    assert calls == [(record.task_id, False)]
    assert updated.status == TaskStatus.PROTOCOL_EXECUTED
    assert updated.runtime["protocol_registry_path"].endswith("protocol_registry.json")
    assert updated.runtime["protocol_feedback_path"].endswith("protocol_feedback.json")

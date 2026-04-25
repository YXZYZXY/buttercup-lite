from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models.task import TaskRecord
from core.storage.layout import (
    adapter_manifest_path,
    execution_plan_path,
    import_manifest_path,
    normalized_packets_path,
    normalized_requests_path,
    protocol_adapter_manifest_path,
    protocol_backend_task_path,
    protocol_checkpoint_path,
    protocol_execution_manifest_path,
    protocol_feedback_path,
    protocol_heartbeat_path,
    protocol_registry_path,
    protocol_repro_manifest_path,
    protocol_stage_state_path,
    protocol_trace_path,
    replay_candidates_path,
    replay_results_path,
    seeds_path,
)


PACKET_NORMALIZE_SCHEMA_VERSION = "protocol.normalized_packets.v1"
REQUEST_NORMALIZE_SCHEMA_VERSION = "protocol.normalized_requests.v1"
SEED_SCHEMA_VERSION = "protocol.seeds.v1"
REPLAY_SCHEMA_VERSION = "protocol.replay.v1"
PROTOCOL_REGISTRY_SCHEMA_VERSION = "protocol.registry.v1"
PROTOCOL_FEEDBACK_SCHEMA_VERSION = "protocol.feedback.v1"
STAGE_STATE_SCHEMA_VERSION = "protocol.stage_state.v1"
DEFAULT_PROTOCOL_TASK_JSON_NAME = "protocol/task.json"


def relative_to_task_root(task_root: str | Path, value: str | Path | None) -> str | None:
    if value is None:
        return None
    root = Path(task_root).resolve()
    path = Path(value)
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError:
        return str(value)
    return str(relative) if str(relative) != "." else "."


def canonical_protocol_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    protocol = str(metadata.get("protocol") or metadata.get("protocol_name") or "unknown_protocol")
    return {
        "protocol": protocol,
        "protocol_name": protocol,
        "replay_backend": str(metadata.get("replay_backend") or "tcp_replay"),
        "replay_mode": str(metadata.get("replay_mode") or "application_payload_first"),
        "connect_timeout_ms": int(metadata.get("connect_timeout_ms") or 1000),
        "replay_timeout_ms": int(metadata.get("replay_timeout_ms") or 3000),
        "target_host": metadata.get("target_host"),
        "target_port": metadata.get("target_port"),
        "target_service_name": metadata.get("target_service_name"),
        "pcap_path": metadata.get("pcap_path"),
        "prompt_template_path": metadata.get("prompt_template_path"),
        "existing_corpus_path": metadata.get("existing_corpus_path"),
        "start_target": bool(metadata.get("start_target", False)),
    }


def build_protocol_contract(metadata: dict[str, Any], *, task_root: str | Path) -> dict[str, Any]:
    canonical = canonical_protocol_metadata(metadata)
    return {
        "protocol_name": canonical["protocol"],
        "protocol_input_contract": {
            "capture_path": canonical["pcap_path"],
            "prompt_template_path": canonical["prompt_template_path"],
            "existing_corpus_path": canonical["existing_corpus_path"],
            "target": {
                "host": canonical["target_host"],
                "port": canonical["target_port"],
                "service_name": canonical["target_service_name"],
            },
        },
        "seed_contract": {
            "supported": True,
            "status": "proto_seed_generation",
            "outputs": [relative_to_task_root(task_root, seeds_path(Path(task_root).name))],
        },
        "execution_contract": {
            "supported": True,
            "status": "proto_runner_execution",
            "outputs": [
                relative_to_task_root(task_root, replay_results_path(Path(task_root).name)),
                relative_to_task_root(task_root, protocol_trace_path(Path(task_root).name)),
            ],
        },
        "trace_contract": {
            "supported": True,
            "trace_path": relative_to_task_root(task_root, protocol_trace_path(Path(task_root).name)),
        },
        "coverage_contract": {
            "supported": False,
            "status": "not_available_for_tcp_replay",
        },
    }


def _relative_layout(task: TaskRecord) -> dict[str, str]:
    return {
        key: relative_to_task_root(task.task_dir, value) or str(value)
        for key, value in task.layout.items()
    }


def write_protocol_adapter_manifest(task: TaskRecord, *, generated_at: str, import_manifest: dict[str, Any]) -> dict[str, Any]:
    canonical = canonical_protocol_metadata(task.metadata)
    payload = {
        "task_id": task.task_id,
        "generated_at": generated_at,
        "adapter_name": "protocol_adapter",
        "adapter_resolution": "protocol",
        "protocol_status": "ready",
        "adapter_type": "protocol",
        "protocol": canonical["protocol"],
        "replay_backend": canonical["replay_backend"],
        "replay_mode": canonical["replay_mode"],
        "target": {
            "host": canonical["target_host"],
            "port": canonical["target_port"],
            "service_name": canonical["target_service_name"],
        },
        "contract": {
            "protocol_name": canonical["protocol"],
            "protocol_input_contract": {
                "capture_path": canonical["pcap_path"],
                "prompt_template_path": canonical["prompt_template_path"],
                "existing_corpus_path": canonical["existing_corpus_path"],
            },
            "execution_contract": {
                "supported": True,
                "worker_slot": "protocol-execution-worker",
                "runtime_manifest": "runtime/protocol_execution_manifest.json",
            },
        },
        "resolved_inputs": import_manifest.get("resolved_paths", {}),
        "layout": _relative_layout(task),
        "evidence_path": relative_to_task_root(task.task_dir, protocol_adapter_manifest_path(task.task_id)),
        "proto_backend_task_path": relative_to_task_root(task.task_dir, protocol_backend_task_path(task.task_id)),
    }
    path = protocol_adapter_manifest_path(task.task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def write_protocol_execution_manifest(task: TaskRecord, *, generated_at: str) -> dict[str, Any]:
    canonical = canonical_protocol_metadata(task.metadata)
    payload: dict[str, Any] = {
        "task_id": task.task_id,
        "generated_at": generated_at,
        "adapter_type": "protocol",
        "protocol": canonical["protocol"],
        "replay_backend": canonical["replay_backend"],
        "replay_mode": canonical["replay_mode"],
        "packet_normalize_schema_version": PACKET_NORMALIZE_SCHEMA_VERSION,
        "request_normalize_schema_version": REQUEST_NORMALIZE_SCHEMA_VERSION,
        "seed_schema_version": SEED_SCHEMA_VERSION,
        "replay_schema_version": REPLAY_SCHEMA_VERSION,
        "protocol_registry_schema_version": PROTOCOL_REGISTRY_SCHEMA_VERSION,
        "protocol_feedback_schema_version": PROTOCOL_FEEDBACK_SCHEMA_VERSION,
        "stage_state_schema_version": STAGE_STATE_SCHEMA_VERSION,
        "manifests": {
            "execution_plan_path": relative_to_task_root(task.task_dir, execution_plan_path(task.task_id)),
            "import_manifest_path": relative_to_task_root(task.task_dir, import_manifest_path(task.task_id)),
            "adapter_manifest_path": relative_to_task_root(task.task_dir, adapter_manifest_path(task.task_id)),
            "protocol_adapter_manifest_path": relative_to_task_root(task.task_dir, protocol_adapter_manifest_path(task.task_id)),
            "protocol_backend_task_path": relative_to_task_root(task.task_dir, protocol_backend_task_path(task.task_id)),
            "protocol_stage_state_path": relative_to_task_root(task.task_dir, protocol_stage_state_path(task.task_id)),
            "protocol_checkpoint_path": relative_to_task_root(task.task_dir, protocol_checkpoint_path(task.task_id)),
            "protocol_heartbeat_path": relative_to_task_root(task.task_dir, protocol_heartbeat_path(task.task_id)),
        },
        "inputs": {
            "pcap_path": canonical["pcap_path"],
            "prompt_template_path": canonical["prompt_template_path"],
            "existing_corpus_path": canonical["existing_corpus_path"],
        },
        "outputs": {
            "normalized_packets_path": relative_to_task_root(task.task_dir, normalized_packets_path(task.task_id)),
            "normalized_requests_path": relative_to_task_root(task.task_dir, normalized_requests_path(task.task_id)),
            "seed_corpus_path": relative_to_task_root(task.task_dir, seeds_path(task.task_id)),
            "replay_candidates_path": relative_to_task_root(task.task_dir, replay_candidates_path(task.task_id)),
            "replay_results_path": relative_to_task_root(task.task_dir, replay_results_path(task.task_id)),
            "protocol_trace_path": relative_to_task_root(task.task_dir, protocol_trace_path(task.task_id)),
            "repro_manifest_path": relative_to_task_root(task.task_dir, protocol_repro_manifest_path(task.task_id)),
            "protocol_feedback_path": relative_to_task_root(task.task_dir, protocol_feedback_path(task.task_id)),
            "protocol_registry_path": relative_to_task_root(task.task_dir, protocol_registry_path(task.task_id)),
        },
    }
    path = protocol_execution_manifest_path(task.task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload

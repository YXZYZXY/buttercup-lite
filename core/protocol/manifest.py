from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.protocol.contracts import build_protocol_contract
from core.storage.layout import protocol_adapter_manifest_path, protocol_execution_manifest_path


def write_protocol_adapter_manifest(task_id: str, *, generated_at: str, metadata: dict[str, Any]) -> Path:
    payload = {
        "task_id": task_id,
        "generated_at": generated_at,
        "adapter_name": "protocol_adapter",
        "adapter_resolution": "protocol",
        "protocol_status": "placeholder_not_implemented",
        "contract": build_protocol_contract(metadata),
        "evidence_path": str(protocol_adapter_manifest_path(task_id)),
        "worker_slot": "protocol-execution-worker",
        "scheduler_slot": "q.tasks.protocol_execution",
    }
    path = protocol_adapter_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_protocol_execution_manifest(
    task_id: str,
    *,
    generated_at: str,
    metadata: dict[str, Any],
    status: str = "NOT_IMPLEMENTED",
) -> Path:
    payload: dict[str, Any] = {
        "task_id": task_id,
        "generated_at": generated_at,
        "adapter_name": "protocol_adapter",
        "status": status,
        "not_implemented_reason": "protocol-specific execution is owned by a future protocol implementation",
        "contract": build_protocol_contract(metadata),
        "evidence_path": str(protocol_execution_manifest_path(task_id)),
    }
    path = protocol_execution_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


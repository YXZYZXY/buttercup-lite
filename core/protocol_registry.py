from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.storage.layout import protocol_feedback_path, protocol_registry_path, protocol_trace_path


def read_protocol_registry(task_id: str) -> dict[str, Any]:
    path = protocol_registry_path(task_id)
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def read_protocol_feedback(task_id: str) -> dict[str, Any]:
    path = protocol_feedback_path(task_id)
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def protocol_artifact_runtime_patch(task_id: str) -> dict[str, Any]:
    registry = read_protocol_registry(task_id)
    feedback = read_protocol_feedback(task_id)
    patch: dict[str, Any] = {
        "protocol_registry_path": str(protocol_registry_path(task_id)),
        "protocol_feedback_path": str(protocol_feedback_path(task_id)),
        "protocol_trace_path": str(protocol_trace_path(task_id)),
        "protocol_adapter_type": registry.get("adapter_type"),
        "protocol_name": registry.get("protocol"),
        "protocol_replay_backend": registry.get("replay_backend"),
        "protocol_artifacts": registry.get("artifacts", {}),
        "protocol_feedback_summary": feedback,
    }
    reports = registry.get("artifacts", {}).get("reports", [])
    if reports:
        patch["protocol_report_paths"] = [entry.get("path") for entry in reports]
    return patch

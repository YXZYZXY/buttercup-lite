from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.storage.layout import (
    coverage_to_selector_bridge_manifest_path,
    function_selector_manifest_path,
    harness_selector_manifest_path,
    seed_mode_semantics_manifest_path,
    seed_family_plan_manifest_path,
    seed_mode_trigger_manifest_path,
    seed_task_sampling_manifest_path,
    selector_feedback_consumption_path,
    weighted_function_selector_manifest_path,
    weighted_harness_selector_manifest_path,
)


def _write(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def write_harness_selector_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(harness_selector_manifest_path(task_id), payload)


def write_function_selector_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(function_selector_manifest_path(task_id), payload)


def write_seed_family_plan_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(seed_family_plan_manifest_path(task_id), payload)


def write_weighted_harness_selector_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(weighted_harness_selector_manifest_path(task_id), payload)


def write_weighted_function_selector_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(weighted_function_selector_manifest_path(task_id), payload)


def write_seed_task_sampling_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(seed_task_sampling_manifest_path(task_id), payload)


def write_seed_mode_trigger_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(seed_mode_trigger_manifest_path(task_id), payload)


def write_selector_feedback_consumption(task_id: str, payload: dict[str, Any]) -> str:
    return _write(selector_feedback_consumption_path(task_id), payload)


def write_seed_mode_semantics_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(seed_mode_semantics_manifest_path(task_id), payload)


def write_coverage_to_selector_bridge_manifest(task_id: str, payload: dict[str, Any]) -> str:
    return _write(coverage_to_selector_bridge_manifest_path(task_id), payload)

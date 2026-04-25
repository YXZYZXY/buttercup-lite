from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.binary.manifest import write_json
from core.storage.layout import runtime_dir


def binary_contamination_report_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_contamination_report.json"


def build_contamination_report(task: Any, *, binary_mode: str, seed_imported_count: int = 0) -> dict[str, Any]:
    runtime = getattr(task, "runtime", {}) or {}
    metadata = getattr(task, "metadata", {}) or {}
    resolved_imports = runtime.get("resolved_imports", {}) or {}

    source_context_used = bool(resolved_imports.get("existing_src_path"))
    source_harness_used = bool(resolved_imports.get("existing_harness_dir"))
    source_dict_used = bool(resolved_imports.get("existing_dict_path"))
    source_options_used = bool(resolved_imports.get("existing_options_path"))
    source_program_model_used = bool(resolved_imports.get("existing_index_path") or runtime.get("index_manifest_path"))

    report = {
        "task_id": task.task_id,
        "binary_mode": binary_mode,
        "binary_input_contract": metadata.get("binary_input_contract") or runtime.get("binary_input_contract"),
        "binary_input_contract_source": metadata.get("binary_input_contract_source")
        or runtime.get("binary_input_contract_source"),
        "source_context_used": source_context_used,
        "source_harness_used": source_harness_used,
        "source_seed_imported_count": int(seed_imported_count),
        "source_dict_used": source_dict_used,
        "source_options_used": source_options_used,
        "source_program_model_used": source_program_model_used,
        "pure_binary_eligible": not any(
            [
                source_context_used,
                source_harness_used,
                seed_imported_count > 0,
                source_dict_used,
                source_options_used,
                source_program_model_used,
            ],
        ),
    }
    return report


def write_contamination_report(task: Any, report: dict[str, Any]) -> Path:
    path = binary_contamination_report_path(task.task_id)
    return write_json(path, report)


def load_contamination_report(task_id: str) -> dict[str, Any]:
    path = binary_contamination_report_path(task_id)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))

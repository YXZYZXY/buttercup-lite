from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def is_binary_task(task_dir: Path) -> bool:
    task = _load_json(task_dir / "task.json")
    runtime = task.get("runtime", {})
    return runtime.get("adapter_resolution") == "binary" or runtime.get("target_mode") == "binary"


def load_binary_execution_manifest(task_dir: Path) -> dict[str, Any]:
    return _load_json(task_dir / "runtime" / "binary_execution_manifest.json")


def load_binary_execution_plan(task_dir: Path) -> dict[str, Any]:
    return _load_json(task_dir / "runtime" / "binary_execution_plan.json")


def binary_candidate_dir(task_dir: Path) -> Path:
    task = _load_json(task_dir / "task.json")
    layout = task.get("layout", {})
    return Path(layout.get("crashes_binary_candidates", task_dir / "crashes" / "binary_candidates"))


def binary_provenance(task_dir: Path) -> dict[str, Any]:
    task = _load_json(task_dir / "task.json")
    runtime = task.get("runtime", {})
    metadata = task.get("metadata", {})
    plan = load_binary_execution_plan(task_dir)
    manifest = load_binary_execution_manifest(task_dir)
    delivery_path = plan.get("input_delivery_path") or manifest.get("input_delivery_path")
    semantics_source = Path(delivery_path).name if delivery_path else None
    if (
        runtime.get("binary_provenance")
        or metadata.get("binary_provenance")
        or task.get("binary_provenance")
        or plan.get("binary_provenance")
    ):
        provenance = (
            runtime.get("binary_provenance")
            or metadata.get("binary_provenance")
            or task.get("binary_provenance")
            or plan.get("binary_provenance")
        )
    elif (
        runtime.get("binary_mode")
        or metadata.get("binary_mode")
        or task.get("binary_mode")
        or plan.get("binary_mode")
    ) == "pure_binary":
        provenance = "pure_binary_input"
    else:
        provenance = "source_derived_binary"
    return {
        "target_mode": "binary",
        "binary_provenance": provenance,
        "binary_origin_task_id": plan.get("reused_source_task_id"),
        "binary_target_name": plan.get("binary_target_name") or task.get("metadata", {}).get("binary_target_name"),
        "binary_analysis_backend": runtime.get("binary_analysis_backend"),
        "launcher_semantics_source": semantics_source,
        "seed_provenance": manifest.get("seed_provenance") or plan.get("seed_provenance"),
        "corpus_provenance": manifest.get("corpus_provenance") or plan.get("corpus_provenance"),
        "input_mode": plan.get("input_mode") or manifest.get("input_mode"),
        "selected_binary_slice_focus": manifest.get("selected_binary_slice_focus") or plan.get("selected_binary_slice_focus"),
        "binary_input_contract": manifest.get("binary_input_contract") or plan.get("binary_input_contract"),
        "binary_input_contract_source": manifest.get("binary_input_contract_source") or plan.get("binary_input_contract_source"),
        "binary_input_contract_confidence": manifest.get("binary_input_contract_confidence") or plan.get("binary_input_contract_confidence"),
        "binary_input_contract_confidence_reason": manifest.get("binary_input_contract_confidence_reason") or plan.get("binary_input_contract_confidence_reason"),
    }


def find_run_record_for_testcase(task_dir: Path, testcase_path: str) -> dict[str, Any]:
    manifest = load_binary_execution_manifest(task_dir)
    testcase_name = Path(testcase_path).name
    for candidate in manifest.get("crash_candidates", []):
        if Path(candidate.get("candidate_path", "")).name == testcase_name:
            input_path = candidate.get("input_path")
            for run_record in manifest.get("run_records", []):
                if run_record.get("input_path") == input_path:
                    return run_record
    for run_record in manifest.get("run_records", []):
        if Path(run_record.get("input_path", "")).name == testcase_name:
            return run_record
    return {}

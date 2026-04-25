from __future__ import annotations

from pathlib import Path
from typing import Any

from core.binary.contamination import load_contamination_report
from core.binary.launcher_resolver import resolve_launcher_binding
from core.binary.manifest import write_json
from core.storage.layout import (
    binary_execution_manifest_copy_path,
    binary_execution_manifest_path,
    binary_execution_plan_copy_path,
    binary_execution_plan_path,
)
from core.utils.settings import load_benchmark_config


def _source_task_id_from_path(path_str: str | None) -> str | None:
    if not path_str:
        return None
    path = Path(path_str)
    parts = list(path.parts)
    if "tasks" not in parts:
        return None
    index = parts.index("tasks")
    if index + 1 < len(parts):
        return parts[index + 1]
    return None


def build_binary_execution_plan(task, now: str) -> dict[str, Any]:
    benchmark = load_benchmark_config(task.metadata)
    resolved_imports = task.runtime.get("resolved_imports", {})
    binding = resolve_launcher_binding(task)
    task_root = Path(task.task_dir)
    contamination_report = load_contamination_report(task.task_id)
    binary_mode = str(
        task.metadata.get("binary_mode")
        or task.runtime.get("binary_mode")
        or contamination_report.get("binary_mode")
        or "binary_native_proof"
    )
    binary_provenance = str(
        task.metadata.get("binary_provenance")
        or task.runtime.get("binary_provenance")
        or ("pure_binary_input" if binary_mode == "pure_binary" else "source_derived_binary")
    )
    reused_source_task_id = (
        benchmark.get("binary", {}).get("source_task_id")
        or _source_task_id_from_path(resolved_imports.get("existing_binary_path"))
        or _source_task_id_from_path(resolved_imports.get("existing_seed_path"))
        or _source_task_id_from_path(resolved_imports.get("existing_corpus_path"))
    )
    input_delivery_path = binding["input_delivery_path"]
    semantics_source = (
        task.metadata.get("binary_input_contract_source")
        or task.runtime.get("binary_input_contract_source")
        or (Path(input_delivery_path).name if input_delivery_path else None)
    )
    selected_binary_slice_focus = (
        task.runtime.get("selected_binary_slice_focus")
        or task.metadata.get("selected_binary_slice_focus")
    )
    binary_seed_dir = task_root / "binary_seed" / "generated"
    binary_active_corpus_dir = task_root / "corpus" / "binary_active"
    seed_provenance_override = task.metadata.get("existing_seed_provenance")
    corpus_provenance_override = task.metadata.get("existing_corpus_provenance")
    if binary_seed_dir.exists() and any(binary_seed_dir.iterdir()):
        seed_sources = [str(binary_seed_dir)]
        seed_provenance = "binary_native_generated"
    else:
        seed_sources = [resolved_imports.get("existing_seed_path")] if resolved_imports.get("existing_seed_path") else []
        if seed_sources:
            seed_provenance = str(seed_provenance_override or "source_side_imported")
        else:
            seed_provenance = None
    if binary_active_corpus_dir.exists() and any(binary_active_corpus_dir.iterdir()):
        corpus_sources = [str(binary_active_corpus_dir)]
        corpus_provenance = "binary_native_generated"
    else:
        corpus_sources = [resolved_imports.get("existing_corpus_path")] if resolved_imports.get("existing_corpus_path") else []
        if corpus_sources:
            corpus_provenance = str(corpus_provenance_override or "source_side_imported")
        else:
            corpus_provenance = None
    crash_sources = [resolved_imports.get("existing_crashes_path")] if resolved_imports.get("existing_crashes_path") else []
    plan = {
        "task_id": task.task_id,
        "generated_at": now,
        "adapter_resolution": task.runtime.get("adapter_resolution", "binary"),
        "target_mode": "binary",
        "binary_mode": binary_mode,
        "binary_provenance": binary_provenance,
        "binary_analysis_backend": task.runtime.get("binary_analysis_backend"),
        "binary_input_contract": task.metadata.get("binary_input_contract")
        or task.runtime.get("binary_input_contract")
        or binding["input_mode"],
        "binary_input_contract_kind": binding.get("binary_input_contract_kind"),
        "binary_input_contract_hints": binding.get("binary_input_contract_hints", []),
        "binary_input_contract_source": semantics_source,
        "binary_input_contract_confidence": binding.get("input_contract_confidence"),
        "binary_input_contract_confidence_reason": binding.get("input_contract_confidence_reason"),
        "selected_binary_path": binding["selected_binary_path"],
        "selected_launcher_path": binding["selected_launcher_path"],
        "selected_wrapper_path": binding["selected_wrapper_path"],
        "input_mode": binding["input_mode"],
        "input_delivery_path": input_delivery_path,
        "working_directory": binding["working_directory"],
        "argv_template": binding["argv_template"],
        "env_overrides": binding["env_overrides"],
        "seed_sources": seed_sources,
        "corpus_sources": corpus_sources,
        "crash_sources": crash_sources,
        "crash_output_dir": task.layout.get("crashes_binary_candidates"),
        "execution_strategy": binding["execution_strategy"],
        "binary_target_name": task.metadata.get("binary_target_name") or Path(binding["selected_binary_path"]).name,
        "selected_binary_slice_focus": selected_binary_slice_focus,
        "binary_origin_task_id": reused_source_task_id,
        "reused_source_task_id": reused_source_task_id,
        "launcher_semantics_source": semantics_source,
        "seed_provenance": seed_provenance,
        "corpus_provenance": corpus_provenance,
        "binary_native_seed_used": bool(task.runtime.get("binary_native_seed_used")),
        "binary_contamination_report_path": str(
            Path(task.task_dir) / "runtime" / "binary_contamination_report.json",
        ),
        "contamination_report": contamination_report,
        "reused_source_side_assets": {
            key: value
            for key, value in resolved_imports.items()
            if key in {"existing_binary_path", "existing_seed_path", "existing_corpus_path", "existing_crashes_path"}
        },
    }
    write_json(binary_execution_plan_path(task.task_id), plan)
    write_json(binary_execution_plan_copy_path(task.task_id), plan)
    return plan


def write_binary_execution_manifest(task_id: str, payload: dict[str, Any]) -> None:
    write_json(binary_execution_manifest_path(task_id), payload)
    write_json(binary_execution_manifest_copy_path(task_id), payload)

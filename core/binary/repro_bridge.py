from __future__ import annotations

from pathlib import Path
from typing import Any

from core.binary.trace_bridge import binary_provenance, load_binary_execution_plan


def enrich_binary_pov(task_dir: Path, traced_crash: dict[str, Any], pov_record: dict[str, Any]) -> dict[str, Any]:
    provenance = binary_provenance(task_dir)
    plan = load_binary_execution_plan(task_dir)
    pov_record.update(
        {
            "target_mode": provenance.get("target_mode"),
            "binary_provenance": provenance.get("binary_provenance"),
            "binary_analysis_backend": provenance.get("binary_analysis_backend"),
            "binary_origin_task_id": provenance.get("binary_origin_task_id"),
            "launcher_semantics_source": provenance.get("launcher_semantics_source"),
            "seed_provenance": provenance.get("seed_provenance"),
            "corpus_provenance": provenance.get("corpus_provenance"),
            "binary_execution_command": traced_crash.get("binary_execution_command"),
            "input_mode": traced_crash.get("input_mode") or plan.get("input_mode"),
            "crash_source": traced_crash.get("crash_source"),
            "selected_binary_slice_focus": traced_crash.get("selected_binary_slice_focus") or provenance.get("selected_binary_slice_focus"),
            "binary_input_contract": traced_crash.get("binary_input_contract") or provenance.get("binary_input_contract"),
            "binary_input_contract_source": traced_crash.get("binary_input_contract_source") or provenance.get("binary_input_contract_source"),
            "binary_input_contract_confidence": traced_crash.get("binary_input_contract_confidence") or provenance.get("binary_input_contract_confidence"),
            "binary_input_contract_confidence_reason": traced_crash.get("binary_input_contract_confidence_reason") or provenance.get("binary_input_contract_confidence_reason"),
            "execution_signal_category": traced_crash.get("execution_signal_category"),
            "execution_signal_reason": traced_crash.get("execution_signal_reason"),
            "execution_input_path": traced_crash.get("execution_input_path"),
            "execution_input_source_kind": traced_crash.get("execution_input_source_kind"),
            "fallback_trigger_reason": traced_crash.get("fallback_trigger_reason"),
            "fallback_from": traced_crash.get("fallback_from"),
            "fallback_to": traced_crash.get("fallback_to"),
            "fallback_effect": traced_crash.get("fallback_effect"),
        },
    )
    return pov_record

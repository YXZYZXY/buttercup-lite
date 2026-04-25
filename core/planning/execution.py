from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.adapters import get_adapter_definition
from core.builder.contracts import (
    resolve_build_decision,
    resolve_oss_fuzz_project_contract_from_import_manifest,
)
from core.models.task import AdapterType, ExecutionMode, TaskRecord
from core.protocol_runtime import (
    canonical_protocol_metadata,
    relative_to_task_root,
    write_protocol_adapter_manifest,
    write_protocol_execution_manifest,
)
from core.storage.layout import (
    adapter_manifest_path,
    binary_adapter_manifest_path,
    execution_plan_path,
    import_manifest_path,
    protocol_adapter_manifest_path,
    protocol_execution_manifest_path,
    source_resolution_manifest_path,
    source_task_normalization_manifest_path,
)
from core.utils.settings import settings, resolve_text_setting


def load_runtime_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    if not manifest_path.exists():
        return {}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def resolve_adapter(task: TaskRecord) -> AdapterType:
    if task.source.adapter_type == AdapterType.OSSFUZZ and task.metadata.get("existing_binary_path"):
        if not task.metadata.get("existing_oss_fuzz_project_path") and not task.metadata.get("existing_project_yaml_path"):
            return AdapterType.BINARY
    return task.source.adapter_type


def _import_exists(import_manifest: dict[str, Any], field_name: str) -> bool:
    return bool(import_manifest.get("assets", {}).get(field_name, {}).get("exists"))


def _stage_mode(import_manifest: dict[str, Any], import_fields: list[str], *, fresh_if_missing: bool = True) -> ExecutionMode:
    present = [field for field in import_fields if _import_exists(import_manifest, field)]
    if not present:
        return ExecutionMode.FRESH if fresh_if_missing else ExecutionMode.IMPORT_ASSISTED
    if len(present) == len(import_fields) or not fresh_if_missing:
        return ExecutionMode.IMPORT_ASSISTED
    return ExecutionMode.HYBRID


def _summarize_reused_assets(import_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    assets = []
    for field_name, entry in import_manifest.get("assets", {}).items():
        if entry.get("exists"):
            assets.append(
                {
                    "field": field_name,
                    "provided_path": entry["provided_path"],
                    "resolved_path": entry["resolved_path"],
                },
            )
    return assets


def _top_level_execution_mode(stage_modes: list[ExecutionMode], reused_assets: list[dict[str, Any]]) -> ExecutionMode:
    if not reused_assets:
        return ExecutionMode.FRESH
    if all(mode == ExecutionMode.IMPORT_ASSISTED for mode in stage_modes):
        return ExecutionMode.IMPORT_ASSISTED
    if any(mode == ExecutionMode.IMPORT_ASSISTED for mode in stage_modes) or any(mode == ExecutionMode.HYBRID for mode in stage_modes):
        return ExecutionMode.HYBRID
    return ExecutionMode.FRESH


def _binary_backend(task: TaskRecord, import_manifest: dict[str, Any]) -> tuple[str, str]:
    requested = resolve_text_setting(task.metadata, "binary_analysis_backend", "")
    if requested and requested.lower() != "auto":
        return str(requested), "explicit_task_override"
    default_backend = settings.binary_default_backend.strip().lower()
    if default_backend not in {"", "auto"}:
        return default_backend, "settings_default_override"
    if _import_exists(import_manifest, "existing_binary_analysis_path"):
        return "imported_analysis", "imported_analysis_available"
    if _import_exists(import_manifest, "existing_wrapper_path") or _import_exists(import_manifest, "existing_launcher_path"):
        return "wrapper_script", "wrapper_or_launcher_available"
    if settings.ida_mcp_configured():
        return "ida_mcp", "ida_mcp_configured"
    return "wrapper_script", "auto_fallback_without_ida_or_imported_analysis"


def _build_binary_plan(task: TaskRecord, now: str, import_manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    reused_assets = _summarize_reused_assets(import_manifest)
    backend, backend_reason = _binary_backend(task, import_manifest)
    adapter_definition = get_adapter_definition(AdapterType.BINARY)
    if task.execution_mode is not None:
        execution_mode = task.execution_mode
    elif _import_exists(import_manifest, "existing_binary_analysis_path"):
        execution_mode = ExecutionMode.IMPORT_ASSISTED
    elif _import_exists(import_manifest, "existing_binary_path"):
        execution_mode = ExecutionMode.HYBRID
    else:
        execution_mode = ExecutionMode.HYBRID

    stages = {
        "binary_analysis": {
            "mode": execution_mode.value,
            "execute": True,
            "queue": "q.tasks.binary_analysis",
            "worker": "binary-analysis-worker",
            "backend": backend,
            "backend_selection_reason": backend_reason,
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_binary_path"),
                import_manifest.get("resolved_paths", {}).get("existing_binary_analysis_path"),
                import_manifest.get("resolved_paths", {}).get("existing_wrapper_path"),
                import_manifest.get("resolved_paths", {}).get("existing_launcher_path"),
            ],
        },
        "binary_seed": {
            "mode": execution_mode.value,
            "execute": True,
            "queue": "q.tasks.binary_seed",
            "worker": "binary-seed-worker",
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_binary_path"),
                import_manifest.get("resolved_paths", {}).get("existing_binary_analysis_path"),
                import_manifest.get("resolved_paths", {}).get("existing_harness_dir"),
                import_manifest.get("resolved_paths", {}).get("existing_dict_path"),
                import_manifest.get("resolved_paths", {}).get("existing_options_path"),
            ],
        },
        "binary_execution": {
            "mode": execution_mode.value,
            "execute": True,
            "queue": "q.tasks.binary_execution",
            "worker": "binary-execution-worker",
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_binary_path"),
                import_manifest.get("resolved_paths", {}).get("existing_seed_path"),
                import_manifest.get("resolved_paths", {}).get("existing_corpus_path"),
                import_manifest.get("resolved_paths", {}).get("existing_crashes_path"),
                import_manifest.get("resolved_paths", {}).get("existing_wrapper_path"),
                import_manifest.get("resolved_paths", {}).get("existing_launcher_path"),
            ],
        },
        "index": {"mode": "disabled", "execute": False, "inputs": []},
        "build": {"mode": "disabled", "execute": False, "inputs": []},
        "seed": {"mode": "disabled", "execute": False, "inputs": []},
        "fuzz": {"mode": "disabled", "execute": False, "inputs": []},
        "trace": {"mode": "disabled", "execute": False, "inputs": []},
        "repro": {"mode": "disabled", "execute": False, "inputs": []},
        "patch": {"mode": "reserved", "execute": False, "inputs": []},
    }
    plan = {
        "task_id": task.task_id,
        "generated_at": now,
        "adapter_resolution": AdapterType.BINARY.value,
        "adapter_name": adapter_definition.name,
        "execution_mode": execution_mode.value,
        "adapter_contracts": adapter_definition.contract_bundle(),
        "reused_assets": reused_assets,
        "workers_to_run": ["binary-analysis-worker", "binary-seed-worker", "binary-execution-worker"],
        "stages": stages,
    }
    execution_plan_file = execution_plan_path(task.task_id)
    execution_plan_file.parent.mkdir(parents=True, exist_ok=True)
    execution_plan_file.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    adapter_manifest = {
        "task_id": task.task_id,
        "generated_at": now,
        "adapter_name": adapter_definition.name,
        "adapter_resolution": AdapterType.BINARY.value,
        "source_adapter": task.source.adapter_type.value,
        "execution_mode": execution_mode.value,
        "contracts": adapter_definition.contract_bundle(),
        "binary_analysis_backend": backend,
        "binary_analysis_backend_reason": backend_reason,
        "source_uri": task.source.uri,
        "binary_target_name": task.metadata.get("binary_target_name"),
        "binary_entry_function": task.metadata.get("binary_entry_function"),
        "resolved_inputs": {
            "existing_binary_path": import_manifest.get("resolved_paths", {}).get("existing_binary_path"),
            "existing_binary_analysis_path": import_manifest.get("resolved_paths", {}).get("existing_binary_analysis_path"),
            "existing_wrapper_path": import_manifest.get("resolved_paths", {}).get("existing_wrapper_path"),
            "existing_launcher_path": import_manifest.get("resolved_paths", {}).get("existing_launcher_path"),
            "existing_src_path": import_manifest.get("resolved_paths", {}).get("existing_src_path"),
            "existing_seed_path": import_manifest.get("resolved_paths", {}).get("existing_seed_path"),
            "existing_corpus_path": import_manifest.get("resolved_paths", {}).get("existing_corpus_path"),
            "existing_crashes_path": import_manifest.get("resolved_paths", {}).get("existing_crashes_path"),
        },
    }
    adapter_manifest_file = adapter_manifest_path(task.task_id)
    adapter_manifest_file.parent.mkdir(parents=True, exist_ok=True)
    adapter_manifest_file.write_text(json.dumps(adapter_manifest, indent=2), encoding="utf-8")

    binary_adapter_file = binary_adapter_manifest_path(task.task_id)
    binary_adapter_file.parent.mkdir(parents=True, exist_ok=True)
    binary_adapter_file.write_text(json.dumps(adapter_manifest, indent=2), encoding="utf-8")
    return plan, adapter_manifest


def _build_protocol_plan(task: TaskRecord, now: str, import_manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    adapter_definition = get_adapter_definition(AdapterType.PROTOCOL)
    execution_mode = task.execution_mode or ExecutionMode.IMPORT_ASSISTED
    protocol = canonical_protocol_metadata(task.metadata)
    protocol_manifest = write_protocol_adapter_manifest(task, generated_at=now, import_manifest=import_manifest)
    protocol_execution_manifest = write_protocol_execution_manifest(task, generated_at=now)
    adapter_contracts = {
        "input_contract": {
            "adapter_name": "protocol_adapter",
            "input_kind": "protocol_local_capture",
            "required_fields": ["source.uri", "metadata.prompt_template_path", "metadata.target_host", "metadata.target_port"],
        },
        "execution_contract": {
            "adapter_name": "protocol_adapter",
            "execution_kind": "proto_runner_execution",
            "queue_names": ["q.tasks.protocol_execution"],
            "worker_slots": ["protocol-execution-worker"],
        },
        "evidence_contract": {
            "manifest_paths": [
                "runtime/protocol_execution_manifest.json",
                "runtime/protocol_stage_state.json",
                "build/out/metadata/protocol_registry.json",
            ],
            "report_paths": [
                "artifacts/traces/protocol_trace.jsonl",
                "artifacts/repro/repro_manifest.json",
                "artifacts/feedback/protocol_feedback.json",
            ],
        },
    }
    stages = {
        "protocol_execution": {
            "mode": execution_mode.value,
            "execute": True,
            "queue": "q.tasks.protocol_execution",
            "worker": "protocol-execution-worker",
            "status": "proto_backend_runner",
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("pcap_path"),
                import_manifest.get("resolved_paths", {}).get("prompt_template_path"),
                import_manifest.get("resolved_paths", {}).get("existing_corpus_path"),
            ],
            "outputs": [
                relative_to_task_root(task.task_dir, protocol_execution_manifest_path(task.task_id)),
                relative_to_task_root(task.task_dir, Path(task.layout["artifacts_normalize"]) / "normalized_packets.json"),
                relative_to_task_root(task.task_dir, Path(task.layout["artifacts_normalize"]) / "normalized_requests.json"),
                relative_to_task_root(task.task_dir, Path(task.layout["corpus_raw"]) / "sample.seeds.json"),
                relative_to_task_root(task.task_dir, Path(task.layout["corpus_replay"]) / "replay_results.json"),
                relative_to_task_root(task.task_dir, Path(task.layout["artifacts_traces"]) / "protocol_trace.jsonl"),
                relative_to_task_root(task.task_dir, Path(task.layout["artifacts_repro"]) / "repro_manifest.json"),
                relative_to_task_root(task.task_dir, Path(task.layout["artifacts_feedback"]) / "protocol_feedback.json"),
                relative_to_task_root(task.task_dir, Path(task.layout["build_out_metadata"]) / "protocol_registry.json"),
            ],
        },
        "index": {"mode": "disabled", "execute": False, "inputs": []},
        "build": {"mode": "disabled", "execute": False, "inputs": []},
        "seed": {"mode": "disabled", "execute": False, "inputs": []},
        "fuzz": {"mode": "disabled", "execute": False, "inputs": []},
        "trace": {"mode": "disabled", "execute": False, "inputs": []},
        "repro": {"mode": "disabled", "execute": False, "inputs": []},
        "patch": {"mode": "reserved", "execute": False, "inputs": []},
    }
    plan = {
        "task_id": task.task_id,
        "generated_at": now,
        "adapter_resolution": AdapterType.PROTOCOL.value,
        "adapter_name": adapter_definition.name,
        "execution_mode": execution_mode.value,
        "adapter_contracts": adapter_contracts,
        "reused_assets": _summarize_reused_assets(import_manifest),
        "workers_to_run": ["protocol-execution-worker"],
        "stages": stages,
    }
    execution_plan_file = execution_plan_path(task.task_id)
    execution_plan_file.parent.mkdir(parents=True, exist_ok=True)
    execution_plan_file.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    adapter_manifest = {
        "task_id": task.task_id,
        "generated_at": now,
        "adapter_name": adapter_definition.name,
        "adapter_resolution": AdapterType.PROTOCOL.value,
        "source_adapter": task.source.adapter_type.value,
        "execution_mode": execution_mode.value,
        "contracts": adapter_contracts,
        "protocol_adapter_manifest_path": relative_to_task_root(task.task_dir, protocol_adapter_manifest_path(task.task_id)),
        "protocol_execution_manifest_path": relative_to_task_root(task.task_dir, protocol_execution_manifest_path(task.task_id)),
        "protocol_name": protocol["protocol"],
        "protocol_input_contract": {
            "capture_path": protocol["pcap_path"],
            "prompt_template_path": protocol["prompt_template_path"],
            "existing_corpus_path": protocol["existing_corpus_path"],
            "target": {
                "host": protocol["target_host"],
                "port": protocol["target_port"],
                "service_name": protocol["target_service_name"],
            },
        },
        "replay_backend": protocol["replay_backend"],
        "replay_mode": protocol["replay_mode"],
        "resolved_inputs": import_manifest.get("resolved_paths", {}),
    }
    adapter_manifest_file = adapter_manifest_path(task.task_id)
    adapter_manifest_file.parent.mkdir(parents=True, exist_ok=True)
    adapter_manifest_file.write_text(json.dumps(adapter_manifest, indent=2), encoding="utf-8")
    protocol_adapter_manifest_path(task.task_id).write_text(
        json.dumps({**adapter_manifest, "protocol_manifest": protocol_manifest, "protocol_execution_manifest": protocol_execution_manifest}, indent=2),
        encoding="utf-8",
    )
    return plan, adapter_manifest


def build_execution_plan(task: TaskRecord, now: str, import_manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    adapter = resolve_adapter(task)
    if adapter == AdapterType.BINARY:
        return _build_binary_plan(task, now, import_manifest)
    if adapter == AdapterType.PROTOCOL:
        return _build_protocol_plan(task, now, import_manifest)
    adapter_definition = get_adapter_definition(AdapterType.OSSFUZZ)
    reused_assets = _summarize_reused_assets(import_manifest)
    source_resolution_manifest = load_runtime_manifest(source_resolution_manifest_path(task.task_id))
    source_normalization_manifest = load_runtime_manifest(source_task_normalization_manifest_path(task.task_id))
    oss_fuzz_contract = resolve_oss_fuzz_project_contract_from_import_manifest(import_manifest)
    build_decision = resolve_build_decision(
        project_name=task.metadata.get("project"),
        imported_build_path=import_manifest.get("resolved_paths", {}).get("existing_build_out_path"),
        oss_fuzz_project_contract=oss_fuzz_contract,
        source_dir=task.layout.get("src"),
        source_resolution=source_resolution_manifest,
        task_id=task.task_id,
    )
    build_capability = build_decision.capability

    has_src_import = _import_exists(import_manifest, "existing_src_path")
    has_index_import = _import_exists(import_manifest, "existing_index_path")
    has_build_import = any(
        _import_exists(import_manifest, field)
        for field in (
            "existing_build_out_path",
            "existing_harness_dir",
            "existing_dict_path",
            "existing_options_path",
            "existing_oss_fuzz_project_path",
            "existing_project_yaml_path",
        )
    )
    has_seed_import = any(
        _import_exists(import_manifest, field)
        for field in ("existing_seed_path", "existing_corpus_path")
    )
    has_crash_import = any(
        _import_exists(import_manifest, field)
        for field in ("existing_crashes_path", "existing_valid_crashes_path")
    )

    if has_index_import:
        index_mode = ExecutionMode.IMPORT_ASSISTED
    elif has_src_import:
        index_mode = ExecutionMode.HYBRID
    else:
        index_mode = ExecutionMode.FRESH

    build_mode = ExecutionMode(build_decision.execution_mode)
    seed_mode = ExecutionMode.IMPORT_ASSISTED if has_seed_import else ExecutionMode.FRESH
    fuzz_mode = ExecutionMode.IMPORT_ASSISTED if (has_build_import or has_seed_import) else ExecutionMode.FRESH
    trace_mode = ExecutionMode.IMPORT_ASSISTED if has_crash_import else ExecutionMode.FRESH
    repro_mode = trace_mode

    execution_mode = _top_level_execution_mode(
        [index_mode, build_mode, seed_mode, fuzz_mode, trace_mode, repro_mode],
        reused_assets,
    )

    stages = {
        "index": {
            "mode": index_mode.value,
            "execute": True,
            "queue": "q.tasks.index",
            "worker": "program-model-worker",
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_src_path"),
                import_manifest.get("resolved_paths", {}).get("existing_index_path"),
                task.layout.get("src"),
            ],
        },
        "build": {
            "mode": build_mode.value,
            "execute": build_decision.execute_builder,
            "queue": "q.tasks.build",
            "worker": "builder-worker",
            "contract": {
                "build_decision": build_decision.to_dict(),
                "oss_fuzz_project_contract": oss_fuzz_contract.to_dict(),
                "build_capability": build_capability.to_dict() if build_capability else None,
                "source_resolution": {
                    "resolution_class": source_resolution_manifest.get("resolution_class"),
                    "selected_build_strategy": source_resolution_manifest.get("selected_build_strategy"),
                    "selected_harness_strategy": source_resolution_manifest.get("selected_harness_strategy"),
                    "selected_oss_fuzz_project": source_resolution_manifest.get("selected_oss_fuzz_project"),
                    "discovered_harnesses": source_resolution_manifest.get("discovered_harnesses", []),
                },
                "requested_build_kinds": [
                    "coverage_build",
                    "fuzzer_build",
                    "tracer_build",
                    "patch_qe_build",
                ],
            },
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_build_out_path"),
                import_manifest.get("resolved_paths", {}).get("existing_harness_dir"),
                import_manifest.get("resolved_paths", {}).get("existing_oss_fuzz_project_path"),
                import_manifest.get("resolved_paths", {}).get("existing_project_yaml_path"),
                str(source_resolution_manifest_path(task.task_id)),
            ],
        },
        "seed": {
            "mode": seed_mode.value,
            "execute": adapter != AdapterType.PROTOCOL,
            "queue": "q.tasks.seed",
            "worker": "seed-worker",
            "task_mode_default": "SEED_INIT",
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_seed_path"),
                import_manifest.get("resolved_paths", {}).get("existing_corpus_path"),
                import_manifest.get("resolved_paths", {}).get("existing_build_out_path"),
                import_manifest.get("resolved_paths", {}).get("existing_harness_dir"),
            ],
        },
        "fuzz": {
            "mode": fuzz_mode.value,
            "execute": adapter != AdapterType.PROTOCOL,
            "queue": "q.tasks.fuzz",
            "worker": "fuzzer-worker",
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_corpus_path"),
                import_manifest.get("resolved_paths", {}).get("existing_build_out_path"),
            ],
        },
        "trace": {
            "mode": trace_mode.value,
            "execute": adapter != AdapterType.PROTOCOL,
            "queue": "q.tasks.trace",
            "worker": "tracer-worker",
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_crashes_path"),
                import_manifest.get("resolved_paths", {}).get("existing_valid_crashes_path"),
            ],
        },
        "repro": {
            "mode": repro_mode.value,
            "execute": adapter != AdapterType.PROTOCOL,
            "queue": "q.tasks.repro",
            "worker": "reproducer-worker",
            "inputs": [
                import_manifest.get("resolved_paths", {}).get("existing_valid_crashes_path"),
            ],
        },
        "patch": {
            "mode": "reserved",
            "execute": False,
            "inputs": [],
        },
    }

    plan = {
        "task_id": task.task_id,
        "generated_at": now,
        "adapter_resolution": adapter.value,
        "adapter_name": adapter_definition.name,
        "execution_mode": execution_mode.value,
        "adapter_contracts": adapter_definition.contract_bundle(),
        "reused_assets": reused_assets,
        "source_task_normalization": {
            "manifest_path": str(source_task_normalization_manifest_path(task.task_id)),
            "repo_first": source_normalization_manifest.get("repo_first"),
            "repo_url": source_normalization_manifest.get("repo_url"),
            "normalized_repo_identity": source_normalization_manifest.get("normalized_repo_identity"),
        },
        "source_resolution": {
            "manifest_path": str(source_resolution_manifest_path(task.task_id)),
            "resolution_class": source_resolution_manifest.get("resolution_class"),
            "selected_oss_fuzz_project": source_resolution_manifest.get("selected_oss_fuzz_project"),
            "selected_build_strategy": source_resolution_manifest.get("selected_build_strategy"),
            "selected_harness_strategy": source_resolution_manifest.get("selected_harness_strategy"),
        },
        "build_auto_resolved": build_decision.auto_resolved,
        "build_registry_fallback_used": build_decision.registry_fallback_used,
        "workers_to_run": [stage["worker"] for stage in stages.values() if stage.get("execute") and stage.get("worker")],
        "stages": stages,
    }
    execution_plan_file = execution_plan_path(task.task_id)
    execution_plan_file.parent.mkdir(parents=True, exist_ok=True)
    execution_plan_file.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    adapter_manifest = {
        "task_id": task.task_id,
        "generated_at": now,
        "adapter_name": adapter_definition.name,
        "adapter_resolution": adapter.value,
        "source_adapter": task.source.adapter_type.value,
        "execution_mode": execution_mode.value,
        "contracts": adapter_definition.contract_bundle(),
        "source_uri": task.source.uri,
        "repo_url": task.metadata.get("repo_url"),
        "project": task.metadata.get("project"),
        "source_task_normalization_manifest_path": str(source_task_normalization_manifest_path(task.task_id)),
        "source_resolution_manifest_path": str(source_resolution_manifest_path(task.task_id)),
        "source_resolution": plan.get("source_resolution"),
        "resolved_inputs": {
            "existing_oss_fuzz_project_path": import_manifest.get("resolved_paths", {}).get("existing_oss_fuzz_project_path"),
            "existing_project_yaml_path": import_manifest.get("resolved_paths", {}).get("existing_project_yaml_path"),
            "existing_binary_path": import_manifest.get("resolved_paths", {}).get("existing_binary_path"),
            "existing_binary_analysis_path": import_manifest.get("resolved_paths", {}).get("existing_binary_analysis_path"),
        },
        "oss_fuzz_project_contract": oss_fuzz_contract.to_dict(),
        "build_decision": build_decision.to_dict(),
        "build_capability": build_capability.to_dict() if build_capability else None,
        "build_auto_resolved": build_decision.auto_resolved,
        "build_registry_fallback_used": build_decision.registry_fallback_used,
    }
    adapter_manifest_file = adapter_manifest_path(task.task_id)
    adapter_manifest_file.parent.mkdir(parents=True, exist_ok=True)
    adapter_manifest_file.write_text(json.dumps(adapter_manifest, indent=2), encoding="utf-8")
    return plan, adapter_manifest

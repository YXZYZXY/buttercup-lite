from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from pathlib import Path

from benchmarks.seed_fixtures import build_binary_heuristic_module as build_benchmark_binary_heuristic_module
from config.dataset_contracts import shape_binary_seed_payload
from core.binary import build_binary_execution_plan, build_binary_ida_runtime_view
from core.binary.contamination import load_contamination_report, write_contamination_report
from core.binary_seed import (
    build_binary_seed_messages,
    build_binary_seed_repair_messages,
    execute_seed_functions,
    parse_seed_module,
    retrieve_binary_context,
    write_binary_seed_manifest,
    write_binary_slice,
)
from core.models.task import TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.seed.llm_client import LLMClient, extract_content
from core.seed.llm_client import LLMCallError, build_non_llm_metadata
from core.seed.llm_audit import write_llm_seed_audit
from core.seed import SeedParseError, parse_seed_module_with_repair
from core.seed_strategy import select_seed_task_mode, write_seed_task_manifest
from core.state.task_state import TaskStateStore
from core.storage.layout import binary_execution_plan_path
from core.utils.settings import (
    resolve_float_setting,
    resolve_int_setting,
    resolve_bool_setting,
    resolve_optional_int_setting,
    resolve_text_setting,
    settings,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("binary-seed-worker")


def _write_text(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def _llm_fields(metadata_obj) -> dict[str, object]:
    return metadata_obj.to_dict()


def _clean_policy_fields(metadata: dict[str, object]) -> dict[str, object]:
    return {
        "verification_mode": resolve_text_setting(metadata, "verification_mode", "standard"),
        "seed_material_policy": resolve_text_setting(metadata, "seed_material_policy", "default"),
        "allow_imported_seed_material": resolve_bool_setting(metadata, "allow_imported_seed_material", True),
        "allow_cached_seed_material": resolve_bool_setting(metadata, "allow_cached_seed_material", False),
        "allow_fallback_non_llm": resolve_bool_setting(metadata, "allow_fallback_non_llm", True),
    }


def _write_failure_manifest(task_id: str, task_store: TaskStateStore, error_message: str) -> None:
    task = task_store.load_task(task_id)
    llm_fields = {
        key: value
        for key, value in task.runtime.items()
        if key.startswith("llm_") or key in {"prompt_sha256", "response_sha256", "generated_by"}
    }
    parser_fields = {
        key: value
        for key, value in task.runtime.items()
        if key in {"first_response_status", "parser_first_pass_success", "parser_repair_attempted", "parser_final_success", "parse_failure_reason"}
    }
    policy_fields = {
        key: value
        for key, value in task.runtime.items()
        if key in {
            "verification_mode",
            "seed_material_policy",
            "allow_imported_seed_material",
            "allow_cached_seed_material",
            "allow_fallback_non_llm",
            "seed_provenance",
            "cached_seed_count",
            "fallback_non_llm_used",
        }
    }
    if not llm_fields:
        llm_fields = _llm_fields(
            build_non_llm_metadata(
                generated_by="binary_seed_worker.failure",
                failure_reason=error_message,
                provenance="fallback_non_llm",
            ),
        )
    write_binary_seed_manifest(
        task_id,
        {
            "task_id": task_id,
            "status": TaskStatus.BINARY_SEED_FAILED.value,
            "errors": [error_message],
            "generated_seed_count": 0,
            "output_files": [],
            "llm_used": False,
            "llm_model": settings.llm_model,
            **parser_fields,
            **llm_fields,
            **policy_fields,
        },
    )


def _merge_binary_seeds(generated_files: list[str], corpus_dir: Path) -> list[str]:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    merged: list[str] = []
    for raw_path in generated_files:
        source = Path(raw_path)
        target = corpus_dir / source.name
        if target.exists():
            suffix = 1
            while (corpus_dir / f"{source.stem}_{suffix}{source.suffix}").exists():
                suffix += 1
            target = corpus_dir / f"{source.stem}_{suffix}{source.suffix}"
        shutil.copy2(source, target)
        merged.append(str(target))
    return merged


def _build_binary_heuristic_module(task_mode: str) -> tuple[str, list[str]]:
    return build_benchmark_binary_heuristic_module(task_mode)


def _shape_binary_seed_payload(
    payload: bytes,
    *,
    seed_index: int,
    dataset_contract_context: dict[str, object],
) -> tuple[bytes, list[str]]:
    return shape_binary_seed_payload(
        payload,
        seed_index=seed_index,
        dataset_contract_context=dataset_contract_context,
    )


def _apply_binary_contract_shaping(
    generated_files: list[str],
    *,
    context: object,
) -> tuple[list[str], list[dict[str, object]]]:
    dataset_contract_context = getattr(context, "summary", {}).get("dataset_contract_context", {}) or {}
    notes: list[dict[str, object]] = []
    if not dataset_contract_context:
        return generated_files, notes

    for index, raw_path in enumerate(generated_files):
        path = Path(raw_path)
        original = path.read_bytes()
        shaped, shaping_notes = _shape_binary_seed_payload(
            original,
            seed_index=index,
            dataset_contract_context=dataset_contract_context,
        )
        if shaped != original:
            path.write_bytes(shaped)
        notes.append(
            {
                "path": str(path),
                "changed": shaped != original,
                "applied_notes": shaping_notes,
                "original_size": len(original),
                "shaped_size": len(shaped),
                "payload_sha256": hashlib.sha256(shaped).hexdigest(),
            }
        )
    return generated_files, notes


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("binary seed received task %s", task_id)
    task_store.update_status(
        task_id,
        TaskStatus.BINARY_SEEDING,
        runtime_patch={"binary_seed_started_at": task_store.now()},
    )
    task = task_store.load_task(task_id)
    client = LLMClient()

    metadata = task.metadata or {}
    seed_generation_attempts = resolve_int_setting(
        metadata,
        "SEED_GENERATION_ATTEMPTS",
        settings.seed_generation_attempts,
    )
    seed_function_timeout_seconds = resolve_int_setting(
        metadata,
        "SEED_FUNCTION_TIMEOUT_SECONDS",
        settings.seed_function_timeout_seconds,
    )
    seed_max_bytes = resolve_int_setting(metadata, "SEED_MAX_BYTES", settings.seed_max_bytes)
    llm_temperature = resolve_float_setting(metadata, "LLM_TEMPERATURE", settings.llm_temperature)
    llm_max_tokens = resolve_optional_int_setting(metadata, "LLM_MAX_TOKENS", settings.llm_max_tokens)
    llm_timeout_seconds = resolve_int_setting(
        metadata,
        "LLM_TIMEOUT_SECONDS",
        settings.llm_timeout_seconds,
    )
    llm_max_retries = resolve_int_setting(metadata, "LLM_MAX_RETRIES", settings.llm_max_retries)
    seed_generation_backend = resolve_text_setting(metadata, "SEED_GENERATION_BACKEND", "auto")
    task_partition = resolve_text_setting(metadata, "task_partition", "official_main")
    policy = _clean_policy_fields(metadata)
    allow_fallback_non_llm = bool(policy["allow_fallback_non_llm"])

    task_dir = Path(task.task_dir)
    plan_path = Path(task.runtime.get("binary_execution_plan_path") or binary_execution_plan_path(task_id))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    coverage_manifest_path = task.runtime.get("coverage_feedback_manifest_path")
    coverage_manifest = (
        json.loads(Path(coverage_manifest_path).read_text(encoding="utf-8"))
        if coverage_manifest_path and Path(coverage_manifest_path).exists()
        else None
    )
    seed_decision = select_seed_task_mode(task, coverage_manifest)
    initial_focus_hint = task.runtime.get("selected_binary_slice_focus") or plan.get("selected_binary_slice_focus")
    context = retrieve_binary_context(
        task_dir,
        input_mode=str(plan.get("input_mode") or "file"),
        launcher_semantics_source=plan.get("binary_input_contract_source") or plan.get("launcher_semantics_source"),
    )
    ida_runtime_view = build_binary_ida_runtime_view(task_id, generated_at=task_store.now())
    selected_target_function = str(ida_runtime_view.get("selected_target_function") or "").strip() or None
    focus_hint = initial_focus_hint or selected_target_function
    slice_manifest_path = write_binary_slice(task_id, context)
    contamination_report = load_contamination_report(task_id)

    require_real_llm = seed_generation_backend == "llm"
    raw_response_text = ""
    previous_broken_response: str | None = None
    parsed_module = None
    last_error: str | None = None
    binary_target_name = str(plan.get("binary_target_name") or task.metadata.get("binary_target_name") or "binary")
    llm_used = False
    backend_used = "heuristic_fallback"
    parser_metadata = {
        "first_response_status": "not_attempted",
        "parser_first_pass_success": False,
        "parser_repair_attempted": False,
        "parser_final_success": False,
        "parse_failure_reason": None,
    }
    llm_metadata = build_non_llm_metadata(
        generated_by="binary_seed_worker.heuristic_fallback",
        failure_reason=(
            "seed_generation_backend=heuristic_fallback"
            if seed_generation_backend == "heuristic_fallback"
            else "LLM not attempted yet"
        ),
    )
    if require_real_llm and not client.enabled():
        llm_metadata = build_non_llm_metadata(
            generated_by="binary_seed_worker.llm",
            failure_reason="real LLM requested but LLM is disabled or API key is missing",
            provenance="fallback_non_llm",
        )
        llm_audit_paths = write_llm_seed_audit(
            task_id,
            target_mode="binary",
            task_partition=task_partition,
            requested_seed_backend=seed_generation_backend,
            actual_seed_backend="llm_unavailable",
            llm_metadata=_llm_fields(llm_metadata),
            seed_provenance="no_seed_generated",
            prompt_template_id=f"binary_seed::{seed_decision.mode}::{binary_target_name}",
            task_should_fail_if_llm_missing=require_real_llm,
            fallback_used=False,
            fallback_reason=llm_metadata.llm_failure_reason,
        )
        task_store.update_runtime(task_id, {**_llm_fields(llm_metadata), **llm_audit_paths, "seed_backend_degraded": True})
        raise RuntimeError(llm_metadata.llm_failure_reason or "real LLM requested but unavailable")
    if seed_generation_backend != "heuristic_fallback" and not client.enabled():
        llm_metadata = build_non_llm_metadata(
            generated_by="binary_seed_worker.heuristic_fallback",
            failure_reason="LLM disabled or API key is missing; using non-LLM fallback",
            provenance="fallback_non_llm",
        )
    if seed_generation_backend != "heuristic_fallback" and client.enabled():
        for _attempt in range(seed_generation_attempts):
            if previous_broken_response and last_error:
                messages = build_binary_seed_repair_messages(
                    binary_target_name=binary_target_name,
                    context=context,
                    task_mode=seed_decision.mode,
                    broken_response=previous_broken_response,
                    parse_error=last_error,
                )
            else:
                messages = build_binary_seed_messages(
                    binary_target_name=binary_target_name,
                    context=context,
                    task_mode=seed_decision.mode,
                    focus_hint=focus_hint,
                    previous_error=last_error,
                )
            try:
                response_payload, response_metadata = client.chat_with_metadata(
                    messages,
                    temperature=llm_temperature,
                    max_tokens=llm_max_tokens,
                    timeout_seconds=llm_timeout_seconds,
                    max_retries=llm_max_retries,
                    generated_by="binary_seed_worker.llm",
                )
                llm_metadata = response_metadata
            except Exception as exc:
                if isinstance(exc, LLMCallError):
                    llm_metadata = exc.metadata
                last_error = str(exc)
                logger.warning("binary seed llm failed task=%s error=%s", task_id, last_error)
                if require_real_llm:
                    llm_audit_paths = write_llm_seed_audit(
                        task_id,
                        target_mode="binary",
                        task_partition=task_partition,
                        requested_seed_backend=seed_generation_backend,
                        actual_seed_backend="llm_failed",
                        llm_metadata=_llm_fields(llm_metadata),
                        seed_provenance="no_seed_generated",
                        prompt_template_id=f"binary_seed::{seed_decision.mode}::{binary_target_name}",
                        task_should_fail_if_llm_missing=require_real_llm,
                        fallback_used=False,
                        fallback_reason=llm_metadata.llm_failure_reason,
                    )
                    task_store.update_runtime(task_id, {**_llm_fields(llm_metadata), **llm_audit_paths, "seed_backend_degraded": True})
                    raise
                break
            raw_response_text = extract_content(response_payload)
            parser_metadata["first_response_status"] = llm_metadata.llm_http_status
            try:
                parsed_module, parser_metadata = parse_seed_module_with_repair(raw_response_text)
                llm_used = True
                backend_used = "llm"
                break
            except SeedParseError as exc:
                parser_metadata = exc.metadata
                last_error = str(exc)
                previous_broken_response = raw_response_text
                llm_metadata.llm_failure_reason = f"LLM response parse failure: {last_error}"
                logger.warning("binary seed parse failed task=%s error=%s", task_id, last_error)
                if require_real_llm and _attempt == seed_generation_attempts - 1:
                    llm_audit_paths = write_llm_seed_audit(
                        task_id,
                        target_mode="binary",
                        task_partition=task_partition,
                        requested_seed_backend=seed_generation_backend,
                        actual_seed_backend="llm_parse_failed",
                        llm_metadata=_llm_fields(llm_metadata),
                        seed_provenance="no_seed_generated",
                        prompt_template_id=f"binary_seed::{seed_decision.mode}::{binary_target_name}",
                        task_should_fail_if_llm_missing=require_real_llm,
                        fallback_used=False,
                        fallback_reason=llm_metadata.llm_failure_reason,
                    )
                    task_store.update_runtime(task_id, {**_llm_fields(llm_metadata), **parser_metadata, **llm_audit_paths, "seed_backend_degraded": True})
                    raise RuntimeError(llm_metadata.llm_failure_reason)

    if parsed_module is None:
        if not allow_fallback_non_llm:
            llm_metadata.llm_provenance = "fallback_non_llm"
            llm_metadata.llm_failure_reason = last_error or "LLM output unavailable and fallback is disabled"
            llm_audit_paths = write_llm_seed_audit(
                task_id,
                target_mode="binary",
                task_partition=task_partition,
                requested_seed_backend=seed_generation_backend,
                actual_seed_backend="llm_failed",
                llm_metadata=_llm_fields(llm_metadata),
                seed_provenance="no_seed_generated",
                prompt_template_id=f"binary_seed::{seed_decision.mode}::{binary_target_name}",
                task_should_fail_if_llm_missing=require_real_llm,
                fallback_used=False,
                fallback_reason=llm_metadata.llm_failure_reason,
            )
            task_store.update_runtime(
                task_id,
                {
                    **_llm_fields(llm_metadata),
                    **parser_metadata,
                    **llm_audit_paths,
                    "fallback_non_llm_used": False,
                    "seed_backend_degraded": True,
                },
            )
            raise RuntimeError(llm_metadata.llm_failure_reason)
        raw_response_text, function_names = _build_binary_heuristic_module(seed_decision.mode)
        parsed_module = parse_seed_module(raw_response_text)
        if not parsed_module.function_names:
            parsed_module.function_names = function_names
        backend_used = "heuristic_fallback"
        llm_metadata.llm_provenance = "fallback_non_llm"
        llm_metadata.generated_by = "binary_seed_worker.heuristic_fallback"

    llm_response_path = Path(task.layout["binary_seed"]) / "llm_response.txt"
    generated_module_path = Path(task.layout["binary_seed"]) / "generated_binary_seed_module.py"
    _write_text(llm_response_path, raw_response_text)
    _write_text(generated_module_path, parsed_module.code)

    generated_files, execution_errors = execute_seed_functions(
        task_id,
        parsed_module,
        Path(task.layout["binary_seed_generated"]),
        max_bytes=seed_max_bytes,
        function_timeout_seconds=seed_function_timeout_seconds,
    )
    if not generated_files:
        raise RuntimeError(
            "binary-native generated functions but none executed successfully: "
            + "; ".join(execution_errors or ["no outputs"])
        )
    generated_files, contract_shaping_notes = _apply_binary_contract_shaping(
        generated_files,
        context=context,
    )

    merged_paths = _merge_binary_seeds(generated_files, Path(task.layout["corpus_binary_active"]))
    cached_seed_count = 0
    fallback_non_llm_used = backend_used == "heuristic_fallback"
    seed_provenance = "binary_native_generated" if llm_used else "fallback_non_llm"
    llm_audit_paths = write_llm_seed_audit(
        task_id,
        target_mode="binary",
        task_partition=task_partition,
        requested_seed_backend=seed_generation_backend,
        actual_seed_backend=backend_used,
        llm_metadata=_llm_fields(llm_metadata),
        seed_provenance=seed_provenance,
        prompt_template_id=f"binary_seed::{seed_decision.mode.lower()}",
        task_should_fail_if_llm_missing=require_real_llm,
        fallback_used=fallback_non_llm_used,
        fallback_reason=llm_metadata.llm_failure_reason if fallback_non_llm_used else None,
    )
    manifest_payload = {
        "task_id": task_id,
        "status": TaskStatus.BINARY_SEEDED.value,
        "target_mode": "binary",
        "seed_task_mode": seed_decision.mode,
        "seed_strategy_reason": seed_decision.reason,
        "seed_budget_multiplier": seed_decision.budget_multiplier,
        "binary_mode": plan.get("binary_mode", "binary_native_proof"),
        "binary_native_seed_used": True,
        "binary_target_name": binary_target_name,
        "binary_analysis_backend": task.runtime.get("binary_analysis_backend"),
        "binary_provenance": task.runtime.get("binary_provenance", "source_derived_binary"),
        "binary_provenance_class": ida_runtime_view.get("provenance_class"),
        "launcher_semantics_source": plan.get("binary_input_contract_source") or plan.get("launcher_semantics_source"),
        "binary_input_contract": plan.get("binary_input_contract") or plan.get("input_mode"),
        "binary_input_contract_confidence": plan.get("binary_input_contract_confidence"),
        "binary_input_contract_confidence_reason": plan.get("binary_input_contract_confidence_reason"),
        "input_mode": plan.get("input_mode"),
        "context_sources": context.context_sources,
        "binary_context_package_path": context.context_package_path,
        "binary_target_selection_manifest_path": str(Path(task.task_dir) / "binary" / "binary_target_selection_manifest.json"),
        "binary_ida_runtime_view_path": str(Path(task.task_dir) / "runtime" / "binary_ida_runtime_view.json"),
        "dynamic_observation_bridge_path": str(Path(task.task_dir) / "runtime" / "dynamic_observation_bridge.json"),
        "slice_manifest_path": str(slice_manifest_path),
        "selected_binary_slice_focus": focus_hint,
        "selected_target_function": selected_target_function,
        "binary_contamination_report_path": str(Path(task.task_dir) / "runtime" / "binary_contamination_report.json"),
        "contamination_report": contamination_report,
        "seed_generation_backend": backend_used,
        "llm_used": llm_used,
        "llm_model": client.model if llm_used else None,
        "llm_temperature": llm_temperature,
        "llm_max_tokens": llm_max_tokens,
        **parser_metadata,
        **_llm_fields(llm_metadata),
        **policy,
        "binary_seed_provenance": seed_provenance,
        "task_partition": task_partition,
        "requested_seed_backend": seed_generation_backend,
        "actual_seed_backend": backend_used,
        "cached_seed_count": cached_seed_count,
        "fallback_non_llm_used": fallback_non_llm_used,
        "llm_seed_audit_manifest_path": llm_audit_paths["llm_seed_audit_manifest_path"],
        "llm_backend_integrity_report_path": llm_audit_paths["llm_backend_integrity_report_path"],
        "seed_backend_degradation_report_path": llm_audit_paths["seed_backend_degradation_report_path"],
        "generated_function_count": len(parsed_module.function_names),
        "generated_functions": parsed_module.function_names,
        "generated_seed_count": len(generated_files),
        "generated_module_path": str(generated_module_path),
        "llm_response_path": str(llm_response_path),
        "contract_shaping_applied": any(item.get("changed") for item in contract_shaping_notes),
        "contract_shaping_notes": contract_shaping_notes,
        "output_files": generated_files,
        "merged_corpus_files": merged_paths,
        "errors": execution_errors,
    }
    manifest_path = write_binary_seed_manifest(task_id, manifest_payload)
    seed_task_manifest_path = write_seed_task_manifest(
        task_id,
        target_mode="binary",
        payload={
            "task_id": task_id,
            "generated_at": task_store.now(),
            "adapter_type": "pure_binary_adapter",
            "seed_mode": seed_decision.mode,
            "selection_rationale": seed_decision.reason,
            "input_evidence_refs": [
                value
                for value in [
                    coverage_manifest_path,
                    task.runtime.get("scheduler_feedback_consumption_path"),
                    str(slice_manifest_path),
                    str(plan_path),
                ]
                if value
            ],
            "selected_target": binary_target_name,
            "selected_binary_slice": str(slice_manifest_path),
            "selected_binary_slice_focus": focus_hint,
            "binary_context_package_path": context.context_package_path,
            "binary_target_selection_manifest_path": str(Path(task.task_dir) / "binary" / "binary_target_selection_manifest.json"),
            "budget_input": {
                "seed_generation_attempts": seed_generation_attempts,
                "seed_budget_multiplier": seed_decision.budget_multiplier,
                "priority": seed_decision.priority,
            },
            "feedback_input": {
                "coverage_feedback_manifest_path": task.runtime.get("coverage_feedback_manifest_path"),
                "seed_strategy_reason": seed_decision.reason,
                "binary_ida_runtime_view_path": str(Path(task.task_dir) / "runtime" / "binary_ida_runtime_view.json"),
            },
            "produced_seed_count": len(generated_files),
            "produced_seeds": generated_files,
            "downstream_execution_target": {
                "queue": QueueNames.BINARY_EXECUTION,
                "binary_target": binary_target_name,
                "corpus_binary_active": task.layout["corpus_binary_active"],
            },
            "downstream_execution_linkage": {
                "enqueue_behavior": "binary seed worker queues binary execution",
                "expected_next_queue": QueueNames.BINARY_EXECUTION,
                "expected_execution_target": binary_target_name,
            },
            "result_summary": {
                "seed_generation_backend": backend_used,
                "llm_used": llm_used,
                "llm_provenance": llm_metadata.llm_provenance,
                "llm_real_call_verified": llm_metadata.llm_real_call_verified,
                "requested_seed_backend": seed_generation_backend,
                "actual_seed_backend": backend_used,
                "generated_seed_count": len(generated_files),
                "binary_input_contract": plan.get("binary_input_contract") or plan.get("input_mode"),
                "contract_shaping_applied": any(item.get("changed") for item in contract_shaping_notes),
                "task_partition": task_partition,
            },
            **parser_metadata,
            **policy,
            "binary_seed_provenance": seed_provenance,
            "task_partition": task_partition,
            "requested_seed_backend": seed_generation_backend,
            "actual_seed_backend": backend_used,
            "cached_seed_count": cached_seed_count,
            "fallback_non_llm_used": fallback_non_llm_used,
            **llm_audit_paths,
            **_llm_fields(llm_metadata),
        },
    )
    contamination_report["source_seed_imported_count"] = 0
    write_contamination_report(task, contamination_report)

    task_store.update_status(
        task_id,
        TaskStatus.BINARY_SEEDED,
        runtime_patch={
            "binary_seed_completed_at": task_store.now(),
            "binary_seed_manifest_path": str(manifest_path),
            "binary_seed_task_manifest_path": str(seed_task_manifest_path),
            "binary_slice_manifest_path": str(slice_manifest_path),
            "binary_native_seed_used": True,
            "binary_seed_generated_count": len(generated_files),
            "contract_shaping_applied": any(item.get("changed") for item in contract_shaping_notes),
            "contract_shaping_notes": contract_shaping_notes,
            "binary_seed_context_sources": context.context_sources,
            "binary_context_package_path": context.context_package_path,
            "binary_target_selection_manifest_path": str(Path(task.task_dir) / "binary" / "binary_target_selection_manifest.json"),
            "binary_ida_runtime_view_path": str(Path(task.task_dir) / "runtime" / "binary_ida_runtime_view.json"),
            "dynamic_observation_bridge_path": str(Path(task.task_dir) / "runtime" / "dynamic_observation_bridge.json"),
            "binary_mode": plan.get("binary_mode", "binary_native_proof"),
            "binary_provenance_class": ida_runtime_view.get("provenance_class"),
            "selected_binary_slice_focus": focus_hint,
            "selected_target_function": selected_target_function,
            "seed_provenance": "binary_native_generated",
            "corpus_provenance": "binary_native_generated",
            "seed_task_mode": seed_decision.mode,
            "seed_strategy_reason": seed_decision.reason,
            "seed_budget_multiplier": seed_decision.budget_multiplier,
            "seed_generation_backend": backend_used,
            "llm_used": llm_used,
            **parser_metadata,
            **_llm_fields(llm_metadata),
            **policy,
            "seed_provenance": seed_provenance,
            "task_partition": task_partition,
            "binary_seed_provenance": seed_provenance,
            "requested_seed_backend": seed_generation_backend,
            "actual_seed_backend": backend_used,
            "cached_seed_count": cached_seed_count,
            "fallback_non_llm_used": fallback_non_llm_used,
            **llm_audit_paths,
        },
    )

    updated_task = task_store.load_task(task_id)
    execution_plan = build_binary_execution_plan(updated_task, task_store.now())
    queue.push(QueueNames.BINARY_EXECUTION, task_id)
    task_store.update_status(
        task_id,
        TaskStatus.QUEUED_BINARY_EXECUTION,
        runtime_patch={
            "binary_execution_plan_path": str(binary_execution_plan_path(task_id)),
            "binary_execution_queue_name": QueueNames.BINARY_EXECUTION,
            "binary_execution_queued_at": task_store.now(),
            "binary_execution_status": TaskStatus.QUEUED_BINARY_EXECUTION.value,
            "binary_execution_strategy": execution_plan.get("execution_strategy"),
        },
    )
    queue.ack(QueueNames.BINARY_SEED, task_id)
    logger.info("task %s binary-native seeded generated=%s", task_id, len(generated_files))


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("binary seed worker started")
    while True:
        task_id = queue.pop(QueueNames.BINARY_SEED, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("binary seed failed for task %s: %s", task_id, exc)
            _write_failure_manifest(task_id, task_store, str(exc))
            existing_runtime = task_store.load_task(task_id).runtime
            llm_fields = {
                key: value
                for key, value in existing_runtime.items()
                if key.startswith("llm_") or key in {"prompt_sha256", "response_sha256", "generated_by"}
            }
            if not llm_fields:
                llm_fields = _llm_fields(
                    build_non_llm_metadata(
                        generated_by="binary_seed_worker.failure",
                        failure_reason=str(exc),
                        provenance="fallback_non_llm",
                    ),
                )
            task_store.update_status(
                task_id,
                TaskStatus.BINARY_SEED_FAILED,
                runtime_patch={
                    "binary_seed_failed_at": task_store.now(),
                    "binary_seed_error": str(exc),
                    **llm_fields,
                },
            )
            queue.ack(QueueNames.BINARY_SEED, task_id)


if __name__ == "__main__":
    main()

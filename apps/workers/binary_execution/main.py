import json
import logging
import time
from pathlib import Path

from core.binary import (
    BinaryExecutionRequest,
    build_binary_execution_plan,
    build_binary_feedback_bridge,
    run_binary_execution,
    stage_binary_execution_inputs,
    write_binary_execution_manifest,
)
from core.binary.contamination import load_contamination_report, write_contamination_report
from core.binary.launcher_resolver import resolve_launcher_binding
from core.models.task import TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.tracer.queue import maybe_enqueue_trace
from core.state.task_state import TaskStateStore
from core.storage.layout import (
    binary_backend_requirements_manifest_path,
    binary_candidate_promotion_report_path,
    binary_feedback_bridge_path,
    binary_observation_comparison_manifest_path,
    binary_project_local_denoising_manifest_path,
    binary_replay_profile_manifest_path,
    binary_runtime_noise_filter_manifest_path,
    binary_runtime_signal_classifier_report_path,
    binary_signal_visibility_manifest_path,
    binary_execution_manifest_path,
    binary_observation_gap_report_path,
    binary_execution_plan_path,
    binary_trace_eligibility_manifest_path,
    binary_signal_promotion_analysis_path,
    contract_confidence_manifest_path,
    dynamic_observation_bridge_path,
    semantic_signal_upgrade_attempts_path,
)
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("binary-execution-worker")


def _queue_binary_generalized_trace(
    task_id: str,
    *,
    task_store: TaskStateStore,
    queue: RedisQueue,
    feedback_bridge_payload: dict,
) -> bool:
    trace_candidates = list(feedback_bridge_payload.get("trace_admission_candidates") or [])
    if not trace_candidates:
        return False
    task = task_store.load_task(task_id)
    if task.status in {TaskStatus.QUEUED_TRACE, TaskStatus.TRACING, TaskStatus.TRACED, TaskStatus.POV_CONFIRMED}:
        return False
    task_store.update_status(
        task_id,
        TaskStatus.QUEUED_TRACE,
        runtime_patch={
            "trace_queue_name": QueueNames.TRACE,
            "trace_queued_at": task_store.now(),
            "trace_gate_decision": "queued",
            "trace_gate_reason": "binary_generalized_candidate_trace_admission_available",
            "trace_gate_candidate_count": len(trace_candidates),
            "trace_gate_candidate_origin_kind": "suspicious_candidate",
            "suspicious_candidate_queue_path": feedback_bridge_payload.get("trace_candidate_queue_path"),
            "suspicious_candidate_count_available": len(trace_candidates),
            "binary_trace_candidate_queue_path": feedback_bridge_payload.get("trace_candidate_queue_path"),
        },
    )
    queue.push(QueueNames.TRACE, task_id)
    return True


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("binary execution received task %s", task_id)
    task_store.update_status(
        task_id,
        TaskStatus.BINARY_EXECUTING,
        runtime_patch={
            "binary_execution_started_at": task_store.now(),
            "binary_execution_status": TaskStatus.BINARY_EXECUTING.value,
        },
    )
    task = task_store.load_task(task_id)
    plan = build_binary_execution_plan(task, task_store.now())
    binding = resolve_launcher_binding(task)
    inputs = stage_binary_execution_inputs(task)
    semantics_source = (
        plan.get("binary_input_contract_source")
        or (Path(binding["input_delivery_path"]).name if binding.get("input_delivery_path") else None)
    )
    request = BinaryExecutionRequest(
        task_id=task_id,
        binary_path=Path(binding["selected_binary_path"]),
        binary_name=task.metadata.get("binary_target_name") or Path(binding["selected_binary_path"]).name,
        analysis_backend=task.runtime.get("binary_analysis_backend", "unknown"),
        selected_launcher_path=Path(binding["selected_launcher_path"]),
        selected_wrapper_path=Path(binding["selected_wrapper_path"]) if binding.get("selected_wrapper_path") else None,
        input_mode=binding["input_mode"],
        input_delivery_path=Path(binding["input_delivery_path"]) if binding.get("input_delivery_path") else None,
        working_directory=Path(binding["working_directory"]),
        argv_template=list(binding["argv_template"]),
        env_overrides=dict(binding.get("env_overrides") or {}),
        seed_sources=list(plan.get("seed_sources") or []),
        corpus_sources=list(plan.get("corpus_sources") or []),
        crash_sources=list(plan.get("crash_sources") or []),
        crash_output_dir=Path(plan["crash_output_dir"]),
        log_dir=Path(task.layout["logs"]),
        execution_strategy=plan["execution_strategy"],
        inputs=inputs,
        metadata={
            **task.metadata,
            "selected_binary_slice_focus": plan.get("selected_binary_slice_focus"),
            "binary_input_contract": plan.get("binary_input_contract") or plan.get("input_mode"),
            "binary_input_contract_kind": plan.get("binary_input_contract_kind"),
            "binary_input_contract_hints": plan.get("binary_input_contract_hints", []),
            "binary_input_contract_source": plan.get("binary_input_contract_source"),
            "binary_input_contract_confidence": plan.get("binary_input_contract_confidence"),
            "binary_input_contract_confidence_reason": plan.get("binary_input_contract_confidence_reason"),
            "binary_slice_manifest_path": task.runtime.get("binary_slice_manifest_path"),
            "launcher_semantics_source": semantics_source,
        },
    )
    result = run_binary_execution(request)
    result.plan = plan
    seed_provenance = plan.get("seed_provenance")
    corpus_provenance = plan.get("corpus_provenance")
    contamination_report = load_contamination_report(task_id)
    imported_input_count = sum(
        1 for entry in inputs if entry.source_kind in {"imported_seed", "imported_corpus", "imported_testcase"}
    )
    imported_sources_are_binary_native = (
        plan.get("seed_provenance") == "binary_native_generated"
        and plan.get("corpus_provenance") == "binary_native_generated"
    )
    contamination_report["source_seed_imported_count"] = 0 if imported_sources_are_binary_native else imported_input_count
    contamination_report["pure_binary_eligible"] = not any(
        [
            contamination_report.get("source_context_used"),
            contamination_report.get("source_harness_used"),
            contamination_report.get("source_seed_imported_count", 0) > 0,
            contamination_report.get("source_dict_used"),
            contamination_report.get("source_options_used"),
            contamination_report.get("source_program_model_used"),
        ],
    )
    contamination_path = write_contamination_report(task, contamination_report)
    manifest = {
        **result.manifest,
        "generated_at": task_store.now(),
        "target_mode": "binary",
        "binary_mode": plan.get("binary_mode", "binary_native_proof"),
        "binary_provenance": plan.get("binary_provenance", "source_derived_binary"),
        "binary_origin_task_id": plan.get("binary_origin_task_id") or plan.get("reused_source_task_id"),
        "launcher_semantics_source": semantics_source,
        "binary_input_contract": plan.get("binary_input_contract") or plan.get("input_mode"),
        "binary_input_contract_kind": plan.get("binary_input_contract_kind"),
        "binary_input_contract_hints": plan.get("binary_input_contract_hints", []),
        "binary_input_contract_source": plan.get("binary_input_contract_source"),
        "binary_input_contract_confidence": plan.get("binary_input_contract_confidence"),
        "binary_input_contract_confidence_reason": plan.get("binary_input_contract_confidence_reason"),
        "seed_provenance": seed_provenance,
        "corpus_provenance": corpus_provenance,
        "selected_binary_slice_focus": plan.get("selected_binary_slice_focus"),
        "binary_execution_plan_path": str(binary_execution_plan_path(task_id)),
        "binary_contamination_report_path": str(contamination_path),
        "contamination_report": contamination_report,
        "reused_source_side_assets": plan.get("reused_source_side_assets", {}),
        "pure_binary_side_outputs": {
            "binary_execution_manifest.json": str(binary_execution_manifest_path(task_id)),
            "binary_candidates_dir": task.layout.get("crashes_binary_candidates"),
            "logs_dir": task.layout.get("logs"),
        },
        "staged_inputs": [entry.model_dump(mode="json") for entry in inputs],
        "binary_native_seed_used": bool(plan.get("binary_native_seed_used")),
        "fallback_trigger_reason": None,
        "fallback_from": None,
        "fallback_to": None,
        "fallback_effect": None,
    }
    write_binary_execution_manifest(task_id, manifest)
    contract_confidence_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "binary_input_contract": manifest.get("binary_input_contract"),
        "binary_input_contract_kind": manifest.get("binary_input_contract_kind"),
        "binary_input_contract_hints": manifest.get("binary_input_contract_hints", []),
        "binary_input_contract_source": manifest.get("binary_input_contract_source"),
        "binary_input_contract_confidence": manifest.get("binary_input_contract_confidence"),
        "binary_input_contract_confidence_reason": manifest.get("binary_input_contract_confidence_reason"),
        "launcher_semantics_source": manifest.get("launcher_semantics_source"),
        "launcher_contract": manifest.get("launcher_contract"),
    }
    contract_confidence_path = contract_confidence_manifest_path(task_id)
    contract_confidence_path.parent.mkdir(parents=True, exist_ok=True)
    contract_confidence_path.write_text(json.dumps(contract_confidence_payload, indent=2), encoding="utf-8")
    target_selection = {}
    if task.runtime.get("binary_target_selection_manifest_path"):
        selection_path = Path(task.runtime["binary_target_selection_manifest_path"])
        if selection_path.exists():
            target_selection = json.loads(selection_path.read_text(encoding="utf-8"))
    selected_target_function = target_selection.get("selected_target_function")
    selected_target_is_project_local = bool(target_selection.get("query_backend_dominant")) or any(
        item.get("project_local_match")
        for item in (target_selection.get("candidate_preview") or [])[:3]
        if item.get("name") == selected_target_function
    )
    promotion_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "signal_category_counts": manifest.get("signal_category_counts", {}),
        "semantic_subcategory_distribution": manifest.get("semantic_subcategory_distribution", {}),
        "promotion_rate": manifest.get("promotion_rate"),
        "candidate_promotion_rules": manifest.get("candidate_promotion_rules"),
        "top_signal_examples": manifest.get("per_input_execution_summary", [])[:8],
        "blocker_summary": (
            "all observed inputs remained in parser-reject or format-mismatch style buckets; current bottleneck is contract-aware seed shaping and target-specific semantic exercise"
            if not result.crash_candidates
            and not any(
                key in {"suspicious_semantic_signal", "semantic_crash_candidate"}
                for key in manifest.get("signal_category_counts", {})
            )
            else None
        ),
    }
    promotion_path = binary_signal_promotion_analysis_path(task_id)
    promotion_path.parent.mkdir(parents=True, exist_ok=True)
    promotion_path.write_text(json.dumps(promotion_payload, indent=2), encoding="utf-8")
    observation_gap_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "selected_target_function": selected_target_function,
        "binary_input_contract": manifest.get("binary_input_contract"),
        "signal_category_counts": manifest.get("signal_category_counts", {}),
        "top_signal_examples": manifest.get("per_input_execution_summary", [])[:8],
        "current_highest_signal_category": (
            "semantic_crash_candidate"
            if result.crash_candidates
            else next(iter(manifest.get("signal_category_counts", {})), None)
        ),
        "observation_gap_summary": (
            "current suspicious signals are dominated by LeakSanitizer/runtime noise during replay; this is strong enough for a project-local watchlist but not yet canonical enough for trace promotion"
            if (manifest.get("signal_category_counts") or {}).get("suspicious_semantic_signal")
            else "all runs returned informational fixed-input replay output; current observation layer cannot distinguish parser-format mismatch from semantically accepted-but-benign execution"
            if not result.crash_candidates
            and list((manifest.get("signal_category_counts") or {}).keys()) == ["informational_runtime_output"]
            else None
        ),
        "next_required_layer": (
            "stronger replay/instrumentation or runtime-noise suppression to separate parser-local fault from sanitizer/runtime wrapper noise"
            if (manifest.get("signal_category_counts") or {}).get("suspicious_semantic_signal")
            else "target-specific stdout/stderr recognizers or protocol-aware parsers"
            if not result.crash_candidates
            else None
        ),
    }
    observation_gap_path = binary_observation_gap_report_path(task_id)
    observation_gap_path.parent.mkdir(parents=True, exist_ok=True)
    observation_gap_path.write_text(json.dumps(observation_gap_payload, indent=2), encoding="utf-8")
    backend_requirements_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "required_for_next_semantic_upgrade": [
            "target-specific stdout/stderr recognizers or protocol-aware parsers",
            "stronger contract-aware seed shaping from launcher/help/output hints",
            "optional richer dynamic observation such as strace/ltrace/lightweight sanitizer build when available",
        ],
        "current_blocker": (
            "fixed-input libFuzzer replay only emits informational runtime output for all seeds"
            if observation_gap_payload.get("observation_gap_summary")
            else None
        ),
    }
    backend_requirements_path = binary_backend_requirements_manifest_path(task_id)
    backend_requirements_path.parent.mkdir(parents=True, exist_ok=True)
    backend_requirements_path.write_text(json.dumps(backend_requirements_payload, indent=2), encoding="utf-8")
    upgrade_attempts_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "attempts": [
            {
                "attempt": "contract_aware_seed_shaping",
                "result": "no_signal_upgrade",
                "reason": observation_gap_payload.get("observation_gap_summary") or "no higher-signal semantic bucket observed",
            }
        ],
    }
    upgrade_attempts_path = semantic_signal_upgrade_attempts_path(task_id)
    upgrade_attempts_path.parent.mkdir(parents=True, exist_ok=True)
    upgrade_attempts_path.write_text(json.dumps(upgrade_attempts_payload, indent=2), encoding="utf-8")
    signal_visibility_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "signal_category_counts": manifest.get("signal_category_counts", {}),
        "semantic_subcategory_distribution": manifest.get("semantic_subcategory_distribution", {}),
        "visible_signal_examples": manifest.get("per_input_execution_summary", [])[:12],
        "stdout_signal_count": sum(1 for record in result.run_records if record.source_of_signal == "stdout"),
        "stderr_signal_count": sum(1 for record in result.run_records if record.source_of_signal == "stderr"),
        "strace_signal_count": sum(1 for record in result.run_records if record.strace_log_path),
        "file_side_effect_count": sum(len(record.observed_file_paths) for record in result.run_records),
        "higher_signal_bucket_present": any(
            key in {
                "semantic_format_mismatch",
                "semantic_usage_rejection",
                "suspicious_semantic_signal",
                "semantic_abort_signal",
                "semantic_memory_violation_like",
                "semantic_crash_candidate",
            }
            for key in (manifest.get("signal_category_counts") or {})
        ),
    }
    signal_visibility_path = binary_signal_visibility_manifest_path(task_id)
    signal_visibility_path.parent.mkdir(parents=True, exist_ok=True)
    signal_visibility_path.write_text(json.dumps(signal_visibility_payload, indent=2), encoding="utf-8")
    replay_profile_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "selected_binary_path": manifest.get("selected_binary_path"),
        "selected_launcher_path": manifest.get("selected_launcher_path"),
        "argv_template": manifest.get("argv_template", []),
        "working_directory": manifest.get("working_directory"),
        "replay_profile": manifest.get("replay_profile", {}),
    }
    replay_profile_path = binary_replay_profile_manifest_path(task_id)
    replay_profile_path.parent.mkdir(parents=True, exist_ok=True)
    replay_profile_path.write_text(json.dumps(replay_profile_payload, indent=2), encoding="utf-8")
    signal_classifier_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "selected_target_function": selected_target_function,
        "classifier_summary": {
            "signal_category_counts": manifest.get("signal_category_counts", {}),
            "semantic_subcategory_distribution": manifest.get("semantic_subcategory_distribution", {}),
            "secondary_direct_rerun_used_count": sum(1 for record in result.run_records if record.secondary_rerun_used),
        },
        "top_examples": [
            {
                "input_path": record.input_path,
                "signal_category": record.signal_category,
                "signal_subcategory": record.signal_subcategory,
                "evidence_snippet": record.evidence_snippet,
                "observation_profile": record.observation_profile,
                "secondary_signal_category": record.secondary_signal_category,
                "secondary_evidence_snippet": record.secondary_evidence_snippet,
            }
            for record in result.run_records[:8]
        ],
    }
    signal_classifier_path = binary_runtime_signal_classifier_report_path(task_id)
    signal_classifier_path.parent.mkdir(parents=True, exist_ok=True)
    signal_classifier_path.write_text(json.dumps(signal_classifier_payload, indent=2), encoding="utf-8")
    watchlist_candidates = []
    for item in manifest.get("per_input_execution_summary", []):
        if item.get("signal_category") != "suspicious_semantic_signal":
            continue
        watchlist_candidates.append(
            {
                "input_path": item.get("input_path"),
                "selected_target_function": selected_target_function,
                "signal_category": item.get("signal_category"),
                "signal_subcategory": item.get("signal_subcategory"),
                "signal_signature": item.get("signal_signature"),
                "evidence_snippet": item.get("evidence_snippet"),
                "promotion_level": "watchlist_semantic_candidate",
            }
        )
        if len(watchlist_candidates) >= 6:
            break
    final_status = (
        TaskStatus.BINARY_CRASH_CANDIDATE_FOUND
        if result.crash_candidates
        else TaskStatus.BINARY_EXECUTED
    )
    trace_eligibility_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "trace_gate_decision": (
            "queued"
            if final_status == TaskStatus.BINARY_CRASH_CANDIDATE_FOUND
            else "watchlist_only"
            if watchlist_candidates and selected_target_is_project_local
            else "blocked"
        ),
        "trace_gate_reason": (
            "semantic_crash_candidate_available"
            if final_status == TaskStatus.BINARY_CRASH_CANDIDATE_FOUND
            else "project_local_suspicious_signal_needs_stronger_replay"
            if watchlist_candidates and selected_target_is_project_local
            else "no_semantic_crash_candidate_promoted"
        ),
        "signal_category_counts": manifest.get("signal_category_counts", {}),
        "candidate_count": len(result.crash_candidates),
        "watchlist_candidate_count": len(watchlist_candidates),
        "selected_target_function": selected_target_function,
        "top_execution_examples": manifest.get("per_input_execution_summary", [])[:8],
    }
    trace_eligibility_path = binary_trace_eligibility_manifest_path(task_id)
    trace_eligibility_path.parent.mkdir(parents=True, exist_ok=True)
    trace_eligibility_path.write_text(json.dumps(trace_eligibility_payload, indent=2), encoding="utf-8")
    candidate_promotion_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "promotion_rate": manifest.get("promotion_rate"),
        "signal_category_counts": manifest.get("signal_category_counts", {}),
        "promoted_candidates": [candidate.model_dump(mode="json") for candidate in result.crash_candidates],
        "watchlist_candidates": watchlist_candidates,
        "selected_target_function": selected_target_function,
        "selected_target_is_project_local": selected_target_is_project_local,
        "non_promoted_examples": [
            {
                "input_path": item.get("input_path"),
                "signal_category": item.get("signal_category"),
                "signal_subcategory": item.get("signal_subcategory"),
                "promotion_reason": item.get("promotion_reason"),
                "evidence_snippet": item.get("evidence_snippet"),
            }
            for item in manifest.get("per_input_execution_summary", [])[:8]
        ],
    }
    candidate_promotion_path = binary_candidate_promotion_report_path(task_id)
    candidate_promotion_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_promotion_path.write_text(json.dumps(candidate_promotion_payload, indent=2), encoding="utf-8")
    observation_comparison_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "binary_context_package_path": task.runtime.get("binary_context_package_path"),
        "binary_target_selection_manifest_path": task.runtime.get("binary_target_selection_manifest_path"),
        "dynamic_observation_bridge_path": str(dynamic_observation_bridge_path(task_id)),
        "static_vs_dynamic": {
            "selected_binary_slice_focus": plan.get("selected_binary_slice_focus"),
            "selected_target_function": selected_target_function,
            "binary_input_contract": manifest.get("binary_input_contract"),
            "dynamic_signal_category_counts": manifest.get("signal_category_counts", {}),
            "dynamic_examples": manifest.get("per_input_execution_summary", [])[:8],
        },
        "binary_project_local_denoising_manifest_path": str(binary_project_local_denoising_manifest_path(task_id)),
        "binary_runtime_noise_filter_manifest_path": str(binary_runtime_noise_filter_manifest_path(task_id)),
    }
    observation_comparison_path = binary_observation_comparison_manifest_path(task_id)
    observation_comparison_path.parent.mkdir(parents=True, exist_ok=True)
    observation_comparison_path.write_text(json.dumps(observation_comparison_payload, indent=2), encoding="utf-8")
    feedback_bridge_payload = build_binary_feedback_bridge(
        task_id,
        generated_at=task_store.now(),
        execution_manifest=manifest,
        trace_eligibility_payload=trace_eligibility_payload,
        candidate_promotion_payload=candidate_promotion_payload,
        signal_promotion_payload=promotion_payload,
        observation_gap_payload=observation_gap_payload,
    )
    task_store.update_status(
        task_id,
        final_status,
        runtime_patch={
            "binary_execution_completed_at": task_store.now(),
            "binary_execution_manifest_path": str(binary_execution_manifest_path(task_id)),
            "binary_execution_status": final_status.value,
            "binary_execution_exit_code": manifest.get("exit_code"),
            "binary_execution_input_count": len(inputs),
            "binary_execution_run_count": len(result.run_records),
            "binary_execution_crash_candidate_count": len(result.crash_candidates),
            "active_harness": request.binary_name,
            "active_harness_path": str(request.binary_path),
            "target_mode": "binary",
            "binary_mode": plan.get("binary_mode", "binary_native_proof"),
            "binary_provenance": plan.get("binary_provenance", "source_derived_binary"),
            "binary_origin_task_id": plan.get("binary_origin_task_id") or plan.get("reused_source_task_id"),
            "launcher_semantics_source": semantics_source,
            "binary_input_contract": plan.get("binary_input_contract") or plan.get("input_mode"),
            "binary_input_contract_kind": plan.get("binary_input_contract_kind"),
            "binary_input_contract_hints": plan.get("binary_input_contract_hints", []),
            "binary_input_contract_source": plan.get("binary_input_contract_source"),
            "binary_input_contract_confidence": plan.get("binary_input_contract_confidence"),
            "binary_input_contract_confidence_reason": plan.get("binary_input_contract_confidence_reason"),
            "seed_provenance": seed_provenance,
            "corpus_provenance": corpus_provenance,
            "binary_native_seed_used": bool(plan.get("binary_native_seed_used")),
            "binary_contamination_report_path": str(contamination_path),
            "binary_signal_promotion_analysis_path": str(promotion_path),
            "contract_confidence_manifest_path": str(contract_confidence_path),
            "binary_observation_gap_report_path": str(observation_gap_path),
            "binary_backend_requirements_manifest_path": str(backend_requirements_path),
            "semantic_signal_upgrade_attempts_path": str(upgrade_attempts_path),
            "binary_signal_visibility_manifest_path": str(signal_visibility_path),
            "binary_trace_eligibility_manifest_path": str(trace_eligibility_path),
            "binary_candidate_promotion_report_path": str(candidate_promotion_path),
            "binary_feedback_bridge_path": str(binary_feedback_bridge_path(task_id)),
            "binary_runtime_signal_classifier_report_path": str(signal_classifier_path),
            "binary_replay_profile_manifest_path": str(replay_profile_path),
            "binary_observation_comparison_manifest_path": str(observation_comparison_path),
            "selected_binary_slice_focus": plan.get("selected_binary_slice_focus"),
            "binary_feedback_action": feedback_bridge_payload.get("next_action"),
            "binary_feedback_state": feedback_bridge_payload.get("feedback_state"),
            "binary_feedback_queue_size": len(feedback_bridge_payload.get("recommended_reseed_targets") or []),
            "binary_trace_admission_count": len(feedback_bridge_payload.get("trace_admission_candidates") or []),
            "binary_trace_candidate_count": int(feedback_bridge_payload.get("trace_candidate_count") or 0),
            "binary_trace_candidate_queue_path": feedback_bridge_payload.get("trace_candidate_queue_path"),
            "binary_watchlist_candidate_count": int(feedback_bridge_payload.get("watchlist_candidate_count") or 0),
            "binary_informational_only": bool(feedback_bridge_payload.get("informational_only")),
            "binary_provenance_class": feedback_bridge_payload.get("provenance_class"),
            "binary_signal_lift_total": int(feedback_bridge_payload.get("signal_lift_total") or 0),
            "binary_signal_lift_reason": feedback_bridge_payload.get("signal_lift_reason"),
            "trace_gate_decision": (
                "queued"
                if final_status == TaskStatus.BINARY_CRASH_CANDIDATE_FOUND
                else "watchlist_only"
                if watchlist_candidates and selected_target_is_project_local
                else "blocked"
            ),
            "trace_gate_reason": (
                "semantic_crash_candidate_available"
                if final_status == TaskStatus.BINARY_CRASH_CANDIDATE_FOUND
                else "project_local_suspicious_signal_needs_stronger_replay"
                if watchlist_candidates and selected_target_is_project_local
                else "no_semantic_crash_candidate_promoted"
            ),
            "trace_gate_semantic_candidate_count": len(result.crash_candidates),
            "trace_gate_watchlist_candidate_count": len(watchlist_candidates),
            "trace_gate_signal_category_counts": manifest.get("signal_category_counts"),
        },
    )
    if final_status == TaskStatus.BINARY_CRASH_CANDIDATE_FOUND:
        maybe_enqueue_trace(task_id, task_store, queue)
    elif feedback_bridge_payload.get("trace_admission_candidates"):
        _queue_binary_generalized_trace(
            task_id,
            task_store=task_store,
            queue=queue,
            feedback_bridge_payload=feedback_bridge_payload,
        )
    queue.ack(QueueNames.BINARY_EXECUTION, task_id)
    logger.info(
        "task %s binary execution complete status=%s runs=%s crash_candidates=%s",
        task_id,
        final_status.value,
        len(result.run_records),
        len(result.crash_candidates),
    )


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("binary execution worker started")
    while True:
        task_id = queue.pop(QueueNames.BINARY_EXECUTION, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("binary execution failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.BINARY_EXECUTION_FAILED,
                runtime_patch={
                    "binary_execution_failed_at": task_store.now(),
                    "binary_execution_error": str(exc),
                    "binary_execution_status": TaskStatus.BINARY_EXECUTION_FAILED.value,
                },
            )
            queue.ack(QueueNames.BINARY_EXECUTION, task_id)


if __name__ == "__main__":
    main()

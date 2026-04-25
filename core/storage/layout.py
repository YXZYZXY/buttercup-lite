from pathlib import Path

from core.utils.settings import settings

TASK_PATHS = {
    "input": "input",
    "inputs": "inputs",
    "src": "src",
    "fuzz_tooling": "fuzz-tooling",
    "diff": "diff",
    "imports": "imports",
    "imports_src": "imports/src",
    "imports_index": "imports/index",
    "imports_build": "imports/build",
    "imports_corpus": "imports/corpus",
    "imports_seed": "imports/seeds",
    "imports_crashes": "imports/crashes/raw",
    "imports_valid_crashes": "imports/crashes/valid",
    "imports_binaries": "imports/binaries",
    "imports_analysis": "imports/analysis",
    "imports_harnesses": "imports/harnesses",
    "imports_wrappers": "imports/wrappers",
    "imports_launchers": "imports/launchers",
    "imports_manifests": "imports/manifests",
    "normalized": "normalized",
    "index": "index",
    "build": "build",
    "seed": "seed",
    "seed_generated": "seed/generated",
    "seed_imported": "seed/imported",
    "corpus": "corpus",
    "corpus_imported": "corpus/imported",
    "corpus_active": "corpus/active",
    "corpus_binary_active": "corpus/binary_active",
    "corpus_shared_active": "corpus/shared_active",
    "corpus_harnesses": "corpus/harnesses",
    "corpus_manifests": "corpus/manifests",
    "crashes": "crashes",
    "crashes_raw": "crashes/raw",
    "crashes_binary_candidates": "crashes/binary_candidates",
    "coverage": "coverage",
    "coverage_snapshots": "coverage/snapshots",
    "trace": "trace",
    "trace_traced_crashes": "trace/traced_crashes",
    "trace_symbolized_frames": "trace/symbolized_frames",
    "pov": "pov",
    "pov_confirmed": "pov/confirmed",
    "reports": "reports",
    "artifacts": "artifacts",
    "artifacts_extracted": "artifacts/extracted",
    "artifacts_normalize": "artifacts/normalize",
    "artifacts_traces": "artifacts/traces",
    "artifacts_repro": "artifacts/repro",
    "artifacts_repro_cases": "artifacts/repro/cases",
    "artifacts_feedback": "artifacts/feedback",
    "patch_reserved": "patch_reserved",
    "patch": "patch",
    "protocol": "protocol",
    "binary": "binary",
    "binary_slice": "binary_slice",
    "binary_seed": "binary_seed",
    "binary_seed_generated": "binary_seed/generated",
    "binary_seed_imported": "binary_seed/imported",
    "logs": "logs",
    "task_meta": "task_meta",
    "runtime": "runtime",
    "corpus_raw": "corpus/raw",
    "corpus_replay": "corpus/replay",
    "corpus_replay_interesting": "corpus/replay/interesting",
    "build_out": "build/out",
    "build_out_harnesses": "build/out/harnesses",
    "build_out_options": "build/out/options",
    "build_out_seed_corpus": "build/out/seed_corpus",
    "build_out_reports": "build/out/reports",
    "build_out_metadata": "build/out/metadata",
}


def tasks_root() -> Path:
    root = Path(settings.data_root)
    root.mkdir(parents=True, exist_ok=True)
    return root


def task_root(task_id: str) -> Path:
    return tasks_root() / task_id


def task_json_path(task_id: str) -> Path:
    return task_root(task_id) / "task.json"


def runtime_dir(task_id: str) -> Path:
    return task_root(task_id) / "runtime"


def execution_plan_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "execution_plan.json"


def import_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "import_manifest.json"


def task_meta_path(task_id: str) -> Path:
    return task_root(task_id) / "task_meta" / "task_meta.json"


def workspace_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "workspace_manifest.json"


def source_task_normalization_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "source_task_normalization_manifest.json"


def source_resolution_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "source_resolution_manifest.json"


def scheduler_fanout_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "scheduler_fanout_manifest.json"


def asset_import_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "asset_import_manifest.json"


def program_model_query_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "codequery_view_manifest.json"


def program_model_backend_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "program_model_backend_manifest.json"


def program_model_query_validation_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "program_model_query_validation_manifest.json"


def query_capability_matrix_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "query_capability_matrix.json"


def sample_query_results_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "sample_query_results.json"


def context_backend_contribution_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "context_backend_contribution.json"


def query_candidate_denoising_report_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "query_candidate_denoising_report.json"


def parser_local_denoising_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "parser_local_denoising_manifest.json"


def richer_typed_relations_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "richer_typed_relations_manifest.json"


def tree_sitter_backend_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "tree_sitter_backend_manifest.json"


def typed_query_results_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "typed_query_results.json"


def target_selection_backend_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "target_selection_backend_manifest.json"


def query_to_target_decision_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "query_to_target_decision_manifest.json"


def llm_seed_audit_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "llm_seed_audit_manifest.json"


def llm_backend_integrity_report_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "llm_backend_integrity_report.json"


def seed_backend_degradation_report_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "seed_backend_degradation_report.json"


def strict_llm_block_report_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "strict_llm_block_report.json"


def seed_init_chain_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "seed_init_chain_manifest.json"


def harness_selector_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "harness_selector_manifest.json"


def function_selector_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "function_selector_manifest.json"


def seed_family_plan_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "seed_family_plan_manifest.json"


def selector_feedback_consumption_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "selector_feedback_consumption.json"


def seed_mode_semantics_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "seed_mode_semantics_manifest.json"


def coverage_to_selector_bridge_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "coverage_to_selector_bridge_manifest.json"


def weighted_harness_selector_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "weighted_harness_selector_manifest.json"


def weighted_function_selector_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "weighted_function_selector_manifest.json"


def seed_task_sampling_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "seed_task_sampling_manifest.json"


def seed_mode_trigger_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "seed_mode_trigger_manifest.json"


def adapter_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "adapter_manifest.json"


def binary_adapter_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_adapter_manifest.json"


def protocol_adapter_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "protocol_adapter_manifest.json"


def protocol_execution_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "protocol_execution_manifest.json"


def binary_analysis_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_analysis_manifest.json"


def binary_execution_plan_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_execution_plan.json"


def binary_execution_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_execution_manifest.json"


def binary_feedback_bridge_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_feedback_bridge.json"


def binary_ida_runtime_view_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_ida_runtime_view.json"


def ida_integration_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "ida_integration_manifest.json"


def ida_backend_capabilities_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "ida_backend_capabilities.json"


def ida_headless_export_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "ida_headless_export_manifest.json"


def binary_function_inventory_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "binary_function_inventory.json"


def binary_callgraph_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "binary_callgraph_manifest.json"


def binary_contract_inference_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "binary_contract_inference_manifest.json"


def ida_to_binary_context_bridge_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "ida_to_binary_context_bridge.json"


def binary_context_package_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "binary_context_package.json"


def binary_target_selection_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "binary_target_selection_manifest.json"


def dynamic_observation_bridge_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "dynamic_observation_bridge.json"


def binary_observation_comparison_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_observation_comparison_manifest.json"


def binary_signal_visibility_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_signal_visibility_manifest.json"


def binary_signal_promotion_analysis_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_signal_promotion_analysis.json"


def contract_confidence_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "contract_confidence_manifest.json"


def semantic_distribution_comparison_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "semantic_distribution_comparison.json"


def binary_trace_eligibility_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_trace_eligibility_manifest.json"


def binary_candidate_promotion_report_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_candidate_promotion_report.json"


def binary_runtime_signal_classifier_report_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_runtime_signal_classifier_report.json"


def binary_replay_profile_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_replay_profile_manifest.json"


def seed_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "seed_manifest.json"


def seed_task_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "seed_task_manifest.json"


def build_matrix_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "build" / "build_matrix_manifest.json"


def fuzzer_registry_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "build" / "fuzzer_registry_manifest.json"


def oss_fuzz_asset_import_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "build" / "oss_fuzz_asset_import_manifest.json"


def optional_assets_handling_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "build" / "optional_assets_handling_manifest.json"


def build_to_fuzzer_registry_bridge_path(task_id: str) -> Path:
    return task_root(task_id) / "build" / "build_to_fuzzer_registry_bridge.json"


def context_package_path(task_id: str) -> Path:
    return task_root(task_id) / "index" / "context_package.json"


def binary_seed_task_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary_seed" / "binary_seed_task_manifest.json"


def fuzz_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "crashes" / "fuzz_manifest.json"


def trace_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "trace" / "trace_manifest.json"


def trace_dedup_index_path(task_id: str) -> Path:
    return task_root(task_id) / "trace" / "dedup_index.json"


def trace_family_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "trace" / "family_manifest.json"


def repro_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "pov" / "repro_manifest.json"


def repro_family_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "pov" / "family_confirmation_manifest.json"


def binary_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "manifest.json"


def binary_analysis_summary_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "analysis_summary.json"


def binary_functions_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "functions.json"


def binary_strings_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "strings.json"


def binary_imports_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "imports.json"


def binary_exports_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "exports.json"


def binary_entrypoints_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "entrypoints.json"


def binary_execution_plan_copy_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "execution_plan.json"


def binary_execution_manifest_copy_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "execution_manifest.json"


def coverage_feedback_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "coverage" / "feedback_manifest.json"


def coverage_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "coverage" / "coverage_manifest.json"


def coverage_summary_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "coverage" / "coverage_summary_manifest.json"


def coverage_artifact_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "coverage" / "coverage_artifact_manifest.json"


def coverage_plane_snapshot_path(task_id: str) -> Path:
    return task_root(task_id) / "coverage" / "coverage_plane_snapshot.json"


def scheduler_feedback_consumption_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "scheduler_feedback_consumption.json"


def binary_slice_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary_slice" / "slice_manifest.json"


def binary_seed_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary_seed" / "binary_seed_manifest.json"


def binary_project_local_denoising_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "binary_project_local_denoising_manifest.json"


def binary_runtime_noise_filter_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "binary" / "binary_runtime_noise_filter_manifest.json"


def campaign_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "campaign_manifest.json"


def campaign_checkpoint_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "campaign_checkpoint.json"


def global_arbitration_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "global_arbitration_manifest.json"


def campaign_runtime_state_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "campaign_runtime_state.json"


def campaign_coverage_plane_state_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "coverage_plane_state.json"


def campaign_coverage_queue_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "coverage_queue.json"


def campaign_coverage_queue_consumption_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "coverage_queue_consumption.json"


def campaign_slot_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "campaign_slot_manifest.json"


def campaign_strength_report_path(task_id: str) -> Path:
    return reports_dir(task_id) / "campaign_strength_report.json"


def campaign_corpus_stage_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "campaign_corpus_stage_manifest.json"


def campaign_corpus_merge_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "campaign_corpus_merge_manifest.json"


def seed_corpus_merge_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "corpus_merge_manifest.json"


def seed_import_material_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "seed" / "import_material_manifest.json"


def campaign_shared_corpus_path(task_id: str) -> Path:
    return task_root(task_id) / "corpus" / "shared_active"


def campaign_harness_corpora_root_path(task_id: str) -> Path:
    return task_root(task_id) / "corpus" / "harnesses"


def patch_priority_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "patch_priority_manifest.json"


def patch_priority_consumption_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "patch_priority_consumption.json"


def patch_request_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_request_manifest.json"


def patch_root_cause_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "root_cause_manifest.json"


def patch_context_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "context_retrieval_manifest.json"


def patch_creation_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_creation_manifest.json"


def patch_candidate_ranking_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_candidate_ranking_manifest.json"


def llm_patch_candidate_ranking_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "llm_patch_candidate_ranking_manifest.json"


def llm_patch_audit_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "llm_patch_audit_manifest.json"


def generalized_patch_strategy_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "generalized_patch_strategy_manifest.json"


def patch_apply_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_apply_manifest.json"


def patch_build_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_build_manifest.json"


def patch_qe_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "qe_manifest.json"


def patch_semantic_validation_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_semantic_validation_manifest.json"


def patch_root_cause_alignment_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_root_cause_alignment_manifest.json"


def semantic_patch_synthesis_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "semantic_patch_synthesis_manifest.json"


def patch_strategy_family_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_strategy_family_manifest.json"


def ground_truth_dependency_report_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "ground_truth_dependency_report.json"


def deterministic_patch_dependency_report_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "deterministic_patch_dependency_report.json"


def patch_freeform_materialization_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_freeform_materialization_manifest.json"


def patch_llm_vs_template_comparison_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_llm_vs_template_comparison.json"


def patch_reflection_retry_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_reflection_retry_manifest.json"


def patch_generalization_report_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_generalization_report.json"


def patch_failure_analysis_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "patch_failure_analysis.json"


def patch_reflection_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "reflection_manifest.json"


def patch_reflection_consumption_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "patch_reflection_consumption.json"


def protocol_checkpoint_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "protocol_checkpoint.json"


def protocol_heartbeat_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "protocol_heartbeat.json"


def protocol_stage_state_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "protocol_stage_state.json"


def protocol_backend_task_path(task_id: str) -> Path:
    return task_root(task_id) / "protocol" / "task.json"


def protocol_feedback_path(task_id: str) -> Path:
    return task_root(task_id) / "artifacts" / "feedback" / "protocol_feedback.json"


def protocol_trace_path(task_id: str) -> Path:
    return task_root(task_id) / "artifacts" / "traces" / "protocol_trace.jsonl"


def protocol_repro_manifest_path(task_id: str) -> Path:
    return task_root(task_id) / "artifacts" / "repro" / "repro_manifest.json"


def protocol_registry_path(task_id: str) -> Path:
    return task_root(task_id) / "build" / "out" / "metadata" / "protocol_registry.json"


def normalized_packets_path(task_id: str) -> Path:
    return task_root(task_id) / "artifacts" / "normalize" / "normalized_packets.json"


def normalized_requests_path(task_id: str) -> Path:
    return task_root(task_id) / "artifacts" / "normalize" / "normalized_requests.json"


def seeds_path(task_id: str) -> Path:
    return task_root(task_id) / "corpus" / "raw" / "sample.seeds.json"


def replay_candidates_path(task_id: str) -> Path:
    return task_root(task_id) / "corpus" / "raw" / "replay_candidates.json"


def replay_results_path(task_id: str) -> Path:
    return task_root(task_id) / "corpus" / "replay" / "replay_results.json"


def binary_observation_gap_report_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_observation_gap_report.json"


def binary_backend_requirements_manifest_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "binary_backend_requirements_manifest.json"


def semantic_signal_upgrade_attempts_path(task_id: str) -> Path:
    return runtime_dir(task_id) / "semantic_signal_upgrade_attempts.json"


def reports_dir(task_id: str) -> Path:
    return task_root(task_id) / "reports"


def pov_inventory_path(task_id: str) -> Path:
    return reports_dir(task_id) / "pov_inventory.json"


def vuln_coverage_path(task_id: str) -> Path:
    return reports_dir(task_id) / "vuln_coverage.json"


def signature_index_report_path(task_id: str) -> Path:
    return reports_dir(task_id) / "signature_index.json"


def pov_lineage_path(task_id: str) -> Path:
    return reports_dir(task_id) / "pov_lineage.json"


def ensure_task_root(task_id: str) -> Path:
    root = task_root(task_id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def create_task_layout(task_id: str) -> dict[str, str]:
    root = ensure_task_root(task_id)
    layout: dict[str, str] = {"root": str(root), "task_json": str(task_json_path(task_id))}
    for key, relative_path in TASK_PATHS.items():
        path = root / relative_path
        path.mkdir(parents=True, exist_ok=True)
        layout[key] = str(path)
    return layout

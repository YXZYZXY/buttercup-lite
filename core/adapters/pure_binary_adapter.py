from __future__ import annotations

from core.adapters.base import AdapterDefinition
from core.contracts.coverage_contract import CoverageContract
from core.contracts.evidence_contract import EvidenceContract
from core.contracts.execution_contract import ExecutionContract
from core.contracts.input_contract import InputContract
from core.models.task import AdapterType
from core.queues.redis_queue import QueueNames


def build_pure_binary_adapter() -> AdapterDefinition:
    return AdapterDefinition(
        name="pure_binary_adapter",
        adapter_type=AdapterType.BINARY,
        input_contract=InputContract(
            adapter_name="pure_binary_adapter",
            input_kind="binary_with_input_contract",
            required_fields=["existing_binary_path", "binary_input_contract"],
            optional_fields=["existing_binary_analysis_path", "existing_wrapper_path", "existing_launcher_path"],
            normalized_paths=["imports/binaries/current", "binary", "binary_slice", "binary_seed/generated", "corpus/binary_active"],
            constraints={"source_contamination_allowed": False},
        ),
        execution_contract=ExecutionContract(
            adapter_name="pure_binary_adapter",
            execution_kind="binary_native_pipeline",
            queue_names=[QueueNames.BINARY_ANALYSIS, QueueNames.BINARY_SEED, QueueNames.BINARY_EXECUTION, QueueNames.TRACE, QueueNames.REPRO],
            worker_slots=["binary-analysis-worker", "binary-seed-worker", "binary-execution-worker", "tracer-worker", "reproducer-worker"],
            required_runtime_keys=["binary_analysis_manifest_path", "binary_seed_manifest_path", "binary_execution_manifest_path"],
            strategy={"input_modes": ["file", "stdin", "argv"]},
        ),
        coverage_contract=CoverageContract(
            adapter_name="pure_binary_adapter",
            coverage_kind="binary_execution_progress_proxy",
            snapshot_paths=["coverage/snapshots"],
            feedback_consumers=["scheduler", "binary_seed_strategy"],
            scheduler_effects=["binary_seed_budget", "binary_seed_mode", "target_priority"],
        ),
        evidence_contract=EvidenceContract(
            adapter_name="pure_binary_adapter",
            manifest_paths=[
                "runtime/binary_adapter_manifest.json",
                "runtime/binary_contamination_report.json",
                "binary_seed/binary_seed_task_manifest.json",
                "runtime/binary_execution_manifest.json",
            ],
            report_paths=["reports/pov_inventory.json", "reports/vuln_coverage.json", "reports/pov_lineage.json"],
            required_fields=["binary_mode", "binary_native_seed_used", "pure_binary_eligible"],
            downstream_consumers=["campaign", "patch_priority"],
        ),
    )


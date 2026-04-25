from __future__ import annotations

from core.adapters.base import AdapterDefinition
from core.contracts.coverage_contract import CoverageContract
from core.contracts.evidence_contract import EvidenceContract
from core.contracts.execution_contract import ExecutionContract
from core.contracts.input_contract import InputContract
from core.models.task import AdapterType
from core.queues.redis_queue import QueueNames


def build_source_adapter() -> AdapterDefinition:
    return AdapterDefinition(
        name="source_adapter",
        adapter_type=AdapterType.OSSFUZZ,
        input_contract=InputContract(
            adapter_name="source_adapter",
            input_kind="source_tree_with_fuzz_tooling",
            required_fields=["source.uri"],
            optional_fields=[
                "existing_src_path",
                "existing_index_path",
                "existing_build_out_path",
                "existing_oss_fuzz_project_path",
                "existing_project_yaml_path",
            ],
            normalized_paths=["src", "imports/src/current", "imports/build/out"],
        ),
        execution_contract=ExecutionContract(
            adapter_name="source_adapter",
            execution_kind="libfuzzer_source_pipeline",
            queue_names=[QueueNames.INDEX, QueueNames.BUILD, QueueNames.SEED, QueueNames.FUZZ, QueueNames.TRACE, QueueNames.REPRO],
            worker_slots=["program-model-worker", "builder-worker", "seed-worker", "fuzzer-worker", "tracer-worker", "reproducer-worker"],
            required_runtime_keys=["index_manifest_path", "build_registry_path", "seed_manifest_path"],
        ),
        coverage_contract=CoverageContract(
            adapter_name="source_adapter",
            coverage_kind="libfuzzer_progress_proxy",
            snapshot_paths=["coverage/snapshots"],
            feedback_consumers=["scheduler", "seed_strategy"],
            scheduler_effects=["seed_budget", "seed_mode", "target_priority"],
        ),
        evidence_contract=EvidenceContract(
            adapter_name="source_adapter",
            manifest_paths=[
                "runtime/adapter_manifest.json",
                "seed/seed_task_manifest.json",
                "coverage/feedback_manifest.json",
                "pov/repro_manifest.json",
            ],
            report_paths=["reports/pov_inventory.json", "reports/vuln_coverage.json", "reports/pov_lineage.json"],
            required_fields=["adapter_resolution", "seed_mode", "scheduler_consumed_feedback"],
            downstream_consumers=["campaign", "patch_priority"],
        ),
    )


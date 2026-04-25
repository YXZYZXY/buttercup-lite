from __future__ import annotations

from core.adapters.base import AdapterDefinition
from core.contracts.coverage_contract import CoverageContract
from core.contracts.evidence_contract import EvidenceContract
from core.contracts.execution_contract import ExecutionContract
from core.contracts.input_contract import InputContract
from core.models.task import AdapterType
from core.queues.redis_queue import QueueNames


def build_protocol_adapter() -> AdapterDefinition:
    return AdapterDefinition(
        name="protocol_adapter",
        adapter_type=AdapterType.PROTOCOL,
        protocol_status="placeholder_not_implemented",
        input_contract=InputContract(
            adapter_name="protocol_adapter",
            input_kind="protocol_metadata_and_io_contract",
            required_fields=["source.uri", "protocol_name", "protocol_input_contract"],
            optional_fields=["existing_seed_path", "existing_corpus_path", "existing_crashes_path"],
            normalized_paths=["runtime/protocol_adapter_manifest.json", "protocol", "corpus/active"],
        ),
        execution_contract=ExecutionContract(
            adapter_name="protocol_adapter",
            execution_kind="protocol_placeholder_execution",
            queue_names=[QueueNames.PROTOCOL_EXECUTION],
            worker_slots=["protocol-execution-worker"],
            required_runtime_keys=["protocol_adapter_manifest_path"],
            strategy={"status": "NOT_IMPLEMENTED", "implementation_owner": "external"},
        ),
        coverage_contract=CoverageContract(
            adapter_name="protocol_adapter",
            coverage_kind="protocol_contract_placeholder",
            snapshot_paths=["coverage/snapshots"],
            feedback_consumers=["scheduler", "seed_strategy"],
            scheduler_effects=["protocol_seed_budget", "protocol_execution_priority"],
        ),
        evidence_contract=EvidenceContract(
            adapter_name="protocol_adapter",
            manifest_paths=[
                "runtime/protocol_adapter_manifest.json",
                "runtime/protocol_execution_manifest.json",
            ],
            report_paths=["reports/protocol_evidence.json"],
            required_fields=["protocol_status", "protocol_input_contract", "not_implemented_reason"],
            downstream_consumers=["scheduler", "campaign", "patch_priority"],
        ),
    )


from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.contracts.coverage_contract import CoverageContract
from core.contracts.evidence_contract import EvidenceContract
from core.contracts.execution_contract import ExecutionContract
from core.contracts.input_contract import InputContract
from core.models.task import AdapterType


@dataclass(frozen=True)
class AdapterDefinition:
    name: str
    adapter_type: AdapterType
    input_contract: InputContract
    execution_contract: ExecutionContract
    coverage_contract: CoverageContract
    evidence_contract: EvidenceContract
    protocol_status: str | None = None

    def contract_bundle(self) -> dict[str, Any]:
        return {
            "adapter_name": self.name,
            "adapter_type": self.adapter_type.value,
            "protocol_status": self.protocol_status,
            "input_contract": self.input_contract.to_dict(),
            "execution_contract": self.execution_contract.to_dict(),
            "coverage_contract": self.coverage_contract.to_dict(),
            "evidence_contract": self.evidence_contract.to_dict(),
        }


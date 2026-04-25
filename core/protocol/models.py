from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProtocolAdapterRequest:
    task_id: str
    protocol_name: str
    protocol_input_contract: dict[str, Any] = field(default_factory=dict)
    protocol_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "protocol_name": self.protocol_name,
            "protocol_input_contract": self.protocol_input_contract,
            "protocol_metadata": self.protocol_metadata,
        }


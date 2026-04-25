from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ExecutionContract:
    adapter_name: str
    execution_kind: str
    queue_names: list[str] = field(default_factory=list)
    worker_slots: list[str] = field(default_factory=list)
    required_runtime_keys: list[str] = field(default_factory=list)
    strategy: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "execution_kind": self.execution_kind,
            "queue_names": self.queue_names,
            "worker_slots": self.worker_slots,
            "required_runtime_keys": self.required_runtime_keys,
            "strategy": self.strategy,
        }


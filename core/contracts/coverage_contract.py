from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CoverageContract:
    adapter_name: str
    coverage_kind: str
    snapshot_paths: list[str] = field(default_factory=list)
    feedback_consumers: list[str] = field(default_factory=list)
    scheduler_effects: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "coverage_kind": self.coverage_kind,
            "snapshot_paths": self.snapshot_paths,
            "feedback_consumers": self.feedback_consumers,
            "scheduler_effects": self.scheduler_effects,
            "metrics": self.metrics,
        }


from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceContract:
    adapter_name: str
    manifest_paths: list[str] = field(default_factory=list)
    report_paths: list[str] = field(default_factory=list)
    required_fields: list[str] = field(default_factory=list)
    downstream_consumers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "manifest_paths": self.manifest_paths,
            "report_paths": self.report_paths,
            "required_fields": self.required_fields,
            "downstream_consumers": self.downstream_consumers,
        }


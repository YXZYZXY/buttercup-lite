from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InputContract:
    adapter_name: str
    input_kind: str
    required_fields: list[str] = field(default_factory=list)
    optional_fields: list[str] = field(default_factory=list)
    normalized_paths: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "input_kind": self.input_kind,
            "required_fields": self.required_fields,
            "optional_fields": self.optional_fields,
            "normalized_paths": self.normalized_paths,
            "constraints": self.constraints,
        }


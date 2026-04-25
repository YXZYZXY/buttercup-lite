from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BinarySlice:
    binary_target_name: str
    entry_candidates: list[dict[str, Any]]
    relevant_functions: list[dict[str, Any]]
    relevant_strings: list[dict[str, Any]]
    relevant_imports: list[dict[str, Any]]
    parser_candidates: list[dict[str, Any]] = field(default_factory=list)
    selected_target_function: dict[str, Any] | None = None
    selection_rationale: list[str] = field(default_factory=list)
    contract_inference: dict[str, Any] = field(default_factory=dict)
    context_sources: list[str] = field(default_factory=list)
    artifact_sources: dict[str, str] = field(default_factory=dict)
    input_mode: str = "file"
    launcher_semantics_source: str | None = None


@dataclass
class BinarySeedContext:
    summary: dict[str, Any]
    binary_slice: BinarySlice
    context_sources: list[str]
    artifact_sources: dict[str, str]
    context_package_path: str | None = None
    dict_snippet: str | None = None
    options_snippet: str | None = None

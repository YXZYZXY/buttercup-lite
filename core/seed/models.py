from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class HarnessSelection:
    name: str
    executable_path: Path
    source_path: Path | None
    dict_path: Path | None = None
    options_path: Path | None = None
    seed_corpus_zip: Path | None = None
    score: int = 0
    reasons: list[str] = field(default_factory=list)


@dataclass
class SeedContext:
    selected_harness: str
    selected_harness_path: str | None
    candidate_harnesses: list[dict[str, Any]]
    harness_source: str
    related_functions: list[dict[str, Any]]
    target_function: dict[str, Any] | None
    selected_target_functions: list[dict[str, Any]]
    callers: list[dict[str, Any]]
    callees: list[dict[str, Any]]
    extended_context_functions: list[dict[str, Any]]
    key_types: list[dict[str, Any]]
    key_constants: list[dict[str, Any]]
    parser_adjacent_candidates: list[dict[str, Any]]
    sample_inputs: list[str]
    dict_snippet: str | None
    options_snippet: str | None
    context_sources: list[str]
    context_package_path: str | None = None
    context_package: dict[str, Any] = field(default_factory=dict)
    selection_rationale: list[str] = field(default_factory=list)


@dataclass
class ParsedSeedModule:
    code: str
    function_names: list[str]

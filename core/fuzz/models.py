from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FuzzTarget:
    harness_name: str
    binary_path: Path
    dict_path: Path | None = None
    options_path: Path | None = None


@dataclass
class FuzzRunResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    harness_name: str
    binary_path: str
    dict_path: str | None
    options_path: str | None
    new_corpus_files: list[str] = field(default_factory=list)
    raw_crashes: list[str] = field(default_factory=list)
    imported_crashes: list[dict[str, str]] = field(default_factory=list)
    helper_seed_inputs: list[dict[str, str]] = field(default_factory=list)

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class BinaryAnalysisBackend(str, Enum):
    IDA_MCP = "ida_mcp"
    IMPORTED_ANALYSIS = "imported_analysis"
    WRAPPER_SCRIPT = "wrapper_script"


class BinaryAnalysisRequest(BaseModel):
    task_id: str
    backend: BinaryAnalysisBackend
    binary_path: Path
    binary_name: str
    source_path: Path | None = None
    imported_analysis_path: Path | None = None
    wrapper_path: Path | None = None
    launcher_path: Path | None = None
    output_dir: Path
    runtime_dir: Path
    metadata: dict[str, Any] = Field(default_factory=dict)


class BinaryToolResult(BaseModel):
    command: list[str]
    return_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    available: bool = True


class BinaryAnalysisResult(BaseModel):
    backend: BinaryAnalysisBackend
    manifest: dict[str, Any]
    summary: dict[str, Any]
    functions: list[dict[str, Any]] = Field(default_factory=list)
    strings: list[dict[str, Any]] = Field(default_factory=list)
    imports: list[dict[str, Any]] = Field(default_factory=list)
    exports: list[dict[str, Any]] = Field(default_factory=list)
    entrypoints: list[dict[str, Any]] = Field(default_factory=list)


class BinaryExecutionInput(BaseModel):
    path: Path
    source_kind: str
    source_path: str
    size: int


class BinaryExecutionRequest(BaseModel):
    task_id: str
    binary_path: Path
    binary_name: str
    analysis_backend: str
    selected_launcher_path: Path
    selected_wrapper_path: Path | None = None
    input_mode: str = "file"
    input_delivery_path: Path | None = None
    working_directory: Path
    argv_template: list[str] = Field(default_factory=list)
    env_overrides: dict[str, str] = Field(default_factory=dict)
    seed_sources: list[str] = Field(default_factory=list)
    corpus_sources: list[str] = Field(default_factory=list)
    crash_sources: list[str] = Field(default_factory=list)
    crash_output_dir: Path
    log_dir: Path
    execution_strategy: str = "corpus-loop"
    inputs: list[BinaryExecutionInput] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BinaryExecutionRunRecord(BaseModel):
    input_path: str
    source_kind: str
    source_path: str
    command: list[str]
    exit_code: int
    stdout_log_path: str
    stderr_log_path: str
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    duration_seconds: float = 0.0
    crash_candidate: bool = False
    crash_reason: str | None = None
    signal_category: str | None = None
    signal_subcategory: str | None = None
    signal_reason: str | None = None
    environment_classification: str | None = None
    environment_reason: str | None = None
    selected_binary_slice_focus: str | None = None
    input_contract: str | None = None
    input_contract_source: str | None = None
    source_of_signal: str | None = None
    evidence_snippet: str | None = None
    signal_signature: str | None = None
    signal_confidence: str | None = None
    signal_explanation: str | None = None
    promotion_decision: str | None = None
    promotion_reason: str | None = None
    strace_log_path: str | None = None
    strace_summary: dict[str, Any] | None = None
    observed_file_paths: list[str] = Field(default_factory=list)
    observation_profile: str | None = None
    secondary_rerun_used: bool = False
    secondary_signal_category: str | None = None
    secondary_evidence_snippet: str | None = None
    timed_out: bool = False


class BinaryCrashCandidate(BaseModel):
    candidate_path: str
    input_path: str
    source_kind: str
    source_path: str
    size: int
    reason: str
    exit_code: int


class BinaryExecutionResult(BaseModel):
    plan: dict[str, Any]
    manifest: dict[str, Any]
    run_records: list[BinaryExecutionRunRecord] = Field(default_factory=list)
    crash_candidates: list[BinaryCrashCandidate] = Field(default_factory=list)

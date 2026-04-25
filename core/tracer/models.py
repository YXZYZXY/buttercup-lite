from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ReplayResult:
    harness_name: str
    binary_path: str
    testcase_path: str
    exit_code: int
    stdout: str
    stderr: str
    command: list[str] = field(default_factory=list)
    launcher_path: str | None = None
    working_directory: str | None = None


@dataclass
class TracedCrash:
    testcase_path: str
    harness_name: str
    binary_path: str
    crash_source: str
    trace_mode: str
    sanitizer: str
    crash_type: str
    crash_state: str
    stacktrace: list[str] = field(default_factory=list)
    stderr_excerpt: str = ""
    signature: str = ""
    target_mode: str | None = None
    binary_provenance: str | None = None
    binary_origin_task_id: str | None = None
    binary_target_name: str | None = None
    binary_analysis_backend: str | None = None
    launcher_semantics_source: str | None = None
    seed_provenance: str | None = None
    corpus_provenance: str | None = None
    binary_execution_command: list[str] = field(default_factory=list)
    input_mode: str | None = None
    selected_binary_slice_focus: str | None = None
    binary_input_contract: str | None = None
    binary_input_contract_source: str | None = None
    binary_input_contract_confidence: str | None = None
    binary_input_contract_confidence_reason: str | None = None
    execution_signal_category: str | None = None
    execution_signal_reason: str | None = None
    execution_input_path: str | None = None
    execution_input_source_kind: str | None = None
    environment_classification: str | None = None
    environment_reason: str | None = None
    fallback_trigger_reason: str | None = None
    fallback_from: str | None = None
    fallback_to: str | None = None
    fallback_effect: str | None = None
    candidate_origin_kind: str | None = None
    candidate_origin_path: str | None = None
    candidate_id: str | None = None
    candidate_reason: str | None = None
    candidate_reasons: list[str] = field(default_factory=list)
    candidate_targets: list[str] = field(default_factory=list)
    candidate_source_kind: str | None = None
    trace_admission_kind: str | None = None
    trace_admission_reason: str | None = None
    crash_detected: bool | None = None
    repro_admission_recommended: bool | None = None
    replay_signal_classification: str | None = None
    replay_signal_summary: list[str] = field(default_factory=list)

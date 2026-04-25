from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from core.binary.crash_candidate import detect_crash_candidate, materialize_crash_candidate
from core.binary.models import (
    BinaryExecutionRequest,
    BinaryExecutionResult,
    BinaryExecutionRunRecord,
)
from core.utils.settings import resolve_int_setting, settings


def _render_command(request: BinaryExecutionRequest, input_path: Path) -> list[str]:
    replacements = {
        "{binary_path}": str(request.binary_path),
        "{launcher_path}": str(request.selected_launcher_path),
        "{wrapper_path}": str(request.selected_wrapper_path) if request.selected_wrapper_path else "",
        "{input_path}": str(input_path),
    }
    command: list[str] = []
    for token in request.argv_template:
        rendered = str(token)
        for placeholder, value in replacements.items():
            rendered = rendered.replace(placeholder, value)
        if rendered:
            command.append(rendered)
    if not command:
        command = [str(request.binary_path), str(input_path)]
    return command


def _merge_env_flag(existing: str | None, additions: list[str]) -> str:
    values: dict[str, str] = {}
    for chunk in (existing or "").split(":"):
        if not chunk:
            continue
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            values[key] = value
        else:
            values[chunk] = "1"
    for chunk in additions:
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            values[key] = value
        else:
            values[chunk] = "1"
    return ":".join(f"{key}={value}" for key, value in values.items())


def _prepare_runtime_env(base_env: dict[str, str]) -> dict[str, str]:
    env = dict(base_env)
    env["ASAN_OPTIONS"] = _merge_env_flag(
        env.get("ASAN_OPTIONS"),
        [
            "abort_on_error=1",
            "symbolize=0",
            "detect_leaks=0",
            "allocator_may_return_null=1",
        ],
    )
    env["LSAN_OPTIONS"] = _merge_env_flag(
        env.get("LSAN_OPTIONS"),
        [
            "detect_leaks=0",
            "verbosity=0",
            "log_threads=0",
        ],
    )
    return env


def _strace_available() -> bool:
    return shutil.which("strace") is not None


def _summarize_strace(path: Path) -> tuple[dict[str, int], list[str]]:
    if not path.exists():
        return {}, []
    syscall_counts: dict[str, int] = {}
    observed_files: list[str] = []
    file_pattern = re.compile(r'"([^"]+)"')
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        syscall = line.split("(", 1)[0].strip()
        if syscall:
            syscall_counts[syscall] = syscall_counts.get(syscall, 0) + 1
        if syscall in {"open", "openat", "stat", "lstat", "access", "readlink"}:
            match = file_pattern.search(line)
            if match:
                observed_files.append(match.group(1))
    deduped_files: list[str] = []
    seen: set[str] = set()
    for item in observed_files:
        if item in seen:
            continue
        seen.add(item)
        deduped_files.append(item)
    return syscall_counts, deduped_files[:32]


INFO_ONLY_PATTERNS = (
    "info:",
    "running:",
    "executed ",
    "*** note:",
    "***",
    "fuzzing was not performed",
    "running 1 inputs 1 time(s) each.",
    "executed ",
)
PARSER_REJECT_PATTERNS = (
    "parse error",
    "parser error",
    "syntax error",
    "invalid input",
    "invalid json",
    "unexpected token",
    "failed to parse",
    "reject",
)
FORMAT_MISMATCH_PATTERNS = (
    "invalid json",
    "unexpected token",
    "unterminated",
    "malformed",
    "trailing comma",
    "bad escape",
    "extra data",
    "wrong format",
    "format error",
)
USAGE_REJECTION_PATTERNS = (
    "usage:",
    "expected argument",
    "missing argument",
    "unknown option",
    "invalid option",
    "must specify",
)


def _first_matching_line(text: str, tokens: tuple[str, ...]) -> str | None:
    for raw_line in text.splitlines():
        lowered = raw_line.lower()
        if any(token in lowered for token in tokens):
            return raw_line.strip()
    return None


def _signal_signature(category: str, subcategory: str | None, evidence: str | None) -> str:
    digest = hashlib.sha256(
        f"{category}:{subcategory or ''}:{evidence or ''}".encode("utf-8"),
    ).hexdigest()
    return digest[:16]


def _classify_environment_issue(stderr: str, stdout: str, exit_code: int) -> tuple[str | None, str | None]:
    combined = f"{stdout}\n{stderr}".lower()
    if any(
        token in combined
        for token in (
            "addresssanitizer:",
            "undefinedbehaviorsanitizer:",
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "attempting double-free",
            "use-after-free",
            "deadly signal",
            "segmentation fault",
        )
    ):
        return None, None
    if "missing glibc loader" in combined or "ld-linux" in combined:
        return "loader_failure", "missing_loader_runtime"
    if "error while loading shared libraries" in combined:
        return "loader_failure", "shared_library_resolution_failed"
    if "usage:" in combined and exit_code == 2:
        return "contract_failure", "launcher_usage_error"
    if "no such file or directory" in combined or "not found" in combined:
        return "environment_failure", "missing_runtime_dependency"
    return None, None


def _classify_execution_signal(
    *,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    crash_detected: bool,
    crash_reason: str,
    timed_out: bool,
    environment_classification: str | None,
    environment_reason: str | None,
) -> dict[str, str | bool | None]:
    combined = f"{stdout}\n{stderr}"
    lowered = combined.lower()
    source_of_signal = "stderr" if stderr.strip() else ("stdout" if stdout.strip() else "exit_code")
    evidence_snippet = None

    if timed_out:
        evidence_snippet = "subprocess timeout expired"
        return {
            "signal_category": "timeout_failure",
            "signal_subcategory": "subprocess_timeout",
            "signal_reason": "timeout_expired",
            "source_of_signal": "timeout",
            "evidence_snippet": evidence_snippet,
            "signal_confidence": "high",
            "signal_explanation": "execution exceeded configured timeout before a semantic crash was observed",
            "promotion_decision": "ignore",
            "promotion_reason": "timeouts are tracked separately and do not qualify as semantic crash candidates",
            "crash_candidate": False,
            "crash_reason": None,
        }

    if environment_classification is not None:
        evidence_snippet = _first_matching_line(combined, ("error", "usage:", "not found", "ld-linux", "shared libraries")) or environment_reason
        return {
            "signal_category": environment_classification,
            "signal_subcategory": environment_reason,
            "signal_reason": environment_reason,
            "source_of_signal": source_of_signal,
            "evidence_snippet": evidence_snippet,
            "signal_confidence": "high",
            "signal_explanation": "runtime environment or launcher contract failed before target semantics could be exercised",
            "promotion_decision": "ignore",
            "promotion_reason": "environmental failures are not promoted into semantic crash candidates",
            "crash_candidate": False,
            "crash_reason": None,
        }

    if "out of memory" in lowered or exit_code in {137, -9}:
        evidence_snippet = _first_matching_line(combined, ("out of memory", "killed"))
        return {
            "signal_category": "oom_failure",
            "signal_subcategory": "resource_exhaustion",
            "signal_reason": "memory_limit_reached",
            "source_of_signal": source_of_signal,
            "evidence_snippet": evidence_snippet,
            "signal_confidence": "medium",
            "signal_explanation": "process appears to have been terminated by memory pressure rather than a target semantic fault",
            "promotion_decision": "ignore",
            "promotion_reason": "OOM is tracked as environment/resource failure, not semantic crash candidate",
            "crash_candidate": False,
            "crash_reason": None,
        }

    if crash_detected or "addresssanitizer:" in lowered or "undefinedbehaviorsanitizer:" in lowered:
        evidence_snippet = _first_matching_line(combined, ("addresssanitizer", "undefinedbehaviorsanitizer", "heap-buffer-overflow", "use-after-free")) or crash_reason
        return {
            "signal_category": "semantic_crash_candidate",
            "signal_subcategory": "semantic_memory_violation_like",
            "signal_reason": crash_reason or "sanitizer_signal",
            "source_of_signal": source_of_signal,
            "evidence_snippet": evidence_snippet,
            "signal_confidence": "high",
            "signal_explanation": "sanitizer or canonical crash evidence indicates a likely target-side memory safety failure",
            "promotion_decision": "promote",
            "promotion_reason": "strong sanitizer or crash evidence",
            "crash_candidate": True,
            "crash_reason": crash_reason or "semantic_memory_violation_like",
        }

    if any(token in lowered for token in ("segmentation fault", "deadly signal", "aborted", "assert", "assertion")) or exit_code in {134, 139, -6, -11}:
        evidence_snippet = _first_matching_line(combined, ("segmentation fault", "deadly signal", "aborted", "assert", "assertion")) or f"exit_code={exit_code}"
        subcategory = "semantic_assertion_failure" if "assert" in lowered else "semantic_abort_signal"
        return {
            "signal_category": "semantic_crash_candidate",
            "signal_subcategory": subcategory,
            "signal_reason": subcategory,
            "source_of_signal": source_of_signal if evidence_snippet != f"exit_code={exit_code}" else "exit_code",
            "evidence_snippet": evidence_snippet,
            "signal_confidence": "medium",
            "signal_explanation": "target terminated via abort/assertion-style signal and is strong enough to merit trace follow-up",
            "promotion_decision": "promote",
            "promotion_reason": "abort/assertion style signal crossed promotion threshold",
            "crash_candidate": True,
            "crash_reason": subcategory,
        }

    usage_reject_line = _first_matching_line(combined, USAGE_REJECTION_PATTERNS)
    if usage_reject_line is not None:
        return {
            "signal_category": "semantic_usage_rejection",
            "signal_subcategory": "usage_or_cli_reject",
            "signal_reason": "semantic_usage_rejection",
            "source_of_signal": source_of_signal,
            "evidence_snippet": usage_reject_line,
            "signal_confidence": "medium",
            "signal_explanation": "target was reached but rejected the input or invocation at the semantic usage layer",
            "promotion_decision": "ignore",
            "promotion_reason": "usage rejection is useful contract evidence but not a crash candidate",
            "crash_candidate": False,
            "crash_reason": None,
        }

    parser_reject_line = _first_matching_line(combined, PARSER_REJECT_PATTERNS)
    if parser_reject_line is not None:
        category = (
            "semantic_format_mismatch"
            if any(token in parser_reject_line.lower() for token in FORMAT_MISMATCH_PATTERNS)
            else "semantic_parser_reject_only"
        )
        subcategory = "format_mismatch" if category == "semantic_format_mismatch" else "parser_reject"
        return {
            "signal_category": category,
            "signal_subcategory": subcategory,
            "signal_reason": category,
            "source_of_signal": source_of_signal,
            "evidence_snippet": parser_reject_line,
            "signal_confidence": "medium",
            "signal_explanation": (
                "input reached a parser-visible format rejection path without surfacing a crash candidate"
                if category == "semantic_format_mismatch"
                else "input exercised parser rejection paths but did not present as a crash candidate"
            ),
            "promotion_decision": "ignore",
            "promotion_reason": "parser rejection without crash semantics is treated as execution noise",
            "crash_candidate": False,
            "crash_reason": None,
        }

    meaningful_lines = [
        line.strip()
        for line in combined.splitlines()
        if line.strip() and not any(prefix in line.lower() for prefix in INFO_ONLY_PATTERNS)
    ]
    fixed_input_line = _first_matching_line(combined, ("executed ", "running 1 inputs 1 time(s) each."))
    if fixed_input_line is not None and exit_code in (0, None):
        return {
            "signal_category": "informational_runtime_output",
            "signal_subcategory": "fixed_input_execution_info",
            "signal_reason": "fixed_input_exercised_without_crash",
            "source_of_signal": source_of_signal,
            "evidence_snippet": fixed_input_line,
            "signal_confidence": "low",
            "signal_explanation": "fixed-input replay reached the target harness and returned cleanly; only libFuzzer informational output was observed",
            "promotion_decision": "ignore",
            "promotion_reason": "no parser rejection, sanitizer, abort, assertion, or suspicious target output was observed",
            "crash_candidate": False,
            "crash_reason": None,
        }

    if not meaningful_lines and exit_code in (0, None):
        evidence_snippet = _first_matching_line(combined, ("info:", "running:", "executed ", "*** note:"))
        return {
            "signal_category": "informational_runtime_output",
            "signal_subcategory": "fixed_input_execution_info",
            "signal_reason": "runtime_info_only",
            "source_of_signal": source_of_signal,
            "evidence_snippet": evidence_snippet,
            "signal_confidence": "low",
            "signal_explanation": "stderr/stdout only contained libFuzzer execution info for fixed-input replay",
            "promotion_decision": "ignore",
            "promotion_reason": "informational output is not semantically suspicious",
            "crash_candidate": False,
            "crash_reason": None,
        }

    if exit_code not in (0, None) or meaningful_lines:
        evidence_snippet = meaningful_lines[0] if meaningful_lines else f"exit_code={exit_code}"
        return {
            "signal_category": "suspicious_semantic_signal",
            "signal_subcategory": "noisy_noncanonical_runtime_signal",
            "signal_reason": f"exit_code={exit_code}" if exit_code not in (0, None) else "noncanonical_runtime_output",
            "source_of_signal": source_of_signal if meaningful_lines else "exit_code",
            "evidence_snippet": evidence_snippet,
            "signal_confidence": "low",
            "signal_explanation": "runtime output may indicate target behavior worth observing, but does not meet crash promotion rules",
            "promotion_decision": "observe",
            "promotion_reason": "noncanonical semantic output retained for later comparison but not traced yet",
            "crash_candidate": False,
            "crash_reason": None,
        }

    return {
        "signal_category": "clean_exit",
        "signal_subcategory": "no_runtime_signal",
        "signal_reason": "no_runtime_signal",
        "source_of_signal": source_of_signal,
        "evidence_snippet": None,
        "signal_confidence": "high",
        "signal_explanation": "execution completed without observable semantic or environmental signal",
        "promotion_decision": "ignore",
        "promotion_reason": "no signal to promote",
        "crash_candidate": False,
        "crash_reason": None,
    }


def run_binary_execution(request: BinaryExecutionRequest) -> BinaryExecutionResult:
    timeout_seconds = resolve_int_setting(
        request.metadata,
        "BINARY_WRAPPER_TIMEOUT_SECONDS",
        settings.binary_wrapper_timeout_seconds,
    )
    env = os.environ.copy()
    env.update({key: str(value) for key, value in request.env_overrides.items()})
    env = _prepare_runtime_env(env)

    run_records: list[BinaryExecutionRunRecord] = []
    crash_candidates = []
    signal_category_counts: dict[str, int] = {}
    for index, execution_input in enumerate(request.inputs, start=1):
        command = _render_command(request, execution_input.path)
        stdout_path = request.log_dir / f"binary-execution-{index:03d}.stdout.log"
        stderr_path = request.log_dir / f"binary-execution-{index:03d}.stderr.log"
        strace_path = request.log_dir / f"binary-execution-{index:03d}.strace.log"
        start = time.monotonic()
        timed_out = False
        observation_profile = "strace_primary" if _strace_available() else "direct_primary"
        secondary_rerun_used = False
        secondary_signal_category = None
        secondary_evidence_snippet = None
        try:
            traced_command = (
                ["strace", "-qq", "-f", "-o", str(strace_path), *command]
                if _strace_available()
                else command
            )
            if request.input_mode == "stdin":
                seed_bytes = execution_input.path.read_bytes()
                completed = subprocess.run(
                    traced_command,
                    cwd=request.working_directory,
                    env=env,
                    input=seed_bytes,
                    capture_output=True,
                    timeout=timeout_seconds,
                )
                stdout_text = completed.stdout.decode("utf-8", errors="replace")
                stderr_text = completed.stderr.decode("utf-8", errors="replace")
            else:
                completed = subprocess.run(
                    traced_command,
                    cwd=request.working_directory,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    errors="replace",
                )
                stdout_text = completed.stdout
                stderr_text = completed.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            completed = subprocess.CompletedProcess(command, returncode=124)
            stdout_text = (
                exc.stdout.decode("utf-8", errors="replace")
                if isinstance(exc.stdout, (bytes, bytearray))
                else (exc.stdout or "")
            )
            stderr_text = (
                exc.stderr.decode("utf-8", errors="replace")
                if isinstance(exc.stderr, (bytes, bytearray))
                else (exc.stderr or "")
            )
        duration = time.monotonic() - start
        stdout_path.write_text(stdout_text, encoding="utf-8")
        stderr_path.write_text(stderr_text, encoding="utf-8")
        crash_detected, reason = detect_crash_candidate(completed.returncode, stdout_text, stderr_text)
        environment_classification, environment_reason = _classify_environment_issue(
            stderr_text,
            stdout_text,
            completed.returncode,
        )
        classification = _classify_execution_signal(
            exit_code=completed.returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            crash_detected=crash_detected,
            crash_reason=reason,
            timed_out=timed_out,
            environment_classification=environment_classification,
            environment_reason=environment_reason,
        )
        if (
            _strace_available()
            and classification["signal_category"] == "suspicious_semantic_signal"
            and "leaksanitizer has encountered a fatal error" in (str(classification.get("evidence_snippet") or "").lower())
        ):
            secondary_rerun_used = True
            observation_profile = "strace_then_direct_rerun"
            try:
                if request.input_mode == "stdin":
                    seed_bytes = execution_input.path.read_bytes()
                    replay_completed = subprocess.run(
                        command,
                        cwd=request.working_directory,
                        env=env,
                        input=seed_bytes,
                        capture_output=True,
                        timeout=timeout_seconds,
                    )
                    replay_stdout_text = replay_completed.stdout.decode("utf-8", errors="replace")
                    replay_stderr_text = replay_completed.stderr.decode("utf-8", errors="replace")
                else:
                    replay_completed = subprocess.run(
                        command,
                        cwd=request.working_directory,
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=timeout_seconds,
                        errors="replace",
                    )
                    replay_stdout_text = replay_completed.stdout
                    replay_stderr_text = replay_completed.stderr
                replay_crash_detected, replay_reason = detect_crash_candidate(
                    replay_completed.returncode,
                    replay_stdout_text,
                    replay_stderr_text,
                )
                replay_environment_classification, replay_environment_reason = _classify_environment_issue(
                    replay_stderr_text,
                    replay_stdout_text,
                    replay_completed.returncode,
                )
                replay_classification = _classify_execution_signal(
                    exit_code=replay_completed.returncode,
                    stdout=replay_stdout_text,
                    stderr=replay_stderr_text,
                    crash_detected=replay_crash_detected,
                    crash_reason=replay_reason,
                    timed_out=False,
                    environment_classification=replay_environment_classification,
                    environment_reason=replay_environment_reason,
                )
                secondary_signal_category = str(replay_classification["signal_category"])
                secondary_evidence_snippet = replay_classification.get("evidence_snippet")
                if replay_classification["signal_category"] != classification["signal_category"] or (
                    replay_classification["signal_category"] == "semantic_crash_candidate"
                ):
                    completed = replay_completed
                    stdout_text = replay_stdout_text
                    stderr_text = replay_stderr_text
                    crash_detected = bool(replay_classification["crash_candidate"])
                    reason = str(replay_classification.get("crash_reason") or "")
                    classification = replay_classification
                    signal_category = str(classification["signal_category"])
                    signal_reason = str(classification["signal_reason"])
                    signal_subcategory = str(classification.get("signal_subcategory") or "")
                    evidence_snippet = classification.get("evidence_snippet")
            except subprocess.TimeoutExpired:
                secondary_signal_category = "timeout_failure"
                secondary_evidence_snippet = "secondary direct replay timed out"
        crash_detected = bool(classification["crash_candidate"])
        reason = str(classification.get("crash_reason") or "")
        signal_category = str(classification["signal_category"])
        signal_reason = str(classification["signal_reason"])
        signal_subcategory = str(classification.get("signal_subcategory") or "")
        evidence_snippet = classification.get("evidence_snippet")
        signal_signature = _signal_signature(signal_category, signal_subcategory, evidence_snippet)
        strace_summary, observed_files = _summarize_strace(strace_path)
        signal_category_counts[signal_category] = signal_category_counts.get(signal_category, 0) + 1
        record = BinaryExecutionRunRecord(
            input_path=str(execution_input.path),
            source_kind=execution_input.source_kind,
            source_path=execution_input.source_path,
            command=command,
            exit_code=completed.returncode,
            stdout_log_path=str(stdout_path),
            stderr_log_path=str(stderr_path),
            stdout_excerpt=stdout_text[:4000],
            stderr_excerpt=stderr_text[:4000],
            duration_seconds=duration,
            crash_candidate=crash_detected,
            crash_reason=reason or None,
            signal_category=signal_category,
            signal_subcategory=signal_subcategory or None,
            signal_reason=signal_reason,
            environment_classification=environment_classification,
            environment_reason=environment_reason,
            selected_binary_slice_focus=str(request.metadata.get("selected_binary_slice_focus") or ""),
            input_contract=str(request.metadata.get("binary_input_contract") or request.input_mode),
            input_contract_source=str(request.metadata.get("binary_input_contract_source") or ""),
            source_of_signal=str(classification.get("source_of_signal") or ""),
            evidence_snippet=str(evidence_snippet or ""),
            signal_signature=signal_signature,
            signal_confidence=str(classification.get("signal_confidence") or ""),
            signal_explanation=str(classification.get("signal_explanation") or ""),
            promotion_decision=str(classification.get("promotion_decision") or ""),
            promotion_reason=str(classification.get("promotion_reason") or ""),
            strace_log_path=str(strace_path) if strace_path.exists() else None,
            strace_summary=strace_summary or None,
            observed_file_paths=observed_files,
            observation_profile=observation_profile,
            secondary_rerun_used=secondary_rerun_used,
            secondary_signal_category=secondary_signal_category,
            secondary_evidence_snippet=str(secondary_evidence_snippet or ""),
            timed_out=timed_out,
        )
        run_records.append(record)
        if crash_detected:
            crash_candidates.append(
                materialize_crash_candidate(
                    task_id=request.task_id,
                    execution_input=execution_input,
                    output_dir=request.crash_output_dir,
                    reason=reason,
                    exit_code=completed.returncode,
                ),
            )

    status = "BINARY_CRASH_CANDIDATE_FOUND" if crash_candidates else "BINARY_EXECUTED"
    manifest = {
        "task_id": request.task_id,
        "status": status,
        "binary_name": request.binary_name,
        "binary_analysis_backend": request.analysis_backend,
        "selected_binary_path": str(request.binary_path),
        "selected_launcher_path": str(request.selected_launcher_path),
        "selected_wrapper_path": str(request.selected_wrapper_path) if request.selected_wrapper_path else None,
        "input_mode": request.input_mode,
        "input_delivery_path": str(request.input_delivery_path) if request.input_delivery_path else None,
        "working_directory": str(request.working_directory),
        "argv_template": request.argv_template,
        "env_overrides": request.env_overrides,
        "seed_sources": request.seed_sources,
        "corpus_sources": request.corpus_sources,
        "crash_sources": request.crash_sources,
        "execution_strategy": request.execution_strategy,
        "input_count": len(request.inputs),
        "run_count": len(run_records),
        "run_records": [record.model_dump(mode="json") for record in run_records],
        "execution_signal_count": sum(count for category, count in signal_category_counts.items() if category != "clean_exit"),
        "signal_category_counts": signal_category_counts,
        "semantic_subcategory_distribution": {
            key: sum(1 for record in run_records if record.signal_subcategory == key)
            for key in sorted({record.signal_subcategory for record in run_records if record.signal_subcategory})
        },
        "promotion_rate": (len(crash_candidates) / len(run_records)) if run_records else 0.0,
        "candidate_promotion_rules": {
            "promote": [
                "semantic_memory_violation_like",
                "semantic_abort_signal",
                "semantic_assertion_failure",
            ],
            "observe": [
                "suspicious_semantic_signal",
            ],
            "ignore": [
                "environment_failure",
                "loader_failure",
                "contract_failure",
                "timeout_failure",
                "oom_failure",
                "semantic_parser_reject_only",
                "semantic_format_mismatch",
                "semantic_usage_rejection",
                "informational_runtime_output",
                "clean_exit",
            ],
        },
        "per_input_execution_summary": [
            {
                "input_path": record.input_path,
                "source_kind": record.source_kind,
                "exit_code": record.exit_code,
                "signal_category": record.signal_category,
                "signal_subcategory": record.signal_subcategory,
                "signal_reason": record.signal_reason,
                "source_of_signal": record.source_of_signal,
                "signal_signature": record.signal_signature,
                "signal_confidence": record.signal_confidence,
                "signal_explanation": record.signal_explanation,
                "promotion_decision": record.promotion_decision,
                "promotion_reason": record.promotion_reason,
                "evidence_snippet": record.evidence_snippet,
                "crash_candidate": record.crash_candidate,
                "crash_reason": record.crash_reason,
                "environment_classification": record.environment_classification,
                "environment_reason": record.environment_reason,
                "selected_binary_slice_focus": record.selected_binary_slice_focus,
            }
            for record in run_records
        ],
        "crash_candidate_count": len(crash_candidates),
        "binary_execution_crash_candidate_count": len(crash_candidates),
        "crash_candidates": [candidate.model_dump(mode="json") for candidate in crash_candidates],
        "stdout_excerpt": run_records[-1].stdout_excerpt if run_records else "",
        "stderr_excerpt": run_records[-1].stderr_excerpt if run_records else "",
        "exit_code": run_records[-1].exit_code if run_records else None,
        "slice_focus_evidence": {
            "selected_binary_slice_focus": request.metadata.get("selected_binary_slice_focus"),
            "slice_manifest_path": request.metadata.get("binary_slice_manifest_path"),
        },
        "input_contract_evidence": {
            "binary_input_contract": request.metadata.get("binary_input_contract") or request.input_mode,
            "binary_input_contract_kind": request.metadata.get("binary_input_contract_kind"),
            "binary_input_contract_hints": request.metadata.get("binary_input_contract_hints", []),
            "binary_input_contract_source": request.metadata.get("binary_input_contract_source"),
            "binary_input_contract_confidence": request.metadata.get("binary_input_contract_confidence"),
            "binary_input_contract_confidence_reason": request.metadata.get("binary_input_contract_confidence_reason"),
            "input_delivery_path": str(request.input_delivery_path) if request.input_delivery_path else None,
            "launcher_semantics_source": request.metadata.get("launcher_semantics_source"),
        },
        "launcher_contract": {
            "launcher_path": str(request.selected_launcher_path),
            "wrapper_path": str(request.selected_wrapper_path) if request.selected_wrapper_path else None,
            "actual_command": run_records[-1].command if run_records else [],
            "working_directory": str(request.working_directory),
        },
        "execution_environment_summary": {
            "environment_failure_count": sum(1 for record in run_records if record.environment_classification == "environment_failure"),
            "loader_failure_count": sum(1 for record in run_records if record.environment_classification == "loader_failure"),
            "contract_failure_count": sum(1 for record in run_records if record.environment_classification == "contract_failure"),
            "timeout_failure_count": sum(1 for record in run_records if record.signal_category == "timeout_failure"),
            "oom_failure_count": sum(1 for record in run_records if record.signal_category == "oom_failure"),
            "suspicious_semantic_signal_count": sum(1 for record in run_records if record.signal_category == "suspicious_semantic_signal"),
            "semantic_crash_candidate_count": len(crash_candidates),
        },
        "replay_profile": {
            "strace_enabled": _strace_available(),
            "asan_options": env.get("ASAN_OPTIONS"),
            "lsan_options": env.get("LSAN_OPTIONS"),
            "secondary_direct_rerun_used": any(record.secondary_rerun_used for record in run_records),
        },
    }
    return BinaryExecutionResult(
        plan={},
        manifest=manifest,
        run_records=run_records,
        crash_candidates=crash_candidates,
    )

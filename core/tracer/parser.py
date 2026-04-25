from __future__ import annotations

import re
from pathlib import Path

from core.tracer.models import ReplayResult, TracedCrash

ASAN_TYPE_PATTERN = re.compile(r"ERROR: AddressSanitizer: ([^\s]+)")
STACK_PATTERN = re.compile(r"^\s*#\d+.*$", re.MULTILINE)
FUNC_PATTERN = re.compile(r"\bin ([^\s].*?)(?:\s+\(|$)")
LIBFUZZER_TIMEOUT_PATTERN = re.compile(r"ERROR: libFuzzer: timeout after (\d+)")
LIBFUZZER_SIGNAL_PATTERN = re.compile(r"ERROR: libFuzzer: deadly signal")
SUMMARY_PATTERN = re.compile(
    r"SUMMARY:\s+AddressSanitizer:\s+[^\s]+\s+(?P<file>[^:\n]+):(?P<line>\d+)(?::\d+)?\s+in\s+(?P<function>[^\n]+)"
)
RUNTIME_FRAME_SKIP_PATTERNS = (
    "compiler-rt",
    "asan_",
    "libasan",
    "__asan",
    "__sanitizer",
    "sanitizer_common",
    "libc.so",
    "ld-linux",
    "libpthread",
    "libgcc",
)


def _environment_classification(stderr: str, exit_code: int) -> tuple[str | None, str | None]:
    lowered = stderr.lower()
    if any(
        token in lowered
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
    if "missing glibc loader" in lowered or "ld-linux" in lowered:
        return "loader_failure", "missing_loader_runtime"
    if "error while loading shared libraries" in lowered:
        return "loader_failure", "shared_library_resolution_failed"
    if "usage:" in lowered and exit_code == 2:
        return "contract_failure", "launcher_usage_error"
    if "no such file or directory" in lowered or "not found" in lowered:
        return "environment_failure", "missing_runtime_dependency"
    return None, None


def _is_runtime_frame(frame_text: str) -> bool:
    lowered = frame_text.lower()
    return any(token in lowered for token in RUNTIME_FRAME_SKIP_PATTERNS)


def parse_replay_result(result: ReplayResult, crash_source: str) -> TracedCrash:
    stderr = result.stderr or result.stdout
    stacktrace = STACK_PATTERN.findall(stderr)
    match = ASAN_TYPE_PATTERN.search(stderr)
    environment_classification, environment_reason = _environment_classification(stderr, result.exit_code)

    if environment_classification is not None:
        crash_type = environment_classification
        crash_state = environment_reason or environment_classification
        sanitizer = "runtime-environment"
        trace_mode = "environment"
    elif match:
        crash_type = match.group(1)
        func_names = []
        for line in stacktrace[:8]:
            func_match = FUNC_PATTERN.search(line)
            if func_match:
                candidate = func_match.group(1).strip()
                if _is_runtime_frame(candidate):
                    continue
                func_names.append(candidate)
            if len(func_names) >= 3:
                break
        if not func_names:
            summary_match = SUMMARY_PATTERN.search(stderr)
            if summary_match:
                func_names.append(
                    f"{summary_match.group('function').strip()} "
                    f"{summary_match.group('file')}:{summary_match.group('line')}"
                )
        crash_state = " | ".join(func_names) if func_names else crash_type
        sanitizer = "address"
        trace_mode = "live_asan"
    else:
        timeout_match = LIBFUZZER_TIMEOUT_PATTERN.search(stderr)
        if timeout_match:
            crash_type = "timeout"
            crash_state = f"timeout:{timeout_match.group(1)}s"
        elif LIBFUZZER_SIGNAL_PATTERN.search(stderr):
            crash_type = "deadly-signal"
            crash_state = "libfuzzer:deadly-signal"
        else:
            name = Path(result.testcase_path).name
            if crash_source == "imported_valid":
                category = "imported"
            elif crash_source == "suspicious_candidate":
                category = "suspicious_candidate"
            else:
                category = "live"
            if name.startswith("imported_"):
                parts = name.split("_", 2)
                if len(parts) >= 2:
                    category = parts[1]
            crash_type = category
            crash_state = f"{category}:{name}"
        if crash_source == "imported_valid":
            sanitizer = "address-import-fallback"
            trace_mode = "fallback"
        elif crash_source == "suspicious_candidate":
            sanitizer = "suspicious-candidate-replay"
            trace_mode = "suspicious_candidate"
        else:
            sanitizer = "unknown-live"
            trace_mode = "fallback"

    return TracedCrash(
        testcase_path=result.testcase_path,
        harness_name=result.harness_name,
        binary_path=result.binary_path,
        crash_source=crash_source,
        trace_mode=trace_mode,
        sanitizer=sanitizer,
        crash_type=crash_type,
        crash_state=crash_state,
        stacktrace=stacktrace,
        stderr_excerpt=stderr[:4000],
        environment_classification=environment_classification,
        environment_reason=environment_reason,
        fallback_trigger_reason=environment_reason if environment_classification is not None else None,
    )

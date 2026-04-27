from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from pathlib import Path

from core.analysis.family_confirmation import build_trace_family_manifest
from core.analysis.suspicious_candidate import (
    GENERALIZED_TRACE_ADMISSION_RESULT_ACTIONABLE,
    GENERALIZED_TRACE_ADMISSION_RESULT_ADMITTED,
    GENERALIZED_TRACE_ADMISSION_RESULT_CLAIM_REJECTED,
    GENERALIZED_TRACE_ADMISSION_RESULT_NO_SIGNAL,
    claim_suspicious_candidates_for_trace,
    finalize_suspicious_candidate_trace,
    requeue_claimed_suspicious_candidates_for_trace,
    record_suspicious_candidate_trace_result,
    summarize_suspicious_candidate_admission,
    suspicious_candidate_trace_results_dir,
    suspicious_candidate_queue_path,
)
from core.binary.trace_bridge import (
    binary_candidate_dir,
    binary_provenance,
    find_run_record_for_testcase,
    is_binary_task,
)
from core.fuzz.harness_binding import active_harness_record, classify_crash_source
from core.models.task import TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.reproducer.queue import maybe_enqueue_repro
from core.state.task_state import TaskStateStore
from core.tracer import (
    candidate_targets,
    compute_signature,
    find_symbolizer,
    parse_replay_result,
    replay_testcase,
    write_trace_manifest,
)
from core.tracer.models import ReplayResult
from core.storage.layout import trace_dedup_index_path, trace_family_manifest_path
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("tracer-worker")

STACK_LINE_PATTERN = re.compile(r"^\s*#(?P<index>\d+)\s+(?P<pc>0x[0-9a-fA-F]+)(?:\s+in\s+(?P<rest>.*))?$")
INLINE_SOURCE_PATTERN = re.compile(
    r"^(?P<function>.+?)\s+(?P<file>(?:/|[A-Za-z0-9_.-]).*?):(?P<line>\d+)(?::(?P<column>\d+))?$"
)
MODULE_OFFSET_PATTERN = re.compile(r"\((?P<module>[^)]+)\+(?P<offset>0x[0-9a-fA-F]+)\)")
SUMMARY_SOURCE_PATTERN = re.compile(
    r"SUMMARY:\s+AddressSanitizer:\s+[^\s]+\s+(?P<file>[^:\n]+):(?P<line>\d+)(?::\d+)?\s+in\s+(?P<function>[^\n]+)"
)
SYMBOLIZED_FRAME_SKIP_PATTERNS = (
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
REPLAY_SIGNAL_TOKENS = (
    "addresssanitizer",
    "undefinedbehaviorsanitizer",
    "memorysanitizer",
    "deadly signal",
    "segmentation fault",
    "timeout",
    "abort",
    "assert",
    "runtime error:",
    "error:",
)
WEAK_SANITIZER_SIGNAL_TOKENS = (
    "error: addresssanitizer",
    "addresssanitizer:",
    "undefinedbehaviorsanitizer",
    "runtime error:",
    "warning: memorysanitizer",
    "memorysanitizer",
)
TRACE_MAX_DURATION_SECONDS = 600


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_source_location(source_location: str | None) -> tuple[str | None, int | None]:
    if not source_location:
        return None, None
    candidate = str(source_location).strip()
    if not candidate or candidate.startswith("??"):
        return None, None
    parts = candidate.rsplit(":", 2)
    if len(parts) >= 2:
        file_part = parts[0]
        line_part = parts[1] if len(parts) == 3 else parts[-1]
        try:
            return file_part, int(line_part)
        except ValueError:
            pass
    return candidate, None


def _is_source_frame(*parts: str | None) -> bool:
    lowered = " ".join(str(part or "") for part in parts).lower()
    return not any(token in lowered for token in SYMBOLIZED_FRAME_SKIP_PATTERNS)


def _parse_stack_frames(traced_crash: dict) -> list[dict]:
    frames: list[dict] = []
    for raw_line in traced_crash.get("stacktrace") or []:
        match = STACK_LINE_PATTERN.match(str(raw_line))
        if match is None:
            continue
        frame: dict[str, object] = {
            "index": int(match.group("index")),
            "pc": match.group("pc"),
            "raw_frame": raw_line,
            "is_source_frame": False,
        }
        rest = (match.group("rest") or "").strip()
        if rest:
            inline_match = INLINE_SOURCE_PATTERN.match(rest)
            if inline_match:
                frame["function"] = inline_match.group("function").strip()
                frame["file"] = inline_match.group("file").strip()
                frame["line"] = int(inline_match.group("line"))
            elif " (" in rest:
                function_name = rest.split(" (", 1)[0].strip()
                if function_name:
                    frame["function"] = function_name
        module_match = MODULE_OFFSET_PATTERN.search(str(raw_line))
        if module_match is not None:
            frame["module_path"] = module_match.group("module")
            frame["module_offset"] = module_match.group("offset")
        if frame.get("file") and frame.get("line") and _is_source_frame(
            str(frame.get("file") or ""),
            str(frame.get("function") or ""),
        ):
            frame["is_source_frame"] = True
        frames.append(frame)
    return frames


def _parse_symbolizer_output(stdout: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for block in [chunk.strip() for chunk in stdout.split("\n\n") if chunk.strip()]:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        function_name = lines[0] if lines else None
        source_location = lines[1] if len(lines) > 1 else None
        file_ref, line_number = _parse_source_location(source_location)
        entries.append(
            {
                "function": function_name,
                "source_location": source_location,
                "file": file_ref,
                "line": line_number,
            }
        )
    return entries


def _symbolize_parsed_frames(binary_path: str, symbolizer: str | None, frames: list[dict]) -> list[dict]:
    if not symbolizer:
        return frames
    inputs: list[str] = []
    positions: list[int] = []
    binary_name = Path(binary_path).name
    for index, frame in enumerate(frames):
        if frame.get("file") and frame.get("line"):
            continue
        module_path = str(frame.get("module_path") or "")
        if module_path and module_path not in {binary_path, binary_name} and Path(module_path).name != binary_name:
            continue
        candidate_value = str(frame.get("module_offset") or frame.get("pc") or "").strip()
        if not candidate_value:
            continue
        inputs.append(candidate_value)
        positions.append(index)
    if not inputs:
        return frames

    completed = subprocess.run(
        [symbolizer, "--obj", binary_path, "--output-style=GNU"],
        input="\n".join(inputs) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    for position, symbolized in zip(positions, _parse_symbolizer_output(completed.stdout)):
        if symbolized.get("function"):
            frames[position]["function"] = symbolized["function"]
        if symbolized.get("source_location"):
            frames[position]["source_location"] = symbolized["source_location"]
        if symbolized.get("file"):
            frames[position]["file"] = symbolized["file"]
        if symbolized.get("line") is not None:
            frames[position]["line"] = symbolized["line"]
        if frames[position].get("file") and frames[position].get("line") and _is_source_frame(
            str(frames[position].get("file") or ""),
            str(frames[position].get("function") or ""),
        ):
            frames[position]["is_source_frame"] = True
    return frames


def _summary_source_frame(traced_crash: dict) -> dict | None:
    summary_match = SUMMARY_SOURCE_PATTERN.search(str(traced_crash.get("stderr_excerpt") or ""))
    if summary_match is None:
        return None
    frame = {
        "index": -1,
        "function": summary_match.group("function").strip(),
        "file": summary_match.group("file").strip(),
        "line": int(summary_match.group("line")),
        "raw_frame": "SUMMARY",
        "is_source_frame": False,
    }
    if _is_source_frame(str(frame["file"]), str(frame["function"])):
        frame["is_source_frame"] = True
        return frame
    return None


def _generic_crash_state(crash_state: str | None, crash_type: str | None) -> bool:
    normalized = str(crash_state or "").strip()
    if not normalized:
        return True
    if normalized == str(crash_type or "").strip():
        return True
    return "/" not in normalized and ":" not in normalized and "|" not in normalized


def _extract_replay_signal_lines(text: str) -> list[str]:
    signal_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if not line:
            continue
        if not any(token in lowered for token in REPLAY_SIGNAL_TOKENS):
            continue
        if line not in signal_lines:
            signal_lines.append(line)
    return signal_lines[:8]


def _decode_timeout_stream(raw_value: str | bytes | None) -> str:
    if raw_value is None:
        return ""
    if isinstance(raw_value, bytes):
        return raw_value.decode("utf-8", errors="replace")
    return str(raw_value)


def _build_timeout_replay_result(
    *,
    binary_path: str,
    harness_name: str,
    testcase_path: str,
    working_directory: Path,
    timeout_error: subprocess.TimeoutExpired,
) -> ReplayResult:
    stderr_text = _decode_timeout_stream(timeout_error.stderr)
    stdout_text = _decode_timeout_stream(timeout_error.stdout)
    timeout_line = f"ERROR: libFuzzer: timeout after {settings.replay_timeout_seconds}"
    if timeout_line.lower() not in stderr_text.lower():
        stderr_text = (
            f"{stderr_text.rstrip()}\n{timeout_line}\n".strip()
            if stderr_text.strip()
            else timeout_line
        )
    raw_command = timeout_error.cmd
    if isinstance(raw_command, (list, tuple)):
        command = [str(part) for part in raw_command if str(part)]
    elif raw_command:
        command = [str(raw_command)]
    else:
        command = [binary_path, testcase_path]
    launcher_path = command[0] if command else binary_path
    return ReplayResult(
        harness_name=harness_name,
        binary_path=binary_path,
        testcase_path=testcase_path,
        exit_code=124,
        stdout=stdout_text,
        stderr=stderr_text,
        command=command,
        launcher_path=launcher_path,
        working_directory=str(working_directory),
    )


def _classify_replay_signal(
    *,
    candidate_origin_kind: str,
    replay_exit_code: int,
    traced_crash,
    replay_timed_out: bool = False,
) -> dict:
    stderr_text = str(traced_crash.stderr_excerpt or "")
    lowered = stderr_text.lower()
    summary_lines = _extract_replay_signal_lines(stderr_text)
    crash_text_signal = bool(
        "segmentation fault" in lowered
        or "deadly signal" in lowered
    )
    timeout_signal = bool(
        replay_timed_out
        or traced_crash.crash_type == "timeout"
        or "timeout after" in lowered
    )
    sanitizer_signal = any(token in lowered for token in WEAK_SANITIZER_SIGNAL_TOKENS)
    crash_detected = bool(
        traced_crash.sanitizer == "address"
        or traced_crash.crash_type in {"timeout", "deadly-signal"}
        or crash_text_signal
    )
    if traced_crash.environment_classification is not None and candidate_origin_kind == "suspicious_candidate":
        return {
            "actionable": False,
            "crash_detected": False,
            "repro_admission_recommended": False,
            "classification": "environment_failure",
            "summary_lines": summary_lines,
            "signal_strength": "none",
            "signal_type": None,
            "replay_timed_out": replay_timed_out,
        }
    if crash_detected:
        strong_signal_type = "timeout" if timeout_signal else "crash"
        if candidate_origin_kind == "suspicious_candidate":
            weak_signal_type = "timeout" if timeout_signal else ("sanitizer" if sanitizer_signal else "crash")
            return {
                "actionable": True,
                "crash_detected": False,
                "repro_admission_recommended": True,
                "classification": "weak_actionable_signal",
                "summary_lines": summary_lines,
                "signal_strength": "weak",
                "signal_type": weak_signal_type,
                "replay_timed_out": replay_timed_out,
            }
        return {
            "actionable": True,
            "crash_detected": True,
            "repro_admission_recommended": True,
            "classification": "crash_like_signal",
            "summary_lines": summary_lines,
            "signal_strength": "strong",
            "signal_type": strong_signal_type,
            "replay_timed_out": replay_timed_out,
        }
    if candidate_origin_kind == "suspicious_candidate":
        weak_signal_type = None
        if timeout_signal:
            weak_signal_type = "timeout"
        elif sanitizer_signal:
            weak_signal_type = "sanitizer"
        elif replay_exit_code not in (0, 1):
            weak_signal_type = "exit_code"
        if weak_signal_type:
            return {
                "actionable": True,
                "crash_detected": False,
                "repro_admission_recommended": True,
                "classification": "weak_actionable_signal",
                "summary_lines": summary_lines,
                "signal_strength": "weak",
                "signal_type": weak_signal_type,
                "replay_timed_out": replay_timed_out,
            }
        return {
            "actionable": False,
            "crash_detected": False,
            "repro_admission_recommended": False,
            "classification": "no_actionable_signal",
            "summary_lines": [],
            "signal_strength": "none",
            "signal_type": None,
            "replay_timed_out": replay_timed_out,
        }
    return {
        "actionable": True,
        "crash_detected": False,
        "repro_admission_recommended": False,
        "classification": "raw_crash_candidate",
        "summary_lines": summary_lines,
        "signal_strength": "strong",
        "signal_type": "crash",
        "replay_timed_out": replay_timed_out,
    }


def _write_symbolized_frames(
    *,
    task_dir: Path,
    symbolized_dir: Path,
    crash_id: str,
    traced_crash: dict,
) -> tuple[str, str, dict | None]:
    symbolized_dir.mkdir(parents=True, exist_ok=True)
    binary_path = str(traced_crash.get("binary_path") or "")
    symbolizer = find_symbolizer(binary_path) if binary_path else None
    frames = _parse_stack_frames(traced_crash)
    frames = _symbolize_parsed_frames(binary_path, symbolizer, frames)
    if not any(frame.get("is_source_frame") for frame in frames):
        summary_frame = _summary_source_frame(traced_crash)
        if summary_frame is not None:
            frames.append(summary_frame)
    primary_source_frame = next((frame for frame in frames if frame.get("is_source_frame")), None)
    if primary_source_frame:
        symbolization_status = "success"
    elif not symbolizer:
        symbolization_status = "no_symbolizer"
    else:
        symbolization_status = "no_source_frames"
    payload = {
        "crash_id": crash_id,
        "symbolizer_path": symbolizer,
        "binary_path": binary_path,
        "frames": frames,
        "primary_source_frame": primary_source_frame,
        "symbolization_status": symbolization_status,
    }
    symbolized_path = symbolized_dir / f"{crash_id}.json"
    symbolized_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(symbolized_path), symbolization_status, primary_source_frame


def _replay_build_variant(task_dir: Path, harness_name: str, binary_path: str) -> dict:
    registry = _load_json(task_dir / "build" / "build_registry.json")
    matrix = _load_json(task_dir / "build" / "build_matrix_manifest.json")
    for item in registry.get("tracer_replay_binaries", []):
        if item.get("name") == harness_name and item.get("path") == binary_path:
            return {
                "replay_build_variant": item.get("build_variant") or "dedicated_tracer_build",
                "replay_binary_path": binary_path,
                "build_matrix_actual_mode": (
                    matrix.get("builds", {}).get("tracer_build", {}).get("actual_mode")
                ),
                "build_matrix_manifest_path": str(task_dir / "build" / "build_matrix_manifest.json"),
            }
    return {
        "replay_build_variant": "reuse_fuzzer_build_for_replay",
        "replay_binary_path": binary_path,
        "build_matrix_actual_mode": (
            matrix.get("builds", {}).get("tracer_build", {}).get("actual_mode")
        ),
        "build_matrix_manifest_path": str(task_dir / "build" / "build_matrix_manifest.json")
        if (task_dir / "build" / "build_matrix_manifest.json").exists()
        else None,
    }


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("tracer received task %s", task_id)
    trace_started_at = task_store.now()
    trace_started_monotonic = time.monotonic()
    task_store.update_status(
        task_id,
        TaskStatus.TRACING,
        runtime_patch={
            "trace_started_at": trace_started_at,
            "trace_timeout_seconds": TRACE_MAX_DURATION_SECONDS,
        },
    )
    task = task_store.load_task(task_id)
    task_dir = Path(task.task_dir)
    binary_mode = is_binary_task(task_dir)
    crashes_raw_dir = binary_candidate_dir(task_dir) if binary_mode else Path(task.layout["crashes_raw"])
    traced_dir = Path(task.layout["trace_traced_crashes"])
    traced_dir.mkdir(parents=True, exist_ok=True)
    symbolized_dir = Path(task.layout.get("trace_symbolized_frames") or (task_dir / "trace" / "symbolized_frames"))
    symbolized_dir.mkdir(parents=True, exist_ok=True)
    candidate_results_dir = suspicious_candidate_trace_results_dir(task_dir)
    candidate_results_dir.mkdir(parents=True, exist_ok=True)
    active_harness = active_harness_record(task_dir)
    provenance = binary_provenance(task_dir) if binary_mode else {}

    dedup_index: dict[str, list[str]] = {}
    traced_paths: list[str] = []
    symbolized_paths: list[str] = []
    traced_artifacts: list[dict[str, object]] = []
    replay_summaries: list[dict] = []
    trace_mode = None
    sanitizer = None
    crash_source_used = None
    trace_input_origin = "raw_crash_directory"
    suspicious_queue_file = str(suspicious_candidate_queue_path(task_dir))
    candidate_result_paths: list[str] = []
    candidate_claim_count = 0
    candidate_trace_artifact_count = 0
    candidate_rejected_count = 0
    candidate_repro_eligible_count = 0
    claimed_candidate_ids: list[str] = []
    processed_candidate_ids: set[str] = set()
    trace_inputs: list[dict] = []
    processed_trace_inputs = 0
    trace_partial_completion = False
    trace_timed_out_at = None

    def _trace_budget_exhausted() -> bool:
        nonlocal trace_partial_completion, trace_timed_out_at
        if trace_partial_completion:
            return True
        elapsed_seconds = time.monotonic() - trace_started_monotonic
        if elapsed_seconds < TRACE_MAX_DURATION_SECONDS:
            return False
        trace_partial_completion = True
        trace_timed_out_at = task_store.now()
        logger.warning(
            "task %s tracing budget exhausted after %.2fs; writing partial trace manifest",
            task_id,
            elapsed_seconds,
        )
        return True

    if crashes_raw_dir.exists():
        for testcase in sorted(path for path in crashes_raw_dir.iterdir() if path.is_file()):
            crash_source = classify_crash_source(testcase)
            if settings.crash_source_policy == "live_raw_only" and crash_source != "live_raw":
                continue
            trace_inputs.append(
                {
                    "testcase_path": str(testcase),
                    "candidate_id": Path(testcase).stem,
                    "candidate_origin_kind": "raw_crash",
                    "candidate_reason": "raw_crash_candidate_available",
                    "candidate_reasons": ["raw_crash_candidate_available"],
                    "candidate_targets": [],
                    "candidate_source_kind": "crashes_raw",
                    "crash_source": crash_source,
                }
            )
    if not trace_inputs:
        trace_input_origin = "binary_candidate_queue" if binary_mode else "generalized_candidate_queue"
        claimed_candidates = claim_suspicious_candidates_for_trace(
            task_dir,
            owner_task_id=task_id,
            claimed_by="apps.workers.tracer.main",
            now_iso=task_store.now(),
        )
        candidate_claim_count = len(claimed_candidates)
        claimed_candidate_ids = [
            str(item.get("candidate_id") or "").strip()
            for item in claimed_candidates
            if str(item.get("candidate_id") or "").strip()
        ]
        for item in claimed_candidates:
            trace_inputs.append(
                {
                    "testcase_path": str(item.get("testcase_path")),
                    "candidate_id": item.get("candidate_id"),
                    "candidate_origin_kind": "suspicious_candidate",
                    "candidate_reason": item.get("candidate_reason"),
                    "candidate_reasons": item.get("candidate_reasons") or [],
                    "candidate_targets": item.get("candidate_targets") or [],
                    "candidate_source_kind": item.get("candidate_source_kind"),
                    "crash_source": "suspicious_candidate",
                    "candidate_confidence": item.get("candidate_confidence"),
                    "candidate_priority": item.get("candidate_priority"),
                    "selected_harness": item.get("selected_harness"),
                    "selected_target_function": item.get("selected_target_function"),
                    "originating_task_id": item.get("originating_task_id"),
                    "originating_round_task_id": item.get("originating_round_task_id"),
                    "source_campaign_task_id": item.get("source_campaign_task_id"),
                    "campaign_round": item.get("campaign_round"),
                    "campaign_session_index": item.get("campaign_session_index"),
                    "project": item.get("project"),
                    "benchmark": item.get("benchmark"),
                    "target_mode": item.get("target_mode"),
                    "trace_claim_token": item.get("trace_claim_token"),
                    "trace_claimed_at": item.get("trace_claimed_at"),
                    "trace_claimed_by": item.get("trace_claimed_by"),
                }
            )
    suspicious_trace_input_count = sum(
        1 for item in trace_inputs if item.get("candidate_origin_kind") == "suspicious_candidate"
    )

    for trace_input in trace_inputs:
        if _trace_budget_exhausted():
            break
        testcase = Path(trace_input["testcase_path"])
        crash_source = str(trace_input.get("crash_source") or "live_raw")
        candidate_origin_kind = str(trace_input.get("candidate_origin_kind") or "raw_crash")
        best = None
        best_signal = None
        for harness_name, binary_path in candidate_targets(task_dir):
            if _trace_budget_exhausted():
                break
            replay_variant = _replay_build_variant(task_dir, harness_name, binary_path) if not binary_mode else {
                "replay_build_variant": "binary_execution_replay",
                "replay_binary_path": binary_path,
                "build_matrix_actual_mode": None,
                "build_matrix_manifest_path": None,
            }
            replay_timed_out = False
            try:
                replay = replay_testcase(binary_path, harness_name, str(testcase), task_dir)
            except subprocess.TimeoutExpired as timeout_error:
                replay_timed_out = True
                replay = _build_timeout_replay_result(
                    binary_path=binary_path,
                    harness_name=harness_name,
                    testcase_path=str(testcase),
                    working_directory=task_dir,
                    timeout_error=timeout_error,
                )
            parsed = parse_replay_result(replay, crash_source)
            parsed.signature = compute_signature(parsed.crash_type, parsed.crash_state)
            signal = _classify_replay_signal(
                candidate_origin_kind=candidate_origin_kind,
                replay_exit_code=replay.exit_code,
                traced_crash=parsed,
                replay_timed_out=replay_timed_out,
            )
            parsed.candidate_origin_kind = candidate_origin_kind
            parsed.candidate_origin_path = str(testcase)
            parsed.candidate_id = str(trace_input.get("candidate_id") or testcase.stem)
            parsed.candidate_reason = str(trace_input.get("candidate_reason") or "")
            parsed.candidate_reasons = list(trace_input.get("candidate_reasons") or [])
            parsed.candidate_targets = list(trace_input.get("candidate_targets") or [])
            parsed.candidate_source_kind = trace_input.get("candidate_source_kind")
            parsed.trace_admission_kind = trace_input_origin
            parsed.trace_admission_reason = (
                parsed.candidate_reason
                or (
                    "generalized_candidate_trace_admission_available"
                    if candidate_origin_kind == "suspicious_candidate"
                    else "raw_crash_candidate_available"
                )
            )
            parsed.crash_detected = bool(signal["crash_detected"])
            parsed.repro_admission_recommended = bool(signal["repro_admission_recommended"])
            parsed.replay_signal_classification = str(signal["classification"])
            parsed.replay_signal_summary = list(signal["summary_lines"])
            parsed.signal_strength = str(signal.get("signal_strength") or "")
            parsed.signal_type = signal.get("signal_type")
            parsed.replay_signal_strength = str(signal.get("signal_strength") or "")
            parsed.replay_signal_type = signal.get("signal_type")
            parsed.replay_timed_out = bool(signal.get("replay_timed_out"))
            parsed.replay_exit_code = replay.exit_code
            run_record = find_run_record_for_testcase(task_dir, str(testcase)) if binary_mode else {}
            if binary_mode:
                parsed.target_mode = provenance.get("target_mode")
                parsed.binary_provenance = provenance.get("binary_provenance")
                parsed.binary_origin_task_id = provenance.get("binary_origin_task_id")
                parsed.binary_target_name = provenance.get("binary_target_name")
                parsed.binary_analysis_backend = provenance.get("binary_analysis_backend")
                parsed.launcher_semantics_source = provenance.get("launcher_semantics_source")
                parsed.seed_provenance = provenance.get("seed_provenance")
                parsed.corpus_provenance = provenance.get("corpus_provenance")
                parsed.binary_execution_command = list(run_record.get("command", replay.command))
                parsed.input_mode = provenance.get("input_mode")
                parsed.selected_binary_slice_focus = provenance.get("selected_binary_slice_focus") or run_record.get("selected_binary_slice_focus")
                parsed.binary_input_contract = provenance.get("binary_input_contract") or run_record.get("input_contract")
                parsed.binary_input_contract_source = provenance.get("binary_input_contract_source") or run_record.get("input_contract_source")
                parsed.binary_input_contract_confidence = provenance.get("binary_input_contract_confidence")
                parsed.binary_input_contract_confidence_reason = provenance.get("binary_input_contract_confidence_reason")
                parsed.execution_signal_category = run_record.get("signal_category")
                parsed.execution_signal_reason = run_record.get("signal_reason")
                parsed.execution_input_path = run_record.get("input_path")
                parsed.execution_input_source_kind = run_record.get("source_kind")
            best = parsed
            best_signal = signal
            replay_summaries.append(
                {
                    "testcase_path": str(testcase),
                    "candidate_id": parsed.candidate_id,
                    "candidate_origin_kind": candidate_origin_kind,
                    "harness_name": harness_name,
                    "exit_code": replay.exit_code,
                    "signature": parsed.signature,
                    "crash_type": parsed.crash_type,
                    "crash_source": crash_source,
                    "trace_mode": parsed.trace_mode,
                    "crash_detected": parsed.crash_detected,
                    "repro_admission_recommended": parsed.repro_admission_recommended,
                    "replay_signal_classification": parsed.replay_signal_classification,
                    "replay_signal_summary": parsed.replay_signal_summary,
                    "signal_strength": parsed.signal_strength,
                    "signal_type": parsed.signal_type,
                    "replay_timed_out": parsed.replay_timed_out,
                    "target_mode": parsed.target_mode,
                    "selected_binary_slice_focus": parsed.selected_binary_slice_focus,
                    "execution_signal_category": parsed.execution_signal_category,
                    "environment_classification": parsed.environment_classification,
                    "environment_reason": parsed.environment_reason,
                    "candidate_origin": str(testcase),
                    "trace_admission_kind": trace_input_origin,
                    "replay_launcher": replay.launcher_path,
                    "replay_command": replay.command,
                    **replay_variant,
                },
            )
            if _trace_budget_exhausted():
                break
            if binary_mode and parsed.environment_classification is not None:
                continue
            if parsed.sanitizer == "address":
                break
            if candidate_origin_kind == "suspicious_candidate" and signal["actionable"]:
                break

        if best is None and trace_partial_completion:
            break
        if best is None and candidate_origin_kind == "suspicious_candidate":
            rejection_reason = "no_replay_targets_available_for_candidate"
            candidate_id = str(trace_input.get("candidate_id") or testcase.stem)
            admission_events = [GENERALIZED_TRACE_ADMISSION_RESULT_CLAIM_REJECTED]
            candidate_result_payload = {
                "task_id": task_id,
                "candidate_id": candidate_id,
                "candidate_origin_kind": candidate_origin_kind,
                "candidate_reason": trace_input.get("candidate_reason"),
                "candidate_reasons": list(trace_input.get("candidate_reasons") or []),
                "candidate_targets": list(trace_input.get("candidate_targets") or []),
                "candidate_priority": trace_input.get("candidate_priority"),
                "candidate_confidence": trace_input.get("candidate_confidence"),
                "testcase_path": str(testcase),
                "selected_harness": trace_input.get("selected_harness"),
                "selected_target_function": trace_input.get("selected_target_function"),
                "originating_task_id": trace_input.get("originating_task_id"),
                "originating_round_task_id": trace_input.get("originating_round_task_id"),
                "source_campaign_task_id": trace_input.get("source_campaign_task_id"),
                "campaign_round": trace_input.get("campaign_round"),
                "campaign_session_index": trace_input.get("campaign_session_index"),
                "project": trace_input.get("project"),
                "benchmark": trace_input.get("benchmark"),
                "target_mode": trace_input.get("target_mode"),
                "trace_admission_kind": trace_input_origin,
                "trace_claim_token": trace_input.get("trace_claim_token"),
                "trace_claimed_at": trace_input.get("trace_claimed_at"),
                "trace_claimed_by": trace_input.get("trace_claimed_by"),
                "trace_state": "trace_rejected",
                "admission_events": admission_events,
                "admission_result": GENERALIZED_TRACE_ADMISSION_RESULT_CLAIM_REJECTED,
                "trace_result_classification": "no_replay_targets_available",
                "trace_rejection_reason": rejection_reason,
                "trace_artifact_path": None,
                "trace_completed_at": task_store.now(),
                "weak_signal_detected": False,
                "weak_signal_type": None,
                "repro_admission_eligibility": "blocked",
                "repro_admission_reason": rejection_reason,
                "replay_attempt_count": 0,
                "replay_attempts": [],
            }
            result_path = record_suspicious_candidate_trace_result(
                task_dir,
                candidate_id=candidate_id,
                result_payload=candidate_result_payload,
            )
            finalize_suspicious_candidate_trace(
                task_dir,
                candidate_id=candidate_id,
                trace_state="trace_rejected",
                now_iso=task_store.now(),
                trace_result_path=result_path,
                trace_result_classification="no_replay_targets_available",
                trace_artifact_path=None,
                trace_rejection_reason=rejection_reason,
                repro_admission_eligibility="blocked",
                repro_admission_reason=rejection_reason,
                admission_events=admission_events,
                admission_result=GENERALIZED_TRACE_ADMISSION_RESULT_CLAIM_REJECTED,
                weak_signal_detected=False,
                weak_signal_type=None,
            )
            candidate_result_paths.append(result_path)
            candidate_rejected_count += 1
            processed_candidate_ids.add(candidate_id)
            continue
        if best is None:
            continue
        traced_payload = dict(best.__dict__)
        trace_artifact_path = None
        trace_state = "trace_rejected"
        trace_result_classification = str((best_signal or {}).get("classification") or "no_actionable_signal")
        trace_rejection_reason = None
        repro_admission_eligibility = (
            "eligible"
            if bool((best_signal or {}).get("repro_admission_recommended"))
            else "blocked"
        )
        repro_admission_reason = (
            "trace_result_recommended"
            if repro_admission_eligibility == "eligible"
            else "trace_result_not_recommended"
        )
        if candidate_origin_kind != "suspicious_candidate" or (best_signal or {}).get("actionable", False):
            target = traced_dir / f"{best.candidate_id or Path(testcase).stem}.json"
            target.write_text(json.dumps(traced_payload, indent=2), encoding="utf-8")
            symbolized_path, symbolization_status, primary_source_frame = _write_symbolized_frames(
                task_dir=task_dir,
                symbolized_dir=symbolized_dir,
                crash_id=target.stem,
                traced_crash=traced_payload,
            )
            traced_payload["symbolized_frames_path"] = symbolized_path
            traced_payload["symbolization_status"] = symbolization_status
            if primary_source_frame and _generic_crash_state(
                str(traced_payload.get("crash_state") or ""),
                str(traced_payload.get("crash_type") or ""),
            ):
                traced_payload["crash_state"] = (
                    f"{primary_source_frame.get('function')} "
                    f"{primary_source_frame.get('file')}:{primary_source_frame.get('line')}"
                )
            traced_payload["signature"] = compute_signature(
                str(traced_payload.get("crash_type") or ""),
                str(traced_payload.get("crash_state") or ""),
            )
            target.write_text(json.dumps(traced_payload, indent=2), encoding="utf-8")
            trace_artifact_path = str(target)
            traced_paths.append(str(target))
            symbolized_paths.append(symbolized_path)
            traced_artifacts.append({"artifact_path": str(target), "payload": traced_payload})
            dedup_index.setdefault(str(traced_payload.get("signature") or ""), []).append(str(target))
            trace_mode = trace_mode or str(traced_payload.get("trace_mode") or "")
            sanitizer = sanitizer or str(traced_payload.get("sanitizer") or "")
            crash_source_used = crash_source_used or crash_source
            if candidate_origin_kind == "suspicious_candidate":
                candidate_trace_artifact_count += 1
                trace_state = "trace_completed"
        elif candidate_origin_kind == "suspicious_candidate":
            trace_rejection_reason = "no_actionable_signal_after_trace_replay"
            candidate_rejected_count += 1
            repro_admission_eligibility = "blocked"
            repro_admission_reason = trace_rejection_reason

        if candidate_origin_kind == "suspicious_candidate":
            candidate_id = str(trace_input.get("candidate_id") or testcase.stem)
            weak_signal_detected = str((best_signal or {}).get("classification") or "") == "weak_actionable_signal"
            final_admission_result = (
                GENERALIZED_TRACE_ADMISSION_RESULT_ACTIONABLE
                if trace_artifact_path
                else GENERALIZED_TRACE_ADMISSION_RESULT_NO_SIGNAL
            )
            admission_events = [GENERALIZED_TRACE_ADMISSION_RESULT_ADMITTED, final_admission_result]
            candidate_result_payload = {
                "task_id": task_id,
                "candidate_id": candidate_id,
                "candidate_origin_kind": candidate_origin_kind,
                "candidate_reason": trace_input.get("candidate_reason"),
                "candidate_reasons": list(trace_input.get("candidate_reasons") or []),
                "candidate_targets": list(trace_input.get("candidate_targets") or []),
                "candidate_source_kind": trace_input.get("candidate_source_kind"),
                "candidate_priority": trace_input.get("candidate_priority"),
                "candidate_confidence": trace_input.get("candidate_confidence"),
                "testcase_path": str(testcase),
                "selected_harness": trace_input.get("selected_harness"),
                "selected_target_function": trace_input.get("selected_target_function"),
                "originating_task_id": trace_input.get("originating_task_id"),
                "originating_round_task_id": trace_input.get("originating_round_task_id"),
                "source_campaign_task_id": trace_input.get("source_campaign_task_id"),
                "campaign_round": trace_input.get("campaign_round"),
                "campaign_session_index": trace_input.get("campaign_session_index"),
                "project": trace_input.get("project"),
                "benchmark": trace_input.get("benchmark"),
                "target_mode": trace_input.get("target_mode"),
                "trace_admission_kind": trace_input_origin,
                "trace_claim_token": trace_input.get("trace_claim_token"),
                "trace_claimed_at": trace_input.get("trace_claimed_at"),
                "trace_claimed_by": trace_input.get("trace_claimed_by"),
                "trace_state": trace_state,
                "admission_events": admission_events,
                "admission_result": final_admission_result,
                "trace_result_classification": trace_result_classification,
                "trace_rejection_reason": trace_rejection_reason,
                "trace_artifact_path": trace_artifact_path,
                "trace_completed_at": task_store.now(),
                "weak_signal_detected": weak_signal_detected,
                "weak_signal_type": traced_payload.get("signal_type"),
                "repro_admission_eligibility": repro_admission_eligibility,
                "repro_admission_reason": repro_admission_reason,
                "replay_attempt_count": len(
                    [
                        item
                        for item in replay_summaries
                        if item.get("candidate_id") == str(trace_input.get("candidate_id") or testcase.stem)
                    ]
                ),
                "replay_attempts": [
                    item
                    for item in replay_summaries
                    if item.get("candidate_id") == str(trace_input.get("candidate_id") or testcase.stem)
                ],
                "best_harness_name": traced_payload.get("harness_name"),
                "best_signature": traced_payload.get("signature"),
                "best_crash_type": traced_payload.get("crash_type"),
                "best_crash_state": traced_payload.get("crash_state"),
                "replay_signal_summary": traced_payload.get("replay_signal_summary") or [],
                "signal_strength": traced_payload.get("signal_strength"),
                "signal_type": traced_payload.get("signal_type"),
                "replay_timed_out": traced_payload.get("replay_timed_out"),
            }
            result_path = record_suspicious_candidate_trace_result(
                task_dir,
                candidate_id=candidate_id,
                result_payload=candidate_result_payload,
            )
            finalize_suspicious_candidate_trace(
                task_dir,
                candidate_id=candidate_id,
                trace_state=trace_state,
                now_iso=task_store.now(),
                trace_result_path=result_path,
                trace_result_classification=trace_result_classification,
                trace_artifact_path=trace_artifact_path,
                trace_rejection_reason=trace_rejection_reason,
                repro_admission_eligibility=repro_admission_eligibility,
                repro_admission_reason=repro_admission_reason,
                admission_events=admission_events,
                admission_result=final_admission_result,
                weak_signal_detected=weak_signal_detected,
                weak_signal_type=traced_payload.get("signal_type"),
            )
            candidate_result_paths.append(result_path)
            if repro_admission_eligibility == "eligible" and trace_artifact_path:
                candidate_repro_eligible_count += 1
            processed_candidate_ids.add(candidate_id)
        processed_trace_inputs += 1
        if trace_partial_completion:
            break

    unprocessed_claimed_candidate_ids = [
        candidate_id
        for candidate_id in claimed_candidate_ids
        if candidate_id not in processed_candidate_ids
    ]
    if unprocessed_claimed_candidate_ids:
        requeue_claimed_suspicious_candidates_for_trace(
            task_dir,
            candidate_ids=unprocessed_claimed_candidate_ids,
            now_iso=task_store.now(),
            reason=(
                "trace_budget_exhausted_before_candidate_processed"
                if trace_partial_completion
                else "trace_candidate_not_processed_in_current_worker_pass"
            ),
        )

    generalized_trace_summary = (
        summarize_suspicious_candidate_admission(task_dir)
        if suspicious_trace_input_count or claimed_candidate_ids
        else {
            "candidate_queue_claim_count": 0,
            "trace_admission_attempt_count": 0,
            "trace_admission_result_distribution": {},
            "trace_admission_final_result_distribution": {},
            "trace_admission_actionable_count": 0,
            "trace_admission_no_signal_count": 0,
            "trace_admission_claimed_rejected_count": 0,
            "trace_admission_result_count": 0,
            "weak_repro_attempted_count": 0,
            "weak_repro_result_distribution": {},
            "admission_rate": 0.0,
        }
    )

    family_manifest = (
        build_trace_family_manifest(task_id, traced_artifacts)
        if traced_artifacts
        else {
            "manifest_version": 1,
            "generated_at": task_store.now(),
            "task_id": task_id,
            "exact_signature_count": 0,
            "loose_cluster_count": 0,
            "candidates": [],
            "clusters": [],
        }
    )
    dedup_path = trace_dedup_index_path(task_id)
    dedup_path.write_text(json.dumps(dedup_index, indent=2), encoding="utf-8")
    repro_candidate_count = sum(
        1
        for artifact in traced_artifacts
        if artifact.get("payload", {}).get("repro_admission_recommended")
        or artifact.get("payload", {}).get("crash_source") == "live_raw"
    )
    repro_candidate_count = max(repro_candidate_count, candidate_repro_eligible_count)
    trace_completed_at = trace_timed_out_at or task_store.now()
    trace_elapsed_seconds = round(time.monotonic() - trace_started_monotonic, 6)
    status = TaskStatus.TRACED.value if traced_paths else TaskStatus.TRACE_FAILED.value
    if traced_paths:
        why_not_promoted = None
    elif trace_partial_completion:
        why_not_promoted = "trace_budget_exhausted"
    elif trace_input_origin == "generalized_candidate_queue":
        why_not_promoted = "no_actionable_suspicious_candidates_after_replay"
    elif not trace_inputs:
        why_not_promoted = "no_trace_inputs_available_after_admission"
    else:
        why_not_promoted = "no_actionable_candidates_after_replay"
    manifest_payload = {
        "task_id": task_id,
        "status": status,
        "selected_harness": active_harness["name"],
        "traced_crashes": traced_paths,
        "generalized_candidate_trace_results_dir": (
            str(candidate_results_dir) if suspicious_trace_input_count else None
        ),
        "generalized_candidate_trace_results": candidate_result_paths,
        "generalized_candidate_claim_count": candidate_claim_count,
        "generalized_candidate_trace_result_count": len(candidate_result_paths),
        "generalized_candidate_trace_artifact_count": candidate_trace_artifact_count,
        "generalized_candidate_rejected_count": candidate_rejected_count,
        "generalized_candidate_repro_eligible_count": candidate_repro_eligible_count,
        "trace_admission_attempt_count": int(generalized_trace_summary.get("trace_admission_attempt_count") or 0),
        "trace_admission_result_distribution": generalized_trace_summary.get("trace_admission_result_distribution") or {},
        "trace_admission_final_result_distribution": generalized_trace_summary.get("trace_admission_final_result_distribution") or {},
        "trace_admission_actionable_count": int(generalized_trace_summary.get("trace_admission_actionable_count") or 0),
        "trace_admission_no_signal_count": int(generalized_trace_summary.get("trace_admission_no_signal_count") or 0),
        "trace_admission_claimed_rejected_count": int(generalized_trace_summary.get("trace_admission_claimed_rejected_count") or 0),
        "weak_repro_attempted_count": int(generalized_trace_summary.get("weak_repro_attempted_count") or 0),
        "weak_repro_result_distribution": generalized_trace_summary.get("weak_repro_result_distribution") or {},
        "admission_rate": float(generalized_trace_summary.get("admission_rate") or 0.0),
        "symbolized_frames": symbolized_paths,
        "dedup_index_path": str(dedup_path),
        "candidate_origin": crash_source_used,
        "crash_source": crash_source_used,
        "trace_admission_kind": trace_input_origin,
        "trace_input_count": len(trace_inputs),
        "trace_inputs_processed_count": processed_trace_inputs,
        "suspicious_trace_candidate_count": suspicious_trace_input_count,
        "suspicious_candidate_queue_path": suspicious_queue_file if suspicious_trace_input_count else None,
        "crash_family": sanitizer or trace_mode,
        "trace_mode": trace_mode,
        "sanitizer": sanitizer,
        "signature_count": len(dedup_index),
        "dedup_signatures": sorted(dedup_index),
        "family_manifest_path": str(trace_family_manifest_path(task_id)),
        "family_exact_signature_count": int(family_manifest.get("exact_signature_count") or 0),
        "family_loose_cluster_count": int(family_manifest.get("loose_cluster_count") or 0),
        "replay_attempts": replay_summaries,
        "replay_build_variant": (
            replay_summaries[0].get("replay_build_variant") if replay_summaries else None
        ),
        "replay_binary_path": (
            replay_summaries[0].get("replay_binary_path") if replay_summaries else None
        ),
        "replay_launcher": replay_summaries[0].get("replay_launcher") if replay_summaries else None,
        "replay_attempt_count": len(replay_summaries),
        "trace_success_reason": (
            "partial_trace_budget_exhausted_with_actionable_results"
            if trace_partial_completion and traced_paths
            else
            "actionable suspicious candidate replay produced"
            if traced_paths and trace_input_origin == "generalized_candidate_queue"
            else "actionable sanitizer/replay signature produced"
            if traced_paths
            else "trace_budget_exhausted_partial_manifest_emitted"
            if trace_partial_completion
            else "generalized candidate trace results persisted without actionable crash"
            if candidate_result_paths and trace_input_origin == "generalized_candidate_queue"
            else None
        ),
        "trace_failure_reason": why_not_promoted,
        "partial_completion": trace_partial_completion,
        "trace_budget_exhausted": trace_partial_completion,
        "trace_timeout_seconds": TRACE_MAX_DURATION_SECONDS,
        "trace_started_at": trace_started_at,
        "trace_completed_at": trace_completed_at,
        "trace_timed_out_at": trace_timed_out_at,
        "trace_elapsed_seconds": trace_elapsed_seconds,
        "can_feed_reproducer": bool(repro_candidate_count),
        "repro_admission_candidate_count": repro_candidate_count,
        "target_mode": provenance.get("target_mode"),
        "binary_provenance": provenance.get("binary_provenance"),
        "binary_origin_task_id": provenance.get("binary_origin_task_id"),
        "binary_target_name": provenance.get("binary_target_name"),
        "binary_analysis_backend": provenance.get("binary_analysis_backend"),
        "launcher_semantics_source": provenance.get("launcher_semantics_source"),
        "seed_provenance": provenance.get("seed_provenance"),
        "corpus_provenance": provenance.get("corpus_provenance"),
        "input_mode": provenance.get("input_mode"),
        "selected_binary_slice_focus": provenance.get("selected_binary_slice_focus"),
        "binary_input_contract": provenance.get("binary_input_contract"),
        "binary_input_contract_source": provenance.get("binary_input_contract_source"),
        "binary_input_contract_confidence": provenance.get("binary_input_contract_confidence"),
        "binary_input_contract_confidence_reason": provenance.get("binary_input_contract_confidence_reason"),
        "fallback_trigger_reason": None,
        "fallback_from": None,
        "fallback_to": None,
        "fallback_effect": None,
        "trace_gate_reason": (
            "generalized_candidate_trace_admission_available"
            if trace_input_origin == "generalized_candidate_queue"
            else "semantic_crash_candidate_available"
            if binary_mode
            else "source_live_raw_candidate_available"
        ),
        "why_not_promoted": why_not_promoted,
    }
    manifest_path = write_trace_manifest(task_id, manifest_payload)
    if not traced_paths:
        task_store.update_status(
            task_id,
            TaskStatus.TRACE_FAILED,
            runtime_patch={
                "trace_completed_at": trace_completed_at,
                "trace_manifest_path": str(manifest_path),
                "trace_dedup_index_path": str(dedup_path),
                "trace_family_manifest_path": str(trace_family_manifest_path(task_id)),
                "traced_crash_count": 0,
                "trace_gate_decision": "partial_completed" if trace_partial_completion else "blocked",
                "trace_gate_reason": why_not_promoted,
                "trace_admission_kind": trace_input_origin,
                "trace_input_count": len(trace_inputs),
                "trace_inputs_processed_count": processed_trace_inputs,
                "suspicious_trace_candidate_count": suspicious_trace_input_count,
                "suspicious_candidate_queue_path": suspicious_queue_file if suspicious_trace_input_count else None,
                "generalized_candidate_claim_count": candidate_claim_count,
                "generalized_candidate_trace_result_count": len(candidate_result_paths),
                "generalized_candidate_trace_artifact_count": candidate_trace_artifact_count,
                "generalized_candidate_repro_eligible_count": candidate_repro_eligible_count,
                "generalized_candidate_trace_results_dir": str(candidate_results_dir) if suspicious_trace_input_count else None,
                "trace_admission_attempt_count": int(generalized_trace_summary.get("trace_admission_attempt_count") or 0),
                "trace_admission_result_distribution": generalized_trace_summary.get("trace_admission_result_distribution") or {},
                "trace_admission_final_result_distribution": generalized_trace_summary.get("trace_admission_final_result_distribution") or {},
                "admission_rate": float(generalized_trace_summary.get("admission_rate") or 0.0),
                "repro_admission_candidate_count": repro_candidate_count,
                "why_not_promoted": why_not_promoted,
                "trace_partial_completion": trace_partial_completion,
                "trace_partial_manifest_path": str(manifest_path) if trace_partial_completion else None,
                "trace_budget_exhausted": trace_partial_completion,
                "trace_timeout_seconds": TRACE_MAX_DURATION_SECONDS,
                "trace_timed_out_at": trace_timed_out_at,
                "trace_elapsed_seconds": trace_elapsed_seconds,
                "trace_replay_attempt_count": len(replay_summaries),
            },
        )
        maybe_enqueue_repro(task_id, task_store, queue)
        queue.ack(QueueNames.TRACE, task_id)
        logger.info("task %s produced no actionable traced crashes", task_id)
        return

    task_store.update_status(
        task_id,
        TaskStatus.TRACED,
        runtime_patch={
            "trace_completed_at": trace_completed_at,
            "trace_manifest_path": str(manifest_path),
            "trace_dedup_index_path": str(dedup_path),
            "trace_family_manifest_path": str(trace_family_manifest_path(task_id)),
            "traced_crash_count": len(traced_paths),
            "trace_symbolized_frames_count": len(symbolized_paths),
            "trace_family_exact_signature_count": int(family_manifest.get("exact_signature_count") or 0),
            "trace_family_loose_cluster_count": int(family_manifest.get("loose_cluster_count") or 0),
            "active_harness": active_harness["name"],
            "active_harness_path": active_harness["path"],
            "trace_admission_kind": trace_input_origin,
            "trace_input_count": len(trace_inputs),
            "trace_inputs_processed_count": processed_trace_inputs,
            "suspicious_trace_candidate_count": suspicious_trace_input_count,
            "suspicious_candidate_queue_path": suspicious_queue_file if suspicious_trace_input_count else None,
            "generalized_candidate_claim_count": candidate_claim_count,
            "generalized_candidate_trace_result_count": len(candidate_result_paths),
            "generalized_candidate_trace_artifact_count": candidate_trace_artifact_count,
            "generalized_candidate_repro_eligible_count": candidate_repro_eligible_count,
            "generalized_candidate_trace_results_dir": str(candidate_results_dir) if suspicious_trace_input_count else None,
            "trace_admission_attempt_count": int(generalized_trace_summary.get("trace_admission_attempt_count") or 0),
            "trace_admission_result_distribution": generalized_trace_summary.get("trace_admission_result_distribution") or {},
            "trace_admission_final_result_distribution": generalized_trace_summary.get("trace_admission_final_result_distribution") or {},
            "admission_rate": float(generalized_trace_summary.get("admission_rate") or 0.0),
            "repro_admission_candidate_count": repro_candidate_count,
            "target_mode": provenance.get("target_mode"),
            "binary_provenance": provenance.get("binary_provenance"),
            "binary_origin_task_id": provenance.get("binary_origin_task_id"),
            "binary_target_name": provenance.get("binary_target_name"),
            "binary_analysis_backend": provenance.get("binary_analysis_backend"),
            "launcher_semantics_source": provenance.get("launcher_semantics_source"),
            "seed_provenance": provenance.get("seed_provenance"),
            "corpus_provenance": provenance.get("corpus_provenance"),
            "trace_mode": trace_mode,
            "selected_binary_slice_focus": provenance.get("selected_binary_slice_focus"),
            "trace_gate_decision": "partial_completed" if trace_partial_completion else "completed",
            "trace_gate_reason": (
                "trace_budget_exhausted_partial_manifest_emitted"
                if trace_partial_completion
                else "actionable_traced_candidates_available"
            ),
            "trace_partial_completion": trace_partial_completion,
            "trace_partial_manifest_path": str(manifest_path) if trace_partial_completion else None,
            "trace_budget_exhausted": trace_partial_completion,
            "trace_timeout_seconds": TRACE_MAX_DURATION_SECONDS,
            "trace_timed_out_at": trace_timed_out_at,
            "trace_elapsed_seconds": trace_elapsed_seconds,
            "trace_replay_attempt_count": len(replay_summaries),
            "closure_mode": (
                "strict_live"
                if crash_source_used == "live_raw" and trace_mode == "live_asan"
                else (
                    "pure_binary_replay"
                    if provenance.get("binary_provenance") == "pure_binary_input" and crash_source_used == "live_raw"
                    else ("imported_fallback" if crash_source_used == "imported_valid" else None)
                )
            ),
        },
    )
    maybe_enqueue_repro(task_id, task_store, queue)
    queue.ack(QueueNames.TRACE, task_id)
    logger.info("task %s traced crashes=%s", task_id, len(traced_paths))


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("tracer worker started")
    while True:
        task_id = queue.pop(QueueNames.TRACE, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("tracer failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.TRACE_FAILED,
                runtime_patch={"trace_error": str(exc), "trace_failed_at": task_store.now()},
            )
            queue.ack(QueueNames.TRACE, task_id)


if __name__ == "__main__":
    main()

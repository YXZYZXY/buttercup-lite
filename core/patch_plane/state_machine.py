from __future__ import annotations

import difflib
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from core.builder.contracts import infer_build_capability, resolve_build_capability
from core.builder.fresh_build import build_ossfuzz_project
from core.reproducer.pov import build_pov_record
from core.seed.llm_client import LLMCallError, LLMClient, build_non_llm_metadata, extract_content
from core.storage.layout import (
    deterministic_patch_dependency_report_path,
    generalized_patch_strategy_manifest_path,
    ground_truth_dependency_report_path,
    llm_patch_audit_manifest_path,
    llm_patch_candidate_ranking_manifest_path,
    patch_apply_manifest_path,
    patch_build_manifest_path,
    patch_candidate_ranking_manifest_path,
    patch_context_manifest_path,
    patch_creation_manifest_path,
    patch_failure_analysis_path,
    patch_freeform_materialization_manifest_path,
    patch_generalization_report_path,
    patch_llm_vs_template_comparison_path,
    patch_qe_manifest_path,
    patch_reflection_manifest_path,
    patch_request_manifest_path,
    patch_root_cause_alignment_manifest_path,
    patch_root_cause_manifest_path,
    patch_strategy_family_manifest_path,
    patch_semantic_validation_manifest_path,
    semantic_patch_synthesis_manifest_path,
    task_root,
)
from core.tracer import compute_signature, parse_replay_result, replay_testcase
from core.utils.settings import expand_local_path, resolve_int_setting, resolve_text_setting, settings

logger = logging.getLogger("patch-plane-state-machine")


def _write(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _normalize_patch_ground_truth_mode(mode: str | None) -> str:
    normalized = str(mode or "").strip().lower()
    if normalized in {"blind", "benchmark_assisted"}:
        return normalized
    return "blind"


def _ground_truth_sort_bonus(ground_truth_dependency: Any, patch_ground_truth_mode: str) -> float:
    if patch_ground_truth_mode != "benchmark_assisted":
        return 0.0
    normalized = str(ground_truth_dependency or "").strip().lower()
    if normalized == "high":
        return 0.12
    if normalized == "medium":
        return 0.06
    if normalized == "low":
        return 0.03
    return 0.0


def _normalize_optional_confidence(value: Any) -> float | str | None:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return str(value)


def _llm_selection_fallback_triggered(
    *,
    selection_source: str,
    llm_selected_candidate: dict[str, Any] | None,
) -> bool:
    if llm_selected_candidate:
        return False
    return selection_source in {
        "deterministic_fallback",
        "deterministic_fallback_unknown_candidate",
        "deterministic_fallback_llm_failure",
    }


def _verifier_gates_passed(
    *,
    build_payload: dict[str, Any] | None = None,
    pov_replay: dict[str, Any] | None = None,
    regression_results: list[dict[str, Any]] | None = None,
    verdict: str | None = None,
) -> list[str]:
    gates: list[str] = []
    build_succeeded = bool(build_payload and build_payload.get("status") == "build_succeeded")
    if build_succeeded:
        gates.append("build")
    elif build_payload is None and verdict in {"pov_failed", "regression_failed", "approved"}:
        gates.append("build")
    if verdict == "build_failed":
        return gates
    pov_passed = False
    if pov_replay is not None:
        pov_passed = not bool(pov_replay.get("crash_detected"))
    elif verdict in {"regression_failed", "approved"}:
        pov_passed = True
    if pov_passed:
        gates.append("pov_replay")
    if verdict == "pov_failed":
        return gates
    regression_passed = False
    if regression_results is not None:
        regression_passed = not any(result.get("crash_detected") for result in regression_results)
    elif verdict == "approved":
        regression_passed = True
    if regression_passed:
        gates.append("regression")
    return gates


def _llm_placeholder_fields(stage: str) -> dict[str, Any]:
    return {
        "llm_enabled_config": settings.llm_enabled,
        "llm_base_url": settings.llm_base_url.rstrip("/"),
        "llm_model": settings.llm_model,
        "llm_provider": None,
        "llm_request_attempted": False,
        "llm_http_status": None,
        "llm_response_received": False,
        "llm_real_call_verified": False,
        "llm_failure_reason": f"{stage} currently uses deterministic local logic, not a real LLM call",
        "llm_provenance": "fallback_non_llm",
        "prompt_sha256": None,
        "response_sha256": None,
        "generated_by": f"patch_plane_state_machine.{stage}",
    }


def _patch_truth_fields(
    *,
    provenance: str,
    semantic_strength: str,
    patch_llm_request_attempted: bool = False,
    patch_llm_real_call_verified: bool = False,
) -> dict[str, Any]:
    return {
        "patch_generation_provenance": provenance,
        "patch_llm_request_attempted": patch_llm_request_attempted,
        "patch_llm_real_call_verified": patch_llm_real_call_verified,
        "patch_semantic_strength": semantic_strength,
    }


def _llm_fields_from_metadata(metadata: Any) -> dict[str, Any]:
    if hasattr(metadata, "to_dict"):
        payload = metadata.to_dict()
    elif isinstance(metadata, dict):
        payload = dict(metadata)
    else:
        payload = {}
    return {
        "llm_enabled_config": payload.get("llm_enabled_config", settings.llm_enabled),
        "llm_base_url": payload.get("llm_base_url", settings.llm_base_url.rstrip("/")),
        "llm_model": payload.get("llm_model", settings.llm_model),
        "llm_provider": payload.get("llm_provider"),
        "llm_request_attempted": payload.get("llm_request_attempted", False),
        "llm_http_status": payload.get("llm_http_status"),
        "llm_response_received": payload.get("llm_response_received", False),
        "llm_real_call_verified": payload.get("llm_real_call_verified", False),
        "llm_failure_reason": payload.get("llm_failure_reason"),
        "llm_provenance": payload.get("llm_provenance", "fallback_non_llm"),
        "prompt_sha256": payload.get("prompt_sha256"),
        "response_sha256": payload.get("response_sha256"),
        "generated_by": payload.get("generated_by"),
        "llm_request_id_hash": payload.get("llm_request_id_hash"),
        "llm_token_usage": payload.get("llm_token_usage"),
    }


def _default_reflection_decision(
    *,
    qe_verdict: str,
    priority_action: str | None,
    creation_payload: dict[str, Any] | None = None,
    attempt_history_count: int = 0,
) -> dict[str, Any]:
    selected_candidate = (creation_payload or {}).get("selected_candidate") or {}
    aligned_invariants = list(selected_candidate.get("vulnerable_invariant_alignment") or [])
    preferred_invariant = aligned_invariants[0] if aligned_invariants else None
    alignment_score = float(selected_candidate.get("vulnerable_invariant_alignment_score") or 0.0)
    if qe_verdict == "approved":
        return {
            "reflection_action": "accept",
            "primary_blocker": "none",
            "invariant_family": preferred_invariant,
            "next_strategy": "accept_current_patch",
            "reason": "QE approved the patch candidate",
            "root_cause_alignment_score": alignment_score,
        }
    if qe_verdict == "build_failed":
        blocker = "buildability"
        next_strategy = "buildability_regression_preserving_rewrite"
        if preferred_invariant in {"deallocation_ownership", "failure_propagation"}:
            next_strategy = "allocator_null_state_repair"
        elif preferred_invariant in {"offset_length_consistency", "parser_state_transition"}:
            next_strategy = "same_family_refinement"
        return {
            "reflection_action": "retry",
            "primary_blocker": blocker,
            "invariant_family": preferred_invariant,
            "next_strategy": next_strategy,
            "reason": "build failure can be retried with a corrected patch family/materialization",
            "root_cause_alignment_score": alignment_score,
        }
    if qe_verdict == "pov_failed":
        return {
            "reflection_action": "retry",
            "primary_blocker": "PoV still reproduces despite same family repair",
            "invariant_family": preferred_invariant,
            "next_strategy": "alternative_family_retry",
            "reason": "patched binary still reproduces the confirmed PoV, so search must escape the current invariant family",
            "root_cause_alignment_score": alignment_score,
        }
    if qe_verdict == "regression_failed":
        return {
            "reflection_action": "retry",
            "primary_blocker": "regression_failed",
            "invariant_family": preferred_invariant,
            "next_strategy": "buildability_regression_preserving_rewrite",
            "reason": "candidate blocked the PoV but regressed previously non-crashing behavior",
            "root_cause_alignment_score": alignment_score,
        }
    if priority_action == "escalate" and attempt_history_count >= 2:
        return {
            "reflection_action": "escalate",
            "primary_blocker": "priority_escalation",
            "invariant_family": preferred_invariant,
            "next_strategy": "escalate_for_manual_review",
            "reason": "priority escalation is only honored after retryable repair attempts are exhausted",
            "root_cause_alignment_score": alignment_score,
        }
    return {
        "reflection_action": "suppress",
        "primary_blocker": "reflection unable to escape local optimum",
        "invariant_family": preferred_invariant,
        "next_strategy": "suppress_patch_path",
        "reason": f"QE verdict {qe_verdict} should suppress this patch path",
        "root_cause_alignment_score": alignment_score,
    }


def _coerce_reflection_action(
    *,
    requested_action: str | None,
    qe_verdict: str,
    priority_action: str | None,
    default_action: str,
    attempt_history_count: int = 0,
) -> str:
    normalized = str(requested_action or "").strip().lower()
    if normalized not in {"accept", "retry", "suppress", "escalate"}:
        return default_action
    if qe_verdict != "approved" and normalized == "accept":
        return default_action
    if qe_verdict == "approved":
        return "accept"
    if qe_verdict in {"build_failed", "pov_failed", "regression_failed"} and normalized == "escalate" and attempt_history_count < 2:
        return "retry"
    if priority_action == "escalate" and normalized == "accept":
        return "escalate"
    return normalized


def _build_reflection_llm_messages(
    *,
    task_id: str,
    qe_verdict: str,
    priority_action: str | None,
    creation_payload: dict[str, Any] | None,
    build_payload: dict[str, Any] | None,
    qe_payload: dict[str, Any] | None,
    attempt_history: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    patch_dir = task_root(task_id) / "patch"
    invariant_report = _load_invariant_report(task_id)
    invariant_alignment = _load_json(patch_dir / "vulnerable_invariant_alignment_report.json")
    diff_text = ""
    if creation_payload:
        diff_path = _host_path(creation_payload.get("diff_path"))
        if diff_path and diff_path.exists():
            diff_text = diff_path.read_text(encoding="utf-8", errors="ignore")[:4000]
    prompt_payload = {
        "task_id": task_id,
        "qe_verdict": qe_verdict,
        "priority_action": priority_action,
        "selected_candidate": (creation_payload or {}).get("selected_candidate"),
        "selected_strategy": (creation_payload or {}).get("strategy"),
        "selected_target_function": (creation_payload or {}).get("selected_target_function"),
        "patch_materialization_mode": (creation_payload or {}).get("patch_materialization_mode"),
        "vulnerable_invariants": invariant_report.get("invariants"),
        "primary_invariant": invariant_report.get("primary_invariant"),
        "candidate_alignment": invariant_alignment.get("candidate_alignment"),
        "qe_reason": (qe_payload or {}).get("reason"),
        "qe_verifier_gates_passed": (qe_payload or {}).get("verifier_gates_passed"),
        "qe_build_status": (build_payload or {}).get("status"),
        "qe_build_error": (build_payload or {}).get("error"),
        "pov_replay": (qe_payload or {}).get("pov_replay"),
        "regression_results": (qe_payload or {}).get("regression_results"),
        "last_patch_diff": diff_text,
        "attempt_history": attempt_history or [],
    }
    return [
        {
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "You are a patch reflection engine deciding the next semantic repair move after build/QE. "
                        "Return strict JSON only. Choose one action from accept, retry, suppress, escalate. "
                        "Use the vulnerable invariant, attempt history, and QE failure to identify the single primary blocker. "
                        "If QE says the PoV still reproduces, do not call this a buildability issue. "
                        "For retryable verdicts on early attempts, prefer retry over escalate; escalate only after the "
                        "search has genuinely failed to escape the current local optimum."
                    ),
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Return JSON with keys: reflection_action, primary_blocker, invariant_family, "
                        "next_strategy, root_cause_alignment_score, reason. "
                        "primary_blocker should compress to one of: buildability, "
                        "PoV still reproduces despite same family repair, wrong invariant family, "
                        "reflection unable to escape local optimum, regression_failed, none, priority_escalation. "
                        "root_cause_alignment_score must be a number between 0 and 1 if you can estimate it.\n\n"
                        + json.dumps(prompt_payload, ensure_ascii=False, indent=2)
                    ),
                }
            ],
        },
    ]


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    candidate = raw_text.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        if "\n" in candidate:
            candidate = candidate.split("\n", 1)[1]
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError("LLM patch proposal did not contain a JSON object")
    return json.loads(candidate[start : end + 1])


def _patch_provenance_from_strategy(strategy: str) -> str:
    if strategy.startswith("semantic_guard_"):
        return "deterministic_rule"
    if strategy.startswith("known_fix_"):
        return "known_fix_assisted"
    if strategy == "intentionally_broken":
        return "manual_template"
    return "deterministic_rule"


def _patch_semantic_strength_from_strategy(strategy: str) -> str:
    if strategy.startswith("semantic_guard_"):
        return "general_semantic_fix"
    if strategy.startswith("known_fix_"):
        return "narrow_rule_based"
    return "placeholder"


def _host_path(path_str: str | None) -> Path | None:
    if not path_str:
        return None
    path = Path(path_str)
    if path.exists():
        return path
    prefix = "/data/tasks/"
    if path_str.startswith(prefix):
        parts = Path(path_str[len(prefix) :])
        return expand_local_path(Path("data/tasks") / parts)
    return path


def _load_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _invariant_report_path(task_id: str) -> Path:
    return task_root(task_id) / "patch" / "vulnerable_invariant_report.json"


def _load_invariant_report(task_id: str) -> dict[str, Any]:
    return _load_json(_invariant_report_path(task_id))


STACK_OFFSET_PATTERN = re.compile(r"\((?P<binary>[^)]+)\+(?P<offset>0x[0-9a-fA-F]+)\)")
TRACE_FRAME_SKIP_PATTERNS = (
    "compiler-rt",
    "asan_",
    "libasan",
    "__asan",
    "__sanitizer",
    "sanitizer_common",
    "libc.so",
    "ld-linux",
)


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


def _find_symbolizer() -> str | None:
    candidates = [
        Path(settings.build_toolchain_prefix).expanduser() / "bin" / "llvm-symbolizer",
        shutil.which("llvm-symbolizer"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        candidate_path = Path(candidate)
        if candidate_path.exists():
            return str(candidate_path)
    return None


def _is_valid_trace_frame(frame: dict[str, Any]) -> bool:
    file_ref = str(frame.get("file") or "").strip()
    function_name = str(frame.get("function") or "").strip()
    line_number = frame.get("line")
    if not file_ref or not function_name:
        return False
    if not isinstance(line_number, int) or line_number <= 0:
        return False
    lowered = f"{file_ref} {function_name}".lower()
    return not any(token in lowered for token in TRACE_FRAME_SKIP_PATTERNS)


def _load_traced_crash(runtime: dict[str, Any]) -> dict[str, Any]:
    repro_manifest = _load_json(_host_path(runtime.get("repro_manifest_path")))
    traced_path = _host_path(repro_manifest.get("source_traced_crash"))
    if traced_path and traced_path.exists():
        return _load_json(traced_path)
    trace_manifest = _load_json(_host_path(runtime.get("trace_manifest_path")))
    traced_paths = trace_manifest.get("traced_crashes") or []
    if traced_paths:
        traced_path = _host_path(traced_paths[0])
        if traced_path and traced_path.exists():
            return _load_json(traced_path)
    return {}


def _symbolize_trace_frames(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    traced = _load_traced_crash(runtime)
    binary_path = _host_path(traced.get("binary_path"))
    stacktrace = traced.get("stacktrace") or []
    symbolizer = _find_symbolizer()
    if not binary_path or not binary_path.exists() or not symbolizer:
        return []
    frames: list[dict[str, Any]] = []
    for raw_line in stacktrace[:16]:
        match = STACK_OFFSET_PATTERN.search(str(raw_line))
        if match is None:
            continue
        offset = match.group("offset")
        completed = subprocess.run(
            [symbolizer, "-e", str(binary_path), offset],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        function_name = lines[0] if lines else None
        source_location = lines[1] if len(lines) > 1 else None
        frame = {
            "raw_frame": raw_line,
            "offset": offset,
            "function": function_name,
            "source_location": source_location,
        }
        parsed_file, parsed_line = _parse_source_location(source_location)
        if parsed_file:
            frame["file"] = parsed_file
        if parsed_line is not None:
            frame["line"] = parsed_line
        frames.append(frame)
    return frames


def _trace_alignment(metadata: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    traced = _load_traced_crash(runtime)
    symbolized_manifest = _load_json(_host_path(traced.get("symbolized_frames_path")))
    symbolized_frames = symbolized_manifest.get("frames") or _symbolize_trace_frames(runtime)
    primary_source_frame = symbolized_manifest.get("primary_source_frame") or {}
    if primary_source_frame and not _is_valid_trace_frame(primary_source_frame):
        primary_source_frame = {}
    source_frames = [frame for frame in symbolized_frames if _is_valid_trace_frame(frame)]
    aligned_frame = primary_source_frame or (source_frames[0] if source_frames else {})
    return {
        "symbolized_frames": symbolized_frames,
        "symbolized_frames_path": traced.get("symbolized_frames_path"),
        "selected_trace_frame": aligned_frame,
        "selected_trace_function": aligned_frame.get("function"),
        "selected_trace_file": aligned_frame.get("file"),
        "selected_trace_line": aligned_frame.get("line"),
        "alignment_strength": (
            "trace_primary_frame"
            if aligned_frame
            else "minimal_hypothesis"
        ),
    }


def _source_root(metadata: dict[str, Any], runtime: dict[str, Any]) -> Path:
    candidates = [
        metadata.get("patch_source_path"),
        metadata.get("source_root"),
        runtime.get("source_root"),
        metadata.get("existing_src_path"),
        runtime.get("resolved_imports", {}).get("existing_src_path"),
        metadata.get("source_uri"),
    ]
    for candidate in candidates:
        path = _host_path(candidate)
        if path and path.exists() and path.is_dir():
            return path
    raise RuntimeError("patch source root is not available")


def _oss_fuzz_project_root(metadata: dict[str, Any], runtime: dict[str, Any]) -> Path:
    candidates = [
        metadata.get("patch_oss_fuzz_project_path"),
        metadata.get("existing_oss_fuzz_project_path"),
        runtime.get("resolved_imports", {}).get("existing_oss_fuzz_project_path"),
    ]
    for candidate in candidates:
        path = _host_path(candidate)
        if path and path.exists() and path.is_dir():
            return path
    raise RuntimeError("oss-fuzz project root is not available for patch build")


def _extract_context(file_path: Path, line_range: list[int] | tuple[int, int] | None, radius: int = 8) -> dict[str, Any]:
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not line_range or len(line_range) != 2:
        start, end = 1, min(len(lines), 40)
    else:
        start = max(1, int(line_range[0]) - radius)
        end = min(len(lines), int(line_range[1]) + radius)
    snippet_lines = [f"{index + 1:5d}: {lines[index]}" for index in range(start - 1, end)]
    return {
        "file_path": str(file_path),
        "line_start": start,
        "line_end": end,
        "snippet": "\n".join(snippet_lines),
    }


def _normalize_source_reference(file_ref: str | None, source_root: Path | None) -> str | None:
    if not file_ref:
        return None
    candidate = _host_path(file_ref) or Path(str(file_ref))
    if source_root is not None:
        try:
            return str(candidate.relative_to(source_root))
        except ValueError:
            pass
        parts = candidate.parts
        if source_root.name in parts:
            source_index = parts.index(source_root.name)
            if source_index + 1 < len(parts):
                return str(Path(*parts[source_index + 1 :]))
    return str(candidate)


def _resolve_source_file(source_root: Path, file_ref: str | None) -> Path | None:
    if not file_ref:
        return None
    raw_path = _host_path(file_ref)
    ref_path = Path(str(file_ref))
    candidates: list[Path] = []
    if raw_path is not None:
        candidates.append(raw_path)
    if not ref_path.is_absolute():
        candidates.append(source_root / ref_path)
        if ref_path.parts and ref_path.parts[0] == source_root.name and len(ref_path.parts) > 1:
            candidates.append(source_root / Path(*ref_path.parts[1:]))
    elif source_root.name in ref_path.parts:
        source_index = ref_path.parts.index(source_root.name)
        if source_index + 1 < len(ref_path.parts):
            candidates.append(source_root / Path(*ref_path.parts[source_index + 1 :]))

    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _select_symbolized_fallback_frame(
    *,
    symbolized_frames: list[dict[str, Any]],
    source_root: Path | None,
) -> dict[str, Any]:
    preferred_frames: list[dict[str, Any]] = []
    secondary_frames: list[dict[str, Any]] = []
    for frame in symbolized_frames:
        if not _is_valid_trace_frame(frame):
            continue
        file_ref = frame.get("file")
        function_name = frame.get("function")
        line_number = frame.get("line")
        if not file_ref or not function_name or not isinstance(line_number, int) or line_number <= 0:
            continue
        resolved_file = _host_path(str(file_ref))
        if resolved_file is None or not resolved_file.exists() or not resolved_file.is_file():
            continue
        frame_copy = dict(frame)
        frame_copy["file"] = _normalize_source_reference(str(resolved_file), source_root)
        if source_root is not None:
            try:
                resolved_file.relative_to(source_root)
            except ValueError:
                secondary_frames.append(frame_copy)
            else:
                preferred_frames.append(frame_copy)
        elif resolved_file.suffix.lower() in {".c", ".cc", ".cpp", ".h"}:
            preferred_frames.append(frame_copy)
        else:
            secondary_frames.append(frame_copy)
    return preferred_frames[0] if preferred_frames else secondary_frames[0] if secondary_frames else {}


def _build_generic_open_ended_patch_messages(
    *,
    task_id: str,
    strategy: str,
    metadata: dict[str, Any],
    runtime: dict[str, Any],
) -> list[dict[str, Any]]:
    root_cause = _load_json(patch_root_cause_manifest_path(task_id))
    context_manifest = _load_json(patch_context_manifest_path(task_id))
    selected_context = context_manifest.get("selected_context") or {}
    traced_crash = _load_traced_crash(runtime)
    payload = {
        "task_id": task_id,
        "ranked_strategy_hint": strategy,
        "root_cause": {
            "file": root_cause.get("file"),
            "function": root_cause.get("function"),
            "line_range": root_cause.get("line_range"),
            "hypothesis": root_cause.get("hypothesis"),
        },
        "crash": {
            "crash_type": traced_crash.get("crash_type"),
            "crash_state": traced_crash.get("crash_state"),
        },
        "selected_context": {
            "file_path": selected_context.get("file_path"),
            "line_start": selected_context.get("line_start"),
            "line_end": selected_context.get("line_end"),
            "snippet": selected_context.get("snippet"),
        },
        "requirements": {
            "output_format": "strict_json_with_proposed_patch_diff",
            "diff_format": "unified_diff_relative_to_source_root",
            "semantic_goal": "eliminate_the_crash_path_without_changing_intended_behavior",
            "strategy_constraint": "open_ended_no_named_strategy_requirement",
        },
    }
    return [
        {
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "You are repairing an unclassified source vulnerability. Return strict JSON only. "
                        "Produce a minimal unified diff relative to the source root. "
                        "Do not limit yourself to named strategy families; prioritize a correct, compilable fix "
                        "that preserves intended behavior for non-crashing inputs. "
                        "The diff MUST use paths relative to the source root. "
                        "Do NOT use absolute paths or add extra directory prefixes like 'src/'. "
                        "For example, use 'cJSON.c', not 'src/cJSON.c' or '/app/src/cJSON.c'. "
                        "Do NOT invent or hallucinate filenames or function names. "
                        "Only reference files and functions explicitly provided in the context above. "
                        "If you cannot generate a valid patch from the given context, return an empty "
                        "string for proposed_patch_diff."
                    ),
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Return JSON with keys: patch_intent, confidence, proposed_patch_diff. "
                        "proposed_patch_diff must be a unified diff relative to the source root. "
                        "Use the root-cause location and crash evidence below. If you cannot produce a safe diff, "
                        "return an empty proposed_patch_diff instead of prose. "
                        "Do not use absolute paths or add extra directory prefixes like 'src/'. "
                        "Only reference files and functions explicitly provided in the context below.\n\n"
                        + json.dumps(payload, ensure_ascii=False, indent=2)
                    ),
                }
            ],
        },
    ]


def _generic_llm_open_ended_synthesis(
    *,
    task_id: str,
    strategy: str,
    source_root: Path,
    metadata: dict[str, Any],
    runtime: dict[str, Any],
    generated_at: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    llm_client = LLMClient()
    fallback: dict[str, Any] = {
        "used": True,
        "strategy": strategy,
        "selection_source": "generic_llm_open_ended_fallback",
        "failure_reason": None,
        "llm_payload": None,
        "llm_metadata": None,
        "freeform_manifest": None,
    }
    if not llm_client.enabled():
        fallback["failure_reason"] = "llm_disabled_no_generic_fallback"
        fallback["llm_metadata"] = build_non_llm_metadata(
            generated_by="patch_plane_state_machine.generic_open_ended_fallback",
            failure_reason=fallback["failure_reason"],
        )
        return None, fallback

    messages = _build_generic_open_ended_patch_messages(
        task_id=task_id,
        strategy=strategy,
        metadata=metadata,
        runtime=runtime,
    )
    try:
        response_payload, llm_metadata = llm_client.chat_with_metadata(
            messages,
            temperature=0.1,
            max_tokens=900,
            timeout_seconds=resolve_int_setting(
                metadata,
                "LLM_PATCH_TIMEOUT_SECONDS",
                resolve_int_setting(metadata, "LLM_TIMEOUT_SECONDS", settings.llm_timeout_seconds),
            ),
            max_retries=resolve_int_setting(
                metadata,
                "LLM_PATCH_MAX_RETRIES",
                resolve_int_setting(metadata, "LLM_MAX_RETRIES", settings.llm_max_retries),
            ),
            generated_by="patch_plane_state_machine.generic_open_ended_fallback",
        )
        llm_payload = _extract_json_object(extract_content(response_payload))
    except (LLMCallError, RuntimeError, json.JSONDecodeError) as exc:
        if isinstance(exc, LLMCallError):
            llm_metadata = exc.metadata
        else:
            llm_metadata = build_non_llm_metadata(
                generated_by="patch_plane_state_machine.generic_open_ended_fallback",
                failure_reason=str(exc),
            )
        fallback["failure_reason"] = "generic_llm_synthesis_failed"
        fallback["llm_payload"] = {"error": str(exc)}
        fallback["llm_metadata"] = llm_metadata
        return None, fallback

    fallback["llm_payload"] = llm_payload
    fallback["llm_metadata"] = llm_metadata
    freeform_result, freeform_manifest = _try_apply_freeform_patch(
        task_id=task_id,
        source_root=source_root,
        llm_payload=llm_payload,
        generated_at=generated_at,
    )
    fallback["freeform_manifest"] = freeform_manifest
    if freeform_result and llm_metadata.llm_real_call_verified:
        freeform_result["strategy"] = "generic_llm_open_ended_patch"
        return freeform_result, fallback

    fallback["failure_reason"] = "generic_llm_synthesis_failed"
    return None, fallback


def _apply_patch_strategy(
    *,
    task_id: str,
    vuln_id: str,
    strategy: str,
    source_root: Path,
    metadata: dict[str, Any],
    runtime: dict[str, Any],
    generated_at: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if strategy == "intentionally_broken":
        source_file = source_root / "cJSON.c"
        if not source_file.exists():
            source_file = source_root / "ini.c"
        original = source_file.read_text(encoding="utf-8")
        patched = "BROKEN_PATCH_TOKEN(\n" + original
        source_file.write_text(patched, encoding="utf-8")
        return {
            "strategy": "intentionally_broken",
            "modified_file": str(source_file),
            "before": "",
            "after": "BROKEN_PATCH_TOKEN(",
            "diff": "".join(
                difflib.unified_diff(
                    original.splitlines(keepends=True),
                    patched.splitlines(keepends=True),
                    fromfile=f"a/{source_file.name}",
                    tofile=f"b/{source_file.name}",
                )
            ),
        }, {"used": False, "failure_reason": None}
    logger.info(
        "[%s] blind mainline patch materialization: strategy=%s vuln=%s via generic freeform synthesis",
        task_id,
        strategy,
        vuln_id or "<unknown>",
    )
    return _generic_llm_open_ended_synthesis(
        task_id=task_id,
        strategy=strategy,
        source_root=source_root,
        metadata=metadata,
        runtime=runtime,
        generated_at=generated_at,
    )


def _candidate_file_from_diff(source_root: Path, diff_text: str) -> Path | None:
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            raw = line[4:].strip().split("\t", 1)[0]
            if raw == "/dev/null":
                continue
            if raw.startswith("b/"):
                raw = raw[2:]
            candidate = source_root / raw
            if candidate.exists() or candidate.parent.exists():
                return candidate
    return None


_HUNK_RE = re.compile(r"^@@ -(?P<old_start>\d+)(?:,\d+)? \+(?P<new_start>\d+)(?:,\d+)? @@(?P<tail>.*)$")


def _normalize_unified_diff_hunks(diff_text: str) -> tuple[str, bool, list[dict[str, Any]]]:
    """Repair common LLM hunk-count drift while preserving the freeform patch."""

    lines = diff_text.splitlines()
    normalized: list[str] = []
    repairs: list[dict[str, Any]] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        match = _HUNK_RE.match(line)
        if not match:
            normalized.append(line)
            i += 1
            continue

        header_index = len(normalized)
        normalized.append(line)
        old_count = 0
        new_count = 0
        body: list[str] = []
        i += 1
        while i < len(lines):
            body_line = lines[i]
            if body_line.startswith("@@ ") or body_line.startswith("--- ") or body_line.startswith("diff "):
                break
            if body_line.startswith("\\"):
                body.append(body_line)
                i += 1
                continue
            if body_line == "":
                # GNU patch treats bare blank hunk lines as malformed; they are context lines.
                body_line = " "
                changed = True
                repairs.append({"repair": "bare_blank_context_line_prefixed", "hunk_header": line})
            prefix = body_line[0]
            if prefix == "-":
                old_count += 1
            elif prefix == "+":
                new_count += 1
            elif prefix == " ":
                old_count += 1
                new_count += 1
            else:
                body_line = " " + body_line
                old_count += 1
                new_count += 1
                changed = True
                repairs.append({"repair": "missing_context_prefix_added", "hunk_header": line})
            body.append(body_line)
            i += 1

        repaired_header = (
            f"@@ -{match.group('old_start')},{old_count} +{match.group('new_start')},{new_count} @@"
            f"{match.group('tail')}"
        )
        if repaired_header != line:
            changed = True
            repairs.append(
                {
                    "repair": "hunk_count_recomputed",
                    "original_header": line,
                    "repaired_header": repaired_header,
                    "old_count": old_count,
                    "new_count": new_count,
                }
            )
        normalized[header_index] = repaired_header
        normalized.extend(body)

    return "\n".join(normalized).rstrip("\n") + "\n", changed, repairs


def _try_apply_freeform_patch(
    *,
    task_id: str,
    source_root: Path,
    llm_payload: dict[str, Any] | None,
    generated_at: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    diff_text = ""
    if isinstance(llm_payload, dict):
        diff_text = str(
            llm_payload.get("proposed_patch_diff")
            or llm_payload.get("patch_diff")
            or llm_payload.get("unified_diff")
            or "",
        ).strip()
    manifest: dict[str, Any] = {
        "task_id": task_id,
        "generated_at": generated_at,
        "llm_freeform_diff_present": bool(diff_text),
        "freeform_attempted": bool(diff_text),
        "freeform_applied": False,
        "freeform_failure_reason": None,
        "freeform_diff_path": None,
    }
    if not diff_text:
        manifest["freeform_failure_reason"] = "llm_payload_did_not_include_unified_diff"
        return None, manifest
    diff_text, normalized, repairs = _normalize_unified_diff_hunks(diff_text)
    diff_text = diff_text.replace("--- a/src/", "--- a/")
    diff_text = diff_text.replace("+++ b/src/", "+++ b/")
    manifest["freeform_diff_normalized"] = normalized
    manifest["freeform_diff_repairs"] = repairs
    patch_dir = task_root(task_id) / "patch"
    freeform_diff_path = patch_dir / "llm_freeform_candidate.diff"
    freeform_diff_path.write_text(diff_text + "\n", encoding="utf-8")
    manifest["freeform_diff_path"] = str(freeform_diff_path)
    before_snapshots: dict[Path, str] = {}
    for candidate in source_root.rglob("*"):
        if candidate.is_file() and candidate.suffix in {".c", ".h", ".cc", ".cpp"}:
            try:
                before_snapshots[candidate] = candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
    result = subprocess.run(
        ["patch", "-p1", "--batch", "--forward"],
        input=diff_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=source_root,
        check=False,
    )
    manifest["patch_command"] = ["patch", "-p1", "--batch", "--forward"]
    manifest["patch_exit_code"] = result.returncode
    manifest["patch_stdout_excerpt"] = result.stdout[-2000:]
    manifest["patch_stderr_excerpt"] = result.stderr[-2000:]
    if result.returncode != 0:
        manifest["freeform_failure_reason"] = "patch_command_failed"
        return None, manifest
    modified_file = _candidate_file_from_diff(source_root, diff_text)
    if modified_file is None:
        changed_files = [
            path
            for path, before in before_snapshots.items()
            if path.exists() and path.read_text(encoding="utf-8", errors="ignore") != before
        ]
        modified_file = changed_files[0] if changed_files else None
    manifest["freeform_applied"] = modified_file is not None
    if modified_file is None:
        manifest["freeform_failure_reason"] = "patch_command_succeeded_but_no_modified_source_file_detected"
        return None, manifest
    return {
        "strategy": "llm_freeform_patch",
        "modified_file": str(modified_file),
        "before": before_snapshots.get(modified_file, ""),
        "after": modified_file.read_text(encoding="utf-8", errors="ignore"),
        "diff": diff_text + "\n",
    }, manifest


def _rank_patch_candidates(*, vuln_id: str, metadata: dict[str, Any], runtime: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    scenario = str(metadata.get("patch_creation_strategy", "trace_ranked_semantic"))
    task_id = str(metadata.get("patch_base_task_id") or metadata.get("task_id") or "")
    patch_ground_truth_mode = _normalize_patch_ground_truth_mode(
        resolve_text_setting(metadata, "PATCH_GROUND_TRUTH_MODE", settings.patch_ground_truth_mode)
    )
    alignment = _load_json(patch_root_cause_alignment_manifest_path(task_id))
    if not alignment:
        alignment = _trace_alignment(metadata, runtime)
    selected_trace_function = str((alignment.get("alignment") or alignment).get("selected_trace_function") or "")
    vulnerable_invariants, invariant_report = _derive_vulnerable_invariants(task_id=task_id, vuln_id=vuln_id)
    patch_dir = task_root(task_id) / "patch"
    patch_dir.mkdir(parents=True, exist_ok=True)
    _write(_invariant_report_path(task_id), invariant_report)
    if scenario == "intentionally_broken":
        candidates = [
            {
                "rank": 1,
                "candidate_id": "intentionally_broken",
                "strategy": "intentionally_broken",
                "strategy_family": "manual_breakage",
                "ranking_score": 0.0,
                "selection_reason": "validation scenario explicitly requests a broken patch path",
                "generalizable": False,
                "ground_truth_dependency": "none",
            },
        ]
        selected = {
            **candidates[0],
            "sort_weight_gt_bonus": 0.0,
            "sort_weight_effective_score": float(candidates[0].get("ranking_score") or 0.0),
            "patch_ground_truth_mode": patch_ground_truth_mode,
        }
        return [selected], selected

    root_cause = _load_json(patch_root_cause_manifest_path(task_id))
    context_manifest = _load_json(patch_context_manifest_path(task_id))
    selected_context = context_manifest.get("selected_context") or {}
    evidence_blob = " ".join(
        [
            selected_trace_function,
            str(root_cause.get("hypothesis") or ""),
            str(selected_context.get("snippet") or ""),
        ]
    ).lower()

    def _has_any(*tokens: str) -> bool:
        return any(token in evidence_blob for token in tokens)

    candidates = [
        {
            "rank": 1,
            "candidate_id": "root_cause_direct_repair",
            "strategy": "root_cause_direct_repair",
            "strategy_family": "root_cause_direct_repair",
            "ranking_score": 0.84 if selected_trace_function else 0.72,
            "selection_reason": "repair the trace-primary frame directly and keep the fix scoped to the observed crash-adjacent logic.",
            "description": "Rewrite the trace-adjacent statement or branch that directly drives the crashing state.",
            "priority": "high",
            "generalizable": True,
            "ground_truth_dependency": "none",
        },
        {
            "rank": 2,
            "candidate_id": "bounds_parser_state_repair",
            "strategy": "bounds_parser_state_repair",
            "strategy_family": "parser_bounds_state_repair",
            "ranking_score": 0.8 if _has_any("offset", "length", "bound", "copy", "capacity", "strlen", "buffer") else 0.61,
            "selection_reason": "trace/context suggest a parser-local bounds, offset, or state-transition inconsistency.",
            "description": "Add or rewrite local bounds/state checks around the parser path that leads into the crash.",
            "priority": "high",
            "generalizable": True,
            "ground_truth_dependency": "none",
        },
        {
            "rank": 3,
            "candidate_id": "allocator_null_state_repair",
            "strategy": "allocator_null_state_repair",
            "strategy_family": "allocator_or_ownership_repair",
            "ranking_score": 0.79 if _has_any("realloc", "free", "delete", "null", "ownership", "allocator") else 0.58,
            "selection_reason": "trace/context suggest stale ownership, allocator failure, or null-state continuation near the crash.",
            "description": "Repair allocator/null-state handling so stale pointers or failed growth do not continue into the crash path.",
            "priority": "high",
            "generalizable": True,
            "ground_truth_dependency": "none",
        },
        {
            "rank": 4,
            "candidate_id": "failure_propagation_rewrite",
            "strategy": "failure_propagation_rewrite",
            "strategy_family": "failure_propagation_guard",
            "ranking_score": 0.76 if _has_any("fail", "error", "invalid", "return", "null") else 0.55,
            "selection_reason": "trace/context suggest an invalid state is detected but execution continues into the crash-producing path.",
            "description": "Short-circuit on the first crash-relevant failure and preserve parser state invariants.",
            "priority": "medium",
            "generalizable": True,
            "ground_truth_dependency": "none",
        },
        {
            "rank": 5,
            "candidate_id": "regression_preserving_rewrite",
            "strategy": "regression_preserving_rewrite",
            "strategy_family": "buildability_regression_preserving_rewrite",
            "ranking_score": 0.49,
            "selection_reason": "fallback family for minimally invasive rewrites when direct repairs or guards destabilize build/regression behavior.",
            "description": "Rewrite the local code shape to preserve buildability and non-crashing behavior while blocking the crash path.",
            "priority": "medium",
            "generalizable": True,
            "ground_truth_dependency": "none",
        },
    ]
    ranked_candidates: list[dict[str, Any]] = []
    alignment_rows: list[dict[str, Any]] = []
    for candidate in candidates:
        base_score = float(candidate.get("ranking_score") or 0.0)
        gt_bonus = _ground_truth_sort_bonus(candidate.get("ground_truth_dependency"), patch_ground_truth_mode)
        aligned_invariants, invariant_alignment_score = _candidate_invariant_alignment(
            candidate=candidate,
            invariants=vulnerable_invariants,
        )
        invariant_bonus = round(invariant_alignment_score * 0.08, 4)
        effective_score = base_score + gt_bonus + invariant_bonus
        ranked_candidates.append(
            {
                **candidate,
                "sort_weight_gt_bonus": gt_bonus,
                "sort_weight_invariant_bonus": invariant_bonus,
                "sort_weight_effective_score": effective_score,
                "patch_ground_truth_mode": patch_ground_truth_mode,
                "vulnerable_invariant_alignment": aligned_invariants,
                "vulnerable_invariant_alignment_score": invariant_alignment_score,
            }
        )
        alignment_rows.append(
            {
                "candidate_id": candidate.get("candidate_id"),
                "strategy": candidate.get("strategy"),
                "strategy_family": candidate.get("strategy_family"),
                "aligned_invariants": aligned_invariants,
                "alignment_score": invariant_alignment_score,
                "effective_score": round(effective_score, 4),
            }
        )
    ranked_candidates.sort(
        key=lambda item: (
            float(item.get("sort_weight_effective_score") or 0.0),
            float(item.get("ranking_score") or 0.0),
        ),
        reverse=True,
    )
    for index, candidate in enumerate(ranked_candidates, start=1):
        candidate["rank"] = index
    _write(
        patch_dir / "vulnerable_invariant_alignment_report.json",
        {
            "task_id": task_id,
            "generated_at": task_store_time(),
            "vuln_id": vuln_id,
            "primary_invariant": invariant_report.get("primary_invariant"),
            "candidate_alignment": alignment_rows,
        },
    )
    return ranked_candidates, ranked_candidates[0]


def _build_patch_llm_messages(
    *,
    task_id: str,
    vuln_id: str,
    metadata: dict[str, Any],
    runtime: dict[str, Any],
    candidate_ranking: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    root_cause = _load_json(patch_root_cause_manifest_path(task_id))
    context_manifest = _load_json(patch_context_manifest_path(task_id))
    selected_context = context_manifest.get("selected_context") or {}
    trace_alignment = _load_json(patch_root_cause_alignment_manifest_path(task_id)).get("alignment") or {}
    invariant_payload = _load_json(task_root(task_id) / "patch" / "vulnerable_invariant_alignment_report.json")
    invariant_report = _load_invariant_report(task_id)
    prompt_payload = {
        "task_id": task_id,
        "patch_target_vuln_id": vuln_id,
        "selected_target_function": runtime.get("selected_target_function"),
        "trace_root_cause": {
            "selected_trace_function": trace_alignment.get("selected_trace_function"),
            "selected_trace_file": trace_alignment.get("selected_trace_file"),
            "selected_trace_line": trace_alignment.get("selected_trace_line"),
            "alignment_strength": trace_alignment.get("alignment_strength"),
        },
        "root_cause": {
            "file": root_cause.get("file"),
            "function": root_cause.get("function"),
            "line_range": root_cause.get("line_range"),
            "hypothesis": root_cause.get("hypothesis"),
        },
        "selected_context": {
            "file_path": selected_context.get("file_path"),
            "line_start": selected_context.get("line_start"),
            "line_end": selected_context.get("line_end"),
            "snippet": selected_context.get("snippet"),
        },
        "candidate_ranking": [
            {
                "candidate_id": candidate.get("candidate_id"),
                "strategy": candidate.get("strategy"),
                "strategy_family": candidate.get("strategy_family"),
                "description": candidate.get("description"),
                "priority": candidate.get("priority"),
                "selection_reason": candidate.get("selection_reason"),
                "generalizable": candidate.get("generalizable"),
                "ground_truth_dependency": candidate.get("ground_truth_dependency"),
                "vulnerable_invariant_alignment": candidate.get("vulnerable_invariant_alignment"),
                "vulnerable_invariant_alignment_score": candidate.get("vulnerable_invariant_alignment_score"),
            }
            for candidate in candidate_ranking
        ],
        "vulnerable_invariants": invariant_report.get("invariants"),
        "primary_invariant": invariant_report.get("primary_invariant"),
        "candidate_invariant_alignment": invariant_payload.get("candidate_alignment"),
    }
    retry_context = metadata.get("patch_retry_context")
    if retry_context:
        prompt_payload["previous_failed_attempt"] = retry_context
    return [
        {
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "You are selecting the best semantic patch proposal for a confirmed vulnerability. "
                        "Return strict JSON only. Prefer the most generalizable candidate aligned to the trace/root-cause frame. "
                        "Rank candidates by trace, context, and invariant evidence only. "
                        "Do not mention markdown fences."
                    ),
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Choose the best patch candidate from the list below and explain why it aligns with the trace/root-cause. "
                        "Return JSON with keys: selected_candidate_id, selected_strategy_family, "
                        "root_cause_frame, patch_intent, confidence, deterministic_materialization_ok, proposed_patch_diff. "
                        "If you can express a safe source edit as a unified diff relative to the source root, include it in proposed_patch_diff. "
                        "If you are not confident in an exact diff, set proposed_patch_diff to an empty string rather than inventing paths. "
                        "If previous_failed_attempt is present, repair that concrete failure. Do not repeat a diff that leaves stale commented code, duplicate braces, truncated hunks, or uncompilable C syntax. "
                        "For C patches, prefer replacing the smallest complete statement/block instead of partially uncommenting old code. "
                        "Explicitly justify why the chosen candidate best matches the observed invariant and trace evidence.\n\n"
                        + json.dumps(prompt_payload, ensure_ascii=False, indent=2)
                    ),
                }
            ],
        },
    ]


def _build_candidate_specific_materialization_messages(
    *,
    task_id: str,
    selected_candidate: dict[str, Any],
    metadata: dict[str, Any],
    runtime: dict[str, Any],
    previous_llm_payload: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    root_cause = _load_json(patch_root_cause_manifest_path(task_id))
    context_manifest = _load_json(patch_context_manifest_path(task_id))
    selected_context = context_manifest.get("selected_context") or {}
    trace_alignment = _load_json(patch_root_cause_alignment_manifest_path(task_id)).get("alignment") or {}
    invariant_report = _load_invariant_report(task_id)
    payload = {
        "task_id": task_id,
        "selected_candidate": {
            "candidate_id": selected_candidate.get("candidate_id"),
            "strategy": selected_candidate.get("strategy"),
            "strategy_family": selected_candidate.get("strategy_family"),
            "description": selected_candidate.get("description"),
            "priority": selected_candidate.get("priority"),
            "selection_reason": selected_candidate.get("selection_reason"),
            "generalizable": selected_candidate.get("generalizable"),
            "ground_truth_dependency": selected_candidate.get("ground_truth_dependency"),
        },
        "selected_target_function": runtime.get("selected_target_function"),
        "trace_root_cause": {
            "selected_trace_function": trace_alignment.get("selected_trace_function"),
            "selected_trace_file": trace_alignment.get("selected_trace_file"),
            "selected_trace_line": trace_alignment.get("selected_trace_line"),
            "alignment_strength": trace_alignment.get("alignment_strength"),
        },
        "root_cause": {
            "file": root_cause.get("file"),
            "function": root_cause.get("function"),
            "line_range": root_cause.get("line_range"),
            "hypothesis": root_cause.get("hypothesis"),
        },
        "selected_context": {
            "file_path": selected_context.get("file_path"),
            "line_start": selected_context.get("line_start"),
            "line_end": selected_context.get("line_end"),
            "snippet": selected_context.get("snippet"),
        },
        "primary_invariant": invariant_report.get("primary_invariant"),
        "vulnerable_invariants": invariant_report.get("invariants"),
        "previous_failed_attempt": metadata.get("patch_retry_context"),
        "previous_llm_payload": previous_llm_payload,
    }
    return [
        {
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "You generate a source patch as a unified diff. Return strict JSON only. "
                        "Do not re-rank candidates. Materialize a diff for the already-selected candidate. "
                        "Keep the diff minimal, compilable C, and aligned to the stated invariant. "
                        "The diff MUST use paths relative to the source root. "
                        "Do NOT use absolute paths or add extra directory prefixes like 'src/'. "
                        "For example, use 'cJSON.c', not 'src/cJSON.c' or '/app/src/cJSON.c'. "
                        "Do NOT invent or hallucinate filenames or function names. "
                        "Only reference files and functions explicitly provided in the context above. "
                        "If you cannot generate a valid patch from the given context, return an empty "
                        "string for proposed_patch_diff."
                    ),
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Return JSON with keys: selected_candidate_id, patch_intent, confidence, proposed_patch_diff. "
                        "selected_candidate_id must match the provided candidate. "
                        "If the previous diff was malformed, repair it. If the previous diff targeted the wrong family, rewrite it for this exact candidate. "
                        "Do not emit markdown fences. Only emit a unified diff relative to the source root. "
                        "Do not use absolute paths or add extra directory prefixes like 'src/'. "
                        "Only reference files and functions explicitly provided in the context below.\n\n"
                        + json.dumps(payload, ensure_ascii=False, indent=2)
                    ),
                }
            ],
        },
    ]


def _resolve_llm_candidate(
    *,
    candidate_ranking: list[dict[str, Any]],
    llm_payload: dict[str, Any],
) -> dict[str, Any] | None:
    selected_candidate_id = str(llm_payload.get("selected_candidate_id") or "").strip()
    selected_family = str(llm_payload.get("selected_strategy_family") or "").strip()
    for candidate in candidate_ranking:
        if selected_candidate_id and candidate.get("candidate_id") == selected_candidate_id:
            return candidate
    for candidate in candidate_ranking:
        if selected_family and candidate.get("strategy_family") == selected_family:
            return candidate
    return None


def _derive_vulnerable_invariants(
    *,
    task_id: str,
    vuln_id: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root_cause = _load_json(patch_root_cause_manifest_path(task_id))
    context_manifest = _load_json(patch_context_manifest_path(task_id))
    selected_context = context_manifest.get("selected_context") or {}
    trace_alignment = _load_json(patch_root_cause_alignment_manifest_path(task_id)).get("alignment") or {}
    trace_function = str(trace_alignment.get("selected_trace_function") or root_cause.get("function") or "").strip()
    hypothesis_blob = " ".join(
        [
            str(root_cause.get("hypothesis") or ""),
            str(selected_context.get("snippet") or ""),
            str(trace_function or ""),
        ]
    ).lower()
    def _priority(*tokens: str, baseline: float) -> float:
        return 1.0 if any(token in hypothesis_blob for token in tokens) else baseline

    invariants: list[dict[str, Any]] = [
        {
            "invariant_id": "offset_length_consistency",
            "summary": "offset, length, and capacity must remain mutually consistent before pointer arithmetic or string-length style walks.",
            "evidence": [
                "trace/context mention offset/length/capacity walk"
                if any(token in hypothesis_blob for token in ("offset", "length", "capacity", "strlen", "buffer", "copy", "size"))
                else None,
            ],
            "priority": _priority("offset", "length", "capacity", "strlen", "buffer", "copy", "size", baseline=0.52),
        },
        {
            "invariant_id": "parser_state_transition",
            "summary": "parser-local state transitions must not advance into an inconsistent state before emitting or copying output.",
            "evidence": [
                "trace/context mention parser state, token, object/array/section, or stack progression"
                if any(token in hypothesis_blob for token in ("parse", "parser", "token", "object", "array", "section", "state", "stack", "depth"))
                else None,
            ],
            "priority": _priority("parse", "parser", "token", "object", "array", "section", "state", "stack", "depth", baseline=0.56),
        },
        {
            "invariant_id": "deallocation_ownership",
            "summary": "reallocation, deallocation, and ownership transfer must not leave stale pointers or null-state continuation.",
            "evidence": [
                "trace/context mention realloc/free/delete/null/ownership"
                if any(token in hypothesis_blob for token in ("realloc", "free", "delete", "null", "ownership", "allocator"))
                else None,
            ],
            "priority": _priority("realloc", "free", "delete", "null", "ownership", "allocator", baseline=0.44),
        },
        {
            "invariant_id": "failure_propagation",
            "summary": "once crash-relevant validation fails, execution must return or short-circuit instead of continuing into unsafe state.",
            "evidence": [
                "trace/context mention error/failure/invalid/return path"
                if any(token in hypothesis_blob for token in ("error", "fail", "invalid", "return", "null"))
                else None,
            ],
            "priority": _priority("error", "fail", "invalid", "return", "null", baseline=0.48),
        },
    ]
    for invariant in invariants:
        invariant["evidence"] = [item for item in (invariant.get("evidence") or []) if item]
    primary = max(invariants, key=lambda item: float(item.get("priority") or 0.0)) if invariants else {}
    report = {
        "task_id": task_id,
        "generated_at": task_store_time(),
        "vuln_id": vuln_id,
        "selected_trace_function": trace_function or None,
        "root_cause_file": root_cause.get("file"),
        "root_cause_function": root_cause.get("function"),
        "primary_invariant": primary.get("invariant_id"),
        "invariants": invariants,
    }
    return invariants, report


def _candidate_invariant_alignment(
    *,
    candidate: dict[str, Any],
    invariants: list[dict[str, Any]],
) -> tuple[list[str], float]:
    strategy = str(candidate.get("strategy") or "")
    strategy_family = str(candidate.get("strategy_family") or "")
    aligned: list[str] = []
    for invariant in invariants:
        invariant_id = str(invariant.get("invariant_id") or "")
        if invariant_id in {"offset_length_consistency", "bounds_consistency"} and any(
            token in strategy or token in strategy_family for token in ("bounds", "offset", "length")
        ):
            aligned.append(invariant_id)
        if invariant_id == "parser_state_transition" and any(
            token in strategy_family for token in ("parser_state", "contract", "guard")
        ):
            aligned.append(invariant_id)
        if invariant_id == "deallocation_ownership" and any(
            token in strategy or token in strategy_family for token in ("realloc", "allocator", "ownership", "null_check")
        ):
            aligned.append(invariant_id)
        if invariant_id == "failure_propagation" and any(
            token in strategy or token in strategy_family for token in ("null_check", "return_early", "error", "guard")
        ):
            aligned.append(invariant_id)
        if invariant_id == "bounded_section_copy" and any(
            token in strategy or token in strategy_family for token in ("bounded", "bounds", "copy")
        ):
            aligned.append(invariant_id)
    score = sum(
        float(invariant.get("priority") or 0.0)
        for invariant in invariants
        if str(invariant.get("invariant_id") or "") in aligned
    )
    return aligned, round(score, 4)


def task_store_time() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _prefer_generalizable_candidate(
    *,
    candidate_ranking: list[dict[str, Any]],
    selected_candidate: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    if not selected_candidate:
        return None, None
    if selected_candidate.get("generalizable"):
        return selected_candidate, None
    top_generalizable = next((candidate for candidate in candidate_ranking if candidate.get("generalizable")), None)
    if not top_generalizable:
        return selected_candidate, None
    selected_score = float(selected_candidate.get("ranking_score") or 0.0)
    generalizable_score = float(top_generalizable.get("ranking_score") or 0.0)
    if generalizable_score >= selected_score + 0.15:
        return top_generalizable, "llm_policy_corrected_generalizable_preference"
    return selected_candidate, None


def write_patch_request(task_id: str, *, now: str, metadata: dict[str, Any], runtime: dict[str, Any]) -> Path:
    return _write(
        patch_request_manifest_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "stage": "PatchRequest",
            "patch_base_task_id": metadata.get("patch_base_task_id"),
            "patch_target_vuln_id": metadata.get("patch_target_vuln_id"),
            "input_pov_path": runtime.get("pov_path"),
            "patch_priority_manifest_path": runtime.get("patch_priority_manifest_path"),
            "scenario": metadata.get("patch_validation_scenario", "real_patch"),
            **_patch_truth_fields(provenance="deterministic_rule", semantic_strength="placeholder"),
            **_llm_placeholder_fields("PatchRequest"),
        },
    )


def write_root_cause(task_id: str, *, now: str, metadata: dict[str, Any], runtime: dict[str, Any]) -> Path:
    alignment = _trace_alignment(metadata, runtime)
    try:
        source_root = _source_root(metadata, runtime)
    except RuntimeError:
        source_root = None

    selected_trace_file = _normalize_source_reference(alignment.get("selected_trace_file"), source_root)
    selected_trace_function = alignment.get("selected_trace_function")
    selected_trace_line = alignment.get("selected_trace_line")
    fallback_applied = False
    if not selected_trace_file or not selected_trace_function or not selected_trace_line:
        fallback_frame = _select_symbolized_fallback_frame(
            symbolized_frames=alignment.get("symbolized_frames") or [],
            source_root=source_root,
        )
        if fallback_frame:
            selected_trace_file = str(fallback_frame.get("file") or selected_trace_file or "")
            selected_trace_function = fallback_frame.get("function") or selected_trace_function
            selected_trace_line = fallback_frame.get("line") or selected_trace_line
            alignment["selected_trace_frame"] = fallback_frame
            alignment["selected_trace_file"] = selected_trace_file
            alignment["selected_trace_function"] = selected_trace_function
            alignment["selected_trace_line"] = selected_trace_line
            fallback_applied = True
            logger.info(
                "[%s] root_cause from symbolized_frames fallback: %s:%s",
                task_id,
                selected_trace_file,
                selected_trace_line,
            )
    else:
        alignment["selected_trace_file"] = selected_trace_file
        if alignment.get("selected_trace_frame"):
            alignment["selected_trace_frame"] = {
                **dict(alignment.get("selected_trace_frame") or {}),
                "file": selected_trace_file,
                "function": selected_trace_function,
                "line": selected_trace_line,
            }

    aligned_function = selected_trace_function
    aligned_file = selected_trace_file
    aligned_line = selected_trace_line
    if aligned_line:
        if fallback_applied:
            line_range = [max(1, int(aligned_line) - 10), int(aligned_line) + 10]
        else:
            line_range = [int(aligned_line), int(aligned_line)]
    else:
        line_range = None
    payload = {
        "task_id": task_id,
        "generated_at": now,
        "stage": "RootCause",
        "status": "localized" if aligned_function or aligned_file else "minimal_hypothesis",
        "input_trace_manifest_path": runtime.get("trace_manifest_path"),
        "input_pov_path": runtime.get("pov_path"),
        "attributed_vuln_id": None,
        "file": aligned_file,
        "function": aligned_function,
        "line_range": line_range,
        "hypothesis": (
            f"trace-primary frame points to {aligned_function} at {aligned_file}:{aligned_line}"
            if aligned_function and alignment.get("selected_trace_file")
            else "Crash is confirmed by PoV; root-cause localization is not available for this task."
        ),
        **_patch_truth_fields(
            provenance="deterministic_rule",
            semantic_strength="general_semantic_fix" if aligned_function else "placeholder",
        ),
        **_llm_placeholder_fields("RootCause"),
    }
    _write(
        patch_root_cause_alignment_manifest_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": metadata.get("patch_target_vuln_id"),
            "alignment": alignment,
        },
    )
    return _write(patch_root_cause_manifest_path(task_id), payload)


def write_context_retrieval(task_id: str, *, now: str, metadata: dict[str, Any], runtime: dict[str, Any]) -> Path:
    root_cause_manifest = _load_json(patch_root_cause_manifest_path(task_id))
    selected_file = root_cause_manifest.get("file")
    selected_line_range = root_cause_manifest.get("line_range")
    source_root = _source_root(metadata, runtime)
    if selected_file and selected_line_range:
        selected_path = _resolve_source_file(source_root, str(selected_file))
        if selected_path is None:
            logger.warning(
                "[%s] context retrieval could not find source file for patch context: %s",
                task_id,
                selected_file,
            )
            payload = {
                "task_id": task_id,
                "generated_at": now,
                "stage": "ContextRetrieval",
                "status": "minimal_context_collected",
                "failure_reason": "source_file_not_found",
                "context_refs": [
                    runtime.get("trace_manifest_path"),
                    runtime.get("repro_manifest_path"),
                    runtime.get("patch_priority_manifest_path"),
                ],
                **_patch_truth_fields(provenance="deterministic_rule", semantic_strength="placeholder"),
                **_llm_placeholder_fields("ContextRetrieval"),
            }
        else:
            context = _extract_context(selected_path, selected_line_range, radius=5)
            context["file_path"] = str(selected_path.relative_to(source_root))
            payload = {
                "task_id": task_id,
                "generated_at": now,
                "stage": "ContextRetrieval",
                "status": "context_selected",
                "context_refs": [
                    runtime.get("trace_manifest_path"),
                    runtime.get("repro_manifest_path"),
                    runtime.get("patch_priority_manifest_path"),
                    context["file_path"],
                ],
                "selected_context": context,
                "selected_vuln_id": metadata.get("patch_target_vuln_id"),
                **_patch_truth_fields(
                    provenance=root_cause_manifest.get("patch_generation_provenance", "deterministic_rule"),
                    semantic_strength="general_semantic_fix",
                ),
                **_llm_placeholder_fields("ContextRetrieval"),
            }
    else:
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "ContextRetrieval",
            "status": "minimal_context_collected",
            "context_refs": [
                runtime.get("trace_manifest_path"),
                runtime.get("repro_manifest_path"),
                runtime.get("patch_priority_manifest_path"),
            ],
            **_patch_truth_fields(provenance="deterministic_rule", semantic_strength="placeholder"),
            **_llm_placeholder_fields("ContextRetrieval"),
        }
    return _write(patch_context_manifest_path(task_id), payload)


def write_patch_creation(
    task_id: str,
    *,
    now: str,
    metadata: dict[str, Any],
    runtime: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    source_root = _source_root(metadata, runtime)
    worktree_root = task_root(task_id) / "patch" / "worktree"
    patched_source_root = worktree_root / source_root.name
    if worktree_root.exists():
        shutil.rmtree(worktree_root)
    shutil.copytree(source_root, patched_source_root)
    vuln_id = str(metadata.get("patch_target_vuln_id", ""))
    candidate_ranking, selected_candidate = _rank_patch_candidates(
        vuln_id=vuln_id,
        metadata=metadata,
        runtime=runtime,
    )
    patch_ground_truth_mode = _normalize_patch_ground_truth_mode(
        resolve_text_setting(metadata, "PATCH_GROUND_TRUTH_MODE", settings.patch_ground_truth_mode)
    )
    rule_rank1_candidate = candidate_ranking[0] if candidate_ranking else None
    llm_messages = _build_patch_llm_messages(
        task_id=task_id,
        vuln_id=vuln_id,
        metadata=metadata,
        runtime=runtime,
        candidate_ranking=candidate_ranking,
    )
    llm_client = LLMClient()
    llm_metadata = build_non_llm_metadata(
        generated_by="patch_plane_state_machine.PatchCreation",
        failure_reason="patch proposal did not attempt a real LLM call",
    )
    llm_patch_payload: dict[str, Any] | None = None
    llm_selected_candidate: dict[str, Any] | None = None
    llm_selection_source = "deterministic_fallback"
    candidate_specific_materialization_payload: dict[str, Any] | None = None
    candidate_specific_materialization_error: str | None = None
    generic_fallback_state: dict[str, Any] = {"used": False, "failure_reason": None}
    if llm_client.enabled():
        try:
            response_payload, llm_metadata = llm_client.chat_with_metadata(
                llm_messages,
                temperature=0.1,
                max_tokens=700,
                timeout_seconds=resolve_int_setting(
                    metadata,
                    "LLM_PATCH_TIMEOUT_SECONDS",
                    resolve_int_setting(metadata, "LLM_TIMEOUT_SECONDS", settings.llm_timeout_seconds),
                ),
                max_retries=resolve_int_setting(
                    metadata,
                    "LLM_PATCH_MAX_RETRIES",
                    resolve_int_setting(metadata, "LLM_MAX_RETRIES", settings.llm_max_retries),
                ),
                generated_by="patch_plane_state_machine.PatchCreation",
            )
            llm_patch_payload = _extract_json_object(extract_content(response_payload))
            llm_selected_candidate = _resolve_llm_candidate(
                candidate_ranking=candidate_ranking,
                llm_payload=llm_patch_payload,
            )
            if llm_selected_candidate:
                preferred_candidate, correction_reason = _prefer_generalizable_candidate(
                    candidate_ranking=candidate_ranking,
                    selected_candidate=llm_selected_candidate,
                )
                selected_candidate = preferred_candidate or llm_selected_candidate
                llm_selection_source = correction_reason or "llm_primary"
                if correction_reason:
                    llm_patch_payload["policy_correction"] = correction_reason
                    llm_patch_payload["original_selected_candidate_id"] = llm_selected_candidate.get("candidate_id")
                    llm_patch_payload["policy_selected_candidate_id"] = selected_candidate.get("candidate_id")
            else:
                llm_selection_source = "deterministic_fallback_unknown_candidate"
        except (LLMCallError, RuntimeError, json.JSONDecodeError) as exc:
            if isinstance(exc, LLMCallError):
                llm_metadata = exc.metadata
            else:
                llm_metadata = build_non_llm_metadata(
                    generated_by="patch_plane_state_machine.PatchCreation",
                    failure_reason=str(exc),
                    prompt_sha256=_llm_fields_from_metadata(llm_metadata).get("prompt_sha256"),
                )
            llm_patch_payload = {"error": str(exc)}
            llm_selection_source = "deterministic_fallback_llm_failure"
    llm_selection_confidence = _normalize_optional_confidence(
        llm_patch_payload.get("confidence") if isinstance(llm_patch_payload, dict) else None
    )
    rule_rank1_candidate_id = str((rule_rank1_candidate or {}).get("candidate_id") or "")
    llm_selected_candidate_id = str((llm_selected_candidate or {}).get("candidate_id") or "")
    llm_vs_rule_agreement = bool(
        rule_rank1_candidate_id
        and llm_selected_candidate_id
        and rule_rank1_candidate_id == llm_selected_candidate_id
    )
    if (
        llm_metadata.llm_real_call_verified
        and llm_patch_payload is not None
        and selected_candidate is not None
    ):
        selected_candidate_id = str(selected_candidate.get("candidate_id") or "")
        llm_selected_candidate_id = str((llm_selected_candidate or {}).get("candidate_id") or "")
        proposed_diff = str(llm_patch_payload.get("proposed_patch_diff") or "")
        needs_candidate_specific_materialization = (
            not proposed_diff.strip()
            or (
                selected_candidate_id
                and llm_selected_candidate_id
                and selected_candidate_id != llm_selected_candidate_id
            )
        )
        if needs_candidate_specific_materialization:
            try:
                materialization_messages = _build_candidate_specific_materialization_messages(
                    task_id=task_id,
                    selected_candidate=selected_candidate,
                    metadata=metadata,
                    runtime=runtime,
                    previous_llm_payload=llm_patch_payload,
                )
                response_payload, materialization_metadata = llm_client.chat_with_metadata(
                    materialization_messages,
                    temperature=0.0,
                    max_tokens=900,
                    timeout_seconds=resolve_int_setting(
                        metadata,
                        "LLM_PATCH_TIMEOUT_SECONDS",
                        resolve_int_setting(metadata, "LLM_TIMEOUT_SECONDS", settings.llm_timeout_seconds),
                    ),
                    max_retries=resolve_int_setting(
                        metadata,
                        "LLM_PATCH_MAX_RETRIES",
                        resolve_int_setting(metadata, "LLM_MAX_RETRIES", settings.llm_max_retries),
                    ),
                    generated_by="patch_plane_state_machine.PatchCreation.materialize_selected_candidate",
                )
                candidate_specific_materialization_payload = _extract_json_object(extract_content(response_payload))
                llm_patch_payload["candidate_specific_materialization"] = {
                    "selected_candidate_id": selected_candidate_id,
                    "materialization_payload": candidate_specific_materialization_payload,
                    "llm_metadata": _llm_fields_from_metadata(materialization_metadata),
                }
                materialized_diff = str(candidate_specific_materialization_payload.get("proposed_patch_diff") or "")
                if materialized_diff.strip():
                    llm_patch_payload["proposed_patch_diff"] = materialized_diff
            except (LLMCallError, RuntimeError, json.JSONDecodeError) as exc:
                candidate_specific_materialization_error = str(exc)
                llm_patch_payload["candidate_specific_materialization_error"] = candidate_specific_materialization_error
    strategy = str(selected_candidate.get("strategy") or metadata.get("patch_creation_strategy", "root_cause_direct_repair"))
    freeform_result, freeform_manifest = _try_apply_freeform_patch(
        task_id=task_id,
        source_root=patched_source_root,
        llm_payload=llm_patch_payload,
        generated_at=now,
    )
    if freeform_result and llm_metadata.llm_real_call_verified:
        patch_result = freeform_result
        materialization_mode = "llm_freeform_unified_diff"
        deterministic_template_applied = False
        deterministic_dependency_level = "fallback_available_not_used"
    else:
        patch_result, generic_fallback_state = _apply_patch_strategy(
            task_id=task_id,
            vuln_id=vuln_id,
            strategy=strategy,
            source_root=patched_source_root,
            metadata=metadata,
            runtime=runtime,
            generated_at=now,
        )
        generic_llm_metadata = generic_fallback_state.get("llm_metadata")
        generic_llm_payload = generic_fallback_state.get("llm_payload")
        generic_freeform_manifest = generic_fallback_state.get("freeform_manifest")
        if generic_fallback_state.get("used"):
            llm_selection_source = str(generic_fallback_state.get("selection_source") or llm_selection_source)
            if generic_llm_metadata is not None:
                llm_metadata = generic_llm_metadata
            if generic_llm_payload is not None:
                llm_patch_payload = {
                    "generic_open_ended_fallback": generic_llm_payload,
                    "previous_candidate_ranking_payload": llm_patch_payload,
                }
            if generic_freeform_manifest is not None:
                freeform_manifest["generic_open_ended_fallback"] = generic_freeform_manifest
        if patch_result is not None:
            if generic_fallback_state.get("used"):
                materialization_mode = "generic_llm_open_ended_diff"
                deterministic_template_applied = False
                deterministic_dependency_level = "generic_llm_open_ended_fallback"
            else:
                materialization_mode = "deterministic_template_helper"
                deterministic_template_applied = True
                deterministic_dependency_level = "materialization_only" if llm_selected_candidate else "primary_path"
        else:
            materialization_mode = "generic_llm_open_ended_failed"
            deterministic_template_applied = False
            deterministic_dependency_level = "generic_llm_open_ended_failed"
    llm_selection_fallback_triggered = _llm_selection_fallback_triggered(
        selection_source=llm_selection_source,
        llm_selected_candidate=llm_selected_candidate,
    )
    _write(patch_freeform_materialization_manifest_path(task_id), freeform_manifest)
    diff_path = task_root(task_id) / "patch" / "candidate.diff"
    if patch_result is None:
        diff_path.write_text("", encoding="utf-8")
    else:
        diff_path.write_text(patch_result["diff"], encoding="utf-8")
    ranking_payload = {
        "task_id": task_id,
        "generated_at": now,
        "patch_target_vuln_id": vuln_id,
        "patch_ground_truth_mode": patch_ground_truth_mode,
        "candidate_ranking": candidate_ranking,
        "selected_candidate": selected_candidate,
        "rule_rank1_candidate": rule_rank1_candidate,
        "trace_manifest_path": runtime.get("trace_manifest_path"),
        "repro_manifest_path": runtime.get("repro_manifest_path"),
        "context_package_path": runtime.get("context_package_path"),
    }
    _write(patch_candidate_ranking_manifest_path(task_id), ranking_payload)
    _write(
        llm_patch_candidate_ranking_manifest_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": vuln_id,
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "selection_source": llm_selection_source,
            "rule_rank1_candidate": rule_rank1_candidate,
            "llm_selected_candidate": llm_selected_candidate,
            "llm_selection_confidence": llm_selection_confidence,
            "llm_selection_fallback_triggered": llm_selection_fallback_triggered,
            "llm_vs_rule_agreement": llm_vs_rule_agreement,
            "llm_patch_payload": llm_patch_payload,
            "candidate_specific_materialization_payload": candidate_specific_materialization_payload,
            "candidate_specific_materialization_error": candidate_specific_materialization_error,
            "fallback_selected_candidate": selected_candidate if not llm_selected_candidate else None,
            "candidate_ranking": candidate_ranking,
        },
    )
    _write(
        patch_strategy_family_manifest_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": vuln_id,
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "strategy_families": [
                {
                    "strategy_family": candidate.get("strategy_family"),
                    "strategy": candidate.get("strategy"),
                    "generalizable": candidate.get("generalizable"),
                    "ground_truth_dependency": candidate.get("ground_truth_dependency"),
                    "sort_weight_gt_bonus": candidate.get("sort_weight_gt_bonus"),
                    "sort_weight_effective_score": candidate.get("sort_weight_effective_score"),
                }
                for candidate in candidate_ranking
            ],
        },
    )
    strategy_payload = {
        "task_id": task_id,
        "generated_at": now,
        "patch_target_vuln_id": vuln_id,
        "patch_ground_truth_mode": patch_ground_truth_mode,
        "selected_strategy": strategy,
        "selected_strategy_family": selected_candidate.get("strategy_family"),
        "selected_strategy_reason": selected_candidate.get("selection_reason"),
        "generalizable": selected_candidate.get("generalizable"),
        "ground_truth_dependency": selected_candidate.get("ground_truth_dependency"),
        "trace_context_dependency": "high",
        "selected_target_function": runtime.get("selected_target_function"),
        "selection_source": llm_selection_source,
    }
    _write(generalized_patch_strategy_manifest_path(task_id), strategy_payload)
    _write(
        semantic_patch_synthesis_manifest_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": vuln_id,
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "selected_candidate": selected_candidate,
            "selected_trace_alignment_path": str(patch_root_cause_alignment_manifest_path(task_id)),
            "selected_target_function": runtime.get("selected_target_function"),
            "semantic_synthesis_mode": (
                "llm_trace_stack_plus_context_ranked_strategy_selection"
                if llm_selected_candidate
                else "trace_stack_plus_context_constrained_patch_synthesis"
            ),
            "candidate_patch_diff_path": str(diff_path),
            "llm_patch_payload": llm_patch_payload,
            "selection_source": llm_selection_source,
            "freeform_materialization_manifest_path": str(patch_freeform_materialization_manifest_path(task_id)),
            "patch_materialization_mode": materialization_mode,
        },
    )
    _write(
        ground_truth_dependency_report_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": vuln_id,
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "selected_candidate": selected_candidate.get("candidate_id"),
            "selected_candidate_ground_truth_dependency": selected_candidate.get("ground_truth_dependency"),
            "all_candidates": [
                {
                    "candidate_id": candidate.get("candidate_id"),
                    "strategy": candidate.get("strategy"),
                    "ground_truth_dependency": candidate.get("ground_truth_dependency"),
                    "generalizable": candidate.get("generalizable"),
                    "sort_weight_gt_bonus": candidate.get("sort_weight_gt_bonus"),
                    "sort_weight_effective_score": candidate.get("sort_weight_effective_score"),
                }
                for candidate in candidate_ranking
            ],
        },
    )
    _write(
        llm_patch_audit_manifest_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": vuln_id,
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "selection_source": llm_selection_source,
            "llm_selection_confidence": llm_selection_confidence,
            "llm_selection_fallback_triggered": llm_selection_fallback_triggered,
            "llm_vs_rule_agreement": llm_vs_rule_agreement,
            "llm_patch_payload": llm_patch_payload,
            **_llm_fields_from_metadata(llm_metadata),
        },
    )
    _write(
        patch_generalization_report_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": vuln_id,
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "selected_candidate": selected_candidate,
            "selection_source": llm_selection_source,
            "llm_selection_confidence": llm_selection_confidence,
            "llm_selection_fallback_triggered": llm_selection_fallback_triggered,
            "llm_vs_rule_agreement": llm_vs_rule_agreement,
            "selected_candidate_generalizable": selected_candidate.get("generalizable"),
            "selected_candidate_ground_truth_dependency": selected_candidate.get("ground_truth_dependency"),
            "selected_candidate_strategy_family": selected_candidate.get("strategy_family"),
            "llm_patch_payload": llm_patch_payload,
            "candidate_specific_materialization_payload": candidate_specific_materialization_payload,
            "candidate_specific_materialization_error": candidate_specific_materialization_error,
            "patch_materialization_mode": materialization_mode,
            "freeform_materialization_manifest_path": str(patch_freeform_materialization_manifest_path(task_id)),
        },
    )
    _write(
        deterministic_patch_dependency_report_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": vuln_id,
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "selection_source": llm_selection_source,
            "deterministic_template_applied": deterministic_template_applied,
            "selected_strategy": strategy,
            "deterministic_dependency_level": deterministic_dependency_level,
        },
    )
    _write(
        patch_llm_vs_template_comparison_path(task_id),
        {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": vuln_id,
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "llm_freeform_diff_present": freeform_manifest.get("llm_freeform_diff_present"),
            "llm_freeform_applied": freeform_manifest.get("freeform_applied"),
            "candidate_specific_materialization_used": bool(candidate_specific_materialization_payload),
            "materialization_mode": materialization_mode,
            "deterministic_template_applied": deterministic_template_applied,
            "deterministic_template_role": "fallback_or_helper",
            "selected_candidate": selected_candidate,
            "llm_patch_payload": llm_patch_payload,
            "comparison_verdict": (
                "llm_generic_open_ended_patch_text_used"
                if materialization_mode == "generic_llm_open_ended_diff"
                else
                "llm_freeform_patch_text_used"
                if materialization_mode == "llm_freeform_unified_diff"
                else "llm_ranked_semantic_strategy_but_template_helper_materialized_text"
            ),
        },
    )
    if patch_result is None:
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "PatchCreation",
            "status": "patch_creation_failed",
            "patch_target_vuln_id": vuln_id,
            "strategy": strategy,
            "selected_candidate": selected_candidate,
            "worktree_source_root": str(patched_source_root),
            "modified_file": None,
            "diff_path": str(diff_path),
            "failure_reason": str(generic_fallback_state.get("failure_reason") or "generic_llm_synthesis_failed"),
            "patch_result_classification": "patch_creation_failed",
            "patch_candidate_ranking_manifest_path": str(patch_candidate_ranking_manifest_path(task_id)),
            "llm_patch_candidate_ranking_manifest_path": str(llm_patch_candidate_ranking_manifest_path(task_id)),
            "llm_patch_audit_manifest_path": str(llm_patch_audit_manifest_path(task_id)),
            "generalized_patch_strategy_manifest_path": str(generalized_patch_strategy_manifest_path(task_id)),
            "semantic_patch_synthesis_manifest_path": str(semantic_patch_synthesis_manifest_path(task_id)),
            "patch_strategy_family_manifest_path": str(patch_strategy_family_manifest_path(task_id)),
            "ground_truth_dependency_report_path": str(ground_truth_dependency_report_path(task_id)),
            "patch_generalization_report_path": str(patch_generalization_report_path(task_id)),
            "deterministic_patch_dependency_report_path": str(deterministic_patch_dependency_report_path(task_id)),
            "patch_freeform_materialization_manifest_path": str(patch_freeform_materialization_manifest_path(task_id)),
            "patch_llm_vs_template_comparison_path": str(patch_llm_vs_template_comparison_path(task_id)),
            "patch_ground_truth_mode": patch_ground_truth_mode,
            "selection_source": llm_selection_source,
            "llm_selection_confidence": llm_selection_confidence,
            "llm_selection_fallback_triggered": llm_selection_fallback_triggered,
            "llm_vs_rule_agreement": llm_vs_rule_agreement,
            "llm_patch_payload": llm_patch_payload,
            "patch_materialization_mode": materialization_mode,
            "verifier_gates_passed": [],
            "generic_open_ended_fallback": {
                "used": generic_fallback_state.get("used", False),
                "failure_reason": generic_fallback_state.get("failure_reason"),
                "freeform_manifest": generic_fallback_state.get("freeform_manifest"),
            },
            "freeform_materialization": freeform_manifest,
            **_patch_truth_fields(
                provenance=_patch_provenance_from_strategy(strategy),
                semantic_strength="placeholder",
                patch_llm_request_attempted=bool(_llm_fields_from_metadata(llm_metadata).get("llm_request_attempted")),
                patch_llm_real_call_verified=bool(_llm_fields_from_metadata(llm_metadata).get("llm_real_call_verified")),
            ),
            **_llm_fields_from_metadata(llm_metadata),
        }
        path = _write(patch_creation_manifest_path(task_id), payload)
        return path, payload
    patch_generation_provenance = (
        "real_llm_patch"
        if llm_metadata.llm_real_call_verified
        and materialization_mode in {"llm_freeform_unified_diff", "generic_llm_open_ended_diff"}
        else _patch_provenance_from_strategy(strategy)
    )
    payload = {
        "task_id": task_id,
        "generated_at": now,
        "stage": "PatchCreation",
        "status": "patch_created",
        "patch_target_vuln_id": vuln_id,
        "strategy": patch_result["strategy"],
        "selected_candidate": selected_candidate,
        "worktree_source_root": str(patched_source_root),
        "modified_file": patch_result["modified_file"],
        "diff_path": str(diff_path),
        "patch_candidate_ranking_manifest_path": str(patch_candidate_ranking_manifest_path(task_id)),
        "llm_patch_candidate_ranking_manifest_path": str(llm_patch_candidate_ranking_manifest_path(task_id)),
        "llm_patch_audit_manifest_path": str(llm_patch_audit_manifest_path(task_id)),
        "generalized_patch_strategy_manifest_path": str(generalized_patch_strategy_manifest_path(task_id)),
        "semantic_patch_synthesis_manifest_path": str(semantic_patch_synthesis_manifest_path(task_id)),
        "patch_strategy_family_manifest_path": str(patch_strategy_family_manifest_path(task_id)),
        "ground_truth_dependency_report_path": str(ground_truth_dependency_report_path(task_id)),
        "patch_generalization_report_path": str(patch_generalization_report_path(task_id)),
        "deterministic_patch_dependency_report_path": str(deterministic_patch_dependency_report_path(task_id)),
        "patch_freeform_materialization_manifest_path": str(patch_freeform_materialization_manifest_path(task_id)),
        "patch_llm_vs_template_comparison_path": str(patch_llm_vs_template_comparison_path(task_id)),
        "patch_ground_truth_mode": patch_ground_truth_mode,
        "selection_source": llm_selection_source,
        "llm_selection_confidence": llm_selection_confidence,
        "llm_selection_fallback_triggered": llm_selection_fallback_triggered,
        "llm_vs_rule_agreement": llm_vs_rule_agreement,
        "llm_patch_payload": llm_patch_payload,
        "patch_materialization_mode": materialization_mode,
        "freeform_materialization": freeform_manifest,
        "verifier_gates_passed": [],
        **_patch_truth_fields(
            provenance=patch_generation_provenance,
            semantic_strength=_patch_semantic_strength_from_strategy(strategy),
            patch_llm_request_attempted=bool(llm_metadata.llm_request_attempted),
            patch_llm_real_call_verified=bool(llm_metadata.llm_real_call_verified),
        ),
        **_llm_fields_from_metadata(llm_metadata),
    }
    path = _write(patch_creation_manifest_path(task_id), payload)
    return path, payload


def write_patch_apply(
    task_id: str,
    *,
    now: str,
    creation_payload: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    if creation_payload.get("status") != "patch_created":
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "PatchApply",
            "status": "patch_not_applied",
            "worktree_source_root": creation_payload.get("worktree_source_root"),
            "modified_file": creation_payload.get("modified_file"),
            "diff_path": creation_payload.get("diff_path"),
            "strategy": creation_payload.get("strategy"),
            "error": creation_payload.get("failure_reason"),
            "patch_result_classification": creation_payload.get("patch_result_classification", "patch_creation_failed"),
            **_patch_truth_fields(
                provenance=creation_payload.get("patch_generation_provenance", "deterministic_rule"),
                semantic_strength=creation_payload.get("patch_semantic_strength", "placeholder"),
                patch_llm_request_attempted=bool(creation_payload.get("patch_llm_request_attempted")),
                patch_llm_real_call_verified=bool(creation_payload.get("patch_llm_real_call_verified")),
            ),
            **_llm_fields_from_metadata(creation_payload),
        }
        path = _write(patch_apply_manifest_path(task_id), payload)
        return path, payload
    payload = {
        "task_id": task_id,
        "generated_at": now,
        "stage": "PatchApply",
        "status": "patch_applied_to_worktree",
        "worktree_source_root": creation_payload.get("worktree_source_root"),
        "modified_file": creation_payload.get("modified_file"),
        "diff_path": creation_payload.get("diff_path"),
        "strategy": creation_payload.get("strategy"),
        "patch_result_classification": "patch_applied",
        **_patch_truth_fields(
            provenance=creation_payload.get("patch_generation_provenance", "deterministic_rule"),
            semantic_strength=creation_payload.get("patch_semantic_strength", "placeholder"),
            patch_llm_request_attempted=bool(creation_payload.get("patch_llm_request_attempted")),
            patch_llm_real_call_verified=bool(creation_payload.get("patch_llm_real_call_verified")),
        ),
        **_llm_fields_from_metadata(creation_payload),
    }
    path = _write(patch_apply_manifest_path(task_id), payload)
    return path, payload


def _load_primary_testcase(metadata: dict[str, Any], runtime: dict[str, Any]) -> Path:
    explicit = metadata.get("patch_testcase_path")
    if explicit:
        path = _host_path(explicit)
        if path and path.exists():
            return path
    trace_manifest = _load_json(_host_path(runtime.get("trace_manifest_path")))
    replay_attempts = trace_manifest.get("replay_attempts", [])
    if replay_attempts:
        path = _host_path(replay_attempts[0].get("testcase_path"))
        if path and path.exists():
            return path
    raise RuntimeError("patch PoV testcase is unavailable")


def _load_regression_inputs(metadata: dict[str, Any], runtime: dict[str, Any], limit: int = 3) -> list[Path]:
    candidates: list[Path] = []
    for key in ("patch_regression_inputs",):
        raw = metadata.get(key) or []
        for item in raw:
            path = _host_path(item)
            if path and path.exists() and path.is_file():
                candidates.append(path)
    if candidates:
        return candidates[:limit]

    bases = []
    for key in ("existing_seed_path", "existing_corpus_path"):
        path = _host_path(metadata.get(key) or runtime.get("resolved_imports", {}).get(key))
        if path and path.exists():
            bases.append(path)
    for base in bases:
        for candidate in sorted(base.rglob("*")):
            if candidate.is_file():
                candidates.append(candidate)
            if len(candidates) >= limit:
                return candidates[:limit]
    return candidates[:limit]


def write_patch_build(
    task_id: str,
    *,
    now: str,
    metadata: dict[str, Any],
    runtime: dict[str, Any],
    creation_payload: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    if creation_payload.get("status") != "patch_created":
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "PatchBuild",
            "status": "build_failed",
            "error": creation_payload.get("failure_reason", "patch creation failed before build"),
            "build_capability": None,
            "auto_resolved": False,
            "registry_fallback_used": False,
            "build_source": "patch_creation_failed_before_build",
            "patch_result_classification": creation_payload.get("patch_result_classification", "patch_creation_failed"),
            **_patch_truth_fields(
                provenance=creation_payload.get("patch_generation_provenance", "deterministic_rule"),
                semantic_strength=creation_payload.get("patch_semantic_strength", "placeholder"),
                patch_llm_request_attempted=bool(creation_payload.get("patch_llm_request_attempted")),
                patch_llm_real_call_verified=bool(creation_payload.get("patch_llm_real_call_verified")),
            ),
            **_llm_fields_from_metadata(creation_payload),
        }
        path = _write(patch_build_manifest_path(task_id), payload)
        return path, payload
    source_root = Path(creation_payload["worktree_source_root"])
    oss_fuzz_project_dir = _oss_fuzz_project_root(metadata, runtime)
    capability = infer_build_capability(
        project_name=metadata.get("project"),
        source_dir=source_root,
        source_resolution={},
    )
    auto_resolved = capability is not None and capability.origin == "auto_resolution"
    registry_fallback_used = False
    if capability is None:
        capability = resolve_build_capability(metadata.get("project") or oss_fuzz_project_dir.name)
        registry_fallback_used = capability is not None
        auto_resolved = False
    if capability is None:
        raise RuntimeError("no build capability available for patch target")
    try:
        registry = build_ossfuzz_project(
            task_id=task_id,
            source_dir=source_root,
            oss_fuzz_project_dir=oss_fuzz_project_dir,
            build_dir=task_root(task_id) / "patch" / "build",
            capability=capability,
        )
        fuzzers = registry.get("fuzzers", [])
        expected = str(metadata.get("expected_harness") or runtime.get("active_harness") or "").strip().lower()
        selected = None
        for item in fuzzers:
            if str(item.get("name", "")).strip().lower() == expected:
                selected = item
                break
        if selected is None and fuzzers:
            selected = fuzzers[0]
        if selected is None:
            tracer_replays = registry.get("tracer_replay_binaries", [])
            for item in tracer_replays:
                if str(item.get("name", "")).strip().lower() == expected:
                    selected = {
                        "name": item.get("name"),
                        "path": item.get("path"),
                        "build_variant": item.get("build_variant"),
                        "selection_source": "tracer_replay_binary",
                    }
                    break
            if selected is None and tracer_replays:
                first = tracer_replays[0]
                selected = {
                    "name": first.get("name"),
                    "path": first.get("path"),
                    "build_variant": first.get("build_variant"),
                    "selection_source": "tracer_replay_binary",
                }
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "PatchBuild",
            "status": "build_succeeded",
            "build_registry_path": str(task_root(task_id) / "patch" / "build" / "build_registry.json"),
            "build_log_path": registry.get("artifacts", {}).get("build_log"),
            "patched_binary_path": selected.get("path") if selected else None,
            "patched_harness_name": selected.get("name") if selected else None,
            "patched_binary_selection_source": selected.get("selection_source") if selected else "fuzzer_binary",
            "patched_binary_build_variant": selected.get("build_variant") if selected else None,
            "build_capability": capability.to_dict(),
            "auto_resolved": auto_resolved,
            "registry_fallback_used": registry_fallback_used,
            "build_source": "oss_fuzz_reuse",
            "patch_result_classification": "patch_applied_and_build_succeeded",
            **_patch_truth_fields(
                provenance=creation_payload.get("patch_generation_provenance", "deterministic_rule"),
                semantic_strength=creation_payload.get("patch_semantic_strength", "placeholder"),
                patch_llm_request_attempted=bool(creation_payload.get("patch_llm_request_attempted")),
                patch_llm_real_call_verified=bool(creation_payload.get("patch_llm_real_call_verified")),
            ),
            **_llm_fields_from_metadata(creation_payload),
        }
    except Exception as exc:
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "PatchBuild",
            "status": "build_failed",
            "error": str(exc),
            "build_capability": capability.to_dict(),
            "auto_resolved": auto_resolved,
            "registry_fallback_used": registry_fallback_used,
            "build_source": "oss_fuzz_reuse",
            "patch_result_classification": "patch_applied_but_build_failed",
            **_patch_truth_fields(
                provenance=creation_payload.get("patch_generation_provenance", "deterministic_rule"),
                semantic_strength=creation_payload.get("patch_semantic_strength", "placeholder"),
                patch_llm_request_attempted=bool(creation_payload.get("patch_llm_request_attempted")),
                patch_llm_real_call_verified=bool(creation_payload.get("patch_llm_real_call_verified")),
            ),
            **_llm_fields_from_metadata(creation_payload),
        }
    path = _write(patch_build_manifest_path(task_id), payload)
    return path, payload


def _replay_input(binary_path: str, harness_name: str, testcase_path: str, cwd: Path) -> dict[str, Any]:
    result = replay_testcase(binary_path, harness_name, testcase_path, cwd)
    parsed = parse_replay_result(result, "live_raw")
    crash_detected = bool("ERROR: AddressSanitizer" in (result.stderr or result.stdout) or result.exit_code != 0)
    return {
        "command": list(result.command),
        "exit_code": result.exit_code,
        "stderr_excerpt": parsed.stderr_excerpt[:2000],
        "signature": compute_signature(parsed.crash_type, parsed.crash_state),
        "crash_detected": crash_detected,
        "crash_type": parsed.crash_type,
        "crash_state": parsed.crash_state,
        "testcase_path": testcase_path,
    }


def write_qe(
    task_id: str,
    *,
    now: str,
    metadata: dict[str, Any] | None = None,
    runtime: dict[str, Any] | None = None,
    build_payload: dict[str, Any] | None = None,
) -> tuple[Path, str]:
    metadata = metadata or {}
    runtime = runtime or {}
    def _write_semantic_validation(
        *,
        verdict: str,
        classification: str,
        build_result: dict[str, Any] | None,
        reason: str,
        pov_replay: dict[str, Any] | None = None,
        regression_results: list[dict[str, Any]] | None = None,
        verifier_gates_passed: list[str] | None = None,
    ) -> None:
        tiers = {
            "syntactic_patch_only": verdict == "build_failed",
            "semantic_patch_candidate": bool(build_result),
            "build_valid_patch": bool(build_result and build_result.get("status") == "build_succeeded"),
            "qe_valid_patch": verdict == "approved",
            "accepted_patch": verdict == "approved",
        }
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "qe_verdict": verdict,
            "patch_result_classification": classification,
            "semantic_validation_tiers": tiers,
            "reason": reason,
            "build_result": build_result,
            "pov_replay": pov_replay,
            "regression_results": regression_results or [],
            "verifier_gates_passed": verifier_gates_passed or [],
        }
        _write(patch_semantic_validation_manifest_path(task_id), payload)
        analysis_payload = {
            "task_id": task_id,
            "generated_at": now,
            "patch_target_vuln_id": metadata.get("patch_target_vuln_id"),
            "qe_verdict": verdict,
            "patch_result_classification": classification,
            "most_likely_failure_stage": (
                "patch_semantically_irrelevant_or_incomplete"
                if verdict == "pov_failed"
                else "patch_build_contract"
                if verdict == "build_failed"
                else "qe_regression"
                if verdict == "regression_failed"
                else "accepted"
            ),
            "observed_pov_signature": (pov_replay or {}).get("signature"),
            "observed_pov_crash_type": (pov_replay or {}).get("crash_type"),
            "analysis": (
                "patched binary builds, but the live crash still reproduces; the selected repair family likely missed the true crash-blocking invariant."
                if verdict == "pov_failed"
                else "build failed before semantic QE could run"
                if verdict == "build_failed"
                else reason
            ),
            "next_minimal_step": (
                "tighten trace-to-invariant alignment and retry with a different semantic repair family"
                if verdict == "pov_failed"
                else "repair build contract first"
                if verdict == "build_failed"
                else "tighten regression corpus coverage and preserve the accepted patch family"
                if verdict == "approved"
                else "expand regression sampling and semantic candidate ranking before the next retry"
            ),
        }
        _write(patch_failure_analysis_path(task_id), analysis_payload)

    if build_payload is None:
        scenario = str(metadata.get("patch_validation_scenario", "qe_fail"))
        if scenario in {"qe_pass", "approved"}:
            verdict = "approved"
            verifier_gates = _verifier_gates_passed(verdict=verdict)
            payload = {
                "task_id": task_id,
                "generated_at": now,
                "stage": "QE",
                "verdict": verdict,
                "reason": "validation scenario requested approved QE result",
                "supported_verdicts": ["build_failed", "pov_failed", "regression_failed", "approved"],
                "verifier_gates_passed": verifier_gates,
                **_patch_truth_fields(provenance="deterministic_rule", semantic_strength="placeholder"),
                **_llm_placeholder_fields("QE"),
            }
            _write_semantic_validation(
                verdict=verdict,
                classification=payload.get("patch_result_classification", "patch_qe_passed"),
                build_result=None,
                reason=payload["reason"],
                verifier_gates_passed=verifier_gates,
            )
            return _write(patch_qe_manifest_path(task_id), payload), verdict
        if scenario == "pov_failed":
            verdict = "pov_failed"
            reason = "PoV replay did not reproduce in validation scenario"
        elif scenario == "regression_failed":
            verdict = "regression_failed"
            reason = "regression signal failed in validation scenario"
        else:
            verdict = "build_failed"
            reason = "build step failed in validation scenario"
        verifier_gates = _verifier_gates_passed(verdict=verdict)
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "QE",
            "verdict": verdict,
            "reason": reason,
            "supported_verdicts": ["build_failed", "pov_failed", "regression_failed", "approved"],
            "verifier_gates_passed": verifier_gates,
            **_patch_truth_fields(provenance="deterministic_rule", semantic_strength="placeholder"),
            **_llm_placeholder_fields("QE"),
        }
        _write_semantic_validation(
            verdict=verdict,
            classification=payload.get("patch_result_classification", "syntactic_patch_only"),
            build_result=None,
            reason=reason,
            verifier_gates_passed=verifier_gates,
        )
        return _write(patch_qe_manifest_path(task_id), payload), verdict

    build_status = build_payload.get("status")
    if build_status != "build_succeeded":
        verdict = "build_failed"
        verifier_gates = _verifier_gates_passed(build_payload=build_payload, verdict=verdict)
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "QE",
            "verdict": verdict,
            "reason": build_payload.get("error", "patch build failed"),
            "build_result": build_payload,
            "patch_result_classification": "patch_applied_but_build_failed",
            "supported_verdicts": ["build_failed", "pov_failed", "regression_failed", "approved"],
            "verifier_gates_passed": verifier_gates,
            **_patch_truth_fields(
                provenance=build_payload.get("patch_generation_provenance", "deterministic_rule"),
                semantic_strength=build_payload.get("patch_semantic_strength", "placeholder"),
                patch_llm_request_attempted=bool(build_payload.get("patch_llm_request_attempted")),
                patch_llm_real_call_verified=bool(build_payload.get("patch_llm_real_call_verified")),
            ),
            **_llm_fields_from_metadata(build_payload),
        }
        _write_semantic_validation(
            verdict=verdict,
            classification="patch_applied_but_build_failed",
            build_result=build_payload,
            reason=build_payload.get("error", "patch build failed"),
            verifier_gates_passed=verifier_gates,
        )
        return _write(patch_qe_manifest_path(task_id), payload), verdict

    testcase_path = str(_load_primary_testcase(metadata, runtime))
    patched_binary_path = build_payload.get("patched_binary_path")
    patched_harness_name = build_payload.get("patched_harness_name")
    if not patched_binary_path or not patched_harness_name:
        verdict = "build_failed"
        reason = "patch build succeeded but no replay-capable binary/harness was registered for QE"
        verifier_gates = _verifier_gates_passed(build_payload=build_payload, verdict=verdict)
        payload = {
            "task_id": task_id,
            "generated_at": now,
            "stage": "QE",
            "verdict": verdict,
            "reason": reason,
            "build_result": build_payload,
            "patch_result_classification": "patch_build_passed_but_replay_profile_missing",
            "supported_verdicts": ["build_failed", "pov_failed", "regression_failed", "approved"],
            "verifier_gates_passed": verifier_gates,
            **_patch_truth_fields(
                provenance=build_payload.get("patch_generation_provenance", "deterministic_rule"),
                semantic_strength=build_payload.get("patch_semantic_strength", "placeholder"),
                patch_llm_request_attempted=bool(build_payload.get("patch_llm_request_attempted")),
                patch_llm_real_call_verified=bool(build_payload.get("patch_llm_real_call_verified")),
            ),
            **_llm_fields_from_metadata(build_payload),
        }
        _write_semantic_validation(
            verdict=verdict,
            classification="patch_build_passed_but_replay_profile_missing",
            build_result=build_payload,
            reason=reason,
            verifier_gates_passed=verifier_gates,
        )
        return _write(patch_qe_manifest_path(task_id), payload), verdict

    binary_path = str(patched_binary_path)
    harness_name = str(patched_harness_name)
    pov_replay = _replay_input(binary_path, harness_name, testcase_path, task_root(task_id))

    regression_inputs = _load_regression_inputs(metadata, runtime)
    regression_results = [
        _replay_input(binary_path, harness_name, str(candidate), task_root(task_id))
        for candidate in regression_inputs
    ]

    if pov_replay["crash_detected"]:
        verdict = "pov_failed"
        reason = "patched binary still crashes on the confirmed PoV testcase"
        patch_result_classification = "patch_build_passed_but_pov_still_reproduces"
    elif any(result["crash_detected"] for result in regression_results):
        verdict = "regression_failed"
        reason = "patched binary regressed on non-crashing seed inputs"
        patch_result_classification = "patch_build_passed_but_regression_failed"
    else:
        verdict = "approved"
        reason = "patched binary builds cleanly, blocks the PoV, and passes sampled regression inputs"
        patch_result_classification = "patch_qe_passed"
    verifier_gates = _verifier_gates_passed(
        build_payload=build_payload,
        pov_replay=pov_replay,
        regression_results=regression_results,
        verdict=verdict,
    )

    payload = {
        "task_id": task_id,
        "generated_at": now,
        "stage": "QE",
        "verdict": verdict,
        "reason": reason,
        "build_result": build_payload,
        "pov_replay": pov_replay,
        "regression_results": regression_results,
        "patch_result_classification": patch_result_classification,
        "supported_verdicts": ["build_failed", "pov_failed", "regression_failed", "approved"],
        "verifier_gates_passed": verifier_gates,
        **_patch_truth_fields(
            provenance=build_payload.get("patch_generation_provenance", "deterministic_rule"),
            semantic_strength=build_payload.get("patch_semantic_strength", "placeholder"),
            patch_llm_request_attempted=bool(build_payload.get("patch_llm_request_attempted")),
            patch_llm_real_call_verified=bool(build_payload.get("patch_llm_real_call_verified")),
        ),
        **_llm_fields_from_metadata(build_payload),
    }
    _write_semantic_validation(
        verdict=verdict,
        classification=patch_result_classification,
        build_result=build_payload,
        reason=reason,
        pov_replay=pov_replay,
        regression_results=regression_results,
        verifier_gates_passed=verifier_gates,
    )
    return _write(patch_qe_manifest_path(task_id), payload), verdict


def write_reflection(
    task_id: str,
    *,
    now: str,
    qe_verdict: str,
    priority_action: str | None,
    metadata: dict[str, Any] | None = None,
    runtime: dict[str, Any] | None = None,
    creation_payload: dict[str, Any] | None = None,
    build_payload: dict[str, Any] | None = None,
    qe_payload: dict[str, Any] | None = None,
    attempt_history: list[dict[str, Any]] | None = None,
) -> tuple[Path, str]:
    default_decision = _default_reflection_decision(
        qe_verdict=qe_verdict,
        priority_action=priority_action,
        creation_payload=creation_payload,
        attempt_history_count=len(attempt_history or []),
    )
    llm_metadata = build_non_llm_metadata(
        generated_by="patch_plane_state_machine.Reflection",
        failure_reason="llm_reflection_not_attempted",
    )
    reflection_payload = dict(default_decision)
    llm_client = LLMClient()
    if llm_client.enabled():
        try:
            response_payload, llm_metadata = llm_client.chat_with_metadata(
                _build_reflection_llm_messages(
                    task_id=task_id,
                    qe_verdict=qe_verdict,
                    priority_action=priority_action,
                    creation_payload=creation_payload,
                    build_payload=build_payload,
                    qe_payload=qe_payload,
                    attempt_history=attempt_history,
                ),
                temperature=0.1,
                max_tokens=450,
                timeout_seconds=resolve_int_setting(
                    metadata or {},
                    "LLM_PATCH_TIMEOUT_SECONDS",
                    resolve_int_setting(metadata or {}, "LLM_TIMEOUT_SECONDS", settings.llm_timeout_seconds),
                ),
                max_retries=resolve_int_setting(
                    metadata or {},
                    "LLM_PATCH_MAX_RETRIES",
                    resolve_int_setting(metadata or {}, "LLM_MAX_RETRIES", settings.llm_max_retries),
                ),
                generated_by="patch_plane_state_machine.Reflection",
            )
            parsed = _extract_json_object(extract_content(response_payload))
            reflection_payload.update(
                {
                    "primary_blocker": parsed.get("primary_blocker") or default_decision.get("primary_blocker"),
                    "invariant_family": parsed.get("invariant_family") or default_decision.get("invariant_family"),
                    "next_strategy": parsed.get("next_strategy") or default_decision.get("next_strategy"),
                    "reason": parsed.get("reason") or default_decision.get("reason"),
                    "root_cause_alignment_score": _normalize_optional_confidence(
                        parsed.get("root_cause_alignment_score")
                    )
                    if parsed.get("root_cause_alignment_score") is not None
                    else default_decision.get("root_cause_alignment_score"),
                    "llm_reflection_payload": parsed,
                }
            )
            action = _coerce_reflection_action(
                requested_action=parsed.get("reflection_action"),
                qe_verdict=qe_verdict,
                priority_action=priority_action,
                default_action=str(default_decision.get("reflection_action")),
                attempt_history_count=len(attempt_history or []),
            )
        except (LLMCallError, RuntimeError, json.JSONDecodeError) as exc:
            if isinstance(exc, LLMCallError):
                llm_metadata = exc.metadata
            else:
                llm_metadata = build_non_llm_metadata(
                    generated_by="patch_plane_state_machine.Reflection",
                    failure_reason=str(exc),
                )
            action = str(default_decision.get("reflection_action"))
            reflection_payload["reason"] = default_decision.get("reason")
            reflection_payload["llm_reflection_error"] = str(exc)
    else:
        action = str(default_decision.get("reflection_action"))
    payload = {
        "task_id": task_id,
        "generated_at": now,
        "stage": "Reflection",
        "qe_verdict": qe_verdict,
        "reflection_action": action,
        "reason": reflection_payload.get("reason"),
        "primary_blocker": reflection_payload.get("primary_blocker"),
        "invariant_family": reflection_payload.get("invariant_family"),
        "next_strategy": reflection_payload.get("next_strategy"),
        "root_cause_alignment_score": reflection_payload.get("root_cause_alignment_score"),
        "attempt_history_count": len(attempt_history or []),
        "llm_reflection_payload": reflection_payload.get("llm_reflection_payload"),
        "llm_reflection_error": reflection_payload.get("llm_reflection_error"),
        "supported_actions": ["accept", "retry", "suppress", "escalate"],
        **_patch_truth_fields(
            provenance="real_llm_patch_reflection"
            if llm_metadata.llm_real_call_verified
            else "deterministic_rule",
            semantic_strength="failure_aware_llm_reflection"
            if llm_metadata.llm_real_call_verified
            else "placeholder",
            patch_llm_request_attempted=bool(llm_metadata.llm_request_attempted),
            patch_llm_real_call_verified=bool(llm_metadata.llm_real_call_verified),
        ),
        **_llm_fields_from_metadata(llm_metadata),
    }
    return _write(patch_reflection_manifest_path(task_id), payload), action


def build_accepted_pov_record(task_id: str, qe_payload: dict[str, Any]) -> Path | None:
    if qe_payload.get("verdict") != "approved":
        return None
    testcase_path = qe_payload.get("pov_replay", {}).get("testcase_path")
    if not testcase_path:
        return None
    traced = {
        "testcase_path": testcase_path,
        "harness_name": qe_payload.get("build_result", {}).get("patched_harness_name"),
        "binary_path": qe_payload.get("build_result", {}).get("patched_binary_path"),
        "sanitizer": "address",
        "signature": qe_payload.get("pov_replay", {}).get("signature"),
        "target_mode": "source",
    }
    record = build_pov_record(traced)
    record["engine"] = "patched-libFuzzer"
    record["source_crash_signature"] = qe_payload.get("pov_replay", {}).get("signature")
    out_path = task_root(task_id) / "patch" / "accepted_pov.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return out_path

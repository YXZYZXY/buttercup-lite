from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ACCESS_KIND_PATTERN = re.compile(r"\b(READ|WRITE)\s+of\s+size\b", re.IGNORECASE)
STACK_OFFSET_PATTERN = re.compile(r"\+0x([0-9a-fA-F]+)")
ASAN_TYPE_PATTERN = re.compile(r"ERROR: AddressSanitizer: ([^\s]+)")
SUMMARY_SOURCE_PATTERN = re.compile(
    r"SUMMARY:\s+AddressSanitizer:\s+[^\s]+\s+(?P<file>[^:\n]+):(?P<line>\d+)(?::\d+)?\s+in\s+(?P<function>[^\n]+)"
)
GENERIC_CRASH_STATES = {"attempting", "unknown"}


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    current = [0] * (len(right) + 1)
    for left_index, left_char in enumerate(left, start=1):
        current[0] = left_index
        for right_index, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            current[right_index] = min(
                current[right_index - 1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + cost,
            )
        previous, current = current, previous
    return previous[len(right)]


def _similarity_ratio(left: str, right: str) -> float:
    total_length = len(left) + len(right)
    if total_length == 0:
        return 1.0
    return (total_length - _levenshtein_distance(left, right)) / float(total_length)


def _longest_common_subsequence(left_frames: list[str], right_frames: list[str]) -> int:
    left_length = len(left_frames)
    right_length = len(right_frames)
    table = [[0 for _ in range(right_length + 1)] for _ in range(left_length + 1)]
    for left_index in range(1, left_length + 1):
        for right_index in range(1, right_length + 1):
            if left_frames[left_index - 1] == right_frames[right_index - 1]:
                table[left_index][right_index] = table[left_index - 1][right_index - 1] + 1
            else:
                table[left_index][right_index] = max(
                    table[left_index - 1][right_index],
                    table[left_index][right_index - 1],
                )
    return table[left_length][right_length]


def _crash_states_are_similar(left: str, right: str, *, compare_threshold: float = 0.8) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    if "FuzzerHash=" in left or "FuzzerHash=" in right:
        return False
    left_lines = [line.strip() for line in left.splitlines() if line.strip()]
    right_lines = [line.strip() for line in right.splitlines() if line.strip()]
    if _longest_common_subsequence(left_lines, right_lines) >= 2:
        return True
    compared = 0
    similarity_sum = 0.0
    for left_line, right_line in zip(left_lines, right_lines):
        compared += 1
        similarity_sum += _similarity_ratio(left_line, right_line)
    if compared <= 0:
        return False
    return (similarity_sum / compared) > compare_threshold


def access_kind_from_excerpt(stderr_excerpt: str | None) -> str | None:
    match = ACCESS_KIND_PATTERN.search(str(stderr_excerpt or ""))
    if match is None:
        return None
    return match.group(1).strip().lower()


def _normalized_file_label(value: str | None) -> str | None:
    candidate = str(value or "").strip()
    if not candidate or candidate.startswith("??"):
        return None
    parts = [part for part in Path(candidate).parts if part not in {"/", ""}]
    if not parts:
        return candidate
    return "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]


def _frame_label(frame: dict[str, Any]) -> str | None:
    function_name = str(frame.get("function") or "").strip()
    file_name = _normalized_file_label(frame.get("file"))
    if file_name and function_name:
        return f"{file_name}::{function_name}"
    if function_name:
        return function_name
    if file_name:
        return file_name
    return None


def _source_frames(traced_crash: dict[str, Any]) -> list[dict[str, Any]]:
    path = str(traced_crash.get("symbolized_frames_path") or "").strip()
    if not path:
        return []
    payload = _read_json(Path(path))
    frames = payload.get("frames") or []
    return [
        dict(frame)
        for frame in frames
        if isinstance(frame, dict) and frame.get("is_source_frame")
    ]


def _stack_offsets_from_lines(lines: list[str], *, limit: int = 3) -> list[str]:
    offsets: list[str] = []
    for line in lines:
        match = STACK_OFFSET_PATTERN.search(str(line))
        if match is None:
            continue
        offsets.append(match.group(1).lower())
        if len(offsets) >= limit:
            break
    return offsets


def _top_stack_offsets(traced_crash: dict[str, Any], *, limit: int = 3) -> list[str]:
    return _stack_offsets_from_lines([str(line) for line in (traced_crash.get("stacktrace") or [])], limit=limit)


def _is_generic_crash_state(crash_state: str, crash_type: str) -> bool:
    normalized_state = str(crash_state or "").strip().lower()
    normalized_type = str(crash_type or "").strip().lower()
    if not normalized_state:
        return True
    if normalized_state == normalized_type:
        return True
    return normalized_state in GENERIC_CRASH_STATES


def _meaningful_crash_data(crash_state: str, crash_type: str, source_anchor: str | None) -> str:
    if not _is_generic_crash_state(crash_state, crash_type):
        return crash_state
    if source_anchor:
        return source_anchor
    return crash_type


def _build_cluster_features(
    *,
    crash_type: str,
    crash_state: str,
    access_kind: str | None,
    source_labels: list[str],
    stack_offsets: list[str],
    primary_function: str | None,
    primary_file: str | None,
    primary_line: int | None,
    harness_name: str | None,
    trace_mode: str | None,
    symbolization_status: str | None,
    signature: str | None = None,
    feature_source: str,
) -> dict[str, Any]:
    stack_anchor = " > ".join(stack_offsets[:2]) if stack_offsets else None
    source_anchor = source_labels[0] if source_labels else None
    crash_data = _meaningful_crash_data(crash_state, crash_type, source_anchor)
    inst_key_lines = source_labels[:3] or stack_offsets[:3]
    inst_key = "\n".join(inst_key_lines) if inst_key_lines else crash_type
    display_anchor = source_anchor or (f"stack:{stack_anchor}" if stack_anchor else f"sig:{str(signature or '')[:12]}")
    cluster_display = "|".join(
        part
        for part in [
            crash_type or "unknown",
            access_kind,
            display_anchor,
        ]
        if part
    )
    return {
        "crash_type": crash_type or "unknown",
        "crash_state": crash_state,
        "access_kind": access_kind,
        "source_anchor": source_anchor,
        "source_frames": source_labels[:3],
        "stack_anchor": stack_anchor,
        "stack_offsets": stack_offsets[:3],
        "stack_primary_offset": stack_offsets[0] if stack_offsets else None,
        "stack_secondary_offset": stack_offsets[1] if len(stack_offsets) > 1 else None,
        "crash_data": crash_data,
        "inst_key": inst_key,
        "display_anchor": display_anchor,
        "cluster_display": cluster_display,
        "cluster_invariant_key": "|".join(
            part
            for part in [
                crash_type or "unknown",
                access_kind,
                source_anchor or stack_anchor or (str(signature or "")[:12] if signature else None),
            ]
            if part
        ),
        "has_specific_state": not _is_generic_crash_state(crash_state, crash_type),
        "primary_function": primary_function,
        "primary_file": primary_file,
        "primary_line": primary_line,
        "harness_name": harness_name,
        "trace_mode": trace_mode,
        "symbolization_status": symbolization_status,
        "feature_source": feature_source,
    }


def derive_loose_cluster_features(traced_crash: dict[str, Any]) -> dict[str, Any]:
    crash_type = str(traced_crash.get("crash_type") or traced_crash.get("crash_state") or "unknown").strip().lower()
    crash_state = str(traced_crash.get("crash_state") or crash_type).strip()
    access_kind = access_kind_from_excerpt(traced_crash.get("stderr_excerpt"))
    source_frames = _source_frames(traced_crash)
    source_labels = [label for label in (_frame_label(frame) for frame in source_frames) if label]
    stack_offsets = _top_stack_offsets(traced_crash)
    return _build_cluster_features(
        crash_type=crash_type,
        crash_state=crash_state,
        access_kind=access_kind,
        source_labels=source_labels,
        stack_offsets=stack_offsets,
        primary_function=str(source_frames[0].get("function") or "").strip() if source_frames else None,
        primary_file=_normalized_file_label(source_frames[0].get("file")) if source_frames else None,
        primary_line=int(source_frames[0].get("line") or 0) if source_frames and source_frames[0].get("line") is not None else None,
        harness_name=str(traced_crash.get("harness_name") or "").strip() or None,
        trace_mode=str(traced_crash.get("trace_mode") or "").strip() or None,
        symbolization_status=str(traced_crash.get("symbolization_status") or "").strip() or None,
        signature=str(traced_crash.get("signature") or "").strip() or None,
        feature_source="trace_artifact",
    )


def derive_replay_loose_cluster_features(
    *,
    stderr_excerpt: str | None,
    signature: str | None,
    harness_name: str | None = None,
    trace_mode: str | None = None,
    fallback_crash_type: str | None = None,
    fallback_crash_state: str | None = None,
) -> dict[str, Any]:
    excerpt = str(stderr_excerpt or "")
    crash_type_match = ASAN_TYPE_PATTERN.search(excerpt)
    crash_type = (
        crash_type_match.group(1).strip().lower()
        if crash_type_match is not None
        else str(fallback_crash_type or "unknown").strip().lower()
    )
    summary_match = SUMMARY_SOURCE_PATTERN.search(excerpt)
    primary_function = summary_match.group("function").strip() if summary_match is not None else None
    primary_file = _normalized_file_label(summary_match.group("file")) if summary_match is not None else None
    primary_line = int(summary_match.group("line")) if summary_match is not None else None
    source_labels = [label for label in [_frame_label({"function": primary_function, "file": primary_file})] if label]
    stack_offsets = _stack_offsets_from_lines(excerpt.splitlines())
    return _build_cluster_features(
        crash_type=crash_type or "unknown",
        crash_state=str(fallback_crash_state or crash_type or "unknown").strip(),
        access_kind=access_kind_from_excerpt(excerpt),
        source_labels=source_labels,
        stack_offsets=stack_offsets,
        primary_function=primary_function,
        primary_file=primary_file,
        primary_line=primary_line,
        harness_name=str(harness_name or "").strip() or None,
        trace_mode=str(trace_mode or "").strip() or None,
        symbolization_status="replay_excerpt",
        signature=str(signature or "").strip() or None,
        feature_source="replay_excerpt",
    )


def compare_loose_cluster_features(
    left: dict[str, Any],
    right: dict[str, Any],
) -> tuple[bool, str]:
    if str(left.get("crash_type") or "") != str(right.get("crash_type") or ""):
        return False, "crash_type_mismatch"
    left_access = str(left.get("access_kind") or "")
    right_access = str(right.get("access_kind") or "")
    if left_access and right_access and left_access != right_access:
        return False, "access_kind_mismatch"
    left_source = str(left.get("source_anchor") or "")
    right_source = str(right.get("source_anchor") or "")
    if left_source and right_source and left_source == right_source:
        return True, "source_anchor_exact"
    if left_source and right_source and left_source != right_source:
        return False, "source_anchor_mismatch"
    left_offsets = [str(item).strip().lower() for item in (left.get("stack_offsets") or []) if str(item).strip()]
    right_offsets = [str(item).strip().lower() for item in (right.get("stack_offsets") or []) if str(item).strip()]
    if left_offsets and right_offsets:
        common_prefix = 0
        for left_offset, right_offset in zip(left_offsets, right_offsets):
            if left_offset != right_offset:
                break
            common_prefix += 1
        if common_prefix >= 2:
            return True, "stack_anchor_exact"
        if left_offsets[0] != right_offsets[0]:
            return False, "stack_top_frame_mismatch"
        if len(left_offsets) >= 2 and len(right_offsets) >= 2 and left_offsets[1] != right_offsets[1]:
            if not (bool(left.get("has_specific_state")) and bool(right.get("has_specific_state"))):
                return False, "stack_second_frame_mismatch"
        if common_prefix == 1 and len(left_offsets) == 1 and len(right_offsets) == 1:
            return True, "stack_top_frame_exact"
    left_stack = str(left.get("stack_anchor") or "")
    right_stack = str(right.get("stack_anchor") or "")
    if left_stack and right_stack and left_stack == right_stack:
        return True, "stack_anchor_exact"
    left_state = str(left.get("crash_data") or "")
    right_state = str(right.get("crash_data") or "")
    if bool(left.get("has_specific_state")) and bool(right.get("has_specific_state")) and _crash_states_are_similar(
        left_state,
        right_state,
    ):
        return True, "crash_data_similarity"
    left_inst = str(left.get("inst_key") or "")
    right_inst = str(right.get("inst_key") or "")
    if left_inst and right_inst and (left_source or right_source or (bool(left.get("has_specific_state")) and bool(right.get("has_specific_state")))) and _crash_states_are_similar(
        left_inst,
        right_inst,
    ):
        return True, "inst_key_similarity"
    return False, "no_similarity"


def assign_loose_cluster_key(
    features: dict[str, Any],
    existing_clusters: list[dict[str, Any]],
) -> tuple[str, str]:
    for cluster in existing_clusters:
        similar, reason = compare_loose_cluster_features(features, cluster.get("features") or {})
        if similar:
            return str(cluster.get("loose_cluster_key") or features.get("cluster_display") or "unknown_cluster"), reason
    return str(features.get("cluster_display") or "unknown_cluster"), "new_cluster"

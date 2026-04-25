from __future__ import annotations

import json
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any


STACK_OFFSET_RE = re.compile(r"\+0x([0-9a-fA-F]+)\)")
WARNING_PREFIXES = ("addr2line:",)


def load_ground_truth(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return {"vulnerabilities": payload}
    return payload


def resolve_task_local_path(raw_path: str | None, task_root: Path | None) -> str | None:
    if not raw_path:
        return raw_path
    candidate = Path(raw_path)
    if candidate.exists():
        return str(candidate)
    if task_root is None:
        return raw_path
    task_id = task_root.name
    marker = f"/data/tasks/{task_id}/"
    if marker in raw_path:
        _, suffix = raw_path.split(marker, 1)
        return str(task_root / suffix)
    return raw_path


def extract_stack_offsets(stacktrace: list[str]) -> list[str]:
    offsets: list[str] = []
    for line in stacktrace:
        match = STACK_OFFSET_RE.search(line)
        if match:
            offsets.append(f"0x{match.group(1)}")
    return offsets


@lru_cache(maxsize=2048)
def _symbolize_offset(binary_path: str, offset: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["addr2line", "-Cfipe", binary_path, offset],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return {"offset": offset, "function": None, "file": None, "line": None}

    lines = [
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip() and not line.strip().startswith(WARNING_PREFIXES)
    ]
    if not lines:
        return {"offset": offset, "function": None, "file": None, "line": None}
    line = lines[-1]
    if " at " not in line:
        return {"offset": offset, "function": line, "file": None, "line": None}
    function_name, location = line.split(" at ", 1)
    file_name = location
    line_number = None
    if ":" in location:
        file_name, _, line_text = location.rpartition(":")
        if line_text.isdigit():
            line_number = int(line_text)
    return {
        "offset": offset,
        "function": function_name.strip() or None,
        "file": Path(file_name).name if file_name else None,
        "line": line_number,
    }


def symbolize_stack(binary_path: str | None, stacktrace: list[str], task_root: Path | None = None) -> list[dict[str, Any]]:
    resolved_binary = resolve_task_local_path(binary_path, task_root)
    if not resolved_binary or not Path(resolved_binary).exists():
        return []
    symbolized: list[dict[str, Any]] = []
    for offset in extract_stack_offsets(stacktrace):
        symbolized.append(_symbolize_offset(resolved_binary, offset))
    return symbolized


def _normalize(text: str | None) -> str:
    return (text or "").strip().lower()


def attribute_traced_crash(
    traced_crash: dict[str, Any],
    ground_truth: dict[str, Any],
    *,
    task_root: Path | None = None,
) -> dict[str, Any]:
    vulnerabilities = ground_truth.get("vulnerabilities", [])
    stacktrace = traced_crash.get("stacktrace", [])
    symbolized_frames = symbolize_stack(traced_crash.get("binary_path"), stacktrace, task_root=task_root)
    observed_functions = {_normalize(frame.get("function")) for frame in symbolized_frames if frame.get("function")}
    observed_files = {_normalize(frame.get("file")) for frame in symbolized_frames if frame.get("file")}
    haystack = "\n".join(
        [
            traced_crash.get("stderr_excerpt", ""),
            traced_crash.get("crash_state", ""),
            traced_crash.get("crash_type", ""),
            traced_crash.get("harness_name", ""),
            " ".join(frame.get("function") or "" for frame in symbolized_frames),
        ]
    ).lower()

    best_match: dict[str, Any] | None = None
    best_score = -1
    for vuln in vulnerabilities:
        score = 0
        reasons: list[str] = []
        if _normalize(vuln.get("type")) == _normalize(traced_crash.get("crash_type")):
            score += 3
            reasons.append("crash_type matched")
        function_names = [_normalize(vuln.get("function"))]
        function_names.extend(_normalize(item) for item in vuln.get("expected_functions", []))
        matched_functions = [name for name in function_names if name and name in observed_functions]
        if matched_functions:
            score += 4
            reasons.append(f"function matched {matched_functions[0]}")
        vuln_file = _normalize(Path(vuln.get("file", "")).name)
        if vuln_file and vuln_file in observed_files:
            score += 2
            reasons.append(f"file matched {vuln_file}")
        if _normalize(vuln.get("expected_harness")) == _normalize(traced_crash.get("harness_name")):
            score += 1
            reasons.append("harness matched")
        for keyword in vuln.get("expected_trigger_pattern", []):
            if _normalize(keyword) and _normalize(keyword) in haystack:
                score += 1
                reasons.append(f"trigger matched {keyword}")
                break
        if score > best_score:
            best_score = score
            best_match = {
                "vuln_id": vuln.get("vuln_id"),
                "score": score,
                "reason": "; ".join(reasons) if reasons else "heuristic score only",
                "matched_file": vuln.get("file"),
                "matched_function": matched_functions[0] if matched_functions else vuln.get("function"),
                "matched_line_range": vuln.get("line_range"),
            }

    if best_match is None or best_score < 5:
        return {
            "attributed_vuln_id": None,
            "attribution_confidence": "low",
            "attribution_reason": "no reliable match",
            "matched_file": None,
            "matched_function": None,
            "matched_line_range": None,
            "symbolized_frames": symbolized_frames,
        }

    confidence = "high" if best_score >= 7 else "medium"
    return {
        "attributed_vuln_id": best_match["vuln_id"],
        "attribution_confidence": confidence,
        "attribution_reason": best_match["reason"],
        "matched_file": best_match["matched_file"],
        "matched_function": best_match["matched_function"],
        "matched_line_range": best_match["matched_line_range"],
        "symbolized_frames": symbolized_frames,
    }

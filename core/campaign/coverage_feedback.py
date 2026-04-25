from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from core.campaign.budgeting import apply_budget_multiplier
from core.campaign.budgeting import redistribute_candidate_weights
from core.campaign.coverage_plane import build_round_coverage_snapshot
from core.coverage import collect_source_coverage_artifacts
from core.queues.redis_queue import QueueNames
from core.seed_strategy import select_seed_task_mode
from core.state.task_state import TaskStateStore
from core.storage.layout import coverage_artifact_manifest_path
from core.storage.layout import coverage_manifest_path
from core.storage.layout import coverage_feedback_manifest_path
from core.storage.layout import coverage_summary_manifest_path
from core.storage.layout import scheduler_feedback_consumption_path
from core.utils.settings import resolve_int_setting, settings

COUNTERS_PATTERN = re.compile(r"Loaded\s+\d+\s+modules\s+\((\d+)\s+inline 8-bit counters\)")
PCS_PATTERN = re.compile(r"Loaded\s+\d+\s+PC tables\s+\((\d+)\s+PCs\)")
SEED_CORPUS_PATTERN = re.compile(r"seed corpus:\s+files:\s+(\d+).*?total:\s+(\d+)b", re.IGNORECASE)
COVERAGE_STALL_DELTA_THRESHOLD = 0.005
UNCOVERED_FUNCTION_SAMPLE_LIMIT = 12


def _load_json(path: Path) -> dict[str, Any]:
    if not str(path) or not path.exists() or path.is_dir():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _coverage_summary_path(task_dir: Path) -> Path:
    return task_dir / "coverage" / "summary.json"


def _build_coverage_summary_payload(current: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    per_file_summary = current.get("per_file_summary", []) or []
    per_function_summary = current.get("per_function_summary", []) or []
    lines_covered = sum(int(item.get("covered_lines", 0) or 0) for item in per_file_summary)
    lines_total = sum(int(item.get("total_lines", 0) or 0) for item in per_file_summary)
    functions_total = len(per_function_summary)
    functions_covered = sum(1 for item in per_function_summary if int(item.get("covered_lines", 0) or 0) > 0)
    return {
        "generated_at": generated_at,
        "coverage_artifacts_level": current.get("coverage_artifacts_level"),
        "coverage_artifact_manifest_path": current.get("coverage_artifact_manifest_path"),
        "lines_covered": lines_covered,
        "lines_total": lines_total,
        "line_coverage_fraction": round(lines_covered / max(lines_total, 1), 4) if lines_total else 0.0,
        "functions_covered": functions_covered,
        "functions_total": functions_total,
        "function_coverage_fraction": round(functions_covered / max(functions_total, 1), 4) if functions_total else 0.0,
    }


def _write_coverage_summary_json(task_dir: Path, current: dict[str, Any]) -> dict[str, Any]:
    payload = _build_coverage_summary_payload(current, generated_at=current.get("captured_at"))
    path = _coverage_summary_path(task_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _coverage_fraction(summary: dict[str, Any], *, covered_key: str, total_key: str, fraction_key: str) -> float | None:
    if summary.get(fraction_key) is not None:
        return float(summary.get(fraction_key) or 0.0)
    total = float(summary.get(total_key) or 0.0)
    if total <= 0:
        return None
    return float(summary.get(covered_key) or 0.0) / total


def _count_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for candidate in path.rglob("*") if candidate.is_file())


def _extract_uncovered_functions(current: dict[str, Any], *, limit: int = UNCOVERED_FUNCTION_SAMPLE_LIMIT) -> list[dict[str, Any]]:
    rows = current.get("per_function_summary", []) or []
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in rows:
        name = str(item.get("name") or item.get("function_name") or "").strip()
        if (
            not name
            or name in seen
            or name == "LLVMFuzzerTestOneInput"
            or name.startswith("<")
        ):
            continue
        total_lines = int(item.get("total_lines", 0) or 0)
        covered_lines = int(item.get("covered_lines", 0) or 0)
        if total_lines <= 0 or covered_lines > 0:
            continue
        seen.add(name)
        selected.append(
            {
                "name": name,
                "covered_lines": covered_lines,
                "total_lines": total_lines,
                "coverage_fraction": float(item.get("coverage_fraction", 0.0) or 0.0),
                "function_paths": list(item.get("function_paths") or []),
            },
        )
    selected.sort(key=lambda item: (-int(item.get("total_lines") or 0), str(item.get("name") or "")))
    return selected[:limit]


def _sample_corpus_entries(path: Path, limit: int = 5) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file():
            continue
        preview = candidate.read_bytes()[:64]
        entries.append(
            {
                "path": str(candidate),
                "name": candidate.name,
                "size": candidate.stat().st_size,
                "sha1": hashlib.sha1(preview).hexdigest(),
                "preview_hex": preview.hex(),
            },
        )
        if len(entries) >= limit:
            break
    return entries


def _recent_stagnation_window(snapshot_paths: list[Path], *, target_mode: str) -> int:
    snapshots = [_load_json(path) for path in snapshot_paths[-4:]]
    if len(snapshots) < 2:
        return 0
    window = 0
    for previous, current in zip(snapshots[:-1], snapshots[1:]):
        if target_mode == "binary":
            counter_growth = int(current.get("execution_run_count") or 0) - int(previous.get("execution_run_count") or 0)
            pc_growth = len(current.get("unique_exit_codes") or []) - len(previous.get("unique_exit_codes") or [])
            raw_growth = int(current.get("raw_crash_count") or 0) - int(previous.get("raw_crash_count") or 0)
            stalled = counter_growth <= 0 and pc_growth <= 0 and raw_growth <= 0
        else:
            counter_growth = int(current.get("inline_8bit_counters") or 0) - int(previous.get("inline_8bit_counters") or 0)
            pc_growth = int(current.get("pc_table_entries") or 0) - int(previous.get("pc_table_entries") or 0)
            new_corpus_files = int(current.get("new_corpus_files") or 0)
            stalled = counter_growth <= 0 and pc_growth <= 0 and new_corpus_files <= 0
        if stalled:
            window += 1
        else:
            window = 0
    return window


def _build_candidate_feedback(
    *,
    task,
    plan: dict[str, Any],
    current: dict[str, Any],
    counter_growth: int,
    pc_growth: int,
    corpus_growth: int,
    raw_crash_growth: int,
    new_corpus_files: int,
    stalled: bool,
    stagnation_window: int,
) -> list[dict[str, Any]]:
    target_mode = current.get("target_mode", "source")
    candidates = (
        _load_binary_candidates(task, plan)
        if target_mode == "binary"
        else _load_source_candidates(task, plan)
    )
    active_candidate = (
        task.runtime.get("selected_binary_slice_focus")
        if target_mode == "binary"
        else (task.runtime.get("selected_target") or task.runtime.get("active_harness"))
    )
    feedback_rows: list[dict[str, Any]] = []
    for candidate in candidates:
        is_active = candidate.get("candidate_id") == active_candidate
        row = {
            "candidate_id": candidate.get("candidate_id"),
            "target_kind": candidate.get("target_kind"),
            "source": candidate.get("source"),
            "is_active": is_active,
            "coverage_delta": {
                "counter_growth": counter_growth if is_active else 0,
                "pc_growth": pc_growth if is_active else 0,
                "corpus_growth": corpus_growth if is_active else 0,
                "new_corpus_files": new_corpus_files if is_active else 0,
                "raw_crash_growth": raw_crash_growth if is_active else 0,
            },
            "recent_stagnation_window": stagnation_window if is_active else max(0, stagnation_window - 1),
            "crash_discovery_signal": int(current.get("raw_crash_count") or 0) if is_active else 0,
        }
        if is_active and stalled and int(current.get("raw_crash_count") or 0) > 0:
            row["target_weight_suggestion"] = round(float(candidate.get("weight", 1.0)) * 1.75, 3)
            row["priority_suggestion"] = "high"
            row["decision_suggestion"] = "boost"
        elif is_active and stalled:
            row["target_weight_suggestion"] = round(float(candidate.get("weight", 1.0)) * 1.35, 3)
            row["priority_suggestion"] = "high"
            row["decision_suggestion"] = "reseed"
        elif is_active:
            row["target_weight_suggestion"] = round(float(candidate.get("weight", 1.0)) * 1.1, 3)
            row["priority_suggestion"] = "normal"
            row["decision_suggestion"] = "hold"
        else:
            row["target_weight_suggestion"] = round(max(0.2, float(candidate.get("weight", 1.0)) * (0.9 if not stalled else 0.6)), 3)
            row["priority_suggestion"] = "low" if stalled else candidate.get("priority", "normal")
            row["decision_suggestion"] = "deprioritize" if stalled else "standby"
        feedback_rows.append(row)
    return feedback_rows


def _parse_int(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    if match is None:
        return None
    return int(match.group(1))


def _task_root(task) -> Path:
    candidate = Path(task.task_dir)
    if candidate.exists():
        return candidate
    return Path(settings.data_root) / task.task_id


def _load_source_candidates(task, plan: dict[str, Any]) -> list[dict[str, Any]]:
    build_registry_path = task.runtime.get("build_registry_path")
    if not build_registry_path:
        return []
    registry_path = Path(build_registry_path)
    if not registry_path.exists():
        return []
    registry = _load_json(registry_path)
    selected = task.runtime.get("selected_harness") or task.runtime.get("active_harness")
    fuzzers = registry.get("fuzzers", [])
    source_only_names = [item.get("name") for item in registry.get("harnesses", []) if item.get("name")]
    candidates: list[dict[str, Any]] = []
    if fuzzers:
        for item in fuzzers:
            name = str(item.get("name") or "")
            if not name:
                continue
            candidates.append(
                {
                    "candidate_id": name,
                    "target_kind": "harness",
                    "weight": 1.25 if name == selected else 1.0,
                    "priority": "normal",
                    "runnable": True,
                    "source": "build_registry.fuzzers",
                },
            )
    for name in source_only_names:
        if name and not any(candidate["candidate_id"] == name for candidate in candidates):
            candidates.append(
                {
                    "candidate_id": name,
                    "target_kind": "harness_source_only",
                    "weight": 0.8,
                    "priority": "low",
                    "runnable": False,
                    "source": "build_registry.harnesses",
                },
            )
    if not candidates:
        fallback = selected or "default_harness"
        candidates.append(
            {
                "candidate_id": fallback,
                "target_kind": "harness",
                "weight": 1.0,
                "priority": "normal",
                "runnable": True,
                "source": "task.runtime",
            },
        )
    return candidates


def _load_binary_candidates(task, plan: dict[str, Any]) -> list[dict[str, Any]]:
    slice_path = task.runtime.get("binary_slice_manifest_path")
    if not slice_path:
        candidate = Path(task.task_dir) / "binary_slice" / "slice_manifest.json"
        slice_path = str(candidate) if candidate.exists() else None
    if not slice_path:
        default_target = (
            plan.get("binary_target_name")
            or task.metadata.get("binary_target_name")
            or task.runtime.get("active_harness")
            or "binary_target"
        )
        return [
            {
                "candidate_id": default_target,
                "target_kind": "binary_target",
                "weight": 1.0,
                "priority": "normal",
                "runnable": True,
                "source": "execution_plan",
            },
        ]

    payload = _load_json(Path(slice_path))
    selected_focus = task.runtime.get("selected_binary_slice_focus")
    candidates: list[dict[str, Any]] = []
    relevant_functions = payload.get("relevant_functions", [])
    entry_candidates = payload.get("entry_candidates", [])
    for item in (relevant_functions[:4] + entry_candidates[:2]):
        name = str(item.get("name") or "")
        if not name or any(candidate["candidate_id"] == name for candidate in candidates):
            continue
        candidates.append(
            {
                "candidate_id": name,
                "target_kind": "binary_slice_focus",
                "weight": 1.25 if name == selected_focus else 1.0,
                "priority": "normal",
                "runnable": True,
                "source": "binary_slice_manifest",
            },
        )
    if not candidates:
        default_target = (
            plan.get("binary_target_name")
            or task.metadata.get("binary_target_name")
            or task.runtime.get("active_harness")
            or "binary_target"
        )
        candidates.append(
            {
                "candidate_id": default_target,
                "target_kind": "binary_target",
                "weight": 1.0,
                "priority": "normal",
                "runnable": True,
                "source": "execution_plan",
            },
        )
    return candidates


def _choose_candidate(
    *,
    task,
    plan: dict[str, Any],
    feedback: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    stalled = bool(feedback.get("stalled"))
    current = feedback.get("current", {})
    raw_crash_count = int(current.get("raw_crash_count") or 0)
    binary_mode = task.runtime.get("target_mode") == "binary" or task.runtime.get("adapter_resolution") == "binary"
    current_selected = (
        task.runtime.get("selected_binary_slice_focus")
        if binary_mode
        else (task.runtime.get("selected_target") or task.runtime.get("active_harness"))
    )
    ordered = candidates[:]
    if stalled and len(ordered) > 1 and raw_crash_count <= 0:
        for candidate in ordered:
            if candidate["candidate_id"] != current_selected and candidate.get("runnable", True):
                return candidate, "coverage stalled without crashes; exploring alternate candidate"
    for candidate in ordered:
        if candidate["candidate_id"] == current_selected:
            if stalled and raw_crash_count > 0:
                return candidate, "coverage stalled but crashes exist; keep current target and boost exploit-oriented work"
            return candidate, "preserve current candidate under stable or unknown coverage signal"
    return ordered[0], "fallback to highest-ranked available candidate"


def collect_coverage_snapshot(task_id: str, task_store: TaskStateStore) -> tuple[Path, dict[str, Any]]:
    task = task_store.load_task(task_id)
    task_dir = _task_root(task)
    target_mode = task.runtime.get("target_mode", "source")
    if target_mode == "binary" or task.runtime.get("adapter_resolution") == "binary":
        manifest_path = Path(task.runtime.get("binary_execution_manifest_path", ""))
        binary_manifest = _load_json(manifest_path)
        run_records = binary_manifest.get("run_records", [])
        executed_bytes = sum(int(item.get("size", 0) or 0) for item in binary_manifest.get("staged_inputs", []))
        if not executed_bytes:
            executed_bytes = sum(
                Path(item.get("input_path", "")).stat().st_size
                for item in run_records
                if item.get("input_path") and Path(item.get("input_path")).exists()
            )
        unique_exit_codes = sorted({item.get("exit_code") for item in run_records if item.get("exit_code") is not None})
        stderr_signal_count = sum(1 for item in run_records if item.get("stderr_excerpt"))
        signal_category_counts = dict(binary_manifest.get("signal_category_counts") or {})
        snapshot = {
            "task_id": task_id,
            "captured_at": task_store.now(),
            "target_mode": "binary",
            "harness_name": task.runtime.get("active_harness") or task.metadata.get("binary_target_name"),
            "coverage_source": "binary_execution_manifest",
            "coverage_kind": "binary_execution_proxy",
            "binary_execution_manifest_path": str(manifest_path) if manifest_path.exists() else None,
            "execution_run_count": int(binary_manifest.get("run_count", len(run_records)) or 0),
            "execution_input_count": int(binary_manifest.get("input_count", 0) or 0),
            "executed_input_bytes": executed_bytes,
            "unique_exit_codes": unique_exit_codes,
            "stderr_signal_count": stderr_signal_count,
            "execution_signal_count": int(binary_manifest.get("execution_signal_count", 0) or 0),
            "signal_category_counts": signal_category_counts,
            "per_input_execution_summary": binary_manifest.get("per_input_execution_summary", []),
            "crash_candidate_count": int(binary_manifest.get("crash_candidate_count", 0) or 0),
            "active_corpus_files": _count_files(Path(task.layout.get("corpus_binary_active", task_dir / "corpus" / "binary_active"))),
            "new_corpus_files": 0,
            "raw_crash_count": int(binary_manifest.get("crash_candidate_count", 0) or 0),
            "selected_binary_slice_focus": task.runtime.get("selected_binary_slice_focus"),
            "slice_focus_evidence": binary_manifest.get("slice_focus_evidence", {}),
            "input_contract_evidence": binary_manifest.get("input_contract_evidence", {}),
            "coverage_probe_binary_path": task.runtime.get("resolved_imports", {}).get("existing_binary_path"),
        }
        snapshots_dir = Path(task.layout.get("coverage_snapshots", task_dir / "coverage" / "snapshots"))
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        snapshot_path = snapshots_dir / f"snapshot-{snapshot['captured_at'].replace(':', '-').replace('+', '_')}.json"
        snapshot_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        return snapshot_path, snapshot

    logs_dir = Path(task.layout.get("logs", task_dir / "logs"))
    stderr_path = logs_dir / "fuzzer.stderr.log"
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="ignore") if stderr_path.exists() else ""
    fuzz_manifest = _load_json(Path(task.runtime.get("fuzz_manifest_path", "")))
    coverage_artifacts = collect_source_coverage_artifacts(task)
    snapshot = {
        "task_id": task_id,
        "captured_at": task_store.now(),
        "target_mode": target_mode,
        "coverage_source": "libfuzzer_stderr_and_manifest",
        "coverage_kind": "source_fuzzer_progress_and_corpus_sampling",
        "harness_name": task.runtime.get("active_harness"),
        "inline_8bit_counters": _parse_int(COUNTERS_PATTERN, stderr_text),
        "pc_table_entries": _parse_int(PCS_PATTERN, stderr_text),
        "seed_corpus_files": None,
        "seed_corpus_total_bytes": None,
        "active_corpus_files": _count_files(Path(task.layout.get("corpus_active", task_dir / "corpus" / "active"))),
        "new_corpus_files": (
            len(fuzz_manifest.get("new_corpus_files", []))
            if isinstance(fuzz_manifest.get("new_corpus_files"), list)
            else int(fuzz_manifest.get("new_corpus_files", 0) or 0)
        ),
        "raw_crash_count": len(fuzz_manifest.get("raw_crashes", [])),
        "coverage_feature_count": (fuzz_manifest.get("coverage_metrics", {}) or {}).get("coverage_feature_count"),
        "coverage_pc_count": (fuzz_manifest.get("coverage_metrics", {}) or {}).get("coverage_pc_count"),
        "corpus_unit_count": (fuzz_manifest.get("coverage_metrics", {}) or {}).get("corpus_unit_count"),
        "unique_signal_count": (fuzz_manifest.get("stderr_signal_summary", {}) or {}).get("unique_signal_count", 0),
        "crash_like_signal_count": (fuzz_manifest.get("stderr_signal_summary", {}) or {}).get("crash_like_signal_count", 0),
        "per_seed_family_contribution": fuzz_manifest.get("per_seed_family_contribution", []),
        "per_target_function_contribution": fuzz_manifest.get("per_target_function_contribution", []),
        "coverage_artifacts_level": coverage_artifacts.get("coverage_artifacts_level"),
        "coverage_artifact_manifest_path": coverage_artifacts.get("coverage_artifact_manifest_path"),
        "per_function_summary": coverage_artifacts.get("per_function_summary", []),
        "per_file_summary": coverage_artifacts.get("per_file_summary", []),
        "covered_function_count": coverage_artifacts.get("covered_function_count", 0),
        "fuzz_manifest_path": task.runtime.get("fuzz_manifest_path"),
        "stderr_log_path": str(stderr_path) if stderr_path.exists() else None,
        "coverage_probe_binary_path": task.runtime.get("active_harness_path"),
        "build_registry_path": task.runtime.get("build_registry_path"),
    }
    coverage_summary = _write_coverage_summary_json(task_dir, snapshot)
    snapshot["coverage_summary"] = coverage_summary
    snapshot["coverage_summary_path"] = str(_coverage_summary_path(task_dir))
    seed_match = SEED_CORPUS_PATTERN.search(stderr_text)
    if seed_match is not None:
        snapshot["seed_corpus_files"] = int(seed_match.group(1))
        snapshot["seed_corpus_total_bytes"] = int(seed_match.group(2))

    snapshots_dir = Path(task.layout.get("coverage_snapshots", task_dir / "coverage" / "snapshots"))
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = snapshots_dir / f"snapshot-{snapshot['captured_at'].replace(':', '-').replace('+', '_')}.json"
    snapshot_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    return snapshot_path, snapshot


def _write_coverage_manifest(
    *,
    task,
    snapshot_path: Path,
    current: dict[str, Any],
    previous: dict[str, Any],
    feedback: dict[str, Any],
) -> Path:
    task_dir = _task_root(task)
    target_mode = current.get("target_mode", "source")
    corpus_dir = (
        Path(task.layout.get("corpus_binary_active", task_dir / "corpus" / "binary_active"))
        if target_mode == "binary"
        else Path(task.layout.get("corpus_active", task_dir / "corpus" / "active"))
    )
    manifest = {
        "task_id": task.task_id,
        "generated_at": current.get("captured_at"),
        "target_mode": target_mode,
        "coverage_snapshot_path": str(snapshot_path),
        "coverage_source": current.get("coverage_source"),
        "coverage_kind": current.get("coverage_kind"),
        "coverage_probe_binary_path": current.get("coverage_probe_binary_path"),
        "coverage_artifact_manifest_path": current.get("coverage_artifact_manifest_path")
        or str(coverage_artifact_manifest_path(task.task_id)),
        "build_registry_path": current.get("build_registry_path") or task.runtime.get("build_registry_path"),
        "build_matrix_manifest_path": task.runtime.get("build_matrix_manifest_path"),
        "binary_slice_manifest_path": task.runtime.get("binary_slice_manifest_path"),
        "active_target": {
            "selected_target": task.runtime.get("selected_target") or task.runtime.get("active_harness"),
            "selected_binary_slice_focus": task.runtime.get("selected_binary_slice_focus"),
            "harness_name": current.get("harness_name"),
        },
        "current_snapshot": current,
        "previous_snapshot": previous,
        "corpus_sampling": {
            "corpus_dir": str(corpus_dir),
            "sample_count": len(_sample_corpus_entries(corpus_dir)),
            "samples": _sample_corpus_entries(corpus_dir),
        },
        "feedback_summary": {
            "stalled": feedback.get("stalled"),
            "proxy_stalled": feedback.get("proxy_stalled"),
            "coverage_stalled": feedback.get("coverage_stalled"),
            "counter_growth": feedback.get("counter_growth"),
            "pc_growth": feedback.get("pc_growth"),
            "feature_growth": feedback.get("feature_growth"),
            "exact_function_growth": feedback.get("exact_function_growth"),
            "corpus_growth": feedback.get("corpus_growth"),
            "raw_crash_growth": feedback.get("raw_crash_growth"),
            "unique_signal_growth": feedback.get("unique_signal_growth"),
            "coverage_line_delta": feedback.get("coverage_line_delta"),
            "coverage_function_delta": feedback.get("coverage_function_delta"),
            "coverage_stall_threshold": feedback.get("coverage_stall_threshold"),
            "recent_stagnation_window": feedback.get("recent_stagnation_window"),
            "seed_strategy_decision": feedback.get("seed_strategy_decision"),
            "candidate_feedback": feedback.get("candidate_feedback"),
        },
    }
    output_path = coverage_manifest_path(task.task_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return output_path


def _write_coverage_summary_manifest(
    *,
    task,
    current: dict[str, Any],
    previous: dict[str, Any],
    feedback: dict[str, Any],
) -> Path:
    context_path = Path(task.runtime.get("context_package_path") or Path(task.task_dir) / "index" / "context_package.json")
    context_package = _load_json(context_path)
    build_registry = _load_json(Path(task.runtime.get("build_registry_path", "")))
    toolchain_bin = Path(settings.build_toolchain_prefix).expanduser() / "bin"
    tool_path = f"{toolchain_bin}:{os.environ.get('PATH', '')}" if toolchain_bin.exists() else None
    llvm_profdata = shutil.which("llvm-profdata", path=tool_path) if tool_path else shutil.which("llvm-profdata")
    llvm_cov = shutil.which("llvm-cov", path=tool_path) if tool_path else shutil.which("llvm-cov")
    profile_data_detected = bool(list(Path(task.task_dir).glob("**/*.profraw")))
    per_file_summary = current.get("per_file_summary", [])
    per_function_summary = current.get("per_function_summary", [])
    payload = {
        "task_id": task.task_id,
        "generated_at": current.get("captured_at"),
        "coverage_level": current.get("coverage_artifacts_level"),
        "coverage_summary_kind": (
            "exact_llvm_cov_summary"
            if current.get("coverage_artifacts_level") == "exact"
            else "partial_llvm_capable_summary"
            if current.get("coverage_artifacts_level") == "partial"
            else "fallback_stderr_corpus_and_program_model_summary"
        ),
        "llvm_tooling": {
            "llvm-profdata": llvm_profdata,
            "llvm-cov": llvm_cov,
            "profile_data_detected": profile_data_detected,
            "summary_limitation": (
                None
                if current.get("coverage_artifacts_level") == "exact"
                else "coverage summary fell back to partial artifacts or stderr/program-model evidence"
            ),
        },
        "coverage_artifacts_level": current.get("coverage_artifacts_level"),
        "coverage_artifact_manifest_path": current.get("coverage_artifact_manifest_path"),
        "per_file_summary": per_file_summary,
        "per_function_summary": per_function_summary,
        "file_function_level_summary": {
            "selected_harness": context_package.get("selected_harness") or task.runtime.get("active_harness"),
            "selected_harness_path": context_package.get("selected_harness_path") or task.runtime.get("active_harness_path"),
            "selected_target_function": context_package.get("selected_target_function"),
            "selected_target_functions": context_package.get("selected_target_functions", []),
            "candidate_harness_count": len(context_package.get("candidate_harnesses", [])),
            "build_fuzzer_count": len(build_registry.get("fuzzers", [])),
            "build_harness_count": len(build_registry.get("harnesses", [])),
        },
        "coverage_delta_summary": {
            "counter_growth": feedback.get("counter_growth"),
            "pc_growth": feedback.get("pc_growth"),
            "feature_growth": feedback.get("feature_growth"),
            "exact_function_growth": feedback.get("exact_function_growth"),
            "corpus_growth": feedback.get("corpus_growth"),
            "new_corpus_files": feedback.get("new_corpus_files"),
            "raw_crash_growth": feedback.get("raw_crash_growth"),
            "unique_signal_growth": feedback.get("unique_signal_growth"),
            "proxy_stalled": feedback.get("proxy_stalled"),
            "coverage_stalled": feedback.get("coverage_stalled"),
            "coverage_line_delta": feedback.get("coverage_line_delta"),
            "coverage_function_delta": feedback.get("coverage_function_delta"),
            "coverage_stall_threshold": feedback.get("coverage_stall_threshold"),
            "recent_stagnation_window": feedback.get("recent_stagnation_window"),
            "stalled": feedback.get("stalled"),
        },
        "coverage_round_delta": {
            "covered_function_delta": len(per_function_summary) - len(previous.get("per_function_summary", []) or []),
            "covered_file_delta": len(per_file_summary) - len(previous.get("per_file_summary", []) or []),
        },
        "downstream_attribution": {
            "per_seed_family_contribution": current.get("per_seed_family_contribution", []),
            "per_target_function_contribution": current.get("per_target_function_contribution", []),
            "candidate_feedback": feedback.get("candidate_feedback", []),
        },
        "evidence_refs": {
            "coverage_manifest_path": task.runtime.get("coverage_manifest_path"),
            "coverage_feedback_manifest_path": task.runtime.get("coverage_feedback_manifest_path"),
            "fuzz_manifest_path": current.get("fuzz_manifest_path"),
            "context_package_path": str(context_path) if context_path.exists() else task.runtime.get("context_package_path"),
            "build_registry_path": task.runtime.get("build_registry_path"),
        },
    }
    path = coverage_summary_manifest_path(task.task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    summary_json_path = _coverage_summary_path(_task_root(task))
    summary_payload = {
        **(current.get("coverage_summary") or _build_coverage_summary_payload(current, generated_at=current.get("captured_at"))),
        "coverage_line_delta": feedback.get("coverage_line_delta"),
        "coverage_function_delta": feedback.get("coverage_function_delta"),
        "coverage_stalled": feedback.get("coverage_stalled"),
        "coverage_stall_threshold": feedback.get("coverage_stall_threshold"),
    }
    summary_json_path.write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")
    return path


def analyze_coverage_feedback(task_id: str, task_store: TaskStateStore) -> tuple[Path, dict[str, Any]]:
    task = task_store.load_task(task_id)
    task_dir = _task_root(task)
    snapshots_dir = Path(task.layout.get("coverage_snapshots", task_dir / "coverage" / "snapshots"))
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    prior_snapshots = sorted(snapshots_dir.glob("snapshot-*.json"))
    previous = _load_json(prior_snapshots[-1]) if prior_snapshots else {}
    snapshot_path, current = collect_coverage_snapshot(task_id, task_store)
    plan = _load_json(Path(task.runtime.get("execution_plan_path", ""))) if task.runtime.get("execution_plan_path") else {}

    if current.get("target_mode") == "binary":
        counter_growth = int(current.get("execution_run_count") or 0) - int(previous.get("execution_run_count") or 0)
        pc_growth = len(current.get("unique_exit_codes") or []) - len(previous.get("unique_exit_codes") or [])
    else:
        counter_growth = (
            int(current["inline_8bit_counters"] or 0) - int(previous.get("inline_8bit_counters") or 0)
            if previous
            else 0
        )
        pc_growth = (
            int(current["pc_table_entries"] or 0) - int(previous.get("pc_table_entries") or 0)
            if previous
            else 0
        )
    corpus_growth = int(current["active_corpus_files"] or 0) - int(previous.get("active_corpus_files") or 0)
    raw_crash_growth = int(current.get("raw_crash_count") or 0) - int(previous.get("raw_crash_count") or 0)
    new_corpus_files = int(current["new_corpus_files"] or 0)
    feature_growth = int(current.get("coverage_feature_count") or 0) - int(previous.get("coverage_feature_count") or 0)
    exact_function_growth = len(current.get("per_function_summary") or []) - len(previous.get("per_function_summary") or [])
    unique_signal_growth = int(current.get("unique_signal_count") or 0) - int(previous.get("unique_signal_count") or 0)
    current_coverage_summary = _load_json(_coverage_summary_path(task_dir))
    previous_coverage_summary = previous.get("coverage_summary", {}) if previous else {}
    uncovered_functions = _extract_uncovered_functions(current)
    coverage_line_delta = None
    coverage_function_delta = None
    coverage_stalled = False
    reseeding_attempted = bool(task.runtime.get("coverage_feedback_reseeding_attempted") or task.runtime.get("campaign_reseeding_attempted"))
    reseeding_triggered = bool(task.runtime.get("coverage_feedback_reseeding_triggered") or task.runtime.get("campaign_reseeding_triggered"))
    reseeding_target_functions = list(
        task.runtime.get("coverage_feedback_reseed_target_functions")
        or task.runtime.get("campaign_reseed_target_functions")
        or []
    )
    reseeding_generated_seed_count = int(
        task.runtime.get("coverage_feedback_reseed_generated_seed_count")
        or task.runtime.get("campaign_reseed_generated_seed_count")
        or 0
    )
    reseeding_reason = task.runtime.get("coverage_feedback_reseed_reason") or task.runtime.get("campaign_reseed_reason")
    current_line_fraction = _coverage_fraction(
        current_coverage_summary,
        covered_key="lines_covered",
        total_key="lines_total",
        fraction_key="line_coverage_fraction",
    )
    previous_line_fraction = _coverage_fraction(
        previous_coverage_summary,
        covered_key="lines_covered",
        total_key="lines_total",
        fraction_key="line_coverage_fraction",
    )
    current_function_fraction = _coverage_fraction(
        current_coverage_summary,
        covered_key="functions_covered",
        total_key="functions_total",
        fraction_key="function_coverage_fraction",
    )
    previous_function_fraction = _coverage_fraction(
        previous_coverage_summary,
        covered_key="functions_covered",
        total_key="functions_total",
        fraction_key="function_coverage_fraction",
    )
    if None not in (
        current_line_fraction,
        previous_line_fraction,
        current_function_fraction,
        previous_function_fraction,
    ):
        coverage_line_delta = round(float(current_line_fraction) - float(previous_line_fraction), 4)
        coverage_function_delta = round(float(current_function_fraction) - float(previous_function_fraction), 4)
        coverage_stalled = (
            coverage_line_delta < COVERAGE_STALL_DELTA_THRESHOLD
            and coverage_function_delta < COVERAGE_STALL_DELTA_THRESHOLD
        )
    if current.get("target_mode") == "binary":
        # For binary execution coverage proxies, corpus file growth is often caused by seed
        # generation rather than real execution progress. Prefer execution-signal deltas.
        proxy_stalled = counter_growth <= 0 and pc_growth <= 0 and raw_crash_growth <= 0
    else:
        # For source tasks with explicit seed stages, the active corpus may grow because the
        # seed worker injected more files. Use fuzzer-observed corpus growth as the stronger
        # signal of execution progress.
        proxy_stalled = (
            counter_growth <= 0
            and pc_growth <= 0
            and feature_growth <= 0
            and exact_function_growth <= 0
            and new_corpus_files <= 0
            and unique_signal_growth <= 0
        )
    stalled = proxy_stalled or coverage_stalled
    stagnation_window = _recent_stagnation_window(prior_snapshots + [snapshot_path], target_mode=str(current.get("target_mode") or "source"))
    attempts_before = resolve_int_setting(task.metadata, "SEED_GENERATION_ATTEMPTS", settings.seed_generation_attempts)
    seed_decision = select_seed_task_mode(task)
    attempts_after = attempts_before
    action = None
    stall_reasons: list[str] = []
    if proxy_stalled:
        stall_reasons.append("coverage proxy stalled: no new counters, no new PCs, and no new corpus/signal growth")
    if coverage_stalled:
        stall_reasons.append(
            "llvm coverage stalled: "
            f"line_delta={coverage_line_delta}, function_delta={coverage_function_delta}, "
            f"threshold={COVERAGE_STALL_DELTA_THRESHOLD}"
        )
    if stalled:
        seed_decision = select_seed_task_mode(task, {"stalled": True, "current": current})
        attempts_after = apply_budget_multiplier(attempts_before, seed_decision.budget_multiplier)
        action = {
            "type": "seed_generation_boost",
            "queue_name": QueueNames.SEED,
            "seed_generation_attempts_before": attempts_before,
            "seed_generation_attempts_after": attempts_after,
            "reason": "; ".join(stall_reasons) if stall_reasons else "coverage feedback reported stall",
            "seed_task_mode": seed_decision.mode,
            "seed_strategy_reason": seed_decision.reason,
            "seed_budget_multiplier": seed_decision.budget_multiplier,
            "uncovered_function_count": len(uncovered_functions),
        }
        task_store.update_task(
            task_id,
            metadata={
                "SEED_GENERATION_ATTEMPTS": attempts_after,
                "coverage_feedback_reason": action["reason"],
                "coverage_feedback_seed_priority": "high",
                "seed_task_mode_recommended": seed_decision.mode,
                "seed_strategy_reason": seed_decision.reason,
            },
        )
        task_store.update_runtime(
            task_id,
            {
                "coverage_feedback_triggered": True,
                "coverage_feedback_action": action["type"],
                "coverage_feedback_queue_name": action["queue_name"],
                "coverage_feedback_reason": action["reason"],
                "coverage_feedback_seed_task_mode": seed_decision.mode,
                "coverage_feedback_seed_strategy_reason": seed_decision.reason,
                "coverage_feedback_seed_budget_multiplier": seed_decision.budget_multiplier,
            },
        )

    candidate_feedback = _build_candidate_feedback(
        task=task,
        plan=plan,
        current=current,
        counter_growth=counter_growth,
        pc_growth=pc_growth,
        corpus_growth=corpus_growth,
        raw_crash_growth=raw_crash_growth,
        new_corpus_files=new_corpus_files,
        stalled=stalled,
        stagnation_window=stagnation_window,
    )

    manifest = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "analysis_mode": "libfuzzer_progress_proxy",
        "current_snapshot_path": str(snapshot_path),
        "previous_snapshot_path": str(prior_snapshots[-1]) if prior_snapshots else None,
        "current": current,
        "previous": previous,
        "uncovered_functions": uncovered_functions,
        "uncovered_function_count": len(uncovered_functions),
        "proxy_stalled": proxy_stalled,
        "coverage_stalled": coverage_stalled,
        "coverage_line_delta": coverage_line_delta,
        "coverage_function_delta": coverage_function_delta,
        "coverage_stall_threshold": COVERAGE_STALL_DELTA_THRESHOLD,
        "counter_growth": counter_growth,
        "pc_growth": pc_growth,
        "feature_growth": feature_growth,
        "exact_function_growth": exact_function_growth,
        "corpus_growth": corpus_growth,
        "raw_crash_growth": raw_crash_growth,
        "new_corpus_files": new_corpus_files,
        "unique_signal_growth": unique_signal_growth,
        "recent_stagnation_window": stagnation_window,
        "stalled": stalled,
        "seed_strategy_decision": {
            "mode": seed_decision.mode,
            "reason": seed_decision.reason,
            "budget_multiplier": seed_decision.budget_multiplier,
            "priority": seed_decision.priority,
        },
        "reseeding_attempted": reseeding_attempted,
        "reseeding_triggered": reseeding_triggered,
        "reseeding_target_functions": reseeding_target_functions,
        "reseeding_generated_seed_count": reseeding_generated_seed_count,
        "reseeding_reason": reseeding_reason,
        "candidate_feedback": candidate_feedback,
        "triggered_action": action,
    }
    coverage_manifest_file = _write_coverage_manifest(
        task=task,
        snapshot_path=snapshot_path,
        current=current,
        previous=previous,
        feedback=manifest,
    )
    coverage_summary_file = _write_coverage_summary_manifest(
        task=task,
        current=current,
        previous=previous,
        feedback=manifest,
    )
    manifest_path = coverage_feedback_manifest_path(task_id)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    coverage_plane_snapshot = build_round_coverage_snapshot(task_id)
    manifest["coverage_strength"] = {
        "exact_or_partial": coverage_plane_snapshot.get("exact_or_partial"),
        "coverage_control_mode": coverage_plane_snapshot.get("coverage_control_mode"),
        "exact_available": coverage_plane_snapshot.get("exact_available"),
        "partial_degraded": coverage_plane_snapshot.get("partial_degraded"),
        "degraded_reason": coverage_plane_snapshot.get("degraded_reason"),
        "covered_function_count": coverage_plane_snapshot.get("covered_function_count"),
        "low_growth_function_count": len(coverage_plane_snapshot.get("low_growth_function_queue") or []),
        "degraded_target_count": len(coverage_plane_snapshot.get("degraded_target_queue") or []),
        "coverage_plane_snapshot_path": str(coverage_artifact_manifest_path(task_id).with_name("coverage_plane_snapshot.json")),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    task_store.update_runtime(
        task_id,
        {
            "coverage_manifest_path": str(coverage_manifest_file),
            "coverage_summary_manifest_path": str(coverage_summary_file),
            "coverage_feedback_manifest_path": str(manifest_path),
            "coverage_last_snapshot_path": str(snapshot_path),
            "coverage_feedback_ready_at": task_store.now(),
            "coverage_exact_or_partial": coverage_plane_snapshot.get("exact_or_partial"),
            "coverage_control_mode": coverage_plane_snapshot.get("coverage_control_mode"),
            "coverage_degraded_reason": coverage_plane_snapshot.get("degraded_reason"),
            "coverage_plane_snapshot_path": str(coverage_artifact_manifest_path(task_id).with_name("coverage_plane_snapshot.json")),
            "coverage_feedback_uncovered_functions": uncovered_functions,
            "coverage_feedback_uncovered_function_count": len(uncovered_functions),
            "coverage_feedback_reseeding_attempted": reseeding_attempted,
            "coverage_feedback_reseeding_triggered": reseeding_triggered,
            "coverage_feedback_reseed_target_functions": reseeding_target_functions,
            "coverage_feedback_reseed_generated_seed_count": reseeding_generated_seed_count,
            "coverage_feedback_reseed_reason": reseeding_reason,
        },
    )
    return manifest_path, manifest


def record_reseeding_feedback(
    task_id: str,
    task_store: TaskStateStore,
    *,
    attempted: bool,
    triggered: bool,
    target_functions: list[dict[str, Any]] | list[str],
    reason: str,
    generated_seed_count: int = 0,
    active_corpus_count: int | None = None,
) -> tuple[Path | None, dict[str, Any]]:
    task = task_store.load_task(task_id)
    path_str = task.runtime.get("coverage_feedback_manifest_path")
    if not path_str:
        return None, {}
    path = Path(path_str)
    payload = _load_json(path)
    if not payload:
        return path, {}
    payload["reseeding_attempted"] = attempted
    payload["reseeding_triggered"] = triggered
    payload["reseeding_target_functions"] = target_functions
    payload["reseeding_generated_seed_count"] = generated_seed_count
    payload["reseeding_active_corpus_count"] = active_corpus_count
    payload["reseeding_reason"] = reason
    payload["reseeding_recorded_at"] = task_store.now()
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    task_store.update_runtime(
        task_id,
        {
            "coverage_feedback_reseeding_attempted": attempted,
            "coverage_feedback_reseeding_triggered": triggered,
            "coverage_feedback_reseed_target_functions": target_functions,
            "coverage_feedback_reseed_generated_seed_count": generated_seed_count,
            "coverage_feedback_reseed_reason": reason,
        },
    )
    return path, payload


def consume_coverage_feedback_for_scheduler(
    *,
    task,
    plan: dict[str, Any],
    now: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    feedback_path = (
        task.runtime.get("coverage_feedback_manifest_path")
        or task.metadata.get("coverage_feedback_manifest_path")
    )
    if not feedback_path:
        return plan, None
    path = Path(feedback_path)
    if not path.exists():
        return plan, None

    feedback = _load_json(path)
    seed_decision = feedback.get("seed_strategy_decision", {})
    seed_stage = dict(plan.get("stages", {}).get("seed", {}))
    binary_seed_stage = dict(plan.get("stages", {}).get("binary_seed", {}))
    target_mode = task.runtime.get("target_mode") or plan.get("target_mode") or task.metadata.get("target_mode") or "source"
    candidates_before = (
        _load_binary_candidates(task, plan)
        if target_mode == "binary" or task.runtime.get("adapter_resolution") == "binary"
        else _load_source_candidates(task, plan)
    )
    candidate_suggestions = {item.get("candidate_id"): item for item in feedback.get("candidate_feedback", [])}
    for candidate in candidates_before:
        suggestion = candidate_suggestions.get(candidate.get("candidate_id"))
        if not suggestion:
            continue
        candidate["coverage_delta"] = suggestion.get("coverage_delta", {})
        candidate["recent_stagnation_window"] = suggestion.get("recent_stagnation_window")
        candidate["crash_discovery_signal"] = suggestion.get("crash_discovery_signal")
        candidate["weight"] = float(suggestion.get("target_weight_suggestion") or candidate.get("weight", 1.0))
        candidate["priority"] = suggestion.get("priority_suggestion") or candidate.get("priority", "normal")
        candidate["decision_suggestion"] = suggestion.get("decision_suggestion")

    before = {
        "seed_task_mode": seed_stage.get("task_mode_default")
        or binary_seed_stage.get("task_mode_default")
        or task.runtime.get("seed_task_mode_default")
        or "SEED_INIT",
        "seed_budget_multiplier": seed_stage.get("budget_multiplier")
        or binary_seed_stage.get("budget_multiplier")
        or 1.0,
        "target_priority": plan.get("target_priority", "normal"),
        "target_weight": float(plan.get("target_weight", 1.0)),
        "selected_target": plan.get("selected_target") or task.runtime.get("selected_target") or task.runtime.get("active_harness"),
        "selected_binary_slice_focus": plan.get("selected_binary_slice_focus") or task.runtime.get("selected_binary_slice_focus"),
        "suppressed": bool(plan.get("suppressed", False)),
    }
    after_mode = seed_decision.get("mode") or before["seed_task_mode"]
    after_multiplier = float(seed_decision.get("budget_multiplier") or before["seed_budget_multiplier"])
    after_priority = seed_decision.get("priority") or ("high" if after_multiplier > 1.0 else before["target_priority"])
    selected_candidate, selection_reason = _choose_candidate(
        task=task,
        plan=plan,
        feedback=feedback,
        candidates=candidates_before,
    )
    candidates_after = redistribute_candidate_weights(
        candidates_before,
        selected_candidate_id=selected_candidate.get("candidate_id"),
        budget_multiplier=after_multiplier,
        stalled=bool(feedback.get("stalled")),
    )

    if seed_stage:
        seed_stage["task_mode_default"] = after_mode
        seed_stage["budget_multiplier"] = after_multiplier
        seed_stage["priority"] = after_priority
        seed_stage["selected_target"] = selected_candidate.get("candidate_id")
        seed_stage["selection_rationale"] = selection_reason
        seed_stage["input_evidence_refs"] = [str(path)]
        plan["stages"]["seed"] = seed_stage
    if binary_seed_stage:
        binary_seed_stage["task_mode_default"] = after_mode
        binary_seed_stage["budget_multiplier"] = after_multiplier
        binary_seed_stage["priority"] = after_priority
        binary_seed_stage["selected_target"] = plan.get("binary_target_name") or task.metadata.get("binary_target_name")
        binary_seed_stage["selected_binary_slice_focus"] = selected_candidate.get("candidate_id")
        binary_seed_stage["selection_rationale"] = selection_reason
        binary_seed_stage["input_evidence_refs"] = [str(path)]
        plan["stages"]["binary_seed"] = binary_seed_stage
    fuzz_stage = dict(plan.get("stages", {}).get("fuzz", {}))
    if fuzz_stage:
        fuzz_stage["priority"] = after_priority
        fuzz_stage["selected_target"] = selected_candidate.get("candidate_id")
        fuzz_stage["weight"] = plan.get("target_weight", 1.0)
        fuzz_stage["selection_rationale"] = selection_reason
        fuzz_stage["input_evidence_refs"] = [str(path)]
        plan["stages"]["fuzz"] = fuzz_stage
    binary_execution_stage = dict(plan.get("stages", {}).get("binary_execution", {}))
    if binary_execution_stage:
        binary_execution_stage["priority"] = after_priority
        binary_execution_stage["selected_binary_slice_focus"] = selected_candidate.get("candidate_id")
        binary_execution_stage["weight"] = plan.get("target_weight", 1.0)
        binary_execution_stage["selection_rationale"] = selection_reason
        binary_execution_stage["input_evidence_refs"] = [str(path)]
        plan["stages"]["binary_execution"] = binary_execution_stage
    plan["target_priority"] = after_priority
    selected_weight = next(
        (
            float(candidate.get("weight_after", candidate.get("weight", 1.0)))
            for candidate in candidates_after
            if candidate.get("candidate_id") == selected_candidate.get("candidate_id")
        ),
        max(0.1, before["target_weight"] * after_multiplier),
    )
    plan["target_weight"] = selected_weight
    plan["selected_target"] = selected_candidate.get("candidate_id")
    if target_mode == "binary" or task.runtime.get("adapter_resolution") == "binary":
        plan["selected_binary_slice_focus"] = selected_candidate.get("candidate_id")
    plan["suppressed"] = False
    plan["scheduler_consumed_feedback"] = True

    consumption = {
        "task_id": task.task_id,
        "consumer": "scheduler",
        "consumed_at": now,
        "source_manifest_path": str(path),
        "reason": (feedback.get("triggered_action") or {}).get("reason")
        or seed_decision.get("reason")
        or "coverage feedback available",
        "before": before,
        "after": {
            "seed_task_mode": after_mode,
            "seed_budget_multiplier": after_multiplier,
            "target_priority": after_priority,
            "target_weight": plan["target_weight"],
            "selected_target": plan.get("selected_target"),
            "selected_binary_slice_focus": plan.get("selected_binary_slice_focus"),
            "suppressed": plan["suppressed"],
        },
        "candidates_before": candidates_before,
        "candidates_after": candidates_after,
        "selected_candidate": {
            "candidate_id": selected_candidate.get("candidate_id"),
            "target_kind": selected_candidate.get("target_kind"),
            "reason": selection_reason,
        },
        "scheduler_side_effects": [
            "updated execution_plan seed/binary_seed task mode",
            "updated seed budget multiplier",
            "updated target priority",
            "selected candidate after arbitration",
        ],
        "feedback_snapshot": {
            "stalled": feedback.get("stalled"),
            "counter_growth": feedback.get("counter_growth"),
            "pc_growth": feedback.get("pc_growth"),
            "feature_growth": feedback.get("feature_growth"),
            "exact_function_growth": feedback.get("exact_function_growth"),
            "corpus_growth": feedback.get("corpus_growth"),
            "raw_crash_growth": feedback.get("raw_crash_growth"),
            "unique_signal_growth": feedback.get("unique_signal_growth"),
            "recent_stagnation_window": feedback.get("recent_stagnation_window"),
        },
    }
    output_path = scheduler_feedback_consumption_path(task.task_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(consumption, indent=2), encoding="utf-8")
    consumption["scheduler_feedback_consumption_path"] = str(output_path)
    return plan, consumption

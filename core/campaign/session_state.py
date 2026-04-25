from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from core.state.task_state import TaskStateStore
from core.storage.layout import task_root


SESSION_EPHEMERAL_DIRS = (
    "logs",
    "crashes/raw",
    "crashes/raw_overflow",
    "trace/traced_crashes",
    "trace/symbolized_frames",
    "pov/confirmed",
    "coverage/raw",
    "coverage/artifacts",
    "seed/generated",
)

SESSION_EPHEMERAL_FILES = (
    "crashes/fuzz_manifest.json",
    "trace/trace_manifest.json",
    "trace/dedup_index.json",
    "trace/family_manifest.json",
    "pov/repro_manifest.json",
    "pov/family_confirmation_manifest.json",
    "coverage/coverage_artifact_manifest.json",
    "coverage/coverage_manifest.json",
    "coverage/coverage_plane_snapshot.json",
    "coverage/coverage_summary_manifest.json",
    "coverage/feedback_manifest.json",
    "coverage/summary.json",
    "seed/seed_manifest.json",
    "seed/seed_task_manifest.json",
    "runtime/llm_seed_audit_manifest.json",
    "runtime/scheduler_feedback_consumption.json",
)

SESSION_RUNTIME_RESET_FIELDS = {
    "campaign_round_failure_stage": None,
    "campaign_round_failure_reason": None,
    "campaign_round_failure_exception_type": None,
    "campaign_round_failure_at": None,
    "campaign_round_failure_attempt": None,
    "campaign_round_failure_retriable": None,
    "campaign_round_seed_attempt": 0,
    "campaign_round_seed_attempts_max": 0,
    "campaign_round_seed_attempts_used": 0,
    "campaign_round_seed_retry_count": 0,
    "seed_generated_count": 0,
    "seed_manifest_path": None,
    "seed_task_manifest_path": None,
    "binary_seed_task_manifest_path": None,
    "fuzz_started_at": None,
    "fuzz_completed_at": None,
    "fuzz_manifest_path": None,
    "fuzz_trace_enqueued": False,
    "fuzz_final_status": None,
    "fuzz_command": None,
    "raw_crash_count": 0,
    "raw_crash_count_total": 0,
    "raw_crash_count_deduped": 0,
    "raw_crash_count_sampled_for_trace": 0,
    "raw_crash_overflow_count": 0,
    "raw_crash_overflow_dir": None,
    "crash_count_live_raw": 0,
    "crash_curation_mode": None,
    "coverage_metrics": {},
    "coverage_artifacts_level": None,
    "coverage_artifact_manifest_path": None,
    "coverage_summary_path": None,
    "stderr_signal_summary": {},
    "suspicious_candidate_queue_path": None,
    "suspicious_candidate_count": 0,
    "suspicious_candidate_trace_worthy_count": 0,
    "suspicious_candidate_reason_summary": [],
    "per_seed_family_contribution": [],
    "per_target_function_contribution": [],
    "trace_started_at": None,
    "trace_completed_at": None,
    "trace_failed_at": None,
    "trace_manifest_path": None,
    "trace_dedup_index_path": None,
    "trace_family_manifest_path": None,
    "traced_crash_count": 0,
    "trace_symbolized_frames_count": 0,
    "trace_gate_decision": None,
    "trace_gate_reason": None,
    "trace_gate_candidate_count": 0,
    "trace_gate_candidate_origin_kind": None,
    "trace_admission_kind": None,
    "trace_input_count": 0,
    "suspicious_trace_candidate_count": 0,
    "repro_admission_candidate_count": 0,
    "why_not_promoted": None,
    "repro_started_at": None,
    "repro_completed_at": None,
    "repro_failed_at": None,
    "repro_manifest_path": None,
    "repro_family_manifest_path": None,
    "repro_error": None,
    "pov_path": None,
    "closure_mode": None,
    "family_confirmed_family_keys": [],
    "family_confirmed_family_count": 0,
    "family_unresolved_loose_cluster_count": 0,
    "coverage_feedback_manifest_path": None,
    "coverage_plane_snapshot_path": None,
}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _relative_file_names(path: Path, *, pattern: str = "*") -> list[str]:
    if not path.exists():
        return []
    if path.is_file():
        return [path.name]
    return sorted(str(candidate.relative_to(path)) for candidate in path.rglob(pattern) if candidate.is_file())


def _count_files(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return 1
    return sum(1 for candidate in path.rglob("*") if candidate.is_file())


def _remove_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _archive_path(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        _remove_path(dst)
    shutil.move(str(src), str(dst))


def session_root(task_id: str) -> Path:
    return task_root(task_id) / "runtime" / "sessions"


def session_dir(task_id: str, session_index: int) -> Path:
    return session_root(task_id) / f"session-{int(session_index):04d}"


def session_summary_path(task_id: str, session_index: int) -> Path:
    return session_dir(task_id, session_index) / "session_summary.json"


def prepare_continuous_session_workspace(
    task_id: str,
    *,
    session_index: int,
    task_store: TaskStateStore,
    continuity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    continuity = dict(continuity or {})
    root = task_root(task_id)
    current_session_dir = session_dir(task_id, session_index)
    current_session_dir.mkdir(parents=True, exist_ok=True)

    archived_dirs: list[str] = []
    archived_files: list[str] = []
    previous_session_index = int(session_index) - 1 if int(session_index) > 1 else 0
    previous_archive_root = None
    if previous_session_index > 0:
        previous_archive_root = session_dir(task_id, previous_session_index) / "archived_live_workspace"
        previous_archive_root.mkdir(parents=True, exist_ok=True)
        for relative in SESSION_EPHEMERAL_DIRS:
            src = root / relative
            if not src.exists():
                continue
            dst = previous_archive_root / relative
            _archive_path(src, dst)
            archived_dirs.append(relative)
        for relative in SESSION_EPHEMERAL_FILES:
            src = root / relative
            if not src.exists():
                continue
            dst = previous_archive_root / relative
            _archive_path(src, dst)
            archived_files.append(relative)

    for relative in SESSION_EPHEMERAL_DIRS:
        _remove_path(root / relative)
    for relative in SESSION_EPHEMERAL_FILES:
        _remove_path(root / relative)

    summary = {
        "task_id": task_id,
        "session_index": int(session_index),
        "started_at": task_store.now(),
        "workspace_reused": bool(continuity.get("workspace_reused")),
        "continuity_mode": continuity.get("continuity_mode") or "fresh_round_clone",
        "previous_session_index": previous_session_index or None,
        "previous_session_summary_path": continuity.get("previous_session_summary_path"),
        "selected_harness_plan": continuity.get("selected_harness"),
        "selected_target_function_plan": continuity.get("selected_target_function"),
        "last_corpus_state_reference": continuity.get("last_corpus_state_reference"),
        "last_coverage_snapshot_reference": continuity.get("last_coverage_snapshot_reference"),
        "last_stagnation_state": continuity.get("last_stagnation_state") or {},
        "archived_previous_live_workspace": {
            "archive_root": str(previous_archive_root) if previous_archive_root else None,
            "archived_dirs": archived_dirs,
            "archived_files": archived_files
        }
    }
    summary_path = session_summary_path(task_id, session_index)
    _write_json(summary_path, summary)
    task_store.update_runtime(
        task_id,
        {
            **SESSION_RUNTIME_RESET_FIELDS,
            "campaign_session_summary_path": str(summary_path),
            "campaign_previous_session_summary_path": continuity.get("previous_session_summary_path"),
            "campaign_session_continuity_mode": continuity.get("continuity_mode") or "fresh_round_clone",
            "campaign_session_workspace_reused": bool(continuity.get("workspace_reused")),
            "campaign_session_archive_root": str(previous_archive_root) if previous_archive_root else None,
            "campaign_session_workspace_prepared_at": summary["started_at"],
        },
    )
    return {**summary, "session_summary_path": str(summary_path)}


def finalize_continuous_session_workspace(
    task_id: str,
    *,
    session_index: int,
    task_store: TaskStateStore,
) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    root = Path(task.task_dir)
    summary_path = session_summary_path(task_id, session_index)
    payload = _read_json(summary_path)
    target_mode = str(task.runtime.get("target_mode") or task.metadata.get("target_mode") or "source")
    corpus_root = root / "corpus" / ("binary_active" if target_mode == "binary" else "active")
    traced_dir = root / "trace" / "traced_crashes"
    pov_dir = root / "pov" / "confirmed"
    raw_dir = root / "crashes" / "raw"

    traced_files = sorted(path.name for path in traced_dir.glob("*.json") if path.is_file())
    confirmed_pov_names = sorted(path.name for path in pov_dir.glob("*.json") if path.is_file())
    raw_crash_files = sorted(path.name for path in raw_dir.glob("*") if path.is_file())
    duration_seconds = 0.0
    started_at = task.runtime.get("fuzz_started_at") or payload.get("started_at")
    completed_at = (
        task.runtime.get("repro_completed_at")
        or task.runtime.get("trace_completed_at")
        or task.runtime.get("fuzz_completed_at")
        or task.runtime.get("repro_failed_at")
        or task.runtime.get("trace_failed_at")
        or task.runtime.get("campaign_round_failure_at")
        or task_store.now()
    )
    if started_at and completed_at:
        try:
            duration_seconds = max(
                0.0,
                (
                    __import__("datetime").datetime.fromisoformat(completed_at)
                    - __import__("datetime").datetime.fromisoformat(started_at)
                ).total_seconds(),
            )
        except ValueError:
            duration_seconds = 0.0
    payload.update(
        {
            "finished_at": task_store.now(),
            "task_status": str(task.status.value if hasattr(task.status, "value") else task.status),
            "target_mode": target_mode,
            "corpus_state_reference": str(corpus_root),
            "corpus_file_count": _count_files(corpus_root),
            "coverage_snapshot_reference": task.runtime.get("coverage_last_snapshot_path"),
            "duration_seconds": round(duration_seconds, 3),
            "raw_crash_count": len(raw_crash_files),
            "raw_crash_files": raw_crash_files,
            "traced_crash_count": len(traced_files),
            "traced_crash_files": traced_files,
            "confirmed_pov_count": len(confirmed_pov_names),
            "confirmed_pov_names": confirmed_pov_names,
            "fuzz_manifest_path": task.runtime.get("fuzz_manifest_path"),
            "trace_manifest_path": task.runtime.get("trace_manifest_path"),
            "repro_manifest_path": task.runtime.get("repro_manifest_path"),
            "coverage_feedback_manifest_path": task.runtime.get("coverage_feedback_manifest_path"),
            "coverage_artifact_manifest_path": task.runtime.get("coverage_artifact_manifest_path"),
            "coverage_summary_path": task.runtime.get("coverage_summary_path"),
            "campaign_round_failure_stage": task.runtime.get("campaign_round_failure_stage"),
            "campaign_round_failure_reason": task.runtime.get("campaign_round_failure_reason"),
        }
    )
    _write_json(summary_path, payload)
    task_store.update_runtime(
        task_id,
        {
            "campaign_session_summary_path": str(summary_path),
            "campaign_session_finalized_at": payload.get("finished_at"),
        },
    )
    return {**payload, "session_summary_path": str(summary_path)}

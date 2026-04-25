from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from apps.workers.binary_analysis.main import process_task as binary_analysis_task
from apps.workers.binary_execution.main import process_task as binary_execution_task
from apps.workers.binary_seed.main import process_task as binary_seed_task
from apps.workers.builder.main import process_task as build_task
from apps.workers.downloader.main import process_task as download_task
from apps.workers.fuzzer.main import process_task as fuzzer_task
from apps.workers.program_model.main import process_task as index_task
from apps.workers.reproducer.main import process_task as repro_task
from apps.workers.scheduler.main import process_task as schedule_task
from apps.workers.seed.main import process_task as seed_task
from apps.workers.tracer.main import process_task as trace_task
from core.analysis.pov_inventory import build_campaign_reports
from core.campaign.coverage_feedback import analyze_coverage_feedback, consume_coverage_feedback_for_scheduler
from core.models.task import AdapterType, ExecutionMode, TaskSource, TaskSpec, TaskStatus
from core.state.task_state import TaskStateStore
from core.storage.layout import execution_plan_path
from scripts.verification_common import (
    BENCHMARKS_ROOT,
    OSS_FUZZ_ROOT,
    PURE_BINARY_DONOR_TASK_ID,
    LocalQueue,
    SOURCE_DONOR_TASK_ID,
    configure_llm_from_env,
    create_task_with_layout,
    donor_task_root,
    write_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = REPO_ROOT / "data" / "tasks"
GROUND_TRUTH = REPO_ROOT / "benchmarks" / "cjson_injected" / "ground_truth.json"
SOURCE_ROOT = BENCHMARKS_ROOT / "cjson-injected"
OSS_FUZZ_PROJECT = OSS_FUZZ_ROOT / "projects" / "cjson"
LIBXML2_SOURCE_ROOT = Path("/home/buttercup2/AI/Run_data/src/libxml2")
LIBXML2_OSS_FUZZ_PROJECT = OSS_FUZZ_ROOT / "projects" / "libxml2"


def _load_json(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    candidate = Path(path)
    if not candidate.exists():
        return {}
    return json.loads(candidate.read_text(encoding="utf-8"))


def _save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _copy_if_exists(source: str | Path | None, destination: Path) -> None:
    if not source:
        return
    source_path = Path(source)
    if not source_path.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, destination)


def _count_json_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.glob("*.json") if item.is_file())


def _coverage_snapshot_count(task_root: Path) -> int:
    return _count_json_files(task_root / "coverage" / "snapshots")


def _pov_count(task_root: Path) -> int:
    return _count_json_files(task_root / "pov" / "confirmed")


def _traced_count(task_root: Path) -> int:
    return _count_json_files(task_root / "trace" / "traced_crashes")


def _consume_scheduler_feedback(task_id: str, task_store: TaskStateStore) -> dict[str, Any] | None:
    task = task_store.load_task(task_id)
    plan_path = execution_plan_path(task_id)
    plan = _load_json(plan_path)
    if not plan:
        return None
    updated_plan, consumption = consume_coverage_feedback_for_scheduler(task=task, plan=plan, now=task_store.now())
    if not consumption:
        return None
    _save_json(plan_path, updated_plan)
    task_store.update_runtime(
        task_id,
        {
            "execution_plan_path": str(plan_path),
            "scheduler_consumed_feedback": True,
            "scheduler_feedback_consumption_path": consumption["scheduler_feedback_consumption_path"],
            "scheduler_feedback_reason": consumption["reason"],
            "scheduler_feedback_before": consumption["before"],
            "scheduler_feedback_after": consumption["after"],
            "selected_target": updated_plan.get("selected_target"),
            "selected_binary_slice_focus": updated_plan.get("selected_binary_slice_focus"),
            "target_priority": updated_plan.get("target_priority"),
            "target_weight": updated_plan.get("target_weight"),
        },
    )
    return consumption


def _build_reports_for_single_task(task_id: str) -> dict[str, Any]:
    return build_campaign_reports(
        campaign_task_id=task_id,
        origin_task_ids=[task_id],
        ground_truth_path=GROUND_TRUTH,
        data_root=DATA_ROOT,
    )


def _run_source_short(task_store: TaskStateStore, queue: LocalQueue, *, label: str, backend: str) -> str:
    spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.OSSFUZZ, uri=str(SOURCE_ROOT), ref=label),
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "project": "cjson",
            "benchmark": label,
            "ground_truth_path": str(GROUND_TRUTH),
            "existing_oss_fuzz_project_path": str(OSS_FUZZ_PROJECT),
            "existing_project_yaml_path": str(OSS_FUZZ_PROJECT / "project.yaml"),
            "SEED_GENERATION_BACKEND": backend,
            "SEED_GENERATION_ATTEMPTS": 2,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": 262144,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": 12,
            "FUZZ_TIMEOUT_SECONDS": 5,
            "FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES": False,
            "ALLOW_IMPORTED_CRASH_FALLBACK": False,
            "verification_mode": "clean_real_llm" if backend == "llm" else "clean_heuristic_fallback",
            "seed_material_policy": "llm_only" if backend == "llm" else "heuristic_only",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": False if backend == "llm" else True,
            "LLM_TEMPERATURE": 0.2,
        },
    )
    _, record = create_task_with_layout(spec, status=TaskStatus.QUEUED_DOWNLOAD)

    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)

    seed_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_if_exists(task.runtime.get("seed_task_manifest_path"), Path(task.task_dir) / "seed" / "seed_task_manifest_run1.json")
    _copy_if_exists(task.runtime.get("seed_manifest_path"), Path(task.task_dir) / "seed" / "seed_manifest_run1.json")
    _copy_if_exists(Path(task.task_dir) / "index" / "context_package.json", Path(task.task_dir) / "index" / "context_package_run1.json")

    if task.status == TaskStatus.QUEUED_FUZZ:
        fuzzer_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_if_exists(task.runtime.get("fuzz_manifest_path"), Path(task.task_dir) / "crashes" / "fuzz_manifest_run1.json")
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(record.task_id, task_store, queue)

    analyze_coverage_feedback(record.task_id, task_store)
    analyze_coverage_feedback(record.task_id, task_store)
    _copy_if_exists(task_store.load_task(record.task_id).runtime.get("coverage_feedback_manifest_path"), Path(task.task_dir) / "coverage" / "feedback_manifest_run1.json")
    _consume_scheduler_feedback(record.task_id, task_store)

    seed_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_if_exists(task.runtime.get("seed_task_manifest_path"), Path(task.task_dir) / "seed" / "seed_task_manifest_run2.json")
    _copy_if_exists(task.runtime.get("seed_manifest_path"), Path(task.task_dir) / "seed" / "seed_manifest_run2.json")
    _copy_if_exists(Path(task.task_dir) / "index" / "context_package.json", Path(task.task_dir) / "index" / "context_package_run2.json")
    if task.status == TaskStatus.QUEUED_FUZZ:
        fuzzer_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_if_exists(task.runtime.get("fuzz_manifest_path"), Path(task.task_dir) / "crashes" / "fuzz_manifest_run2.json")
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(record.task_id, task_store, queue)

    analyze_coverage_feedback(record.task_id, task_store)
    _copy_if_exists(task_store.load_task(record.task_id).runtime.get("coverage_feedback_manifest_path"), Path(task.task_dir) / "coverage" / "feedback_manifest_run2.json")
    _consume_scheduler_feedback(record.task_id, task_store)
    _build_reports_for_single_task(record.task_id)
    return record.task_id


def _run_binary_short(task_store: TaskStateStore, queue: LocalQueue, *, label: str, backend: str) -> str:
    donor_root = donor_task_root(PURE_BINARY_DONOR_TASK_ID)
    binary_source = donor_root / "imports" / "binaries" / "current"
    analysis_path = donor_root / "binary"
    launcher_path = donor_root / "imports" / "launchers" / "current"
    spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.BINARY, uri=str(binary_source), ref=label),
        execution_mode=ExecutionMode.IMPORT_ASSISTED,
        metadata={
            "benchmark": label,
            "ground_truth_path": str(GROUND_TRUTH),
            "binary_target_name": "cjson_read_fuzzer",
            "binary_mode": "pure_binary",
            "binary_provenance": "pure_binary_input",
            "binary_input_contract": "file",
            "binary_input_contract_source": "manual_input_contract",
            "binary_analysis_backend": "auto",
            "existing_binary_analysis_path": str(analysis_path),
            "existing_launcher_path": str(launcher_path),
            "argv_template": [str(launcher_path), "{binary_path}", "{input_path}"],
            "SEED_GENERATION_BACKEND": backend,
            "SEED_GENERATION_ATTEMPTS": 2,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": 262144,
            "verification_mode": "clean_real_llm" if backend == "llm" else "clean_heuristic_fallback",
            "seed_material_policy": "llm_only" if backend == "llm" else "heuristic_only",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": False if backend == "llm" else True,
            "LLM_TEMPERATURE": 0.2,
        },
    )
    _, record = create_task_with_layout(spec, status=TaskStatus.READY)

    schedule_task(record.task_id, task_store, queue)
    binary_analysis_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_BINARY_SEED:
        binary_seed_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_if_exists(task.runtime.get("binary_seed_task_manifest_path"), Path(task.task_dir) / "binary_seed" / "binary_seed_task_manifest_run1.json")
    _copy_if_exists(task.runtime.get("binary_seed_manifest_path"), Path(task.task_dir) / "binary_seed" / "binary_seed_manifest_run1.json")
    _copy_if_exists(task.runtime.get("binary_slice_manifest_path"), Path(task.task_dir) / "binary_slice" / "slice_manifest_run1.json")
    if task.status == TaskStatus.QUEUED_BINARY_EXECUTION:
        binary_execution_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_if_exists(task.runtime.get("binary_execution_manifest_path"), Path(task.task_dir) / "runtime" / "binary_execution_manifest_run1.json")
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(record.task_id, task_store, queue)

    analyze_coverage_feedback(record.task_id, task_store)
    analyze_coverage_feedback(record.task_id, task_store)
    _copy_if_exists(task_store.load_task(record.task_id).runtime.get("coverage_feedback_manifest_path"), Path(task.task_dir) / "coverage" / "feedback_manifest_run1.json")
    _consume_scheduler_feedback(record.task_id, task_store)

    task = task_store.load_task(record.task_id)
    if task.status in {
        TaskStatus.BINARY_EXECUTED,
        TaskStatus.BINARY_CRASH_CANDIDATE_FOUND,
        TaskStatus.TRACED,
        TaskStatus.POV_CONFIRMED,
    }:
        task_store.update_status(
            record.task_id,
            TaskStatus.QUEUED_BINARY_SEED,
            runtime_patch={"binary_reseed_requested_at": task_store.now()},
        )
    binary_seed_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_if_exists(task.runtime.get("binary_seed_task_manifest_path"), Path(task.task_dir) / "binary_seed" / "binary_seed_task_manifest_run2.json")
    _copy_if_exists(task.runtime.get("binary_seed_manifest_path"), Path(task.task_dir) / "binary_seed" / "binary_seed_manifest_run2.json")
    _copy_if_exists(task.runtime.get("binary_slice_manifest_path"), Path(task.task_dir) / "binary_slice" / "slice_manifest_run2.json")
    if task.status == TaskStatus.QUEUED_BINARY_EXECUTION:
        binary_execution_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    _copy_if_exists(task.runtime.get("binary_execution_manifest_path"), Path(task.task_dir) / "runtime" / "binary_execution_manifest_run2.json")
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(record.task_id, task_store, queue)

    analyze_coverage_feedback(record.task_id, task_store)
    _copy_if_exists(task_store.load_task(record.task_id).runtime.get("coverage_feedback_manifest_path"), Path(task.task_dir) / "coverage" / "feedback_manifest_run2.json")
    _consume_scheduler_feedback(record.task_id, task_store)
    _build_reports_for_single_task(record.task_id)
    return record.task_id


def _run_libxml2_smoke(task_store: TaskStateStore, queue: LocalQueue) -> str:
    spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.OSSFUZZ, uri=str(LIBXML2_SOURCE_ROOT), ref="libxml2_context_smoke"),
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "project": "libxml2",
            "benchmark": "libxml2_context_smoke",
            "selected_target": "reader",
            "existing_oss_fuzz_project_path": str(LIBXML2_OSS_FUZZ_PROJECT),
            "existing_project_yaml_path": str(LIBXML2_OSS_FUZZ_PROJECT / "project.yaml"),
            "SEED_GENERATION_BACKEND": "heuristic_fallback",
            "SEED_GENERATION_ATTEMPTS": 1,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 15,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": 6,
            "FUZZ_TIMEOUT_SECONDS": 4,
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
        },
    )
    _, record = create_task_with_layout(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_SEED:
        seed_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_FUZZ:
        fuzzer_task(record.task_id, task_store, queue)
    return record.task_id


def _source_metrics(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    task_dir = Path(task.task_dir)
    seed_manifest = _load_json(task.runtime.get("seed_manifest_path"))
    fuzz_manifest = _load_json(task.runtime.get("fuzz_manifest_path"))
    run1 = _load_json(task_dir / "seed" / "seed_task_manifest_run1.json")
    run2 = _load_json(task_dir / "seed" / "seed_task_manifest_run2.json")
    coverage_feedback = _load_json(task.runtime.get("coverage_feedback_manifest_path"))
    scheduler_feedback = _load_json(task.runtime.get("scheduler_feedback_consumption_path"))
    return {
        "task_id": task_id,
        "status": task.status.value,
        "build_matrix_manifest_path": task.runtime.get("build_matrix_manifest_path"),
        "context_package_path": seed_manifest.get("context_package_path"),
        "run1_mode": run1.get("seed_mode"),
        "run2_mode": run2.get("seed_mode"),
        "generated_seed_count": seed_manifest.get("generated_seed_count", 0),
        "llm_real_call_verified": seed_manifest.get("llm_real_call_verified"),
        "seed_provenance": seed_manifest.get("seed_provenance"),
        "fuzz_started": bool(task.runtime.get("fuzz_started_at")),
        "fuzz_completed": bool(task.runtime.get("fuzz_completed_at")),
        "corpus_growth_count": len(fuzz_manifest.get("new_corpus_files", []) or []),
        "raw_crash_count": len(fuzz_manifest.get("raw_crashes", []) or []),
        "traced_crash_count": _traced_count(task_dir),
        "repro_count": 1 if task.runtime.get("repro_manifest_path") else 0,
        "pov_count": _pov_count(task_dir),
        "coverage_snapshot_count": _coverage_snapshot_count(task_dir),
        "scheduler_feedback_triggered": bool(task.runtime.get("scheduler_feedback_consumption_path")),
        "target_weight_before": (scheduler_feedback.get("before") or {}).get("target_weight"),
        "target_weight_after": (scheduler_feedback.get("after") or {}).get("target_weight"),
        "selected_target_before": (scheduler_feedback.get("before") or {}).get("selected_target"),
        "selected_target_after": (scheduler_feedback.get("after") or {}).get("selected_target"),
        "coverage_feedback_path": task.runtime.get("coverage_feedback_manifest_path"),
        "scheduler_feedback_path": task.runtime.get("scheduler_feedback_consumption_path"),
        "candidate_feedback": coverage_feedback.get("candidate_feedback", []),
        "pov_inventory_path": str(task_dir / "reports" / "pov_inventory.json"),
        "vuln_coverage_path": str(task_dir / "reports" / "vuln_coverage.json"),
    }


def _binary_metrics(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    task_dir = Path(task.task_dir)
    seed_manifest = _load_json(task.runtime.get("binary_seed_manifest_path"))
    exec_manifest = _load_json(task.runtime.get("binary_execution_manifest_path"))
    trace_manifest = _load_json(task.runtime.get("trace_manifest_path"))
    contamination = _load_json(task.runtime.get("binary_contamination_report_path"))
    run1 = _load_json(task_dir / "binary_seed" / "binary_seed_task_manifest_run1.json")
    run2 = _load_json(task_dir / "binary_seed" / "binary_seed_task_manifest_run2.json")
    scheduler_feedback = _load_json(task.runtime.get("scheduler_feedback_consumption_path"))
    return {
        "task_id": task_id,
        "status": task.status.value,
        "run1_mode": run1.get("seed_mode"),
        "run2_mode": run2.get("seed_mode"),
        "generated_seed_count": seed_manifest.get("generated_seed_count", 0),
        "llm_real_call_verified": seed_manifest.get("llm_real_call_verified"),
        "binary_seed_provenance": seed_manifest.get("binary_seed_provenance"),
        "execution_started": bool(task.runtime.get("binary_execution_started_at")),
        "execution_completed": bool(task.runtime.get("binary_execution_completed_at")),
        "run_count": exec_manifest.get("run_count", 0),
        "execution_signal_count": exec_manifest.get("execution_signal_count", 0),
        "signal_category_counts": exec_manifest.get("signal_category_counts", {}),
        "binary_crash_candidate_count": exec_manifest.get("crash_candidate_count", 0),
        "traced_crash_count": _traced_count(task_dir),
        "repro_count": 1 if task.runtime.get("repro_manifest_path") else 0,
        "slice_focus_before": (scheduler_feedback.get("before") or {}).get("selected_binary_slice_focus"),
        "slice_focus_after": (scheduler_feedback.get("after") or {}).get("selected_binary_slice_focus"),
        "input_contract_evidence": exec_manifest.get("input_contract_evidence", {}),
        "trace_replay_attempts": trace_manifest.get("replay_attempts", []),
        "coverage_snapshot_count": _coverage_snapshot_count(task_dir),
        "scheduler_feedback_triggered": bool(task.runtime.get("scheduler_feedback_consumption_path")),
        "binary_signal_promotion_analysis_path": task.runtime.get("binary_signal_promotion_analysis_path"),
        "contract_confidence_manifest_path": task.runtime.get("contract_confidence_manifest_path"),
        "contamination_summary": {
            "pure_binary_eligible": contamination.get("pure_binary_eligible"),
            "source_context_used": contamination.get("source_context_used"),
            "source_harness_used": contamination.get("source_harness_used"),
            "source_seed_imported_count": contamination.get("source_seed_imported_count"),
            "source_dict_used": contamination.get("source_dict_used"),
            "source_options_used": contamination.get("source_options_used"),
            "source_program_model_used": contamination.get("source_program_model_used"),
        },
        "coverage_feedback_path": task.runtime.get("coverage_feedback_manifest_path"),
        "scheduler_feedback_path": task.runtime.get("scheduler_feedback_consumption_path"),
        "binary_execution_manifest_path": task.runtime.get("binary_execution_manifest_path"),
        "trace_manifest_path": task.runtime.get("trace_manifest_path"),
    }


def _libxml2_metrics(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    task_dir = Path(task.task_dir)
    return {
        "task_id": task_id,
        "status": task.status.value,
        "build_matrix_manifest_path": task.runtime.get("build_matrix_manifest_path"),
        "seed_manifest_path": task.runtime.get("seed_manifest_path"),
        "fuzz_manifest_path": task.runtime.get("fuzz_manifest_path"),
        "context_package_path": str(task_dir / "index" / "context_package.json"),
    }


def main() -> int:
    configure_llm_from_env()
    task_store = TaskStateStore()
    queue = LocalQueue()

    source_real_id = _run_source_short(task_store, queue, label="source_plane_strengthening_real_llm_short", backend="llm")
    source_fallback_id = _run_source_short(
        task_store,
        queue,
        label="source_plane_strengthening_fallback_short",
        backend="heuristic_fallback",
    )
    binary_real_id = _run_binary_short(task_store, queue, label="pure_binary_plane_strengthening_real_llm_short", backend="llm")
    binary_fallback_id = _run_binary_short(
        task_store,
        queue,
        label="pure_binary_plane_strengthening_fallback_short",
        backend="heuristic_fallback",
    )
    libxml2_smoke_id = _run_libxml2_smoke(task_store, queue)

    payload = {
        "source_real": _source_metrics(source_real_id, task_store),
        "source_fallback": _source_metrics(source_fallback_id, task_store),
        "binary_real": _binary_metrics(binary_real_id, task_store),
        "binary_fallback": _binary_metrics(binary_fallback_id, task_store),
        "libxml2_smoke": _libxml2_metrics(libxml2_smoke_id, task_store),
    }
    write_report("plane_strengthening_summary.json", payload)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
from core.campaign.coverage_feedback import analyze_coverage_feedback, consume_coverage_feedback_for_scheduler
from core.models.task import AdapterType, ExecutionMode, TaskSource, TaskSpec, TaskStatus
from core.state.task_state import TaskStateStore
from core.storage.layout import execution_plan_path
from scripts.run_plane_strengthening_short_validations import (
    _binary_metrics,
    _run_binary_short,
    _run_source_short,
    _source_metrics,
)
from scripts.verification_common import (
    BENCHMARKS_ROOT,
    OSS_FUZZ_ROOT,
    LocalQueue,
    configure_llm_from_env,
    create_task_with_layout,
    write_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
INIH_SOURCE_ROOT = BENCHMARKS_ROOT / "inih-injected"
INIH_OSS_FUZZ_PROJECT = OSS_FUZZ_ROOT / "projects" / "inih"


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
    if source_path.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)


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
            "target_priority": updated_plan.get("target_priority"),
            "target_weight": updated_plan.get("target_weight"),
        },
    )
    return consumption


def _advance_trace_repro(task_id: str, task_store: TaskStateStore, queue: LocalQueue) -> None:
    task = task_store.load_task(task_id)
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(task_id, task_store, queue)
    task = task_store.load_task(task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(task_id, task_store, queue)


def _run_inih_campaign(task_store: TaskStateStore, queue: LocalQueue, *, label: str, backend: str) -> str:
    spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.OSSFUZZ, uri=str(INIH_SOURCE_ROOT), ref=label),
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "project": "inih",
            "benchmark": label,
            "selected_target": "inihfuzz",
            "existing_oss_fuzz_project_path": str(INIH_OSS_FUZZ_PROJECT),
            "existing_project_yaml_path": str(INIH_OSS_FUZZ_PROJECT / "project.yaml"),
            "SEED_GENERATION_BACKEND": backend,
            "SEED_GENERATION_ATTEMPTS": 2,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": 512,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": 16,
            "FUZZ_TIMEOUT_SECONDS": 5,
            "FUZZ_MAX_LEN": 512,
            "FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES": False,
            "ALLOW_IMPORTED_CRASH_FALLBACK": False,
            "verification_mode": "clean_real_llm" if backend == "llm" else "clean_heuristic_fallback",
            "seed_material_policy": "llm_only" if backend == "llm" else "heuristic_only",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": False if backend == "llm" else True,
            "LLM_TEMPERATURE": 0.25,
        },
    )
    _, record = create_task_with_layout(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)

    for round_index in range(1, 3):
        seed_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        task_dir = Path(task.task_dir)
        _copy_if_exists(task.runtime.get("seed_task_manifest_path"), task_dir / "seed" / f"seed_task_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_manifest_path"), task_dir / "seed" / f"seed_manifest_run{round_index}.json")
        _copy_if_exists(task_dir / "index" / "context_package.json", task_dir / "index" / f"context_package_run{round_index}.json")
        if task.status == TaskStatus.QUEUED_FUZZ:
            fuzzer_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        _copy_if_exists(task.runtime.get("fuzz_manifest_path"), Path(task.task_dir) / "crashes" / f"fuzz_manifest_run{round_index}.json")
        _advance_trace_repro(record.task_id, task_store, queue)
        analyze_coverage_feedback(record.task_id, task_store)
        task = task_store.load_task(record.task_id)
        _copy_if_exists(task.runtime.get("coverage_feedback_manifest_path"), Path(task.task_dir) / "coverage" / f"feedback_manifest_run{round_index}.json")
        _consume_scheduler_feedback(record.task_id, task_store)

        task = task_store.load_task(record.task_id)
        next_mode = "VULN_DISCOVERY" if int(task.runtime.get("raw_crash_count") or 0) > 0 else "SEED_EXPLORE"
        task_store.update_runtime(
            record.task_id,
            {
                "seed_task_mode_override": next_mode,
                "targeted_reseed_reason": (
                    "live raw crash exists; switch to exploit-oriented seed family"
                    if next_mode == "VULN_DISCOVERY"
                    else "no live raw crash yet; switch to parser exploration seed family"
                ),
            },
        )
    return record.task_id


def _inih_metrics(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    task_dir = Path(task.task_dir)
    fuzz1 = _load_json(task_dir / "crashes" / "fuzz_manifest_run1.json")
    fuzz2 = _load_json(task_dir / "crashes" / "fuzz_manifest_run2.json")
    seed1 = _load_json(task_dir / "seed" / "seed_task_manifest_run1.json")
    seed2 = _load_json(task_dir / "seed" / "seed_task_manifest_run2.json")
    trace_manifest = _load_json(task.runtime.get("trace_manifest_path"))
    repro_manifest = _load_json(task.runtime.get("repro_manifest_path"))
    return {
        "task_id": task_id,
        "status": task.status.value,
        "build_matrix_manifest_path": task.runtime.get("build_matrix_manifest_path"),
        "context_package_path": str(task_dir / "index" / "context_package.json"),
        "selected_harness": task.runtime.get("selected_harness"),
        "selected_target_function": task.runtime.get("selected_target_function"),
        "selected_target_functions": task.runtime.get("selected_target_functions"),
        "run1_mode": seed1.get("seed_mode"),
        "run2_mode": seed2.get("seed_mode"),
        "run1_raw_crashes": len(fuzz1.get("raw_crashes", []) or []),
        "run2_raw_crashes": len(fuzz2.get("raw_crashes", []) or []),
        "run1_unique_signal_count": (fuzz1.get("stderr_signal_summary", {}) or {}).get("unique_signal_count"),
        "run2_unique_signal_count": (fuzz2.get("stderr_signal_summary", {}) or {}).get("unique_signal_count"),
        "run1_corpus_growth": len(fuzz1.get("new_corpus_files", []) or []),
        "run2_corpus_growth": len(fuzz2.get("new_corpus_files", []) or []),
        "trace_manifest_path": task.runtime.get("trace_manifest_path"),
        "trace_status": trace_manifest.get("status"),
        "trace_gate_reason": task.runtime.get("trace_gate_reason"),
        "repro_manifest_path": task.runtime.get("repro_manifest_path"),
        "repro_status": repro_manifest.get("status"),
        "closure_mode": task.runtime.get("closure_mode"),
        "coverage_feedback_manifest_path": task.runtime.get("coverage_feedback_manifest_path"),
        "scheduler_feedback_consumption_path": task.runtime.get("scheduler_feedback_consumption_path"),
    }


def main() -> int:
    configure_llm_from_env()
    task_store = TaskStateStore()
    queue = LocalQueue()

    inih_real_id = _run_inih_campaign(task_store, queue, label="inih_discovery_real_llm_short", backend="llm")
    inih_fallback_id = _run_inih_campaign(task_store, queue, label="inih_discovery_fallback_short", backend="heuristic_fallback")
    cjson_real_id = _run_source_short(task_store, queue, label="cjson_tracer_build_real_llm_short", backend="llm")
    cjson_fallback_id = _run_source_short(task_store, queue, label="cjson_tracer_build_fallback_short", backend="heuristic_fallback")
    binary_real_id = _run_binary_short(task_store, queue, label="pure_binary_semantic_signal_real_llm_short", backend="llm")
    binary_fallback_id = _run_binary_short(task_store, queue, label="pure_binary_semantic_signal_fallback_short", backend="heuristic_fallback")

    payload = {
        "inih_real": _inih_metrics(inih_real_id, task_store),
        "inih_fallback": _inih_metrics(inih_fallback_id, task_store),
        "cjson_real": _source_metrics(cjson_real_id, task_store),
        "cjson_fallback": _source_metrics(cjson_fallback_id, task_store),
        "binary_real": _binary_metrics(binary_real_id, task_store),
        "binary_fallback": _binary_metrics(binary_fallback_id, task_store),
    }
    write_report("inih_discovery_closure_summary.json", payload)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

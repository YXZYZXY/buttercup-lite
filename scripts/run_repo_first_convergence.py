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
from scripts.run_plane_strengthening_short_validations import _binary_metrics, _run_binary_short
from scripts.verification_common import LocalQueue, configure_llm_from_env, donor_task_root, write_report

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = REPO_ROOT / "data" / "tasks"
GROUND_TRUTH = REPO_ROOT / "benchmarks" / "cjson_injected" / "ground_truth.json"


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


def _run_source_repo_first(
    task_store: TaskStateStore,
    queue: LocalQueue,
    *,
    label: str,
    repo_url: str,
    git_ref: str | None,
    fuzz_seconds: int,
    max_len: int,
) -> str:
    spec = TaskSpec(
        repo_url=repo_url,
        git_ref=git_ref,
        source_type="git_repo",
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "run_label": label,
            "SEED_GENERATION_BACKEND": "heuristic_fallback",
            "SEED_GENERATION_ATTEMPTS": 2,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": max_len,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": fuzz_seconds,
            "FUZZ_TIMEOUT_SECONDS": 5,
            "FUZZ_MAX_LEN": max_len,
            "FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES": False,
            "ALLOW_IMPORTED_CRASH_FALLBACK": False,
            "verification_mode": "repo_first_auto_resolution_short",
            "seed_material_policy": "clean_generated_only",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": True,
        },
    )
    record = task_store.create_task(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)

    for round_index in range(1, 3):
        task = task_store.load_task(record.task_id)
        if task.status in {
            TaskStatus.INDEXED,
            TaskStatus.BUILT,
            TaskStatus.SEEDED,
            TaskStatus.FUZZ_FAILED,
            TaskStatus.TRACED,
            TaskStatus.POV_CONFIRMED,
        }:
            task_store.update_status(
                record.task_id,
                TaskStatus.QUEUED_SEED,
                runtime_patch={"repo_first_reseed_round": round_index, "reseed_requested_at": task_store.now()},
            )
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
        if task.status == TaskStatus.QUEUED_TRACE:
            trace_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        if task.status == TaskStatus.QUEUED_REPRO:
            repro_task(record.task_id, task_store, queue)
        analyze_coverage_feedback(record.task_id, task_store)
        _copy_if_exists(
            task_store.load_task(record.task_id).runtime.get("coverage_feedback_manifest_path"),
            Path(task.task_dir) / "coverage" / f"feedback_manifest_run{round_index}.json",
        )
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

    if GROUND_TRUTH.exists():
        try:
            build_campaign_reports(
                campaign_task_id=record.task_id,
                origin_task_ids=[record.task_id],
                ground_truth_path=GROUND_TRUTH,
                data_root=DATA_ROOT,
            )
        except Exception:
            pass
    return record.task_id


def _source_repo_first_metrics(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    task_dir = Path(task.task_dir)
    seed1 = _load_json(task_dir / "seed" / "seed_task_manifest_run1.json")
    seed2 = _load_json(task_dir / "seed" / "seed_task_manifest_run2.json")
    fuzz1 = _load_json(task_dir / "crashes" / "fuzz_manifest_run1.json")
    fuzz2 = _load_json(task_dir / "crashes" / "fuzz_manifest_run2.json")
    scheduler_feedback = _load_json(task.runtime.get("scheduler_feedback_consumption_path"))
    return {
        "task_id": task_id,
        "status": task.status.value,
        "repo_url": task.metadata.get("repo_url"),
        "project": task.metadata.get("project"),
        "source_task_normalization_manifest_path": task.runtime.get("source_task_normalization_manifest_path"),
        "source_resolution_manifest_path": task.runtime.get("source_resolution_manifest_path"),
        "workspace_manifest_path": task.runtime.get("workspace_manifest_path"),
        "task_meta_path": task.runtime.get("task_meta_path"),
        "scheduler_fanout_manifest_path": task.runtime.get("scheduler_fanout_manifest_path"),
        "build_matrix_manifest_path": task.runtime.get("build_matrix_manifest_path"),
        "program_model_backend_manifest_path": task.runtime.get("program_model_backend_manifest_path"),
        "program_model_query_manifest_path": task.runtime.get("program_model_query_manifest_path"),
        "context_package_path": task.runtime.get("context_package_path") or str(task_dir / "index" / "context_package.json"),
        "seed_init_chain_manifest_path": task.runtime.get("seed_init_chain_manifest_path"),
        "seed_run1_mode": seed1.get("seed_mode"),
        "seed_run2_mode": seed2.get("seed_mode"),
        "selected_harness": task.runtime.get("selected_harness"),
        "selected_target_function": task.runtime.get("selected_target_function"),
        "raw_crash_count_run1": len(fuzz1.get("raw_crashes", []) or []),
        "raw_crash_count_run2": len(fuzz2.get("raw_crashes", []) or []),
        "trace_manifest_path": task.runtime.get("trace_manifest_path"),
        "repro_manifest_path": task.runtime.get("repro_manifest_path"),
        "closure_mode": task.runtime.get("closure_mode"),
        "coverage_manifest_path": task.runtime.get("coverage_manifest_path"),
        "coverage_summary_manifest_path": task.runtime.get("coverage_summary_manifest_path"),
        "scheduler_feedback_consumption_path": task.runtime.get("scheduler_feedback_consumption_path"),
        "scheduler_selected_target_before": (scheduler_feedback.get("before") or {}).get("selected_target"),
        "scheduler_selected_target_after": (scheduler_feedback.get("after") or {}).get("selected_target"),
        "scheduler_weight_before": (scheduler_feedback.get("before") or {}).get("target_weight"),
        "scheduler_weight_after": (scheduler_feedback.get("after") or {}).get("target_weight"),
    }


def main() -> int:
    configure_llm_from_env()
    task_store = TaskStateStore()
    queue = LocalQueue()

    cjson_id = _run_source_repo_first(
        task_store,
        queue,
        label="cjson_repo_first_auto_resolution",
        repo_url="https://github.com/baiyujun/cjson.git",
        git_ref="fix/buttercup-build",
        fuzz_seconds=12,
        max_len=262144,
    )
    inih_id = _run_source_repo_first(
        task_store,
        queue,
        label="inih_repo_first_auto_resolution",
        repo_url="https://github.com/Misat0N/inih.git",
        git_ref="main",
        fuzz_seconds=16,
        max_len=512,
    )
    binary_real_id = _run_binary_short(task_store, queue, label="repo_first_regression_pure_binary_real_llm", backend="llm")
    binary_fallback_id = _run_binary_short(
        task_store,
        queue,
        label="repo_first_regression_pure_binary_fallback",
        backend="heuristic_fallback",
    )

    payload = {
        "cjson_repo_first": _source_repo_first_metrics(cjson_id, task_store),
        "inih_repo_first": _source_repo_first_metrics(inih_id, task_store),
        "binary_real": _binary_metrics(binary_real_id, task_store),
        "binary_fallback": _binary_metrics(binary_fallback_id, task_store),
    }
    write_report("repo_first_convergence_summary.json", payload)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apps.workers.binary_analysis.main import process_task as binary_analysis_task
from apps.workers.binary_execution.main import process_task as binary_execution_task
from apps.workers.binary_seed.main import process_task as binary_seed_task
from apps.workers.builder.main import process_task as build_task
from apps.workers.downloader.main import process_task as download_task
from apps.workers.fuzzer.main import process_task as fuzzer_task
from apps.workers.patch.main import process_task as patch_task
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
    SOURCE_DONOR_TASK_ID,
    LocalQueue,
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


def _count_json_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.glob("*.json") if item.is_file())


def _count_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.rglob("*") if item.is_file())


def _pov_count(task_root: Path) -> int:
    return _count_json_files(task_root / "pov" / "confirmed")


def _traced_count(task_root: Path) -> int:
    return _count_json_files(task_root / "trace" / "traced_crashes")


def _coverage_snapshot_count(task_root: Path) -> int:
    return _count_json_files(task_root / "coverage" / "snapshots")


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
    donor_root = donor_task_root(SOURCE_DONOR_TASK_ID)
    spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.OSSFUZZ, uri=str(SOURCE_ROOT), ref=label),
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "project": "cjson",
            "benchmark": label,
            "ground_truth_path": str(GROUND_TRUTH),
            "existing_build_out_path": str(donor_root / "build" / "out"),
            "existing_harness_dir": str(SOURCE_ROOT / "fuzzing"),
            "existing_oss_fuzz_project_path": str(OSS_FUZZ_PROJECT),
            "existing_project_yaml_path": str(OSS_FUZZ_PROJECT / "project.yaml"),
            "SEED_GENERATION_BACKEND": backend,
            "SEED_GENERATION_ATTEMPTS": 1,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": 262144,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": 15,
            "FUZZ_TIMEOUT_SECONDS": 5,
            "FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES": False,
            "ALLOW_IMPORTED_CRASH_FALLBACK": False,
            "verification_mode": "clean_real_llm" if backend == "llm" else "clean_heuristic_fallback",
            "seed_material_policy": "llm_only" if backend == "llm" else "heuristic_only",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": False if backend == "llm" else True,
        },
    )
    _, record = create_task_with_layout(spec, status=TaskStatus.QUEUED_DOWNLOAD)

    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)
    seed_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_FUZZ:
        fuzzer_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(record.task_id, task_store, queue)

    analyze_coverage_feedback(record.task_id, task_store)
    analyze_coverage_feedback(record.task_id, task_store)
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
            "SEED_GENERATION_ATTEMPTS": 1,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": 262144,
            "verification_mode": "clean_real_llm" if backend == "llm" else "clean_heuristic_fallback",
            "seed_material_policy": "llm_only" if backend == "llm" else "heuristic_only",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": False if backend == "llm" else True,
        },
    )
    _, record = create_task_with_layout(spec, status=TaskStatus.READY)

    schedule_task(record.task_id, task_store, queue)
    binary_analysis_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_BINARY_SEED:
        binary_seed_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_BINARY_EXECUTION:
        binary_execution_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_TRACE:
        trace_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if task.status == TaskStatus.QUEUED_REPRO:
        repro_task(record.task_id, task_store, queue)

    analyze_coverage_feedback(record.task_id, task_store)
    analyze_coverage_feedback(record.task_id, task_store)
    _consume_scheduler_feedback(record.task_id, task_store)
    _build_reports_for_single_task(record.task_id)
    return record.task_id


def _run_patch_truth_cleanup(task_store: TaskStateStore, queue: LocalQueue) -> str:
    donor = task_store.load_task(SOURCE_DONOR_TASK_ID)
    donor_root = Path(donor.task_dir)
    trace_manifest = donor_root / "trace" / "trace_manifest.json"
    repro_manifest = donor_root / "pov" / "repro_manifest.json"
    testcase_path = donor_root / "crashes" / "raw" / "crash-adc49ec7a3c54d3cb0b7fefe33e7e78fd9d4c528"
    pov_path = donor_root / "pov" / "confirmed" / "crash-adc49ec7a3c54d3cb0b7fefe33e7e78fd9d4c528.json"
    spec = TaskSpec(
        source=donor.source.model_copy(deep=True),
        execution_mode=donor.execution_mode,
        metadata={
            "project": "cjson",
            "benchmark": "patch_truth_cleanup_validation",
            "ground_truth_path": str(GROUND_TRUTH),
            "patch_target_vuln_id": "CJSON_VULN_001_PRINTBUFFER_REALLOC",
            "patch_source_path": str(SOURCE_ROOT),
            "patch_oss_fuzz_project_path": str(OSS_FUZZ_PROJECT),
            "patch_creation_strategy": "auto_known_fix",
            "patch_testcase_path": str(testcase_path),
            "expected_harness": donor.runtime.get("active_harness") or "cjson_read_fuzzer",
        },
    )
    _, record = create_task_with_layout(spec, status=TaskStatus.QUEUED_PATCH)
    task_store.update_runtime(
        record.task_id,
        {
            "target_mode": "source",
            "adapter_resolution": "ossfuzz",
            "active_harness": donor.runtime.get("active_harness") or "cjson_read_fuzzer",
            "trace_manifest_path": str(trace_manifest),
            "repro_manifest_path": str(repro_manifest),
            "pov_path": str(pov_path),
        },
    )
    patch_task(record.task_id, task_store, queue)
    return record.task_id


def _source_metrics(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    task_root = Path(task.task_dir)
    seed_manifest = _load_json(task.runtime.get("seed_manifest_path"))
    fuzz_manifest = _load_json(task.runtime.get("fuzz_manifest_path"))
    reports = {
        "inventory": _load_json(task_root / "reports" / "pov_inventory.json"),
        "coverage": _load_json(task_root / "reports" / "vuln_coverage.json"),
    }
    return {
        "task_id": task_id,
        "status": task.status.value,
        "generated_seed_count": seed_manifest.get("generated_seed_count", 0),
        "seed_provenance": seed_manifest.get("seed_provenance"),
        "llm_provenance": seed_manifest.get("llm_provenance"),
        "llm_real_call_verified": seed_manifest.get("llm_real_call_verified"),
        "imported_seed_count": seed_manifest.get("imported_seed_count", 0),
        "cached_seed_count": seed_manifest.get("cached_seed_count", 0),
        "fallback_non_llm_used": bool(seed_manifest.get("fallback_non_llm_used")),
        "fuzz_started": bool(task.runtime.get("fuzz_started_at")),
        "fuzz_completed": bool(task.runtime.get("fuzz_completed_at")),
        "corpus_growth_count": len(fuzz_manifest.get("new_corpus_files", []) or []),
        "raw_crash_count": len(fuzz_manifest.get("raw_crashes", []) or []),
        "traced_crash_count": _traced_count(task_root),
        "repro_count": 1 if task.runtime.get("repro_manifest_path") else 0,
        "pov_count": _pov_count(task_root),
        "coverage_snapshot_count": _coverage_snapshot_count(task_root),
        "scheduler_feedback_triggered": bool(task.runtime.get("scheduler_feedback_consumption_path")),
        "distinct_signature_count": reports["inventory"].get("distinct_signature_count", 0),
        "vuln_coverage_found_count": reports["coverage"].get("found_vuln_count", 0),
        "seed_manifest_path": task.runtime.get("seed_manifest_path"),
        "fuzz_manifest_path": task.runtime.get("fuzz_manifest_path"),
        "coverage_feedback_manifest_path": task.runtime.get("coverage_feedback_manifest_path"),
        "scheduler_feedback_consumption_path": task.runtime.get("scheduler_feedback_consumption_path"),
        "pov_inventory_path": str(task_root / "reports" / "pov_inventory.json"),
        "vuln_coverage_path": str(task_root / "reports" / "vuln_coverage.json"),
    }


def _binary_metrics(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    task_root = Path(task.task_dir)
    seed_manifest = _load_json(task.runtime.get("binary_seed_manifest_path"))
    exec_manifest = _load_json(task.runtime.get("binary_execution_manifest_path"))
    contamination = _load_json(task.runtime.get("binary_contamination_report_path"))
    reports = {
        "inventory": _load_json(task_root / "reports" / "pov_inventory.json"),
        "coverage": _load_json(task_root / "reports" / "vuln_coverage.json"),
    }
    run_records = exec_manifest.get("run_records", []) or []
    execution_signal_count = sum(
        1
        for item in run_records
        if item.get("exit_code") not in (0, None) or item.get("stderr_excerpt") or item.get("stdout_excerpt")
    )
    scheduler_feedback = _load_json(task.runtime.get("scheduler_feedback_consumption_path"))
    before_focus = (scheduler_feedback.get("before") or {}).get("selected_binary_slice_focus")
    after_focus = (scheduler_feedback.get("after") or {}).get("selected_binary_slice_focus")
    slice_focus_changes = 1 if before_focus and after_focus and before_focus != after_focus else 0
    return {
        "task_id": task_id,
        "status": task.status.value,
        "generated_seed_count": seed_manifest.get("generated_seed_count", 0),
        "binary_seed_provenance": seed_manifest.get("binary_seed_provenance"),
        "llm_provenance": seed_manifest.get("llm_provenance"),
        "llm_real_call_verified": seed_manifest.get("llm_real_call_verified"),
        "execution_started": bool(task.runtime.get("binary_execution_started_at")),
        "execution_completed": bool(task.runtime.get("binary_execution_completed_at")),
        "run_count": exec_manifest.get("run_count", len(run_records)),
        "execution_signal_count": execution_signal_count,
        "binary_crash_candidate_count": exec_manifest.get("crash_candidate_count", 0),
        "traced_crash_count": _traced_count(task_root),
        "repro_count": 1 if task.runtime.get("repro_manifest_path") else 0,
        "pov_count": _pov_count(task_root),
        "coverage_snapshot_count": _coverage_snapshot_count(task_root),
        "slice_focus_changes": slice_focus_changes,
        "scheduler_feedback_triggered": bool(task.runtime.get("scheduler_feedback_consumption_path")),
        "contamination_status_summary": {
            "pure_binary_eligible": contamination.get("pure_binary_eligible"),
            "source_context_used": contamination.get("source_context_used"),
            "source_harness_used": contamination.get("source_harness_used"),
            "source_seed_imported_count": contamination.get("source_seed_imported_count"),
            "source_dict_used": contamination.get("source_dict_used"),
            "source_options_used": contamination.get("source_options_used"),
            "source_program_model_used": contamination.get("source_program_model_used"),
        },
        "binary_seed_manifest_path": task.runtime.get("binary_seed_manifest_path"),
        "binary_execution_manifest_path": task.runtime.get("binary_execution_manifest_path"),
        "coverage_feedback_manifest_path": task.runtime.get("coverage_feedback_manifest_path"),
        "scheduler_feedback_consumption_path": task.runtime.get("scheduler_feedback_consumption_path"),
        "binary_contamination_report_path": task.runtime.get("binary_contamination_report_path"),
        "pov_inventory_path": str(task_root / "reports" / "pov_inventory.json"),
        "vuln_coverage_path": str(task_root / "reports" / "vuln_coverage.json"),
    }


def _write_next_step_readiness(source_real: dict[str, Any], binary_real: dict[str, Any], patch_task_id: str, task_store: TaskStateStore) -> str:
    patch_task = task_store.load_task(patch_task_id)
    qe_manifest = _load_json(patch_task.runtime.get("patch_qe_manifest_path"))
    readiness_path = REPO_ROOT / "reports" / "next_step_readiness.md"
    text = "\n".join(
        [
            "# Next-Step Readiness",
            "",
            "1. Source-side readiness",
            (
                "- Ready to enter build matrix / program model / seed family / coverage plane strengthening, "
                "because clean real-LLM seed generation now reaches downstream fuzz without imported/cached/fallback contamination."
                if source_real.get("llm_real_call_verified")
                and source_real.get("imported_seed_count") == 0
                and source_real.get("cached_seed_count") == 0
                and not source_real.get("fallback_non_llm_used")
                and source_real.get("fuzz_started")
                else "- Not yet ready; clean real-LLM source seed path is still contaminated or not reaching fuzz."
            ),
            "",
            "2. Pure-binary readiness",
            (
                "- Ready to enter input-contract inference / stronger execution feedback / trace linkage strengthening, "
                "because clean real-LLM binary-native seeds now reach binary execution with a clean contamination report."
                if binary_real.get("llm_real_call_verified")
                and binary_real.get("execution_started")
                and binary_real.get("contamination_status_summary", {}).get("pure_binary_eligible")
                else "- Not yet ready; clean pure-binary seed-to-execution linkage is still missing or contaminated."
            ),
            "",
            "3. Patch plane next priority",
            (
                "- Patch semantic quality is the next priority. The current patch plane state machine, build, QE, and reflection are real, "
                "but patch generation is still deterministic / known-fix-assisted and not a general semantic repair capability."
            ),
            "",
            "4. Next three architecture strengthening items",
            "- Build/program model/context plane strengthening for source-side seed quality.",
            "- Source coverage plane and seed task family strengthening with clean real-LLM inputs.",
            "- Pure-binary execution feedback / trace linkage strengthening after clean binary seed-to-execution proof.",
            "",
            "Patch reference",
            f"- Patch task: `{patch_task_id}`",
            f"- QE verdict: `{qe_manifest.get('verdict')}`",
        ]
    )
    readiness_path.write_text(text + "\n", encoding="utf-8")
    return str(readiness_path)


def main() -> int:
    config = configure_llm_from_env()
    task_store = TaskStateStore()
    queue = LocalQueue()

    source_real_id = _run_source_short(task_store, queue, label="source_real_llm_clean_short", backend="llm")
    source_fallback_id = _run_source_short(
        task_store,
        queue,
        label="source_heuristic_fallback_clean_short",
        backend="heuristic_fallback",
    )
    binary_real_id = _run_binary_short(task_store, queue, label="pure_binary_real_llm_clean_short", backend="llm")
    binary_fallback_id = _run_binary_short(
        task_store,
        queue,
        label="pure_binary_fallback_clean_short",
        backend="heuristic_fallback",
    )
    patch_task_id = _run_patch_truth_cleanup(task_store, queue)

    source_real = _source_metrics(source_real_id, task_store)
    source_fallback = _source_metrics(source_fallback_id, task_store)
    binary_real = _binary_metrics(binary_real_id, task_store)
    binary_fallback = _binary_metrics(binary_fallback_id, task_store)
    readiness_path = _write_next_step_readiness(source_real, binary_real, patch_task_id, task_store)
    patch_task = task_store.load_task(patch_task_id)
    patch_summary = {
        "task_id": patch_task_id,
        "status": patch_task.status.value,
        "patch_request_manifest_path": patch_task.runtime.get("patch_request_manifest_path"),
        "patch_root_cause_manifest_path": patch_task.runtime.get("patch_root_cause_manifest_path"),
        "patch_context_manifest_path": patch_task.runtime.get("patch_context_manifest_path"),
        "patch_creation_manifest_path": patch_task.runtime.get("patch_creation_manifest_path"),
        "patch_build_manifest_path": patch_task.runtime.get("patch_build_manifest_path"),
        "patch_qe_manifest_path": patch_task.runtime.get("patch_qe_manifest_path"),
        "patch_reflection_manifest_path": patch_task.runtime.get("patch_reflection_manifest_path"),
        "patch_generation_provenance": patch_task.runtime.get("patch_generation_provenance"),
        "patch_semantic_strength": patch_task.runtime.get("patch_semantic_strength"),
        "patch_llm_request_attempted": patch_task.runtime.get("patch_llm_request_attempted"),
        "patch_llm_real_call_verified": patch_task.runtime.get("patch_llm_real_call_verified"),
    }

    summary = {
        "config": config,
        "source_real_llm_clean_short": source_real,
        "source_heuristic_fallback_clean_short": source_fallback,
        "pure_binary_real_llm_clean_short": binary_real,
        "pure_binary_fallback_clean_short": binary_fallback,
        "patch_truth_cleanup": patch_summary,
        "next_step_readiness_path": readiness_path,
    }
    report_path = write_report("clean_short_revalidation_summary.json", summary)
    print(json.dumps({**summary, "report_path": str(report_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

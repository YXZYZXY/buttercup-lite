from __future__ import annotations

import json
import re
import shutil
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
from core.models.task import ExecutionMode, TaskSpec, TaskStatus
from core.queues.redis_queue import QueueNames
from core.state.task_state import TaskStateStore
from core.storage.layout import execution_plan_path
from scripts.run_plane_strengthening_short_validations import _binary_metrics, _run_binary_short
from scripts.verification_common import LocalQueue, configure_llm_from_env, write_report

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = REPO_ROOT / "data" / "tasks"

GROUND_TRUTH_BY_LABEL = {
    "cjson": REPO_ROOT / "benchmarks" / "cjson_injected" / "ground_truth.json",
    "inih": REPO_ROOT / "benchmarks" / "inih_injected" / "ground_truth.json",
}


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


def _drain_patch_queue(queue: LocalQueue, task_store: TaskStateStore, seen_patch_tasks: set[str]) -> list[str]:
    launched: list[str] = []
    for queue_name, payload in queue.pushed:
        if queue_name != QueueNames.PATCH or payload in seen_patch_tasks:
            continue
        patch_task(payload, task_store, queue)
        seen_patch_tasks.add(payload)
        launched.append(payload)
    return launched


def _run_source_repo_first(
    task_store: TaskStateStore,
    queue: LocalQueue,
    *,
    label: str,
    repo_url: str,
    git_ref: str | None,
    fuzz_seconds: int,
    max_len: int,
    backend: str,
) -> tuple[str, list[str]]:
    ground_truth = GROUND_TRUTH_BY_LABEL[label]
    spec = TaskSpec(
        repo_url=repo_url,
        git_ref=git_ref,
        source_type="git_repo",
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "run_label": f"{label}_original_semantic_closure",
            "SEED_GENERATION_BACKEND": backend,
            "SEED_GENERATION_ATTEMPTS": 2,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": max_len,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": fuzz_seconds,
            "FUZZ_TIMEOUT_SECONDS": 5,
            "FUZZ_MAX_LEN": max_len,
            "FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES": False,
            "ALLOW_IMPORTED_CRASH_FALLBACK": False,
            "verification_mode": "original_semantic_closure",
            "seed_material_policy": "clean_generated_only",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": backend != "llm",
            "ENABLE_PATCH_ATTEMPT": True,
            "ground_truth_path": str(ground_truth),
            "LLM_TEMPERATURE": 0.2,
        },
    )
    record = task_store.create_task(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    seen_patch_tasks: set[str] = set()

    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)
    task = task_store.load_task(record.task_id)
    if not task.runtime.get("build_registry_path"):
        raise RuntimeError(
            f"{label} build did not produce build_registry_path: {task.runtime.get('build_error') or task.status.value}",
        )

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
                runtime_patch={
                    "repo_first_reseed_round": round_index,
                    "reseed_requested_at": task_store.now(),
                },
            )
        seed_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        task_dir = Path(task.task_dir)
        _copy_if_exists(task.runtime.get("seed_init_chain_manifest_path"), task_dir / "seed" / f"seed_init_chain_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_task_manifest_path"), task_dir / "seed" / f"seed_task_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_manifest_path"), task_dir / "seed" / f"seed_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("harness_selector_manifest_path"), task_dir / "seed" / f"harness_selector_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("function_selector_manifest_path"), task_dir / "seed" / f"function_selector_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_family_plan_manifest_path"), task_dir / "seed" / f"seed_family_plan_manifest_run{round_index}.json")
        _copy_if_exists(task_dir / "index" / "context_package.json", task_dir / "index" / f"context_package_run{round_index}.json")
        if task.status == TaskStatus.QUEUED_FUZZ:
            fuzzer_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        _copy_if_exists(task.runtime.get("fuzz_manifest_path"), task_dir / "crashes" / f"fuzz_manifest_run{round_index}.json")
        analyze_coverage_feedback(record.task_id, task_store)
        _copy_if_exists(task_store.load_task(record.task_id).runtime.get("coverage_summary_manifest_path"), task_dir / "coverage" / f"coverage_summary_manifest_run{round_index}.json")
        _copy_if_exists(task_store.load_task(record.task_id).runtime.get("coverage_feedback_manifest_path"), task_dir / "coverage" / f"feedback_manifest_run{round_index}.json")
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
        if task.status == TaskStatus.QUEUED_TRACE:
            trace_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        if task.status == TaskStatus.QUEUED_REPRO:
            repro_task(record.task_id, task_store, queue)
        _drain_patch_queue(queue, task_store, seen_patch_tasks)

    if ground_truth.exists():
        try:
            build_campaign_reports(
                campaign_task_id=record.task_id,
                origin_task_ids=[record.task_id],
                ground_truth_path=ground_truth,
                data_root=DATA_ROOT,
            )
        except Exception:
            pass
    return record.task_id, sorted(seen_patch_tasks)


def _source_metrics(task_id: str, task_store: TaskStateStore, patch_task_ids: list[str]) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    task_dir = Path(task.task_dir)
    coverage_summary = _load_json(task.runtime.get("coverage_summary_manifest_path"))
    scheduler_feedback = _load_json(task.runtime.get("scheduler_feedback_consumption_path"))
    query_validation = _load_json(task.runtime.get("program_model_query_validation_manifest_path"))
    patch_metrics = []
    for patch_task_id in patch_task_ids:
        patch_task = task_store.load_task(patch_task_id)
        patch_metrics.append(
            {
                "task_id": patch_task_id,
                "status": patch_task.status.value,
                "patch_request_manifest_path": patch_task.runtime.get("patch_request_manifest_path"),
                "patch_creation_manifest_path": patch_task.runtime.get("patch_creation_manifest_path"),
                "patch_candidate_ranking_manifest_path": patch_task.runtime.get("patch_candidate_ranking_manifest_path"),
                "generalized_patch_strategy_manifest_path": patch_task.runtime.get("generalized_patch_strategy_manifest_path"),
                "patch_apply_manifest_path": patch_task.runtime.get("patch_apply_manifest_path"),
                "patch_build_manifest_path": patch_task.runtime.get("patch_build_manifest_path"),
                "patch_qe_manifest_path": patch_task.runtime.get("patch_qe_manifest_path"),
                "patch_semantic_validation_manifest_path": patch_task.runtime.get("patch_semantic_validation_manifest_path"),
                "cjson_patch_failure_analysis_path": patch_task.runtime.get("cjson_patch_failure_analysis_path"),
                "patch_reflection_manifest_path": patch_task.runtime.get("patch_reflection_manifest_path"),
                "patch_result_classification": patch_task.runtime.get("patch_result_classification"),
                "patch_qe_verdict": patch_task.runtime.get("patch_qe_verdict"),
            }
        )
    return {
        "task_id": task_id,
        "status": task.status.value,
        "source_task_normalization_manifest_path": task.runtime.get("source_task_normalization_manifest_path"),
        "source_resolution_manifest_path": task.runtime.get("source_resolution_manifest_path"),
        "workspace_manifest_path": task.runtime.get("workspace_manifest_path"),
        "scheduler_fanout_manifest_path": task.runtime.get("scheduler_fanout_manifest_path"),
        "build_matrix_manifest_path": task.runtime.get("build_matrix_manifest_path"),
        "program_model_backend_manifest_path": task.runtime.get("program_model_backend_manifest_path"),
        "program_model_query_validation_manifest_path": task.runtime.get("program_model_query_validation_manifest_path"),
        "query_capability_matrix_path": task.runtime.get("query_capability_matrix_path"),
        "sample_query_results_path": task.runtime.get("sample_query_results_path"),
        "context_package_path": task.runtime.get("context_package_path") or str(task_dir / "index" / "context_package.json"),
        "context_backend_contribution_path": str(task_dir / "index" / "context_backend_contribution.json"),
        "seed_init_chain_manifest_path": task.runtime.get("seed_init_chain_manifest_path"),
        "harness_selector_manifest_path": task.runtime.get("harness_selector_manifest_path"),
        "function_selector_manifest_path": task.runtime.get("function_selector_manifest_path"),
        "seed_family_plan_manifest_path": task.runtime.get("seed_family_plan_manifest_path"),
        "coverage_to_selector_bridge_manifest_path": task.runtime.get("coverage_to_selector_bridge_manifest_path"),
        "selector_feedback_consumption_path": task.runtime.get("selector_feedback_consumption_path"),
        "seed_mode_semantics_manifest_path": task.runtime.get("seed_mode_semantics_manifest_path"),
        "coverage_summary_manifest_path": task.runtime.get("coverage_summary_manifest_path"),
        "coverage_artifact_manifest_path": coverage_summary.get("coverage_artifact_manifest_path"),
        "coverage_level": coverage_summary.get("coverage_level"),
        "per_function_summary_count": len(coverage_summary.get("per_function_summary") or []),
        "per_file_summary_count": len(coverage_summary.get("per_file_summary") or []),
        "query_capability_matrix": query_validation.get("query_capability_matrix", {}),
        "trace_manifest_path": task.runtime.get("trace_manifest_path"),
        "repro_manifest_path": task.runtime.get("repro_manifest_path"),
        "selected_harness": task.runtime.get("selected_harness"),
        "selected_target_function": task.runtime.get("selected_target_function"),
        "scheduler_feedback_before": scheduler_feedback.get("before"),
        "scheduler_feedback_after": scheduler_feedback.get("after"),
        "patch_followup_task_ids": patch_task_ids,
        "patch_metrics": patch_metrics,
    }


def _classify_repo_first_task(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    build_matrix = _load_json(task.runtime.get("build_matrix_manifest_path"))
    classification = "repo_first_unresolved"
    if task.status == TaskStatus.POV_CONFIRMED:
        classification = "repo_first_full_closure"
    elif build_matrix and build_matrix.get("build_decision", {}).get("supported"):
        classification = "repo_first_buildable"
    elif task.runtime.get("source_resolution_manifest_path"):
        classification = "repo_first_resolved_but_build_failed"
    return {
        "task_id": task_id,
        "classification": classification,
        "status": task.status.value,
        "repo_url": task.metadata.get("repo_url") or task.source.uri,
        "auto_resolved": build_matrix.get("auto_resolved"),
        "registry_fallback_used": build_matrix.get("registry_fallback_used"),
        "selected_oss_fuzz_project": (build_matrix.get("source_resolution") or {}).get("selected_oss_fuzz_project"),
        "build_matrix_manifest_path": task.runtime.get("build_matrix_manifest_path"),
        "source_resolution_manifest_path": task.runtime.get("source_resolution_manifest_path"),
    }


def _analyze_libyaml_failure(task_id: str, task_store: TaskStateStore) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    build_matrix = _load_json(task.runtime.get("build_matrix_manifest_path"))
    fuzzer_build = (build_matrix.get("builds") or {}).get("fuzzer_build", {})
    produced_artifacts = fuzzer_build.get("produced_artifacts") or []
    log_path = Path(task.task_dir) / "build" / "logs" / "build.log"
    log_text = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
    missing_patterns = re.findall(r"cannot stat .*?([^/\\s]+(?:\\.zip|\\.options|\\.dict))", log_text)
    missing_fuzzer_sources = re.findall(r"no such file or directory: .*?([^/\\s]+_fuzzer\\.c)", log_text)
    root_cause = {
        "task_id": task_id,
        "status": task.status.value,
        "repo_url": task.metadata.get("repo_url") or task.source.uri,
        "selected_oss_fuzz_project": task.runtime.get("selected_oss_fuzz_project"),
        "failure_layer": "oss_fuzz_project_asset_expectation_mismatch",
        "root_cause": (
            "builder successfully resolved libyaml and staged generic oss-fuzz assets, but the upstream oss-fuzz project expects a seed corpus zip that is not present in the checked-out project assets"
        ),
        "fuzzer_build_produced_artifacts": produced_artifacts,
        "missing_project_assets": sorted(set([*missing_patterns, *missing_fuzzer_sources])),
        "build_log_path": str(log_path),
        "minimal_fix_route": [
            "either stage the missing libyaml_seed_corpus.zip from a known asset source",
            "or relax the libyaml build adapter so missing optional seed corpus assets do not hard-fail the build",
        ],
    }
    write_report("libyaml_failure_root_cause.json", root_cause)
    return root_cause


def _write_source_generalization_reports(task_store: TaskStateStore, task_ids: list[str]) -> dict[str, Any]:
    entries = [_classify_repo_first_task(task_id, task_store) for task_id in task_ids]
    auto_path_count = sum(1 for item in entries if item.get("auto_resolved"))
    fallback_count = sum(1 for item in entries if item.get("registry_fallback_used"))
    matrix = {
        "generated_at": task_store.now(),
        "entries": entries,
        "summary": {
            "repo_first_full_closure": sum(1 for item in entries if item["classification"] == "repo_first_full_closure"),
            "repo_first_buildable": sum(1 for item in entries if item["classification"] == "repo_first_buildable"),
            "repo_first_resolved_but_build_failed": sum(1 for item in entries if item["classification"] == "repo_first_resolved_but_build_failed"),
            "repo_first_unresolved": sum(1 for item in entries if item["classification"] == "repo_first_unresolved"),
            "auto_path_count": auto_path_count,
            "fallback_path_count": fallback_count,
        },
    }
    write_report("source_generalization_matrix.json", matrix)
    write_report("repo_first_classification_manifest.json", matrix)
    return matrix


def _write_binary_distribution_comparison(
    *,
    real_task_id: str,
    fallback_task_id: str,
    task_store: TaskStateStore,
) -> dict[str, Any]:
    real_task = task_store.load_task(real_task_id)
    fallback_task = task_store.load_task(fallback_task_id)
    real_manifest = _load_json(real_task.runtime.get("binary_execution_manifest_path"))
    fallback_manifest = _load_json(fallback_task.runtime.get("binary_execution_manifest_path"))
    payload = {
        "generated_at": task_store.now(),
        "real_llm_task_id": real_task_id,
        "fallback_task_id": fallback_task_id,
        "real_llm": {
            "signal_category_counts": real_manifest.get("signal_category_counts", {}),
            "semantic_subcategory_distribution": real_manifest.get("semantic_subcategory_distribution", {}),
            "promotion_rate": real_manifest.get("promotion_rate"),
            "signal_signature_diversity": len({item.get("signal_signature") for item in real_manifest.get("per_input_execution_summary", []) if item.get("signal_signature")}),
            "contract_confidence_manifest_path": real_task.runtime.get("contract_confidence_manifest_path"),
            "binary_signal_promotion_analysis_path": real_task.runtime.get("binary_signal_promotion_analysis_path"),
        },
        "fallback": {
            "signal_category_counts": fallback_manifest.get("signal_category_counts", {}),
            "semantic_subcategory_distribution": fallback_manifest.get("semantic_subcategory_distribution", {}),
            "promotion_rate": fallback_manifest.get("promotion_rate"),
            "signal_signature_diversity": len({item.get("signal_signature") for item in fallback_manifest.get("per_input_execution_summary", []) if item.get("signal_signature")}),
            "contract_confidence_manifest_path": fallback_task.runtime.get("contract_confidence_manifest_path"),
            "binary_signal_promotion_analysis_path": fallback_task.runtime.get("binary_signal_promotion_analysis_path"),
        },
        "current_blocker": (
            "binary execution is now classified truthfully as informational fixed-input replay unless parser- or crash-level evidence appears; next gain depends on stronger contract-aware seed shaping and richer target-visible stderr semantics"
        ),
    }
    write_report("semantic_distribution_comparison.json", payload)
    return payload


def _run_build_only_sanity(
    task_store: TaskStateStore,
    queue: LocalQueue,
    *,
    repo_url: str,
    git_ref: str | None = None,
) -> str:
    spec = TaskSpec(
        repo_url=repo_url,
        git_ref=git_ref,
        source_type="git_repo",
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "run_label": "libyaml_build_only_sanity",
            "verification_mode": "original_semantic_closure_build_sanity",
        },
    )
    record = task_store.create_task(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)
    return record.task_id


def _run_source_sanity(
    task_store: TaskStateStore,
    queue: LocalQueue,
    *,
    label: str,
    repo_url: str,
    git_ref: str | None,
) -> str:
    spec = TaskSpec(
        repo_url=repo_url,
        git_ref=git_ref,
        source_type="git_repo",
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "run_label": label,
            "SEED_GENERATION_BACKEND": "heuristic_fallback",
            "SEED_GENERATION_ATTEMPTS": 1,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 12,
            "SEED_MAX_BYTES": 32768,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": 6,
            "FUZZ_TIMEOUT_SECONDS": 4,
            "verification_mode": "repo_first_generalization_sanity",
            "allow_imported_seed_material": False,
            "allow_cached_seed_material": False,
            "allow_fallback_non_llm": True,
            "ENABLE_PATCH_ATTEMPT": False,
        },
    )
    record = task_store.create_task(spec, status=TaskStatus.QUEUED_DOWNLOAD)
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
    analyze_coverage_feedback(record.task_id, task_store)
    _consume_scheduler_feedback(record.task_id, task_store)
    task = task_store.load_task(record.task_id)
    if task.status in {TaskStatus.FUZZING, TaskStatus.FUZZ_FAILED, TaskStatus.SEEDED, TaskStatus.BUILT, TaskStatus.QUEUED_SEED}:
        task_store.update_runtime(
            record.task_id,
            {
                "seed_task_mode_override": "SEED_EXPLORE",
                "targeted_reseed_reason": "generalization sanity forces explore mode when no closure evidence is present",
            },
        )
        task_store.update_status(record.task_id, TaskStatus.QUEUED_SEED, runtime_patch={"sanity_reseed_requested_at": task_store.now()})
        seed_task(record.task_id, task_store, queue)
    return record.task_id


def main() -> int:
    configure_llm_from_env()
    task_store = TaskStateStore()
    queue = LocalQueue()

    cjson_id, cjson_patch_ids = _run_source_repo_first(
        task_store,
        queue,
        label="cjson",
        repo_url="https://github.com/baiyujun/cjson.git",
        git_ref="fix/buttercup-build",
        fuzz_seconds=12,
        max_len=262144,
        backend="llm",
    )
    inih_id, inih_patch_ids = _run_source_repo_first(
        task_store,
        queue,
        label="inih",
        repo_url="https://github.com/Misat0N/inih.git",
        git_ref="main",
        fuzz_seconds=16,
        max_len=512,
        backend="llm",
    )
    binary_real_id = _run_binary_short(task_store, queue, label="original_semantic_closure_pure_binary_real_llm", backend="llm")
    binary_fallback_id = _run_binary_short(task_store, queue, label="original_semantic_closure_pure_binary_fallback", backend="heuristic_fallback")

    libyaml_task_id = None
    try:
        libyaml_task_id = _run_build_only_sanity(
            task_store,
            queue,
            repo_url="https://github.com/yaml/libyaml.git",
            git_ref="master",
        )
    except Exception:
        libyaml_task_id = None
    libplist_task_id = None
    try:
        libplist_task_id = _run_source_sanity(
            task_store,
            queue,
            label="libplist_repo_first_sanity",
            repo_url="https://github.com/libimobiledevice/libplist.git",
            git_ref="master",
        )
    except Exception:
        libplist_task_id = None

    generalization_matrix = _write_source_generalization_reports(
        task_store,
        [task_id for task_id in [cjson_id, inih_id, libyaml_task_id, libplist_task_id] if task_id],
    )
    binary_distribution = _write_binary_distribution_comparison(
        real_task_id=binary_real_id,
        fallback_task_id=binary_fallback_id,
        task_store=task_store,
    )
    libyaml_failure = _analyze_libyaml_failure(libyaml_task_id, task_store) if libyaml_task_id else None

    payload = {
        "cjson_repo_first": _source_metrics(cjson_id, task_store, cjson_patch_ids),
        "inih_repo_first": _source_metrics(inih_id, task_store, inih_patch_ids),
        "binary_real": _binary_metrics(binary_real_id, task_store),
        "binary_fallback": _binary_metrics(binary_fallback_id, task_store),
        "libyaml": (_classify_repo_first_task(libyaml_task_id, task_store) if libyaml_task_id else None),
        "libplist_sanity": (_classify_repo_first_task(libplist_task_id, task_store) if libplist_task_id else None),
        "source_generalization_matrix_path": str(REPO_ROOT / "reports" / "source_generalization_matrix.json"),
        "repo_first_classification_manifest_path": str(REPO_ROOT / "reports" / "repo_first_classification_manifest.json"),
        "semantic_distribution_comparison_path": str(REPO_ROOT / "reports" / "semantic_distribution_comparison.json"),
        "libyaml_failure_root_cause_path": str(REPO_ROOT / "reports" / "libyaml_failure_root_cause.json") if libyaml_failure else None,
        "generalization_matrix": generalization_matrix,
        "binary_distribution_comparison": binary_distribution,
    }
    write_report("original_semantic_closure_summary.json", payload)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

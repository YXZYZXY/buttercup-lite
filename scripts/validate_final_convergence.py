from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path

from apps.workers.campaign.main import process_task as campaign_process_task
from apps.workers.patch.main import process_task as patch_process_task
from apps.workers.scheduler.main import process_task as scheduler_process_task
from core.campaign.coverage_feedback import analyze_coverage_feedback
from core.campaign.executor import InMemoryQueue
from core.models.task import TaskSpec, TaskStatus
from core.state.task_state import TaskStateStore
from core.storage.layout import create_task_layout
from core.utils.settings import settings

DATA_ROOT = "/home/buttercup2/Project/buttercup-lite/data/tasks"
REPO_ROOT = Path("/home/buttercup2/Project/buttercup-lite")
GROUND_TRUTH = str(REPO_ROOT / "benchmarks" / "cjson_injected" / "ground_truth.json")
SOURCE_TREE = "/home/buttercup2/Project/benchmarks/cjson-injected"
OSS_FUZZ_PROJECT = "/home/buttercup2/Project/oss-fuzz/oss-fuzz/projects/cjson"
SOURCE_DONOR = "d15e7148-1f38-4536-9487-d6346e07afb6"
PURE_BINARY_DONOR = "ee48d355-ce4c-4417-87a4-81fb415c4fd2"
REPORT_PATH = REPO_ROOT / "reports" / "final_convergence_validation.json"


def _host_path(path_str: str | None) -> Path | None:
    if not path_str:
        return None
    path = Path(path_str)
    if path.exists():
        return path
    prefix = "/data/tasks/"
    if path_str.startswith(prefix):
        return Path(DATA_ROOT) / path_str[len(prefix) :]
    return path


def _clone_spec(task_store: TaskStateStore, task_id: str) -> TaskSpec:
    donor = task_store.load_task(task_id)
    return TaskSpec(
        source=donor.source.model_copy(deep=True),
        execution_mode=donor.execution_mode,
        metadata=deepcopy(donor.metadata),
    )


def _new_task_from_spec(
    task_store: TaskStateStore,
    spec: TaskSpec,
    status: TaskStatus,
    *,
    metadata_patch: dict | None = None,
    runtime_patch: dict | None = None,
):
    record = task_store.create_task(spec, status=status)
    layout = create_task_layout(record.task_id)
    task_store.update_task(
        record.task_id,
        layout=layout,
        metadata=metadata_patch or {},
        runtime=runtime_patch or {},
    )
    return task_store.load_task(record.task_id)


def _copy_file(src: Path | None, dst: Path) -> Path | None:
    if src is None or not src.exists():
        return None
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def _copy_tree(src: Path | None, dst: Path) -> Path | None:
    if src is None or not src.exists():
        return None
    shutil.copytree(src, dst, dirs_exist_ok=True)
    return dst


def _load_task_json(task_id: str) -> dict:
    return json.loads((Path(DATA_ROOT) / task_id / "task.json").read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _prepare_source_coverage_task(task_store: TaskStateStore, queue: InMemoryQueue) -> str:
    donor = task_store.load_task(SOURCE_DONOR)
    task = _new_task_from_spec(
        task_store,
        _clone_spec(task_store, SOURCE_DONOR),
        TaskStatus.READY,
        metadata_patch={
            "benchmark": "final_convergence_source_coverage",
            "ground_truth_path": GROUND_TRUTH,
        },
        runtime_patch={
            "target_mode": "source",
            "active_harness": donor.runtime.get("active_harness"),
            "active_harness_path": donor.runtime.get("active_harness_path"),
        },
    )
    task_root = Path(task.task_dir)
    donor_root = Path(donor.task_dir)
    fuzz_manifest_dst = _copy_file(
        _host_path(donor.runtime.get("fuzz_manifest_path")),
        task_root / "crashes" / "fuzz_manifest.json",
    )
    build_registry_dst = _copy_file(
        _host_path(donor.runtime.get("build_registry_path")),
        task_root / "build" / "build_registry.json",
    )
    _copy_file(donor_root / "logs" / "fuzzer.stderr.log", task_root / "logs" / "fuzzer.stderr.log")
    _copy_tree(donor_root / "corpus" / "active", task_root / "corpus" / "active")
    task_store.update_runtime(
        task.task_id,
        {
            "fuzz_manifest_path": str(fuzz_manifest_dst),
            "build_registry_path": str(build_registry_dst),
            "target_mode": "source",
            "active_harness": donor.runtime.get("active_harness"),
            "active_harness_path": donor.runtime.get("active_harness_path"),
        },
    )
    analyze_coverage_feedback(task.task_id, task_store)
    scheduler_process_task(task.task_id, task_store, queue)
    return task.task_id


def _prepare_binary_coverage_task(task_store: TaskStateStore, queue: InMemoryQueue) -> str:
    donor = task_store.load_task(PURE_BINARY_DONOR)
    task = _new_task_from_spec(
        task_store,
        _clone_spec(task_store, PURE_BINARY_DONOR),
        TaskStatus.READY,
        metadata_patch={
            "benchmark": "final_convergence_pure_binary_coverage",
            "ground_truth_path": GROUND_TRUTH,
        },
        runtime_patch={
            "target_mode": "binary",
            "adapter_resolution": "binary",
            "binary_analysis_backend": donor.runtime.get("binary_analysis_backend", "auto"),
        },
    )
    task_root = Path(task.task_dir)
    donor_root = Path(donor.task_dir)
    exec_manifest_dst = _copy_file(
        _host_path(donor.runtime.get("binary_execution_manifest_path")),
        task_root / "runtime" / "binary_execution_manifest.json",
    )
    slice_manifest_dst = _copy_file(
        _host_path(donor.runtime.get("binary_slice_manifest_path")),
        task_root / "binary_slice" / "slice_manifest.json",
    )
    _copy_tree(donor_root / "corpus" / "binary_active", task_root / "corpus" / "binary_active")
    task_store.update_runtime(
        task.task_id,
        {
            "binary_execution_manifest_path": str(exec_manifest_dst),
            "binary_slice_manifest_path": str(slice_manifest_dst) if slice_manifest_dst else None,
            "selected_binary_slice_focus": donor.runtime.get("selected_binary_slice_focus"),
            "target_mode": "binary",
            "adapter_resolution": "binary",
            "binary_analysis_backend": donor.runtime.get("binary_analysis_backend", "auto"),
            "binary_input_contract": donor.runtime.get("binary_input_contract", "file"),
            "binary_input_contract_source": donor.runtime.get("binary_input_contract_source", "manual_input_contract"),
            "resolved_imports": deepcopy(donor.runtime.get("resolved_imports", {})),
        },
    )
    analyze_coverage_feedback(task.task_id, task_store)
    analyze_coverage_feedback(task.task_id, task_store)
    scheduler_process_task(task.task_id, task_store, queue)
    return task.task_id


def _create_regression_inputs(task_root: Path) -> list[str]:
    regression_dir = task_root / "patch" / "regression_inputs"
    regression_dir.mkdir(parents=True, exist_ok=True)
    samples = {
        "regression_1.json": "{}\n",
        "regression_2.json": "[]\n",
        "regression_3.json": "{\"key\":\"value\"}\n",
    }
    paths: list[str] = []
    for name, content in samples.items():
        path = regression_dir / name
        path.write_text(content, encoding="utf-8")
        paths.append(str(path))
    return paths


def _prepare_patch_task(task_store: TaskStateStore, queue: InMemoryQueue, *, broken: bool) -> str:
    donor = task_store.load_task(SOURCE_DONOR)
    donor_root = Path(donor.task_dir)
    trace_manifest = donor_root / "trace" / "trace_manifest.json"
    repro_manifest = donor_root / "pov" / "repro_manifest.json"
    testcase_path = donor_root / "crashes" / "raw" / "crash-adc49ec7a3c54d3cb0b7fefe33e7e78fd9d4c528"
    pov_path = donor_root / "pov" / "confirmed" / "crash-adc49ec7a3c54d3cb0b7fefe33e7e78fd9d4c528.json"

    task = _new_task_from_spec(
        task_store,
        _clone_spec(task_store, SOURCE_DONOR),
        TaskStatus.QUEUED_PATCH,
        metadata_patch={
            "benchmark": "final_convergence_patch_failure" if broken else "final_convergence_patch_success",
            "ground_truth_path": GROUND_TRUTH,
            "patch_target_vuln_id": "CJSON_VULN_001_PRINTBUFFER_REALLOC",
            "patch_source_path": SOURCE_TREE,
            "patch_oss_fuzz_project_path": OSS_FUZZ_PROJECT,
            "patch_creation_strategy": "intentionally_broken" if broken else "auto_known_fix",
            "patch_testcase_path": str(testcase_path),
            "expected_harness": donor.runtime.get("active_harness") or "cjson_read_fuzzer",
        },
        runtime_patch={
            "target_mode": "source",
            "adapter_resolution": "ossfuzz",
            "active_harness": donor.runtime.get("active_harness") or "cjson_read_fuzzer",
            "trace_manifest_path": str(trace_manifest),
            "repro_manifest_path": str(repro_manifest),
            "pov_path": str(pov_path),
        },
    )
    regression_inputs = _create_regression_inputs(Path(task.task_dir))
    task_store.update_task(task.task_id, metadata={"patch_regression_inputs": regression_inputs})
    patch_process_task(task.task_id, task_store, queue)
    return task.task_id


def _prepare_arbitration_task(
    task_store: TaskStateStore,
    queue: InMemoryQueue,
    *,
    source_task_id: str,
    binary_task_id: str,
    patch_success_task_id: str,
    patch_retry_task_id: str,
) -> str:
    donor = task_store.load_task(SOURCE_DONOR)
    task = _new_task_from_spec(
        task_store,
        TaskSpec(
            source=donor.source.model_copy(deep=True),
            execution_mode=donor.execution_mode,
            metadata={
                "benchmark": "global_arbitration_v2_validation",
                "ground_truth_path": GROUND_TRUTH,
                "campaign_duration_seconds": 0,
                "workload_task_ids": [
                    source_task_id,
                    binary_task_id,
                    patch_success_task_id,
                    patch_retry_task_id,
                ],
                "target_mode": "source",
            },
        ),
        TaskStatus.CAMPAIGN_QUEUED,
    )
    campaign_process_task(task.task_id, task_store, queue, requeue=False)
    return task.task_id


def main() -> None:
    settings.data_root = DATA_ROOT
    task_store = TaskStateStore()
    queue = InMemoryQueue()

    source_task_id = _prepare_source_coverage_task(task_store, queue)
    binary_task_id = _prepare_binary_coverage_task(task_store, queue)
    patch_success_task_id = _prepare_patch_task(task_store, queue, broken=False)
    patch_retry_task_id = _prepare_patch_task(task_store, queue, broken=True)
    arbitration_task_id = _prepare_arbitration_task(
        task_store,
        queue,
        source_task_id=source_task_id,
        binary_task_id=binary_task_id,
        patch_success_task_id=patch_success_task_id,
        patch_retry_task_id=patch_retry_task_id,
    )

    source_task = task_store.load_task(source_task_id)
    binary_task = task_store.load_task(binary_task_id)
    patch_success = task_store.load_task(patch_success_task_id)
    patch_retry = task_store.load_task(patch_retry_task_id)
    arbitration_task = task_store.load_task(arbitration_task_id)

    report = {
        "source_coverage_task_id": source_task_id,
        "source_coverage_manifest_path": source_task.runtime.get("coverage_manifest_path"),
        "source_coverage_feedback_manifest_path": source_task.runtime.get("coverage_feedback_manifest_path"),
        "source_scheduler_feedback_consumption_path": source_task.runtime.get("scheduler_feedback_consumption_path"),
        "source_execution_plan_path": source_task.runtime.get("execution_plan_path"),
        "pure_binary_coverage_task_id": binary_task_id,
        "pure_binary_coverage_manifest_path": binary_task.runtime.get("coverage_manifest_path"),
        "pure_binary_coverage_feedback_manifest_path": binary_task.runtime.get("coverage_feedback_manifest_path"),
        "pure_binary_scheduler_feedback_consumption_path": binary_task.runtime.get("scheduler_feedback_consumption_path"),
        "pure_binary_execution_plan_path": binary_task.runtime.get("execution_plan_path"),
        "patch_success_task_id": patch_success_task_id,
        "patch_success_status": patch_success.status.value,
        "patch_success_request_manifest_path": patch_success.runtime.get("patch_request_manifest_path"),
        "patch_success_root_cause_manifest_path": patch_success.runtime.get("patch_root_cause_manifest_path"),
        "patch_success_context_manifest_path": patch_success.runtime.get("patch_context_manifest_path"),
        "patch_success_creation_manifest_path": patch_success.runtime.get("patch_creation_manifest_path"),
        "patch_success_build_manifest_path": patch_success.runtime.get("patch_build_manifest_path"),
        "patch_success_qe_manifest_path": patch_success.runtime.get("patch_qe_manifest_path"),
        "patch_success_reflection_manifest_path": patch_success.runtime.get("patch_reflection_manifest_path"),
        "patch_success_accepted_pov_path": patch_success.runtime.get("patch_accepted_pov_path"),
        "patch_retry_task_id": patch_retry_task_id,
        "patch_retry_status": patch_retry.status.value,
        "patch_retry_qe_manifest_path": patch_retry.runtime.get("patch_qe_manifest_path"),
        "patch_retry_reflection_manifest_path": patch_retry.runtime.get("patch_reflection_manifest_path"),
        "global_arbitration_task_id": arbitration_task_id,
        "global_arbitration_manifest_path": arbitration_task.runtime.get("global_arbitration_manifest_path"),
        "global_arbitration_selected_candidates": arbitration_task.runtime.get("global_arbitration_selected_candidates"),
    }
    _write_json(REPORT_PATH, report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path

from apps.workers.campaign.main import process_task as campaign_process_task
from apps.workers.patch.main import process_task as patch_process_task
from apps.workers.protocol_execution.main import process_task as protocol_process_task
from apps.workers.scheduler.main import process_task as scheduler_process_task
from core.campaign.coverage_feedback import analyze_coverage_feedback
from core.campaign.executor import InMemoryQueue
from core.models.task import AdapterType, ExecutionMode, TaskSource, TaskSpec, TaskStatus
from core.patch_priority import write_patch_priority_manifest
from core.state.task_state import TaskStateStore
from core.storage.layout import create_task_layout
from core.utils.settings import settings

DATA_ROOT = "/home/buttercup2/Project/buttercup-lite/data/tasks"
GROUND_TRUTH = "/home/buttercup2/Project/buttercup-lite/benchmarks/cjson_injected/ground_truth.json"
SOURCE_DONOR = "d15e7148-1f38-4536-9487-d6346e07afb6"
PURE_BINARY_DONOR = "ee48d355-ce4c-4417-87a4-81fb415c4fd2"
REPORT_PATH = Path("/home/buttercup2/Project/buttercup-lite/reports/live_behavior_validation.json")


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
        source=TaskSource.model_validate(donor.source.model_dump()),
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


def _copy_file(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def _copy_tree(src: Path, dst: Path) -> Path:
    if src.exists():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    return dst


def main() -> None:
    settings.data_root = DATA_ROOT
    task_store = TaskStateStore()
    queue = InMemoryQueue()
    root = Path(DATA_ROOT)

    source_donor = task_store.load_task(SOURCE_DONOR)
    source_task = _new_task_from_spec(
        task_store,
        _clone_spec(task_store, SOURCE_DONOR),
        TaskStatus.READY,
        runtime_patch={
            "target_mode": "source",
            "active_harness": source_donor.runtime.get("active_harness"),
            "active_harness_path": source_donor.runtime.get("active_harness_path"),
        },
    )
    source_root = Path(source_task.task_dir)
    source_fuzz_manifest_src = _host_path(source_donor.runtime["fuzz_manifest_path"])
    source_fuzz_manifest_dst = _copy_file(source_fuzz_manifest_src, source_root / "crashes" / "fuzz_manifest.json")
    source_stderr_src = _host_path(str(Path(source_donor.layout["logs"]) / "fuzzer.stderr.log"))
    _copy_file(source_stderr_src, source_root / "logs" / "fuzzer.stderr.log")
    task_store.update_runtime(
        source_task.task_id,
        {
            "fuzz_manifest_path": str(source_fuzz_manifest_dst),
            "target_mode": "source",
            "active_harness": source_donor.runtime.get("active_harness"),
            "active_harness_path": source_donor.runtime.get("active_harness_path"),
        },
    )
    source_feedback_path, _ = analyze_coverage_feedback(source_task.task_id, task_store)
    scheduler_process_task(source_task.task_id, task_store, queue)
    source_task = task_store.load_task(source_task.task_id)

    binary_donor = task_store.load_task(PURE_BINARY_DONOR)
    binary_task = _new_task_from_spec(
        task_store,
        _clone_spec(task_store, PURE_BINARY_DONOR),
        TaskStatus.READY,
        runtime_patch={
            "target_mode": "binary",
            "adapter_resolution": "binary",
            "binary_analysis_backend": binary_donor.runtime.get("binary_analysis_backend", "ida_mcp"),
            "binary_input_contract": binary_donor.runtime.get("binary_input_contract", "file"),
            "binary_input_contract_source": binary_donor.runtime.get("binary_input_contract_source", "manual_input_contract"),
        },
    )
    binary_root = Path(binary_task.task_dir)
    binary_exec_src = _host_path(binary_donor.runtime["binary_execution_manifest_path"])
    binary_exec_dst = _copy_file(binary_exec_src, binary_root / "runtime" / "binary_execution_manifest.json")
    _copy_tree(_host_path(binary_donor.layout["corpus_binary_active"]), binary_root / "corpus" / "binary_active")
    task_store.update_runtime(
        binary_task.task_id,
        {
            "binary_execution_manifest_path": str(binary_exec_dst),
            "target_mode": "binary",
            "adapter_resolution": "binary",
            "binary_analysis_backend": binary_donor.runtime.get("binary_analysis_backend", "ida_mcp"),
            "binary_input_contract": binary_donor.runtime.get("binary_input_contract", "file"),
            "binary_input_contract_source": binary_donor.runtime.get("binary_input_contract_source", "manual_input_contract"),
        },
    )
    analyze_coverage_feedback(binary_task.task_id, task_store)
    binary_feedback_path, _ = analyze_coverage_feedback(binary_task.task_id, task_store)
    scheduler_process_task(binary_task.task_id, task_store, queue)
    binary_task = task_store.load_task(binary_task.task_id)

    protocol_spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.PROTOCOL, uri="protocol://placeholder/cjson"),
        execution_mode=ExecutionMode.IMPORT_ASSISTED,
        metadata={
            "protocol_name": "placeholder_proto",
            "protocol_input_contract": {"mode": "frame", "transport": "tcp"},
            "ground_truth_path": GROUND_TRUTH,
        },
    )
    protocol_task = _new_task_from_spec(task_store, protocol_spec, TaskStatus.READY)
    scheduler_process_task(protocol_task.task_id, task_store, queue)
    protocol_process_task(protocol_task.task_id, task_store, queue)
    protocol_task = task_store.load_task(protocol_task.task_id)

    common_patch_runtime = {
        "pov_path": str(root / SOURCE_DONOR / "pov" / "confirmed"),
        "trace_manifest_path": str(root / SOURCE_DONOR / "trace" / "trace_manifest.json"),
        "repro_manifest_path": str(root / SOURCE_DONOR / "pov" / "repro_manifest.json"),
        "target_mode": "source",
        "adapter_resolution": "ossfuzz",
    }
    patch_fail = _new_task_from_spec(
        task_store,
        _clone_spec(task_store, SOURCE_DONOR),
        TaskStatus.QUEUED_PATCH,
        metadata_patch={"patch_validation_scenario": "qe_fail"},
        runtime_patch=common_patch_runtime,
    )
    patch_process_task(patch_fail.task_id, task_store, queue)
    patch_fail = task_store.load_task(patch_fail.task_id)

    patch_escalate = _new_task_from_spec(
        task_store,
        _clone_spec(task_store, SOURCE_DONOR),
        TaskStatus.QUEUED_PATCH,
        metadata_patch={"patch_validation_scenario": "qe_fail"},
        runtime_patch=common_patch_runtime,
    )
    escalate_manifest = write_patch_priority_manifest(
        patch_escalate.task_id,
        generated_at=task_store.now(),
        pov_paths=["/tmp/pov-escalate.json"],
        trace_manifest_path=common_patch_runtime["trace_manifest_path"],
        repro_manifest_path=common_patch_runtime["repro_manifest_path"],
        target_mode="source",
        adapter_resolution="ossfuzz",
        repeated_signature_count=11,
    )
    task_store.update_runtime(patch_escalate.task_id, {"patch_priority_manifest_path": str(escalate_manifest)})
    patch_process_task(patch_escalate.task_id, task_store, queue)
    patch_escalate = task_store.load_task(patch_escalate.task_id)

    patch_campaign = _new_task_from_spec(
        task_store,
        TaskSpec(
            source=TaskSource.model_validate(source_donor.source.model_dump()),
            execution_mode=source_donor.execution_mode,
            metadata={
                "benchmark": "patch_plane_validation",
                "ground_truth_path": GROUND_TRUTH,
                "origin_task_ids": [patch_fail.task_id, patch_escalate.task_id],
                "campaign_duration_seconds": 0,
                "target_mode": "source",
            },
        ),
        TaskStatus.CAMPAIGN_QUEUED,
    )
    campaign_process_task(patch_campaign.task_id, task_store, queue, requeue=False)
    patch_campaign = task_store.load_task(patch_campaign.task_id)

    binary_campaign = _new_task_from_spec(
        task_store,
        TaskSpec(
            source=TaskSource.model_validate(binary_donor.source.model_dump()),
            execution_mode=binary_donor.execution_mode,
            metadata={
                **deepcopy(binary_donor.metadata),
                "benchmark": "pure_binary_control_loop_smoke",
                "ground_truth_path": GROUND_TRUTH,
                "base_task_id": PURE_BINARY_DONOR,
                "campaign_duration_seconds": 600,
                "FUZZ_MAX_TOTAL_TIME_SECONDS": 5,
                "target_mode": "binary",
            },
        ),
        TaskStatus.CAMPAIGN_QUEUED,
        runtime_patch={
            "target_mode": "binary",
            "adapter_resolution": "binary",
            "binary_provenance": "pure_binary_input",
        },
    )
    for _ in range(3):
        campaign_process_task(binary_campaign.task_id, task_store, queue, requeue=False)
    binary_campaign = task_store.load_task(binary_campaign.task_id)

    report = {
        "source_coverage_task_id": source_task.task_id,
        "source_coverage_feedback_path": str(source_feedback_path),
        "source_scheduler_consumption_path": source_task.runtime.get("scheduler_feedback_consumption_path"),
        "source_execution_plan_path": source_task.runtime.get("execution_plan_path"),
        "source_live_seed_mode": source_task.runtime.get("seed_task_mode_default"),
        "source_seed_init_baseline_path": str(root / SOURCE_DONOR / "seed" / "seed_manifest.json"),
        "binary_coverage_task_id": binary_task.task_id,
        "binary_coverage_feedback_path": str(binary_feedback_path),
        "binary_scheduler_consumption_path": binary_task.runtime.get("scheduler_feedback_consumption_path"),
        "binary_execution_plan_path": binary_task.runtime.get("execution_plan_path"),
        "binary_live_seed_mode": binary_task.runtime.get("seed_task_mode_default"),
        "binary_seed_init_baseline_path": str(root / PURE_BINARY_DONOR / "binary_seed" / "binary_seed_manifest.json"),
        "protocol_task_id": protocol_task.task_id,
        "protocol_adapter_manifest_path": protocol_task.runtime.get("protocol_adapter_manifest_path"),
        "protocol_execution_manifest_path": protocol_task.runtime.get("protocol_execution_manifest_path"),
        "protocol_checkpoint_path": protocol_task.runtime.get("protocol_checkpoint_path"),
        "patch_fail_task_id": patch_fail.task_id,
        "patch_fail_reflection_manifest_path": patch_fail.runtime.get("patch_reflection_manifest_path"),
        "patch_fail_action": patch_fail.runtime.get("patch_reflection_action"),
        "patch_escalate_task_id": patch_escalate.task_id,
        "patch_escalate_priority_manifest_path": patch_escalate.runtime.get("patch_priority_manifest_path"),
        "patch_escalate_reflection_manifest_path": patch_escalate.runtime.get("patch_reflection_manifest_path"),
        "patch_escalate_action": patch_escalate.runtime.get("patch_reflection_action"),
        "patch_campaign_task_id": patch_campaign.task_id,
        "patch_campaign_manifest_path": patch_campaign.runtime.get("campaign_manifest_path"),
        "patch_campaign_checkpoint_path": patch_campaign.runtime.get("campaign_checkpoint_path"),
        "patch_priority_consumed_inputs": patch_campaign.runtime.get("patch_priority_consumed_inputs"),
        "patch_reflection_consumed_inputs": patch_campaign.runtime.get("patch_reflection_consumed_inputs"),
        "pure_binary_campaign_task_id": binary_campaign.task_id,
        "pure_binary_campaign_manifest_path": binary_campaign.runtime.get("campaign_manifest_path"),
        "pure_binary_campaign_checkpoint_path": binary_campaign.runtime.get("campaign_checkpoint_path"),
        "pure_binary_campaign_iterations_total": binary_campaign.runtime.get("campaign_iterations_total"),
        "pure_binary_campaign_round_records": binary_campaign.runtime.get("campaign_round_records"),
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

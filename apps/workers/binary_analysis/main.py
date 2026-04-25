import logging
import time
from pathlib import Path

from core.binary import (
    BinaryAnalysisBackend,
    BinaryAnalysisRequest,
    build_binary_execution_plan,
    run_binary_analysis,
)
from core.binary.contamination import build_contamination_report, write_contamination_report
from core.models.task import TaskStatus
from core.planning.execution import load_runtime_manifest
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.storage.layout import (
    binary_analysis_manifest_path,
    binary_execution_plan_path,
    task_root,
)
from core.utils.settings import resolve_text_setting, settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("binary-analysis-worker")


def _resolve_backend(task) -> BinaryAnalysisBackend:
    backend = task.runtime.get("binary_analysis_backend") or task.metadata.get("binary_analysis_backend")
    if backend and str(backend).lower() != "auto":
        return BinaryAnalysisBackend(str(backend))
    resolved_imports = task.runtime.get("resolved_imports", {})
    if resolved_imports.get("existing_binary_analysis_path"):
        return BinaryAnalysisBackend.IMPORTED_ANALYSIS
    if resolved_imports.get("existing_wrapper_path") or resolved_imports.get("existing_launcher_path"):
        return BinaryAnalysisBackend.WRAPPER_SCRIPT
    if settings.ida_mcp_configured():
        return BinaryAnalysisBackend.IDA_MCP
    configured = resolve_text_setting(task.metadata, "binary_analysis_backend", settings.binary_default_backend)
    if str(configured).lower() == "auto":
        return BinaryAnalysisBackend.WRAPPER_SCRIPT
    return BinaryAnalysisBackend(configured)


def _resolve_binary_path(task) -> Path:
    resolved = task.runtime.get("resolved_imports", {}).get("existing_binary_path")
    if resolved:
        return Path(resolved).resolve()
    return Path(task.source.uri).resolve()


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("binary analysis received task %s", task_id)
    task_store.update_status(
        task_id,
        TaskStatus.BINARY_ANALYZING,
        runtime_patch={
            "binary_analysis_started_at": task_store.now(),
        },
    )
    task = task_store.load_task(task_id)
    backend = _resolve_backend(task)
    binary_path = _resolve_binary_path(task)
    resolved_imports = task.runtime.get("resolved_imports", {})
    request = BinaryAnalysisRequest(
        task_id=task_id,
        backend=backend,
        binary_path=binary_path,
        binary_name=task.metadata.get("binary_target_name") or binary_path.name,
        source_path=Path(resolved_imports["existing_src_path"]) if resolved_imports.get("existing_src_path") else None,
        imported_analysis_path=Path(resolved_imports["existing_binary_analysis_path"])
        if resolved_imports.get("existing_binary_analysis_path")
        else None,
        wrapper_path=Path(resolved_imports["existing_wrapper_path"]) if resolved_imports.get("existing_wrapper_path") else None,
        launcher_path=Path(resolved_imports["existing_launcher_path"]) if resolved_imports.get("existing_launcher_path") else None,
        output_dir=task_root(task_id) / "binary",
        runtime_dir=task_root(task_id) / "runtime",
        metadata=task.metadata,
    )

    result = run_binary_analysis(request)
    raw_binary_mode = task.metadata.get("binary_mode") or task.runtime.get("binary_mode")
    binary_mode = str(raw_binary_mode or "binary_native_proof")
    binary_provenance = task.metadata.get("binary_provenance") or task.runtime.get("binary_provenance")
    if not binary_provenance:
        if raw_binary_mode == "pure_binary":
            binary_provenance = "pure_binary_input"
        elif raw_binary_mode in {None, "", "source_derived"}:
            binary_provenance = "source_derived_binary"
        else:
            binary_provenance = "binary_native_proof"
    contamination_report = build_contamination_report(task, binary_mode=binary_mode, seed_imported_count=0)
    contamination_path = write_contamination_report(task, contamination_report)
    selected_backend = result.manifest.get("selected_backend", backend.value)
    fallback_used = bool(result.manifest.get("fallback_used"))
    fallback_reason = result.manifest.get("fallback_reason")
    updated_task = task_store.load_task(task_id)
    scheduler_plan = load_runtime_manifest(updated_task.runtime.get("execution_plan_path"))
    binary_seed_stage = scheduler_plan.get("stages", {}).get("binary_seed", {})
    next_status = (
        TaskStatus.QUEUED_BINARY_SEED
        if binary_seed_stage.get("execute")
        else TaskStatus.QUEUED_BINARY_EXECUTION
    )
    task_store.update_status(
        task_id,
        next_status,
        runtime_patch={
            "binary_analysis_completed_at": task_store.now(),
            "binary_analysis_backend": selected_backend,
            "binary_analysis_manifest_path": str(binary_analysis_manifest_path(task_id)),
            "binary_analysis_summary_path": result.manifest.get("analysis_summary_path"),
            "ida_integration_manifest_path": str(task_root(task_id) / "binary" / "ida_integration_manifest.json"),
            "ida_backend_capabilities_path": str(task_root(task_id) / "binary" / "ida_backend_capabilities.json"),
            "ida_headless_export_manifest_path": str(task_root(task_id) / "binary" / "ida_headless_export_manifest.json"),
            "binary_function_inventory_path": str(task_root(task_id) / "binary" / "binary_function_inventory.json"),
            "binary_callgraph_manifest_path": str(task_root(task_id) / "binary" / "binary_callgraph_manifest.json"),
            "binary_contract_inference_manifest_path": str(task_root(task_id) / "binary" / "binary_contract_inference_manifest.json"),
            "ida_to_binary_context_bridge_path": str(task_root(task_id) / "binary" / "ida_to_binary_context_bridge.json"),
            "binary_function_count": len(result.functions),
            "binary_string_count": len(result.strings),
            "binary_import_count": len(result.imports),
            "binary_export_count": len(result.exports),
            "binary_entrypoint_count": len(result.entrypoints),
            "binary_analysis_fallback": fallback_used,
            "binary_analysis_fallback_reason": fallback_reason,
            "binary_analysis_requested_backend": backend.value,
            "binary_analysis_backend_reason": task.runtime.get("binary_analysis_backend_reason"),
            "binary_mode": binary_mode,
            "binary_provenance": str(binary_provenance),
            "binary_input_contract": task.metadata.get("binary_input_contract"),
            "binary_input_contract_source": task.metadata.get("binary_input_contract_source"),
            "binary_contamination_report_path": str(contamination_path),
        },
    )
    updated_task = task_store.load_task(task_id)
    execution_plan = build_binary_execution_plan(updated_task, task_store.now())
    runtime_patch = {
        "binary_execution_plan_path": str(binary_execution_plan_path(task_id)),
        "binary_execution_strategy": execution_plan.get("execution_strategy"),
    }
    if binary_seed_stage.get("execute"):
        queue.push(QueueNames.BINARY_SEED, task_id)
        runtime_patch.update(
            {
                "binary_seed_queue_name": QueueNames.BINARY_SEED,
                "binary_seed_queued_at": task_store.now(),
            },
        )
    else:
        queue.push(QueueNames.BINARY_EXECUTION, task_id)
        runtime_patch.update(
            {
                "binary_execution_queue_name": QueueNames.BINARY_EXECUTION,
                "binary_execution_queued_at": task_store.now(),
                "binary_execution_status": TaskStatus.QUEUED_BINARY_EXECUTION.value,
            },
        )
    task_store.update_runtime(task_id, runtime_patch)
    queue.ack(QueueNames.BINARY_ANALYSIS, task_id)
    logger.info(
        "task %s binary analysis complete backend=%s functions=%s strings=%s next=%s",
        task_id,
        selected_backend,
        len(result.functions),
        len(result.strings),
        "binary-seed" if binary_seed_stage.get("execute") else "binary-execution",
    )


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("binary analysis worker started")
    while True:
        task_id = queue.pop(QueueNames.BINARY_ANALYSIS, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("binary analysis failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.BINARY_ANALYSIS_FAILED,
                runtime_patch={
                    "binary_analysis_failed_at": task_store.now(),
                    "binary_analysis_error": str(exc),
                },
            )
            queue.ack(QueueNames.BINARY_ANALYSIS, task_id)


if __name__ == "__main__":
    main()

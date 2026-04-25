from __future__ import annotations

import json
from pathlib import Path

from apps.workers.binary_analysis.main import process_task as binary_analysis_task
from apps.workers.binary_seed.main import _write_failure_manifest, process_task as binary_seed_task
from apps.workers.scheduler.main import process_task as schedule_task
from core.models.task import AdapterType, ExecutionMode, TaskSource, TaskSpec, TaskStatus
from scripts.verification_common import (
    LocalQueue,
    PURE_BINARY_DONOR_TASK_ID,
    configure_llm_from_env,
    create_task_with_layout,
    donor_task_root,
    write_report,
)


def main() -> int:
    config = configure_llm_from_env()
    donor_root = donor_task_root(PURE_BINARY_DONOR_TASK_ID)
    binary_source = donor_root / "imports" / "binaries" / "current"
    analysis_path = donor_root / "binary"
    launcher_path = donor_root / "imports" / "launchers" / "current"

    spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.BINARY, uri=str(binary_source), ref="verify_binary_seed_llm"),
        execution_mode=ExecutionMode.IMPORT_ASSISTED,
        metadata={
            "benchmark": "verify_binary_seed_llm",
            "binary_target_name": "cjson_read_fuzzer",
            "binary_mode": "pure_binary",
            "binary_provenance": "pure_binary_input",
            "binary_input_contract": "file",
            "binary_input_contract_source": "manual_input_contract",
            "binary_analysis_backend": "auto",
            "existing_binary_analysis_path": str(analysis_path),
            "existing_launcher_path": str(launcher_path),
            "argv_template": [
                str(launcher_path),
                "{binary_path}",
                "{input_path}",
            ],
            "SEED_GENERATION_BACKEND": "llm",
            "SEED_GENERATION_ATTEMPTS": 1,
            "SEED_FUNCTION_TIMEOUT_SECONDS": 20,
            "SEED_MAX_BYTES": 262144,
        },
    )
    task_store, record = create_task_with_layout(spec, status=TaskStatus.READY)
    queue = LocalQueue()

    schedule_task(record.task_id, task_store, queue)
    binary_analysis_task(record.task_id, task_store, queue)
    seed_error: str | None = None
    try:
        binary_seed_task(record.task_id, task_store, queue)
    except Exception as exc:
        seed_error = str(exc)
        _write_failure_manifest(record.task_id, task_store, seed_error)
        task_store.update_status(
            record.task_id,
            TaskStatus.BINARY_SEED_FAILED,
            runtime_patch={
                "binary_seed_error": seed_error,
                "binary_seed_failed_at": task_store.now(),
            },
        )

    task = task_store.load_task(record.task_id)
    manifest_path = Path(
        task.runtime.get("binary_seed_manifest_path") or Path(task.task_dir) / "binary_seed" / "binary_seed_manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    result = {
        "task_id": record.task_id,
        "status": task.status.value,
        "seed_error": seed_error,
        "request_attempted": manifest.get("llm_request_attempted"),
        "response_received": manifest.get("llm_response_received"),
        "http_status": manifest.get("llm_http_status"),
        "llm_real_call_verified": manifest.get("llm_real_call_verified"),
        "parser_success": bool(manifest.get("llm_used")),
        "generated_seeds_count": manifest.get("generated_seed_count", 0),
        "seed_generation_backend": manifest.get("seed_generation_backend"),
        "llm_provenance": manifest.get("llm_provenance"),
        "imported_seed_count": manifest.get("imported_seed_count"),
        "prompt_sha256": manifest.get("prompt_sha256"),
        "response_sha256": manifest.get("response_sha256"),
        "generated_by": manifest.get("generated_by"),
        "binary_seed_manifest_path": str(manifest_path),
        "binary_seed_task_manifest_path": task.runtime.get("binary_seed_task_manifest_path"),
        "binary_execution_plan_path": task.runtime.get("binary_execution_plan_path"),
        "binary_slice_manifest_path": task.runtime.get("binary_slice_manifest_path"),
        "binary_contamination_report_path": task.runtime.get("binary_contamination_report_path"),
        **config,
    }
    report_path = write_report("verify_binary_seed_llm_path.json", result)
    print(json.dumps({**result, "report_path": str(report_path)}, indent=2))
    return 0 if (task.status == TaskStatus.BINARY_SEEDED and manifest.get("llm_provenance") == "real_llm") else 1


if __name__ == "__main__":
    raise SystemExit(main())

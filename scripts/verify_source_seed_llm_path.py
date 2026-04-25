from __future__ import annotations

import json
from pathlib import Path

from apps.workers.builder.main import process_task as build_task
from apps.workers.downloader.main import process_task as download_task
from apps.workers.program_model.main import process_task as index_task
from apps.workers.scheduler.main import process_task as schedule_task
from apps.workers.seed.main import _write_failure_manifest, process_task as seed_task
from core.models.task import AdapterType, ExecutionMode, TaskSource, TaskSpec, TaskStatus
from scripts.verification_common import (
    BENCHMARKS_ROOT,
    OSS_FUZZ_ROOT,
    SOURCE_DONOR_TASK_ID,
    LocalQueue,
    configure_llm_from_env,
    create_task_with_layout,
    donor_task_root,
    write_report,
)


def main() -> int:
    config = configure_llm_from_env()
    donor_root = donor_task_root(SOURCE_DONOR_TASK_ID)
    source_root = BENCHMARKS_ROOT / "cjson-injected"
    oss_fuzz_project_root = OSS_FUZZ_ROOT / "projects" / "cjson"

    spec = TaskSpec(
        source=TaskSource(adapter_type=AdapterType.OSSFUZZ, uri=str(source_root), ref="verify_source_seed_llm"),
        execution_mode=ExecutionMode.HYBRID,
        metadata={
            "project": "cjson",
            "benchmark": "verify_source_seed_llm",
            "existing_build_out_path": str(donor_root / "build" / "out"),
            "existing_harness_dir": str(source_root / "fuzzing"),
            "existing_oss_fuzz_project_path": str(oss_fuzz_project_root),
            "existing_project_yaml_path": str(oss_fuzz_project_root / "project.yaml"),
            "SEED_GENERATION_BACKEND": "llm",
            "SEED_GENERATION_ATTEMPTS": 1,
            "SEED_MAX_BYTES": 262144,
        },
    )
    task_store, record = create_task_with_layout(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    queue = LocalQueue()

    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)
    seed_error: str | None = None
    try:
        seed_task(record.task_id, task_store, queue)
    except Exception as exc:
        seed_error = str(exc)
        _write_failure_manifest(record.task_id, task_store, seed_error)
        task_store.update_status(
            record.task_id,
            TaskStatus.SEED_FAILED,
            runtime_patch={
                "seed_error": seed_error,
                "seed_failed_at": task_store.now(),
            },
        )

    task = task_store.load_task(record.task_id)
    manifest_path = Path(task.runtime.get("seed_manifest_path") or Path(task.task_dir) / "seed" / "seed_manifest.json")
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
        "seed_manifest_path": str(manifest_path),
        "seed_task_manifest_path": task.runtime.get("seed_task_manifest_path"),
        "execution_plan_path": task.runtime.get("execution_plan_path"),
        **config,
    }
    report_path = write_report("verify_source_seed_llm_path.json", result)
    print(json.dumps({**result, "report_path": str(report_path)}, indent=2))
    return 0 if (task.status == TaskStatus.SEEDED and manifest.get("llm_provenance") == "real_llm") else 1


if __name__ == "__main__":
    raise SystemExit(main())

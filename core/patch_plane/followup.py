from __future__ import annotations

import json
from pathlib import Path

from core.models.task import TaskSpec, TaskStatus
from core.queues.redis_queue import QueueNames
from core.state.task_state import TaskStateStore
from core.storage.layout import create_task_layout
from core.utils.settings import resolve_bool_setting


def _load_json(path_str: str | None) -> dict:
    if not path_str:
        return {}
    path = Path(path_str)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def maybe_enqueue_patch_followup(task_id: str, task_store: TaskStateStore, queue) -> str | None:
    task = task_store.load_task(task_id)
    if task.runtime.get("target_mode") == "binary" or task.runtime.get("adapter_resolution") == "binary":
        return None
    if not resolve_bool_setting(task.metadata, "ENABLE_PATCH_ATTEMPT", False):
        return None
    if task.runtime.get("patch_followup_task_id"):
        return str(task.runtime.get("patch_followup_task_id"))

    project = str(task.metadata.get("project") or "").strip().lower()
    repro_manifest = _load_json(task.runtime.get("repro_manifest_path"))
    testcase_path = repro_manifest.get("testcase_path")
    patch_source_path = task.runtime.get("source_root") or task.metadata.get("source_root") or task.layout.get("src")
    patch_oss_fuzz_project_path = (
        task.runtime.get("resolved_imports", {}).get("existing_oss_fuzz_project_path")
        or task.metadata.get("existing_oss_fuzz_project_path")
    )
    trace_manifest_path = task.runtime.get("trace_manifest_path")
    repro_manifest_path = task.runtime.get("repro_manifest_path")
    active_harness = task.runtime.get("active_harness")
    if not patch_source_path or not patch_oss_fuzz_project_path or not testcase_path or not active_harness:
        return None
    spec = TaskSpec(
        source=task.source.model_copy(deep=True),
        execution_mode=task.execution_mode,
        metadata={
            "project": project,
            "benchmark": f"{project}_patch_followup",
            "patch_base_task_id": task_id,
            "patch_source_path": patch_source_path,
            "patch_oss_fuzz_project_path": patch_oss_fuzz_project_path,
            "patch_testcase_path": testcase_path,
            "expected_harness": active_harness,
            "ENABLE_PATCH_ATTEMPT": False,
        },
    )
    patch_task = task_store.create_task(spec, status=TaskStatus.QUEUED_PATCH)
    task_store.update_task(patch_task.task_id, layout=create_task_layout(patch_task.task_id))
    task_store.update_runtime(
        patch_task.task_id,
        {
            "target_mode": "source",
            "adapter_resolution": "ossfuzz",
            "active_harness": task.runtime.get("active_harness"),
            "active_harness_path": task.runtime.get("active_harness_path"),
            "trace_manifest_path": trace_manifest_path,
            "repro_manifest_path": repro_manifest_path,
            "pov_path": task.runtime.get("pov_path"),
            "source_root": patch_source_path,
        },
    )
    task_store.update_runtime(
        task_id,
        {
            "patch_followup_task_id": patch_task.task_id,
            "patch_followup_status": TaskStatus.QUEUED_PATCH.value,
        },
    )
    queue.push(QueueNames.PATCH, patch_task.task_id)
    return patch_task.task_id

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models.task import TaskRecord
from core.storage.layout import task_meta_path, workspace_manifest_path


def _metadata_value(task: TaskRecord, *names: str) -> Any:
    for name in names:
        if name in task.metadata:
            return task.metadata[name]
    return None


def _source_entry(source_type: str, *, uri: str | None, ref: str | None, localized_path: str | None) -> dict[str, Any]:
    return {
        "type": source_type,
        "uri": uri,
        "ref": ref,
        "localized_path": localized_path,
    }


def write_workspace_manifest(
    task: TaskRecord,
    *,
    layout: dict[str, str],
    runtime: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    """Write original-Buttercup-like workspace metadata for a lite task.

    Original Buttercup downloader materializes a task directory with src/,
    fuzz-tooling/, diff/ and task metadata. Lite keeps the same directories but
    also records exactly how each one was normalized.
    """

    project = _metadata_value(task, "project", "fuzz_tooling_project_name", "project_name")
    deadline = _metadata_value(task, "deadline", "deadline_at")
    duration = _metadata_value(task, "duration", "duration_seconds")
    payload = {
        "task_id": task.task_id,
        "generated_at": generated_at,
        "compat_source": "original_buttercup.downloader.TaskMeta",
        "project_name": project,
        "focus": _metadata_value(task, "focus") or project,
        "task_type": _metadata_value(task, "task_type") or "full",
        "duration_seconds": duration,
        "deadline": deadline,
        "source_entries": [
            _source_entry(
                "repo",
                uri=task.source.uri,
                ref=task.source.ref,
                localized_path=runtime.get("source_root") or layout.get("src"),
            ),
            _source_entry(
                "fuzz-tooling",
                uri=_metadata_value(task, "fuzz_tooling_url", "fuzz_tooling_repo_url"),
                ref=_metadata_value(task, "fuzz_tooling_ref", "fuzz_tooling_branch"),
                localized_path=runtime.get("fuzz_tooling_root") or layout.get("fuzz_tooling"),
            ),
            _source_entry(
                "diff",
                uri=_metadata_value(task, "diff_url", "diff_path"),
                ref=None,
                localized_path=layout.get("diff"),
            ),
        ],
        "canonical_layout": {
            "task_dir": task.task_dir,
            "src": layout.get("src"),
            "fuzz_tooling": layout.get("fuzz_tooling"),
            "diff": layout.get("diff"),
            "task_meta": str(task_meta_path(task.task_id)),
            "imports": layout.get("imports"),
            "index": layout.get("index"),
            "build": layout.get("build"),
            "seed": layout.get("seed"),
            "corpus": layout.get("corpus"),
            "crashes": layout.get("crashes"),
            "trace": layout.get("trace"),
            "pov": layout.get("pov"),
            "patch_reserved": layout.get("patch_reserved"),
        },
        "normalization": {
            "source_contract_kind": runtime.get("source_contract_kind"),
            "source_localized_from": runtime.get("source_localized_from"),
            "fuzz_tooling_contract_kind": runtime.get("fuzz_tooling_contract_kind"),
            "fuzz_tooling_localized_from": runtime.get("fuzz_tooling_localized_from"),
            "existing_oss_fuzz_project_path": runtime.get("existing_oss_fuzz_project_path")
            or task.metadata.get("existing_oss_fuzz_project_path"),
            "existing_project_yaml_path": runtime.get("existing_project_yaml_path")
            or task.metadata.get("existing_project_yaml_path"),
        },
    }

    meta = {
        "project_name": project,
        "focus": payload["focus"],
        "task_id": task.task_id,
        "metadata": task.metadata,
        "compat_source": "original_buttercup.common.task_meta.TaskMeta",
    }
    meta_file = task_meta_path(task.task_id)
    meta_file.parent.mkdir(parents=True, exist_ok=True)
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    manifest_file = workspace_manifest_path(task.task_id)
    manifest_file.parent.mkdir(parents=True, exist_ok=True)
    manifest_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {**payload, "workspace_manifest_path": str(manifest_file), "task_meta_path": str(meta_file)}

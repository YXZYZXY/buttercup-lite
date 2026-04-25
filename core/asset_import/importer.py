from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models.task import TaskRecord
from core.storage.layout import asset_import_manifest_path


ASSET_CATEGORIES = {
    "prebuilt_index_artifacts": ["existing_index_path"],
    "prebuilt_fuzz_build_outputs": [
        "existing_build_out_path",
        "existing_harness_dir",
        "existing_dict_path",
        "existing_options_path",
    ],
    "seed_corpus": [
        "existing_seed_path",
        "existing_corpus_path",
    ],
    "crash_samples": [
        "existing_crashes_path",
        "existing_valid_crashes_path",
    ],
    "traced_inputs": [
        "existing_valid_crashes_path",
    ],
    "binary_inputs": [
        "existing_binary_path",
        "existing_binary_analysis_path",
        "existing_wrapper_path",
        "existing_launcher_path",
    ],
    "oss_fuzz_assets": [
        "existing_oss_fuzz_project_path",
        "existing_project_yaml_path",
    ],
}


def _entry(field_name: str, import_manifest: dict[str, Any]) -> dict[str, Any]:
    assets = import_manifest.get("assets", {})
    resolved_paths = import_manifest.get("resolved_paths", {})
    asset = assets.get(field_name, {})
    return {
        "field": field_name,
        "provided_path": asset.get("provided_path"),
        "resolved_path": resolved_paths.get(field_name) or asset.get("resolved_path"),
        "exists": bool(asset.get("exists")),
        "kind": asset.get("kind"),
        "strategy": asset.get("strategy"),
    }


def write_asset_import_manifest(task: TaskRecord, import_manifest: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    categories: dict[str, list[dict[str, Any]]] = {}
    for category, fields in ASSET_CATEGORIES.items():
        categories[category] = [_entry(field, import_manifest) for field in fields]
    payload = {
        "task_id": task.task_id,
        "generated_at": generated_at,
        "compat_source": "original_buttercup engineering reuse pattern",
        "mode": "import-and-continue" if import_manifest.get("resolved_paths") else "fresh-run",
        "supported_asset_categories": list(ASSET_CATEGORIES),
        "categories": categories,
        "resolved_paths": import_manifest.get("resolved_paths", {}),
        "imported_asset_count": sum(
            1
            for entries in categories.values()
            for item in entries
            if item.get("exists")
        ),
    }
    path = asset_import_manifest_path(task.task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {**payload, "asset_import_manifest_path": str(path)}

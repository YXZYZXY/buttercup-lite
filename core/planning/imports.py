from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from core.asset_import import write_asset_import_manifest
from core.models.task import AdapterType, TaskRecord
from core.protocol_runtime import relative_to_task_root
from core.storage.layout import import_manifest_path
from core.utils.settings import expand_local_path

IMPORT_FIELD_SPECS = {
    "existing_src_path": {"layout_key": "imports_src", "alias": "current"},
    "existing_index_path": {"layout_key": "imports_index", "alias": "current"},
    "existing_build_out_path": {"layout_key": "imports_build", "alias": "out"},
    "existing_corpus_path": {"layout_key": "imports_corpus", "alias": "current"},
    "existing_seed_path": {"layout_key": "imports_seed", "alias": "current"},
    "existing_crashes_path": {"layout_key": "imports_crashes", "alias": "current"},
    "existing_valid_crashes_path": {"layout_key": "imports_valid_crashes", "alias": "current"},
    "existing_binary_path": {"layout_key": "imports_binaries", "alias": "current"},
    "existing_binary_analysis_path": {"layout_key": "imports_analysis", "alias": "current"},
    "existing_harness_dir": {"layout_key": "imports_harnesses", "alias": "current"},
    "existing_dict_path": {"layout_key": "imports_build", "alias": "dict"},
    "existing_options_path": {"layout_key": "imports_build", "alias": "options"},
    "existing_oss_fuzz_project_path": {"layout_key": "imports_manifests", "alias": "oss_fuzz_project"},
    "existing_project_yaml_path": {"layout_key": "imports_manifests", "alias": "project.yaml"},
    "existing_wrapper_path": {"layout_key": "imports_wrappers", "alias": "current"},
    "existing_launcher_path": {"layout_key": "imports_launchers", "alias": "current"},
}


def _raw_value(task: TaskRecord, field_name: str) -> str | None:
    if field_name == "existing_binary_path" and task.source.adapter_type.value == "binary":
        return task.runtime.get(field_name) or task.metadata.get(field_name) or task.source.uri
    return task.runtime.get(field_name) or task.metadata.get(field_name)


def _remove_existing_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    if path.exists() and path.is_dir():
        shutil.rmtree(path)


def _link_asset(source_path: Path, destination_path: Path) -> Path:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists() or destination_path.is_symlink():
        _remove_existing_path(destination_path)
    destination_path.symlink_to(source_path, target_is_directory=source_path.is_dir())
    return destination_path


def _copy_asset(source_path: Path, destination_path: Path) -> Path:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists() or destination_path.is_symlink():
        _remove_existing_path(destination_path)
    shutil.copy2(source_path, destination_path)
    return destination_path


def _stage_protocol_imports(task: TaskRecord, now: str) -> dict[str, Any]:
    task_root = Path(task.task_dir)
    localized_inputs = dict(task.runtime.get("localized_inputs") or {})
    assets: dict[str, Any] = {}
    resolved_paths: dict[str, str] = {}
    for field_name in ("pcap_path", "prompt_template_path", "existing_corpus_path"):
        raw_value = localized_inputs.get(field_name) or task.metadata.get(field_name)
        if not raw_value:
            continue
        candidate = Path(raw_value)
        resolved = candidate if candidate.is_absolute() else (task_root / candidate).resolve()
        relative_path = relative_to_task_root(task_root, resolved) or str(raw_value)
        entry: dict[str, Any] = {
            "field": field_name,
            "provided_path": relative_path,
            "resolved_path": relative_path,
            "exists": resolved.exists(),
            "imported_at": now,
            "strategy": "localized",
            "kind": "directory" if resolved.is_dir() else "file",
        }
        assets[field_name] = entry
        if resolved.exists():
            resolved_paths[field_name] = relative_path
    manifest = {
        "task_id": task.task_id,
        "generated_at": now,
        "assets": assets,
        "resolved_paths": resolved_paths,
        "asset_import_manifest_path": None,
        "asset_import_mode": "protocol_localized",
        "imported_asset_count": len(resolved_paths),
    }
    manifest_path = import_manifest_path(task.task_id)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def stage_task_imports(task: TaskRecord, now: str) -> dict[str, Any]:
    if task.source.adapter_type == AdapterType.PROTOCOL:
        return _stage_protocol_imports(task, now)

    assets: dict[str, Any] = {}
    resolved_paths: dict[str, str] = {}

    for field_name, spec in IMPORT_FIELD_SPECS.items():
        raw_value = _raw_value(task, field_name)
        if not raw_value:
            continue

        source_path = expand_local_path(raw_value)
        layout_root = Path(task.layout[spec["layout_key"]])
        destination_path = layout_root / spec["alias"]
        entry: dict[str, Any] = {
            "field": field_name,
            "provided_path": str(source_path),
            "resolved_path": str(destination_path),
            "exists": source_path.exists(),
            "imported_at": now,
            "strategy": "symlink",
        }

        if source_path.exists():
            if field_name == "existing_binary_path" and source_path.is_file():
                _copy_asset(source_path, destination_path)
                entry["strategy"] = "copy"
            else:
                _link_asset(source_path, destination_path)
            entry["kind"] = "directory" if source_path.is_dir() else "file"
            resolved_paths[field_name] = str(destination_path)
        else:
            entry["kind"] = "missing"

        assets[field_name] = entry

    manifest = {
        "task_id": task.task_id,
        "generated_at": now,
        "assets": assets,
        "resolved_paths": resolved_paths,
    }
    asset_import_manifest = write_asset_import_manifest(task, manifest, generated_at=now)
    manifest["asset_import_manifest_path"] = asset_import_manifest["asset_import_manifest_path"]
    manifest["asset_import_mode"] = asset_import_manifest["mode"]
    manifest["imported_asset_count"] = asset_import_manifest["imported_asset_count"]
    manifest_path = import_manifest_path(task.task_id)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

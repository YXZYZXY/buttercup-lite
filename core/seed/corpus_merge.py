from __future__ import annotations

import logging
import shutil
import tempfile
import zipfile
from pathlib import Path

from core.campaign.corpus_merger import merge_corpus_layers
from core.utils.settings import settings
from core.storage.layout import (
    seed_corpus_merge_manifest_path,
    seed_import_material_manifest_path,
    task_json_path,
)

logger = logging.getLogger(__name__)


def _task_id_from_path(path: Path) -> str | None:
    parts = path.resolve().parts
    try:
        index = parts.index("tasks")
    except ValueError:
        return None
    if index + 1 >= len(parts):
        return None
    return parts[index + 1]


def _task_context_from_path(path: Path) -> dict[str, str | None]:
    task_id = _task_id_from_path(path)
    if not task_id:
        return {"task_id": None, "project": None, "lane": None, "target_mode": None}
    payload = {}
    task_json = task_json_path(task_id)
    if task_json.exists():
        try:
            import json

            payload = json.loads(task_json.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
    metadata = payload.get("metadata") or {}
    runtime = payload.get("runtime") or {}
    lane = (
        runtime.get("fabric_lane")
        or runtime.get("campaign_lane")
        or metadata.get("fabric_lane")
        or metadata.get("campaign_lane")
    )
    if not lane:
        if metadata.get("generalized_source") or runtime.get("generalized_source"):
            lane = "generalized"
        elif metadata.get("binary_mode") or runtime.get("binary_mode"):
            lane = "binary"
        else:
            lane = "source"
    target_mode = metadata.get("target_mode") or runtime.get("target_mode") or ("binary" if lane == "binary" else "source")
    return {
        "task_id": task_id,
        "project": metadata.get("project"),
        "lane": str(lane),
        "target_mode": str(target_mode),
    }


def stage_imported_seed_material(
    *,
    imported_seed_path: str | None,
    imported_corpus_path: str | None,
    seed_corpus_zips: list[str],
    output_dir: Path,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    task_ctx = _task_context_from_path(output_dir)
    layers: list[dict[str, object]] = []
    temp_dirs: list[tempfile.TemporaryDirectory[str]] = []

    try:
        if imported_seed_path and Path(imported_seed_path).exists():
            layers.append(
                {
                    "root": str(Path(imported_seed_path)),
                    "label": "imported_seed",
                    "scope": "task_seed_import",
                    "project": task_ctx["project"],
                    "lane": task_ctx["lane"],
                    "target_mode": task_ctx["target_mode"],
                    "priority_weight": 3.5,
                    "task_id": task_ctx["task_id"],
                }
            )
        if imported_corpus_path and Path(imported_corpus_path).exists():
            layers.append(
                {
                    "root": str(Path(imported_corpus_path)),
                    "label": "imported_seed",
                    "scope": "task_seed_import",
                    "project": task_ctx["project"],
                    "lane": task_ctx["lane"],
                    "target_mode": task_ctx["target_mode"],
                    "priority_weight": 3.4,
                    "task_id": task_ctx["task_id"],
                }
            )
        for index, zip_path_str in enumerate(seed_corpus_zips):
            zip_path = Path(zip_path_str)
            if not zip_path.exists():
                continue
            temp_dir = tempfile.TemporaryDirectory(prefix=f"seed-corpus-zip-{index}-")
            temp_dirs.append(temp_dir)
            extract_root = Path(temp_dir.name)
            with zipfile.ZipFile(zip_path) as zf:
                for member in zf.namelist():
                    member_name = Path(member).name
                    if not member_name:
                        continue
                    target = extract_root / member_name
                    target.write_bytes(zf.read(member))
            layers.append(
                {
                    "root": str(extract_root),
                    "label": "seed_corpus_zip",
                    "scope": "task_seed_import",
                    "project": task_ctx["project"],
                    "lane": task_ctx["lane"],
                    "target_mode": task_ctx["target_mode"],
                    "priority_weight": 3.2,
                    "task_id": task_ctx["task_id"],
                }
            )

        if not layers:
            return 0

        task_id = str(task_ctx["task_id"] or "")
        manifest_path = seed_import_material_manifest_path(task_id) if task_id else output_dir.parent / "import_material_manifest.json"
        index_path = manifest_path.with_name("import_material_index.json")
        summary = merge_corpus_layers(
            output_dir,
            layers,
            destination_kind="seed_import",
            destination_scope="task_seed_import",
            destination_project=str(task_ctx["project"] or ""),
            destination_lane=str(task_ctx["lane"] or ""),
            destination_target_mode=str(task_ctx["target_mode"] or ""),
            destination_harness=None,
            decision_log_path=manifest_path,
            index_path=index_path,
            max_files=settings.seed_import_sample_limit,
            max_bytes=16 * 1024 * 1024,
            per_semantic_limit=2,
        )
        logger.info(
            "staged imported seed material into %s selected=%s copied=%s semantic_pruned=%s",
            output_dir,
            summary["selected_count"],
            summary["copied_count"],
            summary["semantic_pruned_count"],
        )
        return int(summary["file_count_after"])
    finally:
        for temp_dir in temp_dirs:
            temp_dir.cleanup()


def merge_generated_seeds(
    generated_files: list[str],
    corpus_active_dir: Path,
    *,
    imported_seed_dir: Path | None = None,
) -> list[str]:
    corpus_active_dir.mkdir(parents=True, exist_ok=True)
    task_ctx = _task_context_from_path(corpus_active_dir)
    temp_dir = tempfile.TemporaryDirectory(prefix="generated-seeds-")
    temp_root = Path(temp_dir.name)
    try:
        for index, file_path_str in enumerate(generated_files):
            file_path = Path(file_path_str)
            if not file_path.exists():
                continue
            target = temp_root / f"{index:04d}_{file_path.name}"
            shutil.copy2(file_path, target)

        layers: list[dict[str, object]] = [
            {
                "root": str(temp_root),
                "label": "generated_seed",
                "scope": "round_local",
                "project": task_ctx["project"],
                "lane": task_ctx["lane"],
                "target_mode": task_ctx["target_mode"],
                "priority_weight": 7.0,
                "task_id": task_ctx["task_id"],
            }
        ]
        if imported_seed_dir and imported_seed_dir.exists():
            layers.append(
                {
                    "root": str(imported_seed_dir),
                    "label": "imported_seed",
                    "scope": "task_seed_import",
                    "project": task_ctx["project"],
                    "lane": task_ctx["lane"],
                    "target_mode": task_ctx["target_mode"],
                    "priority_weight": 3.5,
                    "task_id": task_ctx["task_id"],
                }
            )

        task_id = str(task_ctx["task_id"] or "")
        manifest_path = seed_corpus_merge_manifest_path(task_id) if task_id else corpus_active_dir.parent / "corpus_merge_manifest.json"
        index_path = manifest_path.with_name("corpus_merge_index.json")
        summary = merge_corpus_layers(
            corpus_active_dir,
            layers,
            destination_kind="seed_active",
            destination_scope="round_local",
            destination_project=str(task_ctx["project"] or ""),
            destination_lane=str(task_ctx["lane"] or ""),
            destination_target_mode=str(task_ctx["target_mode"] or ""),
            destination_harness=None,
            decision_log_path=manifest_path,
            index_path=index_path,
            max_files=256,
            max_bytes=64 * 1024 * 1024,
            per_semantic_limit=2,
        )
        logger.info(
            "merged generated seeds into %s selected=%s copied=%s deleted=%s cross_harness=%s",
            corpus_active_dir,
            summary["selected_count"],
            summary["copied_count"],
            summary["deleted_count"],
            summary["cross_harness_selected_count"],
        )
        return [
            str(item["destination_path"])
            for item in summary.get("selected_files", [])
            if item.get("source_label") in {"generated_seed", "imported_seed"}
        ]
    finally:
        temp_dir.cleanup()

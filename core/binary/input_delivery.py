from __future__ import annotations

import shutil
from pathlib import Path

from core.binary.models import BinaryExecutionInput
from core.utils.settings import resolve_bool_setting, resolve_int_setting, settings


def _reset_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def _iter_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    if path.is_file():
        return [path]
    return sorted(candidate for candidate in path.iterdir() if candidate.is_file())


def _stage_group(
    *,
    source_path: Path | None,
    source_kind: str,
    imported_dir: Path,
    active_dir: Path,
    prefix: str,
    limit: int,
) -> list[BinaryExecutionInput]:
    if source_path is None or not source_path.exists():
        return []
    staged: list[BinaryExecutionInput] = []
    for index, candidate in enumerate(_iter_files(source_path)):
        if index >= limit:
            break
        target_name = f"{prefix}_{index:03d}_{candidate.name}"
        imported_path = imported_dir / target_name
        active_path = active_dir / target_name
        shutil.copy2(candidate, imported_path)
        shutil.copy2(imported_path, active_path)
        staged.append(
            BinaryExecutionInput(
                path=active_path,
                source_kind=source_kind,
                source_path=str(candidate),
                size=active_path.stat().st_size,
            ),
        )
    return staged


def stage_binary_execution_inputs(task) -> list[BinaryExecutionInput]:
    resolved_imports = task.runtime.get("resolved_imports", {})
    binary_mode = str(task.runtime.get("binary_mode") or task.metadata.get("binary_mode") or "")
    imported_dir = Path(task.layout["corpus_imported"])
    active_dir = Path(task.layout["corpus_active"])
    binary_active_dir = Path(task.layout.get("corpus_binary_active", active_dir))
    binary_generated_dir = Path(task.layout.get("binary_seed_generated", Path(task.task_dir) / "binary_seed" / "generated"))
    _reset_directory(imported_dir)
    _reset_directory(active_dir)
    _reset_directory(binary_active_dir)

    sample_limit = resolve_int_setting(task.metadata, "SEED_IMPORT_SAMPLE_LIMIT", settings.seed_import_sample_limit)
    crash_limit = resolve_int_setting(
        task.metadata,
        "FUZZ_IMPORTED_VALID_SEED_LIMIT",
        settings.fuzz_imported_valid_seed_limit,
    )
    allow_imported_seed_material = resolve_bool_setting(task.metadata, "allow_imported_seed_material", True)
    allow_source_side_imports = allow_imported_seed_material and binary_mode != "pure_binary"

    inputs: list[BinaryExecutionInput] = []
    inputs.extend(
        _stage_group(
            source_path=binary_generated_dir if binary_generated_dir.exists() else None,
            source_kind="binary_native_corpus",
            imported_dir=imported_dir,
            active_dir=binary_active_dir,
            prefix="binary_corpus",
            limit=sample_limit,
        ),
    )
    if allow_source_side_imports:
        inputs.extend(
            _stage_group(
                source_path=Path(resolved_imports["existing_seed_path"]) if resolved_imports.get("existing_seed_path") else None,
                source_kind="imported_seed",
                imported_dir=imported_dir,
                active_dir=active_dir,
                prefix="seed",
                limit=sample_limit,
            ),
        )
        inputs.extend(
            _stage_group(
                source_path=Path(resolved_imports["existing_corpus_path"]) if resolved_imports.get("existing_corpus_path") else None,
                source_kind="imported_corpus",
                imported_dir=imported_dir,
                active_dir=active_dir,
                prefix="corpus",
                limit=sample_limit,
            ),
        )
        inputs.extend(
            _stage_group(
                source_path=Path(resolved_imports["existing_crashes_path"]) if resolved_imports.get("existing_crashes_path") else None,
                source_kind="imported_testcase",
                imported_dir=imported_dir,
                active_dir=active_dir,
                prefix="testcase",
                limit=crash_limit,
            ),
        )
    if not inputs:
        raise RuntimeError("no binary execution inputs were staged")
    return inputs

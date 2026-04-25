from __future__ import annotations

import shutil
from pathlib import Path

INDEX_ARTIFACT_NAMES = (
    "manifest.json",
    "source_files.txt",
    "cscope.files",
    "cscope.out",
    "cscope.in.out",
    "cscope.po.out",
    "tags",
    "codequery.db",
    "symbols.json",
)


def _copy_file(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination


def import_source_tree(source_path: str | Path, destination_dir: str | Path) -> Path:
    source = Path(source_path).expanduser().resolve()
    destination = Path(destination_dir)
    if not source.exists() or not source.is_dir():
        raise FileNotFoundError(source)

    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        return destination

    for child in source.iterdir():
        target = destination / child.name
        if child.is_dir():
            shutil.copytree(child, target, dirs_exist_ok=True)
        else:
            shutil.copy2(child, target)

    return destination


def _find_index_artifact(search_roots: list[Path], name: str) -> Path | None:
    for root in search_roots:
        candidate = root / name
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def import_index_artifacts(
    source_path: str | Path,
    raw_import_dir: str | Path,
    canonical_index_dir: str | Path,
) -> dict[str, str]:
    source = Path(source_path).expanduser().resolve()
    raw_dir = Path(raw_import_dir)
    index_dir = Path(canonical_index_dir)
    if not source.exists():
        raise FileNotFoundError(source)

    raw_dir.mkdir(parents=True, exist_ok=True)
    index_dir.mkdir(parents=True, exist_ok=True)

    search_roots: list[Path]
    if source.is_dir():
        search_roots = [source]
        nested_index = source / "index"
        if nested_index.exists() and nested_index.is_dir():
            search_roots.append(nested_index)
    else:
        search_roots = [source.parent]

    imported: dict[str, str] = {}
    for artifact_name in INDEX_ARTIFACT_NAMES:
        artifact_source = _find_index_artifact(search_roots, artifact_name)
        if artifact_source is None:
            if source.is_file() and source.name == artifact_name:
                artifact_source = source
            else:
                continue

        raw_destination = _copy_file(artifact_source, raw_dir / artifact_name)
        if artifact_name != "manifest.json":
            canonical_destination = _copy_file(artifact_source, index_dir / artifact_name)
            imported[artifact_name] = str(canonical_destination)
        else:
            imported[artifact_name] = str(raw_destination)

    return imported

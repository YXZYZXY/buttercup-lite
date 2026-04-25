from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

STANDARD_FILES = {
    "manifest": "manifest.json",
    "summary": "analysis_summary.json",
    "functions": "functions.json",
    "strings": "strings.json",
    "imports": "imports.json",
    "exports": "exports.json",
    "entrypoints": "entrypoints.json",
}


def import_binary_asset(source_path: Path, destination_path: Path) -> Path:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists() or destination_path.is_symlink():
        if destination_path.is_dir() and not destination_path.is_symlink():
            shutil.rmtree(destination_path)
        else:
            destination_path.unlink()
    destination_path.symlink_to(source_path, target_is_directory=source_path.is_dir())
    return destination_path


def _load_json(path: Path, fallback: Any) -> Any:
    if not path.exists() or not path.is_file():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return fallback


def load_imported_analysis(analysis_root: Path) -> dict[str, Any]:
    root = analysis_root
    if root.is_file():
        root = root.parent
    loaded: dict[str, Any] = {}
    for key, filename in STANDARD_FILES.items():
        loaded[key] = _load_json(root / filename, {} if key in {"manifest", "summary"} else [])
    return loaded

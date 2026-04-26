import json
from pathlib import Path
from typing import Any

from core.program_model.runtime_query import ProgramModelRuntimeView, get_runtime_view
from core.storage.layout import task_root


def build_index(*args, **kwargs):
    from core.program_model.code_index import build_index as _build_index

    return _build_index(*args, **kwargs)


def build_context_package(*args, **kwargs):
    from core.program_model.context_package import build_context_package as _build_context_package

    return _build_context_package(*args, **kwargs)


def _index_dir(task_id: str) -> Path:
    return task_root(task_id) / "index"


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def get_index_manifest(task_id: str) -> dict[str, Any]:
    return _read_json(_index_dir(task_id) / "manifest.json", {})


def list_source_files(task_id: str) -> list[str]:
    source_files_path = _index_dir(task_id) / "source_files.txt"
    if not source_files_path.exists():
        return []
    return [line for line in source_files_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def search_symbol(task_id: str, name: str) -> list[dict[str, Any]]:
    needle = name.lower()
    symbols = _read_json(_index_dir(task_id) / "symbols.json", [])
    return [symbol for symbol in symbols if needle in str(symbol.get("name", "")).lower()]


def load_function_candidates(task_id: str, name: str) -> list[dict[str, Any]]:
    function_kinds = {"f", "function", "prototype", "method"}
    return [
        symbol
        for symbol in search_symbol(task_id, name)
        if str(symbol.get("kind", "")).lower() in function_kinds
    ]


__all__ = [
    "build_index",
    "build_context_package",
    "ProgramModelRuntimeView",
    "get_runtime_view",
    "get_index_manifest",
    "list_source_files",
    "search_symbol",
    "load_function_candidates",
]

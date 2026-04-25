from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models.task import ExecutionMode
from core.program_model.fact_index import extract_function_facts, extract_type_facts
from core.program_model.importer import import_index_artifacts, import_source_tree
from core.program_model.index_request import IndexRequest
from core.utils.settings import settings

SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".inc",
    ".inl",
    ".ipp",
    ".java",
    ".kt",
    ".go",
    ".rs",
    ".py",
    ".js",
    ".ts",
}
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "build",
    "dist",
    "__pycache__",
}
CONTROL_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch"}
FUNCTION_PATTERN = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s\*\(\),]*?\s+)?([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
    re.MULTILINE,
)
TAG_LINE_PATTERN = re.compile(r"^(\d+);\"$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def collect_source_files(source_dir: Path) -> list[Path]:
    if not source_dir.exists():
        return []

    collected: list[Path] = []
    for candidate in source_dir.rglob("*"):
        if not candidate.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in candidate.parts):
            continue
        if candidate.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        collected.append(candidate.resolve())

    return sorted(collected)


def _run_optional_command(command: list[str], cwd: Path, timeout: int = 300) -> dict[str, Any]:
    tool_name = command[0]
    tool_path = shutil.which(tool_name)
    search_paths: list[str] = []
    for prefix_str in (settings.program_model_toolchain_prefix, settings.build_toolchain_prefix):
        prefix = Path(prefix_str).expanduser()
        for candidate in (prefix / "bin", prefix / "usr" / "bin"):
            if candidate.exists():
                search_paths.append(str(candidate))
    if tool_name == "ctags":
        search_candidates = ["ctags", "ctags-universal"]
    else:
        search_candidates = [tool_name]
    path_env = os.pathsep.join(search_paths) if search_paths else None
    if tool_path is None and path_env:
        for candidate in search_candidates:
            tool_path = shutil.which(candidate, path=path_env)
            if tool_path is not None:
                break
    if tool_path is None:
        return {"available": False, "ran": False}

    try:
        completed = subprocess.run(
            [tool_path, *command[1:]],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=None if path_env is None else {**os.environ, "PATH": f"{path_env}:{os.environ.get('PATH', '')}"},
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "ran": True, "exit_code": None, "timed_out": True}

    return {
        "available": True,
        "ran": True,
        "tool_path": tool_path,
        "exit_code": completed.returncode,
        "timed_out": False,
        "stderr": completed.stderr[-500:],
    }


def _normalize_symbol_path(raw_path: str, source_root: Path | None) -> str:
    path = Path(raw_path)
    if path.is_absolute() or source_root is None:
        return str(path)
    return str((source_root / path).resolve())


def _parse_tag_line_number(pattern: str, extras: list[str]) -> int | None:
    for extra in extras:
        if not extra.startswith("line:"):
            continue
        try:
            return int(extra.split(":", 1)[1])
        except ValueError:
            return None

    match = TAG_LINE_PATTERN.match(pattern.strip())
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def load_symbols_from_tags(tags_path: Path, source_root: Path | None) -> list[dict[str, Any]]:
    if not tags_path.exists():
        return []

    symbols: list[dict[str, Any]] = []
    for line in tags_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("!_TAG"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, file_path, pattern, *extras = parts
        kind = extras[0] if extras else "symbol"
        line_number = _parse_tag_line_number(pattern, extras[1:])

        symbols.append(
            {
                "name": name,
                "kind": kind,
                "file": _normalize_symbol_path(file_path, source_root),
                "line": line_number,
                "source": "ctags",
            },
        )

    return deduplicate_symbols(symbols)


def scan_source_symbols(source_files: list[Path]) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []
    for source_file in source_files:
        try:
            text = source_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            match = FUNCTION_PATTERN.match(line)
            if match is None:
                continue
            symbol_name = match.group(1)
            if symbol_name in CONTROL_KEYWORDS:
                continue
            symbols.append(
                {
                    "name": symbol_name,
                    "kind": "function",
                    "file": str(source_file),
                    "line": line_number,
                    "source": "regex",
                },
            )

    return deduplicate_symbols(symbols)


def deduplicate_symbols(symbols: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, int | None]] = set()
    unique: list[dict[str, Any]] = []
    for symbol in symbols:
        key = (
            str(symbol.get("name", "")),
            str(symbol.get("kind", "")),
            str(symbol.get("file", "")),
            symbol.get("line"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(symbol)
    return unique


def _canonical_artifact_map(index_dir: Path) -> dict[str, str]:
    artifacts = {}
    for artifact_name in (
        "manifest.json",
        "source_files.txt",
        "cscope.files",
        "cscope.out",
        "cscope.in.out",
        "cscope.po.out",
        "tags",
        "codequery.db",
        "symbols.json",
        "function_facts.json",
        "type_facts.json",
        "call_graph.json",
    ):
        artifact_path = index_dir / artifact_name
        if artifact_path.exists():
            artifacts[artifact_name] = str(artifact_path)
    return artifacts


def build_index(request: IndexRequest) -> dict[str, Any]:
    request.source_dir.mkdir(parents=True, exist_ok=True)
    request.index_dir.mkdir(parents=True, exist_ok=True)
    request.imports_src_dir.mkdir(parents=True, exist_ok=True)
    request.imports_index_dir.mkdir(parents=True, exist_ok=True)

    imported_from: dict[str, str] = {}
    if request.existing_src_path:
        import_source_tree(request.existing_src_path, request.source_dir)
        imported_from["src"] = str(Path(request.existing_src_path).expanduser())
    elif Path(request.source_uri).exists() and Path(request.source_uri).is_dir():
        import_source_tree(request.source_uri, request.source_dir)

    imported_index_artifacts: dict[str, str] = {}
    if request.existing_index_path:
        imported_index_artifacts = import_index_artifacts(
            request.existing_index_path,
            request.imports_index_dir,
            request.index_dir,
        )
        imported_from["index"] = str(Path(request.existing_index_path).expanduser())

    source_files = collect_source_files(request.source_dir)
    source_files_txt = request.index_dir / "source_files.txt"
    cscope_files = request.index_dir / "cscope.files"

    if source_files:
        source_lines = [str(path) for path in source_files]
        _write_lines(source_files_txt, source_lines)
        _write_lines(cscope_files, source_lines)
    elif source_files_txt.exists():
        source_files = [Path(line) for line in _read_lines(source_files_txt)]
    elif cscope_files.exists():
        source_files = [Path(line) for line in _read_lines(cscope_files)]
        _write_lines(source_files_txt, [str(path) for path in source_files])

    if not source_files and not imported_index_artifacts:
        raise RuntimeError("no source files or imported index artifacts available for indexing")

    tool_runs: dict[str, Any] = {
        "ctags": {"available": False, "ran": False},
        "cscope": {"available": False, "ran": False},
        "cqmakedb": {"available": False, "ran": False},
    }
    if source_files:
        tool_runs["cscope"] = _run_optional_command(
            ["cscope", "-cbq"],
            cwd=request.index_dir,
            timeout=300,
        )
        tool_runs["ctags"] = _run_optional_command(
            ["ctags", "--fields=+in", "-n", "-L", "cscope.files", "-f", "tags"],
            cwd=request.index_dir,
            timeout=300,
        )
        if (request.index_dir / "cscope.out").exists() and (request.index_dir / "tags").exists():
            tool_runs["cqmakedb"] = _run_optional_command(
                ["cqmakedb", "-s", "codequery.db", "-c", "cscope.out", "-t", "tags", "-p"],
                cwd=request.index_dir,
                timeout=1800,
            )

    symbols = load_symbols_from_tags(request.index_dir / "tags", request.source_dir)
    if not symbols:
        symbols = scan_source_symbols(source_files)

    symbols_path = request.index_dir / "symbols.json"
    symbols_path.write_text(json.dumps(symbols, indent=2), encoding="utf-8")
    function_facts, call_graph = extract_function_facts(source_files)
    function_facts_path = request.index_dir / "function_facts.json"
    function_facts_path.write_text(json.dumps(function_facts, indent=2), encoding="utf-8")
    type_facts = extract_type_facts(source_files)
    type_facts_path = request.index_dir / "type_facts.json"
    type_facts_path.write_text(json.dumps(type_facts, indent=2), encoding="utf-8")
    call_graph_path = request.index_dir / "call_graph.json"
    call_graph_path.write_text(json.dumps(call_graph, indent=2), encoding="utf-8")

    if imported_index_artifacts:
        mode = ExecutionMode.IMPORT_ASSISTED.value
    elif imported_from.get("src"):
        mode = ExecutionMode.HYBRID.value
    else:
        mode = ExecutionMode.FRESH.value

    manifest = {
        "task_id": request.task_id,
        "mode": mode,
        "generated_at": utc_now(),
        "imported_at": utc_now() if imported_from else None,
        "imported_from": imported_from,
        "source_root": str(request.source_dir),
        "source_file_count": len(source_files),
        "symbol_count": len(symbols),
        "function_fact_count": len(function_facts),
        "type_fact_count": len(type_facts),
        "tools": tool_runs,
        "artifacts": _canonical_artifact_map(request.index_dir),
    }
    manifest_path = request.index_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    manifest["artifacts"] = _canonical_artifact_map(request.index_dir)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

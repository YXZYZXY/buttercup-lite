from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.utils.settings import settings


@dataclass
class CQSearchMatch:
    value: str
    file: str
    line: int
    body: str

    @classmethod
    def from_line(cls, line: str) -> "CQSearchMatch | None":
        try:
            value, file_line, body = line.split("\t", 2)
            file_path, line_str = file_line.rsplit(":", 1)
            return cls(
                value=value,
                file=file_path,
                line=int(line_str),
                body=body,
            )
        except (ValueError, TypeError):
            return None


def _tool_prefixes() -> list[Path]:
    prefixes = []
    for prefix_str in (settings.program_model_toolchain_prefix, settings.build_toolchain_prefix):
        prefix = Path(prefix_str).expanduser()
        if prefix.exists():
            prefixes.append(prefix)
    return prefixes


def tool_environment() -> dict[str, str]:
    env = os.environ.copy()
    path_entries: list[str] = []
    lib_entries: list[str] = []
    for prefix in _tool_prefixes():
        for candidate in (prefix / "bin", prefix / "usr" / "bin"):
            if candidate.exists():
                path_entries.append(str(candidate))
        for candidate in (
            prefix / "lib",
            prefix / "lib64",
            prefix / "usr" / "lib",
            prefix / "usr" / "lib" / "x86_64-linux-gnu",
        ):
            if candidate.exists():
                lib_entries.append(str(candidate))
    if path_entries:
        env["PATH"] = os.pathsep.join([*path_entries, env.get("PATH", "")]).strip(os.pathsep)
    if lib_entries:
        env["LD_LIBRARY_PATH"] = os.pathsep.join([*lib_entries, env.get("LD_LIBRARY_PATH", "")]).strip(os.pathsep)
    return env


def resolve_tool(name: str, tool_runs: dict[str, Any] | None = None) -> str | None:
    tool_runs = tool_runs or {}
    preferred = ((tool_runs.get(name) or {}).get("tool_path") if tool_runs else None) or None
    if preferred and Path(preferred).exists():
        return str(preferred)
    candidates = [name]
    if name == "ctags":
        candidates.append("ctags-universal")
    env = tool_environment()
    for candidate in candidates:
        path = shutil.which(candidate, path=env.get("PATH"))
        if path:
            return path
    return None


def _run_cqsearch(
    *,
    database_path: Path,
    query_kind: str,
    search_term: str,
    file_path: str | None = None,
    limit: int = 16,
) -> list[CQSearchMatch]:
    cqsearch = resolve_tool("cqsearch")
    if cqsearch is None or not database_path.exists():
        return []
    command = [
        cqsearch,
        "-s",
        str(database_path),
        "-p",
        query_kind,
        "-t",
        search_term,
        "-u",
    ]
    if search_term != "*":
        command.append("-e")
    if file_path:
        command.extend(["-b", file_path])
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=tool_environment(),
        cwd=str(database_path.parent),
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        return []
    results: list[CQSearchMatch] = []
    for raw_line in completed.stdout.splitlines():
        match = CQSearchMatch.from_line(raw_line)
        if match is None:
            continue
        results.append(match)
        if len(results) >= limit:
            break
    return results


def original_like_backend_details(source_manifest: dict[str, Any]) -> dict[str, Any]:
    artifacts = source_manifest.get("artifacts", {})
    tool_runs = source_manifest.get("tools", {})
    index_dir = Path(artifacts.get("manifest.json", "")).parent if artifacts.get("manifest.json") else None
    codequery_db = Path(artifacts["codequery.db"]) if artifacts.get("codequery.db") else None

    tool_paths = {
        "cscope": resolve_tool("cscope", tool_runs),
        "ctags": resolve_tool("ctags", tool_runs),
        "cqmakedb": resolve_tool("cqmakedb", tool_runs),
        "cqsearch": resolve_tool("cqsearch", tool_runs),
    }
    parts_enabled: list[str] = []
    if artifacts.get("cscope.out") and tool_paths["cscope"]:
        parts_enabled.append("cscope_index")
    if artifacts.get("tags") and tool_paths["ctags"]:
        parts_enabled.append("ctags_index")
    if artifacts.get("codequery.db") and tool_paths["cqmakedb"]:
        parts_enabled.append("cqmakedb_database")
    if artifacts.get("codequery.db") and tool_paths["cqsearch"]:
        parts_enabled.append("cqsearch_queries")

    sample_results: dict[str, Any] = {"functions": [], "symbols": []}
    if codequery_db and codequery_db.exists() and tool_paths["cqsearch"]:
        sample_results["functions"] = [
            match.__dict__
            for match in _run_cqsearch(database_path=codequery_db, query_kind="2", search_term="*", limit=5)
        ]
        sample_results["symbols"] = [
            match.__dict__
            for match in _run_cqsearch(database_path=codequery_db, query_kind="1", search_term="*", limit=5)
        ]

    missing_tools = [name for name, path in tool_paths.items() if path is None]
    cqmakedb_run = tool_runs.get("cqmakedb") or {}
    db_generation_blocker = None
    if artifacts.get("codequery.db"):
        db_generation_blocker = None
    elif cqmakedb_run.get("available") and cqmakedb_run.get("ran") and cqmakedb_run.get("exit_code") not in (0, None):
        stderr = str(cqmakedb_run.get("stderr") or "")
        if "Unsupported cscope parameters" in stderr:
            db_generation_blocker = "cscope_output_generated_with_incompatible_flags_for_cqmakedb"
        else:
            db_generation_blocker = "cqmakedb_failed_without_database_output"
    elif not tool_paths["cqmakedb"]:
        db_generation_blocker = "cqmakedb_tool_missing"
    elif not artifacts.get("cscope.out"):
        db_generation_blocker = "cscope_index_missing"
    elif not artifacts.get("tags"):
        db_generation_blocker = "ctags_index_missing"

    original_backend_available = all(
        [
            bool(artifacts.get("cscope.out")),
            bool(artifacts.get("tags")),
            bool(artifacts.get("codequery.db")),
            bool(tool_paths["cscope"]),
            bool(tool_paths["ctags"]),
            bool(tool_paths["cqmakedb"]),
            bool(tool_paths["cqsearch"]),
        ],
    )
    if original_backend_available:
        backend_kind = "original_like_codequery_cqsearch"
    elif parts_enabled:
        backend_kind = "original_like_partial_index"
    else:
        backend_kind = "lite_static_fact_fallback"

    query_backend_capabilities = {
        "function_definitions": bool(tool_paths["cqsearch"] and artifacts.get("codequery.db")),
        "callers_callees": bool(tool_paths["cqsearch"] and artifacts.get("codequery.db")),
        "types_symbols": bool(artifacts.get("tags") and tool_paths["ctags"]),
        "file_index": bool(artifacts.get("cscope.files")),
        "tree_sitter": False,
    }
    return {
        "backend_kind": backend_kind,
        "original_backend_available": original_backend_available,
        "original_backend_parts_enabled": parts_enabled,
        "artifact_paths": artifacts,
        "tool_paths": tool_paths,
        "query_backend_capabilities": query_backend_capabilities,
        "missing_tools": missing_tools,
        "sample_results": sample_results,
        "index_dir": str(index_dir) if index_dir else None,
        "db_generation_blocker": db_generation_blocker,
        "tool_runs": tool_runs,
    }


class OriginalLikeQueryView:
    def __init__(
        self,
        *,
        index_dir: Path,
        function_facts: list[dict[str, Any]],
        type_facts: list[dict[str, Any]],
        backend_manifest: dict[str, Any],
    ) -> None:
        self.index_dir = index_dir
        self.function_facts = function_facts
        self.type_facts = type_facts
        self.backend_manifest = backend_manifest
        codequery_db = backend_manifest.get("artifact_paths", {}).get("codequery.db")
        self.codequery_db = Path(codequery_db) if codequery_db else None

    def available(self) -> bool:
        capabilities = self.backend_manifest.get("query_backend_capabilities", {})
        return bool(capabilities.get("function_definitions")) and self.codequery_db is not None and self.codequery_db.exists()

    def raw_query(self, *, query_kind: str, search_term: str, file_path: str | None = None, limit: int = 16) -> list[dict[str, Any]]:
        if self.codequery_db is None or not self.codequery_db.exists():
            return []
        return [
            match.__dict__
            for match in _run_cqsearch(
                database_path=self.codequery_db,
                query_kind=query_kind,
                search_term=search_term,
                file_path=file_path,
                limit=limit,
            )
        ]

    def _match_function_fact(self, match: CQSearchMatch) -> dict[str, Any]:
        file_name = Path(match.file).name
        candidates = [
            fact
            for fact in self.function_facts
            if str(fact.get("name")) == match.value
            and Path(str(fact.get("file") or "")).name == file_name
        ]
        if not candidates:
            candidates = [fact for fact in self.function_facts if str(fact.get("name")) == match.value]
        if candidates:
            nearest = sorted(candidates, key=lambda fact: abs(int(fact.get("line") or 0) - match.line))[0]
            enriched = dict(nearest)
            enriched.setdefault("query_backend", "cqsearch")
            return enriched
        return {
            "name": match.value,
            "file": match.file,
            "line": match.line,
            "snippet": match.body,
            "body_excerpt": match.body,
            "query_backend": "cqsearch",
        }

    def get_functions(self, function_name: str, *, fuzzy: bool = True, file_path: str | None = None) -> list[dict[str, Any]]:
        if not self.available():
            return []
        results: list[CQSearchMatch] = []
        for flag in ("1", "2"):
            results.extend(
                _run_cqsearch(
                    database_path=self.codequery_db,
                    query_kind=flag,
                    search_term=function_name,
                    file_path=file_path,
                    limit=24,
                ),
            )
        if fuzzy and not results:
            results.extend(
                _run_cqsearch(
                    database_path=self.codequery_db,
                    query_kind="2",
                    search_term="*",
                    limit=64,
                ),
            )
            results = [
                item
                for item in results
                if function_name.lower() in item.value.lower() or item.value.lower() in function_name.lower()
            ]
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        for match in results:
            key = (match.value, match.file, match.line)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(self._match_function_fact(match))
        return deduped

    def get_callers(self, function_name: str, *, file_path: str | None = None) -> list[dict[str, Any]]:
        if not self.available():
            return []
        results = _run_cqsearch(
            database_path=self.codequery_db,
            query_kind="6",
            search_term=function_name,
            limit=24,
        )
        callers: list[dict[str, Any]] = []
        seen: set[tuple[str, str | None]] = set()
        for match in results:
            for caller in self.get_functions(match.value, fuzzy=False, file_path=match.file or file_path):
                key = (str(caller.get("name")), str(caller.get("file")))
                if key in seen:
                    continue
                seen.add(key)
                callers.append(caller)
        return callers

    def get_callees(self, function_name: str, *, file_path: str | None = None) -> list[dict[str, Any]]:
        if not self.available():
            return []
        results = _run_cqsearch(
            database_path=self.codequery_db,
            query_kind="7",
            search_term=function_name,
            file_path=file_path,
            limit=24,
        )
        callees: list[dict[str, Any]] = []
        seen: set[tuple[str, str | None]] = set()
        for match in results:
            for callee in self.get_functions(match.value, fuzzy=False):
                key = (str(callee.get("name")), str(callee.get("file")))
                if key in seen:
                    continue
                seen.add(key)
                callees.append(callee)
        return callees

    def get_types(self, type_name: str, *, fuzzy: bool = True, file_path: str | None = None) -> list[dict[str, Any]]:
        if self.codequery_db is None or not self.codequery_db.exists():
            return []
        results: list[CQSearchMatch] = []
        for flag in ("1", "3"):
            results.extend(
                _run_cqsearch(
                    database_path=self.codequery_db,
                    query_kind=flag,
                    search_term=type_name,
                    file_path=file_path,
                    limit=24,
                ),
            )
        if fuzzy and not results:
            results.extend(
                _run_cqsearch(
                    database_path=self.codequery_db,
                    query_kind="1",
                    search_term="*",
                    limit=64,
                ),
            )
            results = [
                item
                for item in results
                if type_name.lower() in item.value.lower() or item.value.lower() in type_name.lower()
            ]
        seen: set[tuple[str, str, int]] = set()
        selected: list[dict[str, Any]] = []
        by_name = {}
        for fact in self.type_facts:
            name = str(fact.get("name") or "")
            if name and name not in by_name:
                by_name[name] = fact
        for match in results:
            key = (match.value, match.file, match.line)
            if key in seen:
                continue
            seen.add(key)
            enriched = dict(by_name.get(match.value, {}))
            if not enriched:
                enriched = {
                    "name": match.value,
                    "file": match.file,
                    "line": match.line,
                    "snippet": match.body,
                    "body_excerpt": match.body,
                }
            enriched.setdefault("query_backend", "cqsearch")
            selected.append(enriched)
        return selected


def _sample_function_names(function_facts: list[dict[str, Any]]) -> list[str]:
    preferred: list[str] = []
    fallback: list[str] = []
    for fact in function_facts:
        name = str(fact.get("name") or "")
        if not name:
            continue
        lowered = name.lower()
        if any(token in lowered for token in ("parse", "read", "load", "decode", "print", "stream", "string")):
            if name not in preferred:
                preferred.append(name)
        elif name not in fallback:
            fallback.append(name)
    return (preferred[:3] + fallback[:3])[:4]


def _sample_type_names(type_facts: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for fact in type_facts:
        name = str(fact.get("name") or "")
        if not name or name == "<anonymous>":
            continue
        if name not in names:
            names.append(name)
        if len(names) >= 3:
            break
    return names


def build_query_validation_payload(
    *,
    backend_manifest: dict[str, Any],
    function_facts: list[dict[str, Any]],
    type_facts: list[dict[str, Any]],
    task_id: str,
) -> dict[str, Any]:
    view = OriginalLikeQueryView(
        index_dir=Path(backend_manifest.get("artifact_paths", {}).get("manifest.json", "")).parent
        if backend_manifest.get("artifact_paths", {}).get("manifest.json")
        else Path(),
        function_facts=function_facts,
        type_facts=type_facts,
        backend_manifest=backend_manifest,
    )
    sample_functions = _sample_function_names(function_facts)
    sample_types = _sample_type_names(type_facts)
    sample_results: dict[str, Any] = {
        "function_definitions": {},
        "callers": {},
        "callees": {},
        "types": {},
        "raw_symbol_search": {},
    }
    capability_matrix: dict[str, Any] = {}
    blocker = backend_manifest.get("db_generation_blocker")
    for function_name in sample_functions:
        matches = view.get_functions(function_name, fuzzy=False)
        sample_results["function_definitions"][function_name] = matches[:3]
        if matches:
            sample_results["callers"][function_name] = view.get_callers(function_name)[:5]
            sample_results["callees"][function_name] = view.get_callees(function_name, file_path=str(matches[0].get("file") or ""))[:5]
        sample_results["raw_symbol_search"][function_name] = view.raw_query(query_kind="2", search_term=function_name, limit=5)
    for type_name in sample_types:
        sample_results["types"][type_name] = view.get_types(type_name, fuzzy=False)[:3]

    capability_matrix["function_definitions"] = {
        "backend_requested": True,
        "backend_used": "original_like_query_backend" if view.available() else "lite_fallback",
        "supported": bool(view.available()),
        "sample_queries": sample_functions,
        "non_empty_result_count": sum(1 for value in sample_results["function_definitions"].values() if value),
        "blocker": blocker if not view.available() else None,
    }
    capability_matrix["callers_callees"] = {
        "backend_requested": True,
        "backend_used": "original_like_query_backend" if view.available() else "lite_fallback",
        "supported": bool(view.available()),
        "caller_hits": sum(len(value) for value in sample_results["callers"].values()),
        "callee_hits": sum(len(value) for value in sample_results["callees"].values()),
        "blocker": blocker if not view.available() else None,
    }
    capability_matrix["types_symbols"] = {
        "backend_requested": True,
        "backend_used": "original_like_query_backend" if view.codequery_db and view.codequery_db.exists() else "lite_fallback",
        "supported": bool(view.codequery_db and view.codequery_db.exists()),
        "sample_queries": sample_types,
        "non_empty_result_count": sum(1 for value in sample_results["types"].values() if value),
        "blocker": blocker if not (view.codequery_db and view.codequery_db.exists()) else None,
    }
    capability_matrix["symbol_search"] = {
        "backend_requested": True,
        "backend_used": "original_like_query_backend" if view.codequery_db and view.codequery_db.exists() else "lite_fallback",
        "supported": bool(view.codequery_db and view.codequery_db.exists()),
        "sample_queries": sample_functions,
        "non_empty_result_count": sum(1 for value in sample_results["raw_symbol_search"].values() if value),
        "blocker": blocker if not (view.codequery_db and view.codequery_db.exists()) else None,
    }
    capability_matrix["file_adjacency"] = {
        "backend_requested": True,
        "backend_used": "cscope_files_and_query_results" if backend_manifest.get("artifact_presence", {}).get("cscope_files") else "lite_fallback",
        "supported": bool(backend_manifest.get("artifact_presence", {}).get("cscope_files")),
        "sample_file_count": len(
            {
                item.get("file")
                for group in sample_results["function_definitions"].values()
                for item in group
                if isinstance(item, dict) and item.get("file")
            }
        ),
        "blocker": "cscope_files_missing" if not backend_manifest.get("artifact_presence", {}).get("cscope_files") else None,
    }
    capability_matrix["entry_slice_evidence"] = {
        "backend_requested": True,
        "backend_used": "original_like_query_backend" if view.available() else "lite_fallback",
        "supported": bool(view.available()),
        "sample_entry_functions": sample_functions,
        "caller_or_callee_evidence_available": bool(
            any(sample_results["callers"].values()) or any(sample_results["callees"].values())
        ),
        "blocker": blocker if not view.available() else None,
    }
    return {
        "task_id": task_id,
        "backend_kind": backend_manifest.get("backend_kind"),
        "original_backend_available": backend_manifest.get("original_backend_available"),
        "db_generation_blocker": blocker,
        "query_capability_matrix": capability_matrix,
        "sample_query_results": sample_results,
    }

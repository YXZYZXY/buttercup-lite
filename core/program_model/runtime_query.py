from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.buttercup_compat.program_model import LiteCodeQueryView
from core.storage.layout import task_root


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_task_dir(task_id: str) -> Path:
    primary = task_root(task_id)
    if primary.exists():
        return primary
    repo_root = Path(__file__).resolve().parents[2]
    fallback = repo_root / "data" / "tasks" / task_id
    if fallback.exists():
        return fallback
    return primary


def _artifact_signature(path: Path) -> tuple[int, int]:
    if not path.exists():
        return (0, 0)
    stat = path.stat()
    return (int(stat.st_mtime_ns), int(stat.st_size))


@dataclass
class _ProgramModelIndex:
    task_id: str
    index_dir: Path
    built_at: str
    build_duration_ms: float
    signature: tuple[tuple[int, int], ...]
    query_view: LiteCodeQueryView
    facts_by_name: dict[str, dict[str, Any]]
    lowercase_name_map: dict[str, str]
    callers_graph: dict[str, list[str]]
    callees_graph: dict[str, list[str]]
    type_facts: list[dict[str, Any]]


_INDEX_CACHE: dict[tuple[str, tuple[tuple[int, int], ...]], _ProgramModelIndex] = {}


def _index_signature(index_dir: Path) -> tuple[tuple[int, int], ...]:
    return (
        _artifact_signature(index_dir / "function_facts.json"),
        _artifact_signature(index_dir / "call_graph.json"),
        _artifact_signature(index_dir / "type_facts.json"),
        _artifact_signature(index_dir / "program_model_backend_manifest.json"),
    )


def _build_index(task_id: str) -> _ProgramModelIndex:
    started = time.perf_counter()
    task_dir = _resolve_task_dir(task_id)
    index_dir = task_dir / "index"
    query_view = LiteCodeQueryView(
        task_id=task_id,
        index_dir=index_dir,
        function_facts=_load_json(index_dir / "function_facts.json", []),
        type_facts=_load_json(index_dir / "type_facts.json", []),
        call_graph=_load_json(index_dir / "call_graph.json", {}),
        backend_manifest=_load_json(index_dir / "program_model_backend_manifest.json", {}),
        original_like_backend=None,
    )
    facts_by_name = {
        str(fact.get("name") or ""): dict(fact)
        for fact in list(query_view.function_facts or [])
        if str(fact.get("name") or "").strip()
    }
    callers_graph: dict[str, list[str]] = {}
    callees_graph: dict[str, list[str]] = {}
    for name, fact in facts_by_name.items():
        graph_entry = query_view.call_graph.get(name, {}) if isinstance(query_view.call_graph, dict) else {}
        callers = list(dict.fromkeys(graph_entry.get("callers") or fact.get("callers") or []))
        callees = list(dict.fromkeys(graph_entry.get("callees") or fact.get("callees") or []))
        callers_graph[name] = [str(item) for item in callers if str(item).strip()]
        callees_graph[name] = [str(item) for item in callees if str(item).strip()]
    build_duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
    return _ProgramModelIndex(
        task_id=task_id,
        index_dir=index_dir,
        built_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        build_duration_ms=build_duration_ms,
        signature=_index_signature(index_dir),
        query_view=query_view,
        facts_by_name=facts_by_name,
        lowercase_name_map={name.lower(): name for name in facts_by_name},
        callers_graph=callers_graph,
        callees_graph=callees_graph,
        type_facts=list(query_view.type_facts or []),
    )


def _get_cached_index(task_id: str) -> tuple[_ProgramModelIndex, bool]:
    index_dir = _resolve_task_dir(task_id) / "index"
    signature = _index_signature(index_dir)
    cache_key = (str(index_dir), signature)
    cached = _INDEX_CACHE.get(cache_key)
    if cached is not None:
        return cached, True
    built = _build_index(task_id)
    _INDEX_CACHE.clear()
    _INDEX_CACHE[cache_key] = built
    return built, False


@dataclass
class ProgramModelRuntimeView:
    index: _ProgramModelIndex
    cache_hit: bool = False
    query_call_count: int = 0
    query_counts: dict[str, int] = field(default_factory=dict)
    recent_queries: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_task(cls, task_id: str) -> "ProgramModelRuntimeView":
        index, cache_hit = _get_cached_index(task_id)
        return cls(index=index, cache_hit=cache_hit)

    def _normalize_name(self, function_name: str | None) -> str:
        normalized = str(function_name or "").strip()
        if not normalized:
            return ""
        if normalized in self.index.facts_by_name:
            return normalized
        return self.index.lowercase_name_map.get(normalized.lower(), normalized)

    def _fact(self, function_name: str | None) -> dict[str, Any]:
        normalized = self._normalize_name(function_name)
        if not normalized:
            return {}
        return dict(self.index.facts_by_name.get(normalized) or {})

    def _record_query(self, query_name: str, target: Any, result_count: int, *, extra: dict[str, Any] | None = None) -> None:
        self.query_call_count += 1
        self.query_counts[query_name] = self.query_counts.get(query_name, 0) + 1
        self.recent_queries.append(
            {
                "query": query_name,
                "target": target,
                "result_count": int(result_count),
                **(extra or {}),
            }
        )
        if len(self.recent_queries) > 24:
            self.recent_queries = self.recent_queries[-24:]

    def _compact_fact(
        self,
        fact: dict[str, Any],
        *,
        relation: str,
        distance: int,
        source: str,
    ) -> dict[str, Any]:
        payload = dict(fact)
        payload["relation"] = relation
        payload["distance"] = int(distance)
        payload["pm_query_source"] = source
        return payload

    def _type_facts_for_function(self, fact: dict[str, Any], *, limit: int = 8) -> list[dict[str, Any]]:
        blob = "\n".join(
            [
                str(fact.get("signature") or ""),
                str(fact.get("snippet") or ""),
                str(fact.get("body_excerpt") or ""),
            ]
        )
        matches: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for type_fact in self.index.type_facts:
            name = str(type_fact.get("name") or "").strip()
            if not name or name == "<anonymous>" or name not in blob:
                continue
            key = (name, str(type_fact.get("file") or ""))
            if key in seen:
                continue
            seen.add(key)
            matches.append(dict(type_fact))
            if len(matches) >= limit:
                break
        return matches

    def _bfs(
        self,
        *,
        roots: list[str],
        graph: dict[str, list[str]],
        relation: str,
        source: str,
        depth: int,
        max_nodes: int = 64,
    ) -> list[dict[str, Any]]:
        normalized_roots = [self._normalize_name(item) for item in roots if self._normalize_name(item)]
        queue: deque[tuple[str, int]] = deque((item, 0) for item in normalized_roots)
        visited = set(normalized_roots)
        results: list[dict[str, Any]] = []
        seen_result_names: set[str] = set()
        while queue and len(results) < max_nodes:
            current, current_depth = queue.popleft()
            if current_depth >= max(1, int(depth)):
                continue
            for neighbor in list(graph.get(current) or []):
                normalized = self._normalize_name(neighbor)
                if not normalized or normalized in visited:
                    continue
                visited.add(normalized)
                fact = self._fact(normalized)
                if fact and normalized not in seen_result_names:
                    results.append(
                        self._compact_fact(
                            fact,
                            relation=relation,
                            distance=current_depth + 1,
                            source=source,
                        )
                    )
                    seen_result_names.add(normalized)
                queue.append((normalized, current_depth + 1))
        return results

    def get_function_context(self, func_name: str) -> dict[str, Any]:
        fact = self._fact(func_name)
        callers = self.get_callers(func_name, depth=2)
        callees = self.get_callees(func_name, depth=2)
        type_facts = self._type_facts_for_function(fact)
        payload = {
            "function": fact,
            "callers": callers,
            "callees": callees,
            "type_facts": type_facts,
        }
        self._record_query(
            "get_function_context",
            self._normalize_name(func_name),
            (1 if fact else 0) + len(callers) + len(callees) + len(type_facts),
        )
        return payload

    def get_callers(self, func_name: str, depth: int = 2) -> list[dict[str, Any]]:
        normalized = self._normalize_name(func_name)
        results = self._bfs(
            roots=[normalized],
            graph=self.index.callers_graph,
            relation="caller",
            source="pm_callers",
            depth=max(1, int(depth)),
        )
        self._record_query("get_callers", normalized, len(results), extra={"depth": int(depth)})
        return results

    def get_callees(self, func_name: str, depth: int = 2) -> list[dict[str, Any]]:
        normalized = self._normalize_name(func_name)
        results = self._bfs(
            roots=[normalized],
            graph=self.index.callees_graph,
            relation="callee",
            source="pm_callees",
            depth=max(1, int(depth)),
        )
        self._record_query("get_callees", normalized, len(results), extra={"depth": int(depth)})
        return results

    def get_slice_by_entry(self, entry_func: str) -> list[dict[str, Any]]:
        normalized = self._normalize_name(entry_func)
        fact = self._fact(normalized)
        results: list[dict[str, Any]] = []
        if fact:
            results.append(
                self._compact_fact(
                    fact,
                    relation="entry",
                    distance=0,
                    source="pm_slice",
                )
            )
        results.extend(
            self._bfs(
                roots=[normalized],
                graph=self.index.callees_graph,
                relation="entry_reachable",
                source="pm_slice",
                depth=4,
                max_nodes=96,
            )
        )
        self._record_query("get_slice_by_entry", normalized, len(results))
        return results

    def get_slice_by_stacktrace(self, frames: list[dict[str, Any]] | list[str]) -> list[dict[str, Any]]:
        roots: list[str] = []
        for frame in list(frames or [])[:8]:
            if isinstance(frame, dict):
                candidate = frame.get("function") or frame.get("name")
            else:
                candidate = frame
            normalized = self._normalize_name(str(candidate or "").strip())
            if normalized and normalized not in roots:
                roots.append(normalized)
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for root in roots:
            fact = self._fact(root)
            if fact and root not in seen:
                results.append(
                    self._compact_fact(
                        fact,
                        relation="stacktrace_frame",
                        distance=0,
                        source="pm_stacktrace_slice",
                    )
                )
                seen.add(root)
            for item in self._bfs(
                roots=[root],
                graph=self.index.callers_graph,
                relation="stacktrace_caller",
                source="pm_stacktrace_slice",
                depth=1,
                max_nodes=12,
            ) + self._bfs(
                roots=[root],
                graph=self.index.callees_graph,
                relation="stacktrace_callee",
                source="pm_stacktrace_slice",
                depth=1,
                max_nodes=12,
            ):
                name = str(item.get("name") or "").strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                results.append(item)
                if len(results) >= 18:
                    break
            if len(results) >= 18:
                break
        self._record_query(
            "get_slice_by_stacktrace",
            roots,
            len(results),
            extra={"frame_count": len(list(frames or []))},
        )
        return results

    def summary_payload(self) -> dict[str, Any]:
        return {
            "task_id": self.index.task_id,
            "index_dir": str(self.index.index_dir),
            "cache_hit": bool(self.cache_hit),
            "index_built_at": self.index.built_at,
            "index_build_duration_ms": self.index.build_duration_ms,
            "query_call_count": int(self.query_call_count),
            "query_counts": dict(self.query_counts),
            "recent_queries": list(self.recent_queries),
            "function_fact_count": len(self.index.facts_by_name),
            "type_fact_count": len(self.index.type_facts),
        }


def get_runtime_view(task_id: str) -> ProgramModelRuntimeView:
    return ProgramModelRuntimeView.from_task(task_id)


__all__ = ["ProgramModelRuntimeView", "get_runtime_view"]

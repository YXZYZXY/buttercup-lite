from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.program_model_backends.original_like import OriginalLikeQueryView
from core.storage.layout import program_model_query_manifest_path, task_root


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class LiteCodeQueryView:
    """CodeQueryPersistent-shaped view backed by lite's local index artifacts."""

    task_id: str
    index_dir: Path
    function_facts: list[dict[str, Any]]
    type_facts: list[dict[str, Any]]
    call_graph: dict[str, Any]
    backend_manifest: dict[str, Any]
    original_like_backend: OriginalLikeQueryView | None

    @classmethod
    def from_task(cls, task_id: str) -> "LiteCodeQueryView":
        index_dir = task_root(task_id) / "index"
        return cls(
            task_id=task_id,
            index_dir=index_dir,
            function_facts=_load_json(index_dir / "function_facts.json", []),
            type_facts=_load_json(index_dir / "type_facts.json", []),
            call_graph=_load_json(index_dir / "call_graph.json", {}),
            backend_manifest=_load_json(index_dir / "program_model_backend_manifest.json", {}),
            original_like_backend=None,
        )

    def __post_init__(self) -> None:
        self.original_like_backend = OriginalLikeQueryView(
            index_dir=self.index_dir,
            function_facts=self.function_facts,
            type_facts=self.type_facts,
            backend_manifest=self.backend_manifest,
        )

    def get_functions(self, function_name: str, *, fuzzy: bool = True) -> list[dict[str, Any]]:
        if self.original_like_backend and self.original_like_backend.available():
            results = self.original_like_backend.get_functions(function_name, fuzzy=fuzzy)
            if results:
                return results
        needle = function_name.lower()
        exact = [fact for fact in self.function_facts if str(fact.get("name", "")).lower() == needle]
        if exact or not fuzzy:
            return exact
        return [
            fact
            for fact in self.function_facts
            if needle in str(fact.get("name", "")).lower() or str(fact.get("name", "")).lower() in needle
        ]

    def get_callers(self, function_name: str, *, file_path: str | None = None) -> list[dict[str, Any]]:
        if self.original_like_backend and self.original_like_backend.available():
            results = self.original_like_backend.get_callers(function_name, file_path=file_path)
            if results:
                return results
        graph = self.call_graph.get(function_name, {})
        caller_names = graph.get("callers", [])
        by_name = {str(fact.get("name")): fact for fact in self.function_facts if fact.get("name")}
        results = [by_name[name] for name in caller_names if name in by_name]
        if file_path:
            normalized = str(file_path)
            filtered = [fact for fact in results if str(fact.get("file") or "") == normalized]
            if filtered:
                return filtered
        return results

    def get_callees(self, function_name: str, *, file_path: str | None = None) -> list[dict[str, Any]]:
        primary = next((fact for fact in self.function_facts if str(fact.get("name")) == function_name), None)
        if self.original_like_backend and self.original_like_backend.available():
            results = self.original_like_backend.get_callees(
                function_name,
                file_path=file_path or (str(primary.get("file")) if primary else None),
            )
            if results:
                return results
        graph = self.call_graph.get(function_name, {})
        callee_names = graph.get("callees", [])
        by_name = {str(fact.get("name")): fact for fact in self.function_facts if fact.get("name")}
        results = [by_name[name] for name in callee_names if name in by_name]
        if file_path:
            normalized = str(file_path)
            filtered = [fact for fact in results if str(fact.get("file") or "") == normalized]
            if filtered:
                return filtered
        return results

    def get_types_referenced_by(self, snippets: list[str], *, limit: int = 12) -> list[dict[str, Any]]:
        blob = "\n".join(snippets)
        matches: list[dict[str, Any]] = []
        for fact in self.type_facts:
            name = str(fact.get("name") or "")
            if not name or name == "<anonymous>":
                continue
            if name in blob:
                matches.append(fact)
            if len(matches) >= limit:
                break
        return matches

    def write_manifest(
        self,
        *,
        generated_at: str,
        source_manifest: dict[str, Any] | None = None,
        backend_manifest: dict[str, Any] | None = None,
    ) -> Path:
        backend_manifest = backend_manifest or {}
        payload = {
            "task_id": self.task_id,
            "generated_at": generated_at,
            "compat_source": "original_buttercup.program_model.CodeQueryPersistent",
            "implementation": backend_manifest.get("backend") or "lite_adapted_query_view",
            "backend_strength": backend_manifest.get("backend_strength"),
            "backend_kind": backend_manifest.get("backend_kind"),
            "query_examples": backend_manifest.get("query_examples", {}),
            "reason_not_direct_import": (
                "original CodeQueryPersistent requires full ChallengeTask/docker/codequery runtime; "
                "lite keeps task_dir manifests and consumes available cscope/ctags/codequery artifacts before static fallback"
            ),
            "query_methods": [
                "get_functions",
                "get_callers",
                "get_callees",
                "get_types_referenced_by",
            ],
            "artifact_sources": {
                "function_facts": str(self.index_dir / "function_facts.json"),
                "type_facts": str(self.index_dir / "type_facts.json"),
                "call_graph": str(self.index_dir / "call_graph.json"),
                "symbols": str(self.index_dir / "symbols.json"),
            },
            "source_manifest": source_manifest or {},
            "program_model_backend_manifest_path": backend_manifest.get("program_model_backend_manifest_path"),
            "program_model_query_validation_manifest_path": str(self.index_dir / "program_model_query_validation_manifest.json"),
            "query_capability_matrix_path": str(self.index_dir / "query_capability_matrix.json"),
            "sample_query_results_path": str(self.index_dir / "sample_query_results.json"),
            "program_model_backend": backend_manifest,
            "function_fact_count": len(self.function_facts),
            "type_fact_count": len(self.type_facts),
        }
        path = program_model_query_manifest_path(self.task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

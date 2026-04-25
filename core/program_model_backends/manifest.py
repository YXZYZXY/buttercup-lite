from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.program_model_backends.original_like import (
    build_query_validation_payload,
    original_like_backend_details,
)
from core.program_model_backends.tree_sitter_backend import write_tree_sitter_manifests
from core.storage.layout import (
    program_model_backend_manifest_path,
    program_model_query_validation_manifest_path,
    query_capability_matrix_path,
    sample_query_results_path,
    tree_sitter_backend_manifest_path,
    typed_query_results_path,
)


def _artifact_exists(artifacts: dict[str, str], name: str) -> bool:
    value = artifacts.get(name)
    return bool(value and Path(value).exists())


def _load_source_files(source_manifest: dict[str, Any]) -> list[Path]:
    explicit = [Path(item) for item in source_manifest.get("source_files", []) if item]
    if explicit:
        return explicit
    artifacts = source_manifest.get("artifacts", {})
    source_files_txt = artifacts.get("source_files.txt") or artifacts.get("cscope.files")
    if not source_files_txt:
        return []
    path = Path(source_files_txt)
    if not path.exists():
        return []
    return [Path(line.strip()) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_program_model_backend_manifest(
    task_id: str,
    *,
    generated_at: str,
    source_manifest: dict[str, Any],
    function_facts: list[dict[str, Any]],
    type_facts: list[dict[str, Any]],
) -> dict[str, Any]:
    tools = source_manifest.get("tools", {})
    artifacts = source_manifest.get("artifacts", {})
    original_like = original_like_backend_details(source_manifest)
    source_file_paths = _load_source_files(source_manifest)
    tree_sitter = write_tree_sitter_manifests(
        task_id=task_id,
        generated_at=generated_at,
        source_files=source_file_paths,
        function_facts=function_facts,
        type_facts=type_facts,
        tree_sitter_backend_manifest_path=tree_sitter_backend_manifest_path(task_id),
        typed_query_results_path=typed_query_results_path(task_id),
    )
    original_like["query_backend_capabilities"]["tree_sitter"] = bool(tree_sitter.get("tree_sitter_available"))
    cscope_available = bool((tools.get("cscope") or {}).get("available"))
    ctags_available = bool((tools.get("ctags") or {}).get("available"))
    cqmakedb_available = bool((tools.get("cqmakedb") or {}).get("available"))
    codequery_db_exists = _artifact_exists(artifacts, "codequery.db")
    cscope_exists = _artifact_exists(artifacts, "cscope.out")
    tags_exists = _artifact_exists(artifacts, "tags")

    if original_like["backend_kind"] == "original_like_codequery_cqsearch":
        backend = "original_like_codequery_cqsearch"
        backend_strength = "real_cscope_ctags_codequery_artifacts_and_queries"
    elif codequery_db_exists:
        backend = "codequery_persistent_artifacts"
        backend_strength = "closest_lite_runtime_to_original"
    elif original_like["backend_kind"] == "original_like_partial_index":
        backend = "original_like_partial_index"
        backend_strength = "real_cscope_ctags_artifacts_without_full_cqsearch_lane"
    elif cscope_exists or tags_exists:
        backend = "cscope_ctags_backed_query_view"
        backend_strength = "partial_original_runtime_artifacts"
    else:
        backend = "lite_static_fact_query_view"
        backend_strength = "fallback_static_facts"

    payload = {
        "task_id": task_id,
        "generated_at": generated_at,
        "original_reference": "buttercup.program_model.CodeQueryPersistent",
        "backend": backend,
        "backend_strength": backend_strength,
        "original_backend_requested": True,
        "backend_kind": original_like["backend_kind"],
        "original_backend_available": original_like["original_backend_available"],
        "original_backend_parts_enabled": original_like["original_backend_parts_enabled"],
        "artifact_paths": original_like["artifact_paths"],
        "tool_paths": original_like["tool_paths"],
        "query_backend_capabilities": original_like["query_backend_capabilities"],
        "missing_tools": original_like["missing_tools"],
        "query_examples": original_like["sample_results"],
        "db_generation_blocker": original_like.get("db_generation_blocker"),
        "tree_sitter_backend_manifest_path": tree_sitter["tree_sitter_backend_manifest_path"],
        "typed_query_results_path": tree_sitter["typed_query_results_path"],
        "tree_sitter_backend": tree_sitter,
        "tool_availability": {
            "cscope": cscope_available,
            "ctags": ctags_available,
            "cqmakedb": cqmakedb_available,
            "cqsearch": bool(original_like["tool_paths"].get("cqsearch")),
            "tree_sitter": tree_sitter.get("tree_sitter_available", False),
        },
        "tool_runs": tools,
        "artifact_presence": {
            "source_files": _artifact_exists(artifacts, "source_files.txt"),
            "cscope_files": _artifact_exists(artifacts, "cscope.files"),
            "cscope_out": cscope_exists,
            "tags": tags_exists,
            "codequery_db": codequery_db_exists,
            "symbols": _artifact_exists(artifacts, "symbols.json"),
            "function_facts": _artifact_exists(artifacts, "function_facts.json"),
            "type_facts": _artifact_exists(artifacts, "type_facts.json"),
            "call_graph": _artifact_exists(artifacts, "call_graph.json"),
            "typed_query_results": Path(tree_sitter["typed_query_results_path"]).exists(),
        },
        "query_backend_contract": {
            "function_definitions": True,
            "callers_callees": True,
            "types_macros_constants": True,
            "tree_sitter": tree_sitter.get("tree_sitter_available", False),
            "codequery_sql": codequery_db_exists,
        },
        "wrapper_reason": (
            "lite keeps task_dir manifests and source-local execution; when original CodeQuery tools are present, "
            "their artifacts are generated and consumed, otherwise the same query categories are backed by static facts"
        ),
        "source_manifest_path": str(Path(artifacts.get("manifest.json", "")).resolve()) if artifacts.get("manifest.json") else None,
        "artifacts": artifacts,
    }
    path = program_model_backend_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {**payload, "program_model_backend_manifest_path": str(path)}


def write_program_model_query_validation_manifests(
    task_id: str,
    *,
    generated_at: str,
    function_facts: list[dict[str, Any]],
    type_facts: list[dict[str, Any]],
    backend_manifest: dict[str, Any],
) -> dict[str, Any]:
    validation = build_query_validation_payload(
        backend_manifest=backend_manifest,
        function_facts=function_facts,
        type_facts=type_facts,
        task_id=task_id,
    )
    validation_payload = {
        "task_id": task_id,
        "generated_at": generated_at,
        **validation,
    }
    validation_path = program_model_query_validation_manifest_path(task_id)
    validation_path.parent.mkdir(parents=True, exist_ok=True)
    validation_path.write_text(json.dumps(validation_payload, indent=2), encoding="utf-8")

    capability_matrix = {
        "task_id": task_id,
        "generated_at": generated_at,
        "backend_kind": backend_manifest.get("backend_kind"),
        "matrix": validation.get("query_capability_matrix", {}),
    }
    capability_path = query_capability_matrix_path(task_id)
    capability_path.parent.mkdir(parents=True, exist_ok=True)
    capability_path.write_text(json.dumps(capability_matrix, indent=2), encoding="utf-8")

    sample_payload = {
        "task_id": task_id,
        "generated_at": generated_at,
        "backend_kind": backend_manifest.get("backend_kind"),
        "sample_query_results": validation.get("sample_query_results", {}),
    }
    sample_path = sample_query_results_path(task_id)
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    sample_path.write_text(json.dumps(sample_payload, indent=2), encoding="utf-8")
    return {
        **validation_payload,
        "program_model_query_validation_manifest_path": str(validation_path),
        "query_capability_matrix_path": str(capability_path),
        "sample_query_results_path": str(sample_path),
    }

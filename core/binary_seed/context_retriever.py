from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.binary_seed.models import BinarySeedContext, BinarySlice
from core.storage.layout import (
    binary_context_package_path,
    binary_project_local_denoising_manifest_path,
    binary_runtime_noise_filter_manifest_path,
    binary_target_selection_manifest_path,
    dynamic_observation_bridge_path,
)

ENTRY_KEYWORDS = (
    "main",
    "fuzzer",
    "parse",
    "read",
    "load",
    "scan",
    "decode",
    "stream",
)
FUNCTION_KEYWORDS = (
    "parse",
    "read",
    "load",
    "scan",
    "decode",
    "print",
    "delete",
    "string",
    "object",
    "array",
    "malloc",
    "free",
    "copy",
    "mem",
    "alloc",
    "stream",
    "file",
    "json",
    "xml",
    "ini",
    "yaml",
)
IMPORT_KEYWORDS = ("malloc", "free", "memcpy", "strcpy", "fopen", "fread", "read", "write", "strlen", "getopt")
STRING_KEYWORDS = ("json", "{", "}", "[", "]", "parse", "usage", "stdin", "file", "xml", "ini", "yaml")
RUNTIME_NOISE_TOKENS = (
    "fuzzer",
    "llvm",
    "sanitizer",
    "tracepc",
    "dataflow",
    "collectdataflow",
    "workerthread",
    "mutate",
    "crossover",
    "minimizecrashinput",
    "__sanitizer",
    "__asan",
    "__ubsan",
    "__lsan",
    "lsan",
    "ubsan",
    "__interceptor",
    "interceptor",
    "pthread",
    "libc_start",
)
LIBC_NOISE_TOKENS = (
    "strlen",
    "memcmp",
    "memcpy",
    "malloc",
    "free",
    "realloc",
    "operator new",
    "operator delete",
    "pthread_self",
    "pthread_create",
    "__libc_start_main",
)
CPP_RUNTIME_NOISE_PREFIXES = (
    "_ZNSt",
    "_ZSt",
    "_ZNKSt",
    "_ZTVN",
    "_ZTSN",
    "_ZTIN",
    "_ZN6fuzzer",
    "_ZN11__sanitizer",
    "_ZN6__asan",
    "_ZN14__interception",
)
RUNTIME_NOISE_PREFIXES = (
    "__asan",
    "__ubsan",
    "__lsan",
    "__sanitizer",
    "__interceptor",
    "___interceptor",
    "_start",
    ".init",
    ".fini",
    ".plt",
    "_GLOBAL__sub_I_",
    "register_tm_clones",
    "deregister_tm_clones",
    "frame_dummy",
    "__do_global_dtors_aux",
)
PROJECT_TOKEN_HINTS = {
    "cjson": ("cjson", "cjson_", "parsewithlength", "parsewithopts", "printbuffer"),
    "inih": ("ini_", "ini_parse", "ini_reader", "inih"),
    "libyaml": ("yaml_", "yaml_parser", "yaml_scanner", "yaml_emitter"),
    "libxml2": ("xml", "html", "xmlparse", "xmlread", "xmlreader", "xmlload"),
    "miniz": ("mz_", "tinfl", "tdefl", "miniz"),
    "h3": ("h3_", "cell", "polygon", "geo", "latlng"),
    "libspng": ("spng_", "png_", "libspng"),
    "libplist": ("plist_", "bplist", "oplist", "xplist", "jplist", "libplist"),
    "zlib": ("zlib", "inflate", "deflate", "gz", "crc32", "adler32"),
}


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _matches(text: str, keywords: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def _load_task_json(task_dir: Path) -> dict[str, Any]:
    path = task_dir / "task.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _derive_project_tokens(task_dir: Path, summary: dict[str, Any]) -> tuple[str | None, tuple[str, ...], dict[str, Any]]:
    task_payload = _load_task_json(task_dir)
    metadata = task_payload.get("metadata") or {}
    project_name: str | None = None
    dataset_manifest_path = metadata.get("dataset_binary_package_manifest_path")
    if dataset_manifest_path:
        dataset_payload = _load_json(Path(dataset_manifest_path), {})
        project_name = str(dataset_payload.get("project_name") or "").strip().lower() or None
    if project_name is None:
        ref = str((task_payload.get("source") or {}).get("ref") or metadata.get("run_label") or summary.get("binary_name") or "").lower()
        for candidate in PROJECT_TOKEN_HINTS:
            if candidate in ref:
                project_name = candidate
                break
    if project_name:
        normalized = project_name.lower()
        if normalized not in PROJECT_TOKEN_HINTS:
            for candidate in PROJECT_TOKEN_HINTS:
                if candidate in normalized:
                    project_name = candidate
                    break
    tokens = list(PROJECT_TOKEN_HINTS.get(project_name or "", ()))
    binary_name = str(summary.get("binary_name") or "").lower()
    if binary_name and binary_name not in {"current", "binary", "a.out"}:
        tokens.append(binary_name)
    extra = [
        token
        for token in (
            str(metadata.get("benchmark_profile_name") or "").lower(),
            str(metadata.get("repo_name") or "").lower(),
        )
        if token
    ]
    tokens.extend(extra)
    normalized_tokens: list[str] = []
    for token in tokens:
        token = token.strip().lower()
        if not token or token in normalized_tokens:
            continue
        normalized_tokens.append(token)
    return project_name, tuple(normalized_tokens), {
        "project_name": project_name,
        "project_tokens": normalized_tokens,
        "dataset_binary_package_manifest_path": dataset_manifest_path,
        "source_ref": (task_payload.get("source") or {}).get("ref"),
    }


def _load_dataset_contract_context(task_dir: Path) -> dict[str, Any]:
    task_payload = _load_task_json(task_dir)
    metadata = task_payload.get("metadata") or {}
    dataset_manifest_path = metadata.get("dataset_binary_package_manifest_path")
    if not dataset_manifest_path:
        return {}
    payload = _load_json(Path(dataset_manifest_path), {})
    return {
        "dataset_binary_package_manifest_path": dataset_manifest_path,
        "contract_kind": payload.get("contract_kind"),
        "contract_hints": payload.get("contract_hints", []),
        "provenance": payload.get("provenance", {}),
        "layer": payload.get("layer"),
        "project_name": payload.get("project_name"),
    }


def _is_runtime_noise_name(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith("sub_"):
        # Stripped/opaque binaries often expose parser-local functions as IDA auto-names.
        # Keep them in the candidate pool and let later scoring/noise filters decide.
        return False
    if any(lowered.startswith(prefix.lower()) for prefix in RUNTIME_NOISE_PREFIXES):
        return True
    if any(lowered.startswith(prefix.lower()) for prefix in CPP_RUNTIME_NOISE_PREFIXES):
        return True
    if any(token in lowered for token in RUNTIME_NOISE_TOKENS):
        return True
    if "flagparser" in lowered or "tracepc" in lowered or "sancov" in lowered:
        return True
    return False


def _project_local_match(name: str, project_tokens: tuple[str, ...]) -> bool:
    lowered = name.lower()
    return any(token and token in lowered for token in project_tokens)


def _collect_filtered(path: Path, *, name_field: str, keywords: tuple[str, ...], limit: int) -> list[dict]:
    items = _load_json(path, [])
    seen: set[str] = set()
    selected: list[dict] = []
    for item in items:
        text = str(item.get(name_field, ""))
        if not text or text in seen:
            continue
        if _matches(text, keywords):
            selected.append(item)
            seen.add(text)
        if len(selected) >= limit:
            break
    return selected


def _read_optional_text(path: Path | None, limit: int = 1500) -> str | None:
    if path is None or not path.exists():
        return None
    return path.read_text(encoding="utf-8", errors="ignore")[:limit]


def _is_test_or_fixture_path(path_str: str | None) -> bool:
    lowered = str(path_str or "").lower()
    return any(token in lowered for token in ("/tests/", "/test/", "/fixtures/", "/examples/", "/unity/"))


def _normalize_typed_functions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("typed_functions")
    if raw is None:
        raw = payload.get("functions")
    if isinstance(raw, dict):
        entries = [dict(item) for item in raw.values() if isinstance(item, dict)]
    elif isinstance(raw, list):
        entries = [dict(item) for item in raw if isinstance(item, dict)]
    else:
        entries = []
    ranked: list[dict[str, Any]] = []
    for entry in entries:
        if not entry.get("name") or _is_test_or_fixture_path(entry.get("file")):
            continue
        score = 0
        if entry.get("parser_adjacent"):
            score += 4
        score += len(entry.get("parser_tokens") or [])
        score += min(int(entry.get("call_count") or 0), 6)
        entry["_source_rank"] = score
        ranked.append(entry)
    ranked.sort(
        key=lambda item: (
            int(item.get("_source_rank") or 0),
            int(item.get("line") or 0),
            str(item.get("name") or ""),
        ),
        reverse=True,
    )
    for entry in ranked:
        entry.pop("_source_rank", None)
    return ranked


def _normalize_source_parser_adjacent(
    typed_payload: dict[str, Any],
    typed_functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    raw = typed_payload.get("parser_adjacent_candidates")
    if isinstance(raw, list):
        candidates = [dict(item) for item in raw if isinstance(item, dict)]
    else:
        candidates = []
    filtered = [item for item in candidates if item.get("name") and not _is_test_or_fixture_path(item.get("file"))]
    if filtered:
        return filtered
    return [
        dict(item)
        for item in typed_functions
        if item.get("parser_adjacent") or (item.get("parser_tokens") or [])
    ]


def _normalize_function_symbols(symbols: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for symbol in symbols:
        if symbol.get("kind") != "f":
            continue
        if _is_test_or_fixture_path(symbol.get("file")):
            continue
        name = str(symbol.get("name") or "")
        file_path = str(symbol.get("file") or "")
        if not name:
            continue
        dedupe_key = (name, file_path)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        selected.append(dict(symbol))
    return selected


def _load_source_index_context(task_dir: Path) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    task_payload = _load_task_json(task_dir)
    metadata = task_payload.get("metadata") or {}
    runtime = task_payload.get("runtime") or {}
    binary_mode = str(runtime.get("binary_mode") or metadata.get("binary_mode") or "")
    binary_provenance = str(runtime.get("binary_provenance") or metadata.get("binary_provenance") or "")
    source_derived = binary_mode == "source_derived_binary" or binary_provenance == "source_derived_binary"
    if not source_derived:
        return {"source_context_available": False}, [], {}

    resolved_imports = runtime.get("resolved_imports") or {}
    index_root = resolved_imports.get("existing_index_path")
    if not index_root:
        return {"source_context_available": False}, [], {}

    index_dir = Path(index_root)
    if not index_dir.exists():
        return {"source_context_available": False}, [], {}

    typed_path = index_dir / "typed_query_results.json"
    context_package_path = index_dir / "context_package.json"
    symbols_path = index_dir / "symbols.json"

    typed_payload_outer = _load_json(typed_path, {})
    typed_payload = typed_payload_outer.get("typed_query_results") if isinstance(typed_payload_outer, dict) else {}
    if not isinstance(typed_payload, dict):
        typed_payload = {}

    typed_functions = _normalize_typed_functions(typed_payload)[:10]
    source_parser_adjacent = _normalize_source_parser_adjacent(typed_payload, typed_functions)[:5]
    symbols_payload = _load_json(symbols_path, [])
    source_function_symbols = _normalize_function_symbols(symbols_payload)[:20] if isinstance(symbols_payload, list) else []
    context_package_payload = _load_json(context_package_path, {})

    context_sources: list[str] = []
    artifact_sources: dict[str, str] = {}
    if typed_path.exists():
        context_sources.append(str(typed_path))
        artifact_sources["source_typed_query_results"] = str(typed_path)
    if context_package_path.exists():
        context_sources.append(str(context_package_path))
        artifact_sources["source_context_package"] = str(context_package_path)
    if symbols_path.exists():
        context_sources.append(str(symbols_path))
        artifact_sources["source_symbols"] = str(symbols_path)

    return (
        {
            "source_context_available": bool(typed_functions or source_parser_adjacent or source_function_symbols),
            "source_index_path": str(index_dir),
            "source_typed_query_results_path": str(typed_path) if typed_path.exists() else None,
            "source_context_package_path": str(context_package_path) if context_package_path.exists() else None,
            "source_symbols_path": str(symbols_path) if symbols_path.exists() else None,
            "source_typed_functions": typed_functions,
            "source_parser_adjacent": source_parser_adjacent,
            "source_function_symbols": source_function_symbols,
            "source_selected_target_functions": context_package_payload.get("selected_target_functions", [])[:5]
            if isinstance(context_package_payload, dict)
            else [],
        },
        context_sources,
        artifact_sources,
    )


def _score_candidate(
    candidate: dict[str, Any],
    *,
    callgraph: dict[str, Any],
    contract_inference: dict[str, Any],
    project_tokens: tuple[str, ...],
) -> tuple[float, list[str]]:
    reasons: list[str] = []
    name = str(candidate.get("name") or "")
    lowered = name.lower()
    score = 0.0
    if _is_runtime_noise_name(name):
        return -5.0, ["runtime_or_instrumentation_noise"]
    if any(token in lowered for token in LIBC_NOISE_TOKENS):
        return -3.0, ["libc_noise"]
    if _project_local_match(name, project_tokens):
        score += 3.2
        reasons.append("project_local_symbol")
    if _matches(name, FUNCTION_KEYWORDS):
        score += 2.0
        reasons.append("parser_like_name")
    if candidate.get("referenced_by_strings") or candidate.get("string_refs"):
        score += 2.1
        reasons.append("string_xref")
    callees_by_function = callgraph.get("callees_by_function") or {}
    callers_by_function = callgraph.get("callers_by_function") or {}
    degree = len(callees_by_function.get(name, [])) + len(callers_by_function.get(name, []))
    if degree:
        score += min(degree, 8) * 0.18
        reasons.append("callgraph_degree")
    if candidate.get("is_entry_candidate"):
        score += 0.8
        reasons.append("entry_candidate")
    selected_input_mode = str(contract_inference.get("selected_input_mode") or "")
    if "file" in selected_input_mode and any(token in lowered for token in ("file", "read", "load", "parse", "stream")):
        score += 0.7
        reasons.append("file_contract_alignment")
    if "stdin" in selected_input_mode and any(token in lowered for token in ("read", "stream", "parse")):
        score += 0.5
        reasons.append("stdin_contract_alignment")
    if any(token in lowered for token in ("parse", "decode", "scan", "stream", "reader", "load")):
        score += 1.0
        reasons.append("parser_entry_bias")
    if any(token in lowered for token in ("parse", "read_from", "from_memory", "scan", "decode", "load")):
        score += 1.15
        reasons.append("parser_core_bias")
    if any(
        token in lowered
        for token in (
            "initialize",
            "delete",
            "write_to_stream",
            "write_",
            "emit",
            "dump",
            "print",
            "save",
            "serialize",
            "writer",
        )
    ):
        score -= 0.95
        reasons.append("non_parsing_api_penalty")
    if "argv" in selected_input_mode or "file" in selected_input_mode:
        if any(token in lowered for token in ("read_from_file", "from_memory", "parse", "scan", "load")):
            score += 0.55
            reasons.append("argv_file_parser_bonus")
    return round(score, 4), reasons


def retrieve_binary_context(task_dir: Path, *, input_mode: str, launcher_semantics_source: str | None) -> BinarySeedContext:
    binary_dir = task_dir / "binary"
    runtime_dir = task_dir / "runtime"
    summary = _load_json(binary_dir / "analysis_summary.json", {})
    dataset_contract_context = _load_dataset_contract_context(task_dir)
    source_context_payload, source_context_sources, source_artifact_sources = _load_source_index_context(task_dir)
    project_name, project_tokens, project_token_evidence = _derive_project_tokens(task_dir, summary)
    function_inventory = _load_json(binary_dir / "binary_function_inventory.json", {})
    callgraph = _load_json(binary_dir / "binary_callgraph_manifest.json", {})
    contract_inference = _load_json(binary_dir / "binary_contract_inference_manifest.json", {})
    ida_bridge = _load_json(binary_dir / "ida_to_binary_context_bridge.json", {})
    functions = _load_json(binary_dir / "functions.json", [])
    strings_payload = _load_json(binary_dir / "strings.json", [])
    imports_payload = _load_json(binary_dir / "imports.json", [])
    entrypoints_payload = _load_json(binary_dir / "entrypoints.json", [])
    previous_execution = _load_json(runtime_dir / "binary_execution_manifest.json", {})

    entry_candidates = [
        item
        for item in (ida_bridge.get("entry_candidates") or entrypoints_payload[:16])
        if str(item.get("name") or "")
        and not _is_runtime_noise_name(str(item.get("name") or ""))
    ][:20]
    inventory_parser_candidates = [
        item
        for item in (function_inventory.get("parser_candidates") or [])
        if str(item.get("name") or "")
    ]
    parser_candidates = [
        item
        for item in inventory_parser_candidates
        if not _is_runtime_noise_name(str(item.get("name") or ""))
    ][:48]
    if not parser_candidates:
        parser_candidates = _collect_filtered(
            binary_dir / "functions.json",
            name_field="name",
            keywords=FUNCTION_KEYWORDS,
            limit=64,
        )
    function_lookup = {str(item.get("name")): dict(item) for item in functions if str(item.get("name") or "")}
    string_ref_examples = ida_bridge.get("string_reference_examples") or []
    string_ref_map = {item.get("value"): item.get("referenced_functions") for item in string_ref_examples if isinstance(item, dict)}
    functions_with_string_refs = {
        str(function_name)
        for refs in string_ref_map.values()
        for function_name in (refs or [])
        if function_name
    }
    seed_candidates: list[dict[str, Any]] = []
    seen_seed_names: set[str] = set()
    for source_list in (parser_candidates, inventory_parser_candidates, functions):
        for candidate in source_list:
            name = str(candidate.get("name") or "")
            if not name or name in seen_seed_names:
                continue
            if _is_runtime_noise_name(name):
                continue
            lowered = name.lower()
            if not (
                _project_local_match(name, project_tokens)
                or _matches(name, FUNCTION_KEYWORDS)
                or candidate.get("string_refs")
                or name in functions_with_string_refs
                or any(token in lowered for token in ("parse", "load", "scan", "stream", "reader", "yaml_", "ini_", "cjson", "xml"))
            ):
                continue
            seed_candidates.append(function_lookup.get(name, dict(candidate)))
            seen_seed_names.add(name)
        if len(seed_candidates) >= 96:
            break
    candidate_records: list[dict[str, Any]] = []
    runtime_noise_removed = 0
    for candidate in seed_candidates:
        item = dict(candidate)
        item["is_entry_candidate"] = any(str(entry.get("name")) == str(item.get("name")) for entry in entry_candidates)
        referenced_by_strings = [
            value
            for value, refs in string_ref_map.items()
            if item.get("name") in (refs or [])
        ][:8]
        if referenced_by_strings:
            item["referenced_by_strings"] = referenced_by_strings
        score, reasons = _score_candidate(
            item,
            callgraph=callgraph,
            contract_inference=contract_inference,
            project_tokens=project_tokens,
        )
        item["selection_score"] = score
        item["selection_reasons"] = reasons
        item["project_local_match"] = _project_local_match(str(item.get("name") or ""), project_tokens)
        if score <= 0.0 and "runtime_or_instrumentation_noise" in reasons:
            runtime_noise_removed += 1
        candidate_records.append(item)
    candidate_records.sort(key=lambda item: float(item.get("selection_score") or 0.0), reverse=True)
    candidate_records = [item for item in candidate_records if float(item.get("selection_score") or 0.0) > 0.0]
    selected_target = candidate_records[0] if candidate_records else (entry_candidates[0] if entry_candidates else None)
    selection_rationale = list(selected_target.get("selection_reasons") or []) if isinstance(selected_target, dict) else []
    if selected_target and not selection_rationale:
        selection_rationale = ["fallback_to_entry_candidate"]

    relevant_functions = candidate_records[:24]
    relevant_strings = _collect_filtered(
        binary_dir / "strings.json",
        name_field="value",
        keywords=STRING_KEYWORDS,
        limit=24,
    )
    relevant_imports = _collect_filtered(
        binary_dir / "imports.json",
        name_field="name",
        keywords=IMPORT_KEYWORDS,
        limit=24,
    )
    context_sources = [
        str(binary_dir / "analysis_summary.json"),
        str(binary_dir / "binary_function_inventory.json"),
        str(binary_dir / "binary_callgraph_manifest.json"),
        str(binary_dir / "binary_contract_inference_manifest.json"),
        str(binary_dir / "ida_to_binary_context_bridge.json"),
        str(binary_dir / "functions.json"),
        str(binary_dir / "strings.json"),
        str(binary_dir / "imports.json"),
        str(binary_dir / "entrypoints.json"),
    ]
    context_sources.extend(source_context_sources)
    artifact_sources = {
        "analysis_summary": str(binary_dir / "analysis_summary.json"),
        "binary_function_inventory": str(binary_dir / "binary_function_inventory.json"),
        "binary_callgraph_manifest": str(binary_dir / "binary_callgraph_manifest.json"),
        "binary_contract_inference_manifest": str(binary_dir / "binary_contract_inference_manifest.json"),
        "ida_to_binary_context_bridge": str(binary_dir / "ida_to_binary_context_bridge.json"),
        "entrypoints": str(binary_dir / "entrypoints.json"),
        "functions": str(binary_dir / "functions.json"),
        "strings": str(binary_dir / "strings.json"),
        "imports": str(binary_dir / "imports.json"),
        "dataset_binary_package_manifest": dataset_contract_context.get("dataset_binary_package_manifest_path"),
    }
    artifact_sources.update(source_artifact_sources)
    dict_path = task_dir / "imports" / "build" / "dict"
    options_path = task_dir / "imports" / "build" / "options"
    enriched_summary = {
        **summary,
        "dataset_contract_context": dataset_contract_context,
        "dataset_contract_hints": dataset_contract_context.get("contract_hints", []),
        **source_context_payload,
    }

    package_payload = {
        "binary_target_name": str(summary.get("binary_name") or task_dir.name),
        "summary": enriched_summary,
        "selected_target_function": selected_target,
        "selected_target_functions": [item.get("name") for item in candidate_records[:6]],
        "selection_rationale": selection_rationale,
        "entry_candidates": entry_candidates,
        "parser_candidates": [item for item in parser_candidates[:32] if not _is_runtime_noise_name(str(item.get("name") or ""))],
        "contract_inference": contract_inference,
        "dataset_contract_context": dataset_contract_context,
        "relevant_functions": relevant_functions,
        "relevant_strings": relevant_strings,
        "relevant_imports": relevant_imports,
        "project_token_evidence": project_token_evidence,
        "dynamic_observation": {
            "signal_category": previous_execution.get("signal_category"),
            "signal_subcategory": previous_execution.get("signal_subcategory"),
            "signal_signature": previous_execution.get("signal_signature"),
            "raw_execution_records": len(previous_execution.get("run_records") or []),
        },
        "dataset_contract_hints": dataset_contract_context.get("contract_hints", []),
        "source_context_available": source_context_payload.get("source_context_available", False),
        "source_typed_functions": source_context_payload.get("source_typed_functions", []),
        "source_parser_adjacent": source_context_payload.get("source_parser_adjacent", []),
        "source_function_symbols": source_context_payload.get("source_function_symbols", []),
        "source_selected_target_functions": source_context_payload.get("source_selected_target_functions", []),
        "context_sources": context_sources,
        "artifact_sources": artifact_sources,
    }
    context_package_path_str = _write_json(binary_context_package_path(task_dir.name), package_payload)
    _write_json(
        binary_target_selection_manifest_path(task_dir.name),
        {
            "task_id": task_dir.name,
            "selection_backend": "ida_inventory_plus_callgraph_plus_contract_inference",
            "selected_target_function": (selected_target or {}).get("name") if isinstance(selected_target, dict) else None,
            "selected_target_functions": [item.get("name") for item in candidate_records[:6]],
            "selection_rationale": selection_rationale,
            "project_name": project_name,
            "project_tokens": list(project_tokens),
            "dataset_contract_hints": dataset_contract_context.get("contract_hints", []),
            "query_backend_dominant": bool(selected_target and selected_target.get("project_local_match")),
            "candidate_count": len(candidate_records),
            "candidate_preview": [
                {
                    "name": item.get("name"),
                    "score": item.get("selection_score"),
                    "reasons": item.get("selection_reasons"),
                    "project_local_match": item.get("project_local_match"),
                }
                for item in candidate_records[:12]
            ],
        },
    )
    _write_json(
        binary_project_local_denoising_manifest_path(task_dir.name),
        {
            "task_id": task_dir.name,
            "project_name": project_name,
            "project_tokens": list(project_tokens),
            "selected_target_function": (selected_target or {}).get("name") if isinstance(selected_target, dict) else None,
            "dataset_contract_hints": dataset_contract_context.get("contract_hints", []),
            "project_local_candidates": [
                {
                    "name": item.get("name"),
                    "score": item.get("selection_score"),
                    "reasons": item.get("selection_reasons"),
                }
                for item in candidate_records
                if item.get("project_local_match")
            ][:16],
            "project_token_evidence": project_token_evidence,
        },
    )
    _write_json(
        binary_runtime_noise_filter_manifest_path(task_dir.name),
        {
            "task_id": task_dir.name,
            "project_name": project_name,
            "project_tokens": list(project_tokens),
            "runtime_noise_prefixes": list(RUNTIME_NOISE_PREFIXES),
            "cpp_runtime_noise_prefixes": list(CPP_RUNTIME_NOISE_PREFIXES),
            "runtime_noise_tokens": list(RUNTIME_NOISE_TOKENS),
            "libc_noise_tokens": list(LIBC_NOISE_TOKENS),
            "inventory_parser_candidate_count": len(inventory_parser_candidates),
            "seed_candidate_count_before_scoring": len(seed_candidates),
            "runtime_noise_removed_estimate": runtime_noise_removed,
        },
    )
    _write_json(
        dynamic_observation_bridge_path(task_dir.name),
        {
            "task_id": task_dir.name,
            "previous_execution_manifest_path": str(runtime_dir / "binary_execution_manifest.json"),
            "contract_inference_manifest_path": str(binary_dir / "binary_contract_inference_manifest.json"),
            "observation_to_selection_bridge": selection_rationale,
            "dynamic_observation_summary": package_payload["dynamic_observation"],
            "dataset_contract_context": dataset_contract_context,
        },
    )

    binary_slice = BinarySlice(
        binary_target_name=str(summary.get("binary_name") or task_dir.name),
        entry_candidates=entry_candidates,
        relevant_functions=relevant_functions,
        relevant_strings=relevant_strings[:20],
        relevant_imports=relevant_imports[:20],
        parser_candidates=parser_candidates[:20],
        selected_target_function=selected_target if isinstance(selected_target, dict) else None,
        selection_rationale=selection_rationale,
        contract_inference=contract_inference,
        context_sources=context_sources,
        artifact_sources=artifact_sources,
        input_mode=input_mode,
        launcher_semantics_source=launcher_semantics_source,
    )
    return BinarySeedContext(
        summary=enriched_summary,
        binary_slice=binary_slice,
        context_sources=context_sources,
        artifact_sources=artifact_sources,
        context_package_path=context_package_path_str,
        dict_snippet=_read_optional_text(dict_path),
        options_snippet=_read_optional_text(options_path, limit=800),
    )

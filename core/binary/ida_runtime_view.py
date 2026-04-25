from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.storage.layout import (
    binary_callgraph_manifest_path,
    binary_contract_inference_manifest_path,
    binary_function_inventory_path,
    binary_ida_runtime_view_path,
    binary_target_selection_manifest_path,
    ida_to_binary_context_bridge_path,
    task_json_path,
)

RUNTIME_NOISE_TOKENS = (
    "__asan",
    "__sanitizer",
    "__interceptor",
    "__lsan",
    "__ubsan",
    "sanitizer",
    "malloc",
    "free",
    "memcpy",
    "memcmp",
    "strlen",
    "strcpy",
    "operator new",
    "operator delete",
)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def normalize_binary_provenance_class(binary_mode: str | None, binary_provenance: str | None) -> str:
    raw = " ".join(part for part in [str(binary_mode or ""), str(binary_provenance or "")] if part).lower()
    if "source_derived" in raw or "source-derived" in raw:
        return "source-derived"
    if "opaque" in raw:
        return "opaque"
    if raw:
        return "native"
    return "unknown"


def _is_runtime_noise(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return True
    return any(token in lowered for token in RUNTIME_NOISE_TOKENS)


def _trim_candidates(
    entries: list[dict[str, Any]] | None,
    *,
    limit: int,
    include_score: bool = False,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in entries or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name or name in seen or _is_runtime_noise(name):
            continue
        payload = {
            "name": name,
            "address": item.get("address"),
            "project_local_match": bool(item.get("project_local_match")),
            "reasons": list(item.get("reasons") or item.get("selection_reasons") or []),
        }
        if include_score:
            payload["score"] = float(item.get("score") or item.get("selection_score") or 0.0)
        selected.append({key: value for key, value in payload.items() if value not in (None, [], "", False)})
        seen.add(name)
        if len(selected) >= limit:
            break
    return selected


def _callgraph_neighbors(selected_target: str | None, callgraph_payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not selected_target:
        return []
    callers: set[str] = set()
    callees: set[str] = set()
    for edge in callgraph_payload.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        caller = str(edge.get("caller") or "").strip()
        callee = str(edge.get("callee") or "").strip()
        if caller == selected_target and callee and not _is_runtime_noise(callee):
            callees.add(callee)
        if callee == selected_target and caller and not _is_runtime_noise(caller):
            callers.add(caller)
        if len(callers) + len(callees) >= 24:
            break
    neighbors = [
        {"name": name, "direction": "caller"}
        for name in sorted(callers)
    ] + [
        {"name": name, "direction": "callee"}
        for name in sorted(callees)
    ]
    return neighbors[:16]


def _contract_hints(
    metadata: dict[str, Any],
    runtime: dict[str, Any],
    contract_payload: dict[str, Any],
    selection_payload: dict[str, Any],
) -> list[str]:
    hints: list[str] = []
    for raw_hint in (
        metadata.get("binary_contract_hints") or []
    ) + (
        runtime.get("binary_input_contract_hints") or []
    ) + (
        selection_payload.get("dataset_contract_hints") or []
    ) + (
        contract_payload.get("usage_lines") or []
    ):
        hint = str(raw_hint or "").strip()
        if hint and hint not in hints:
            hints.append(hint)
        if len(hints) >= 12:
            break
    return hints


def build_binary_ida_runtime_view(task_id: str, *, generated_at: str | None = None) -> dict[str, Any]:
    task_payload = _read_json(task_json_path(task_id), {})
    metadata = dict(task_payload.get("metadata") or {})
    runtime = dict(task_payload.get("runtime") or {})
    function_inventory = _read_json(binary_function_inventory_path(task_id), {})
    callgraph_payload = _read_json(binary_callgraph_manifest_path(task_id), {})
    contract_payload = _read_json(binary_contract_inference_manifest_path(task_id), {})
    ida_bridge_payload = _read_json(ida_to_binary_context_bridge_path(task_id), {})
    selection_payload = _read_json(binary_target_selection_manifest_path(task_id), {})

    binary_mode = str(metadata.get("binary_mode") or runtime.get("binary_mode") or "").strip() or None
    binary_provenance = str(metadata.get("binary_provenance") or runtime.get("binary_provenance") or "").strip() or None
    provenance_class = normalize_binary_provenance_class(binary_mode, binary_provenance)

    focus_candidates = _trim_candidates(
        selection_payload.get("candidate_preview")
        or function_inventory.get("parser_candidates")
        or ida_bridge_payload.get("parser_candidates"),
        limit=12,
        include_score=True,
    )
    parser_candidates = _trim_candidates(
        ida_bridge_payload.get("parser_candidates") or function_inventory.get("parser_candidates"),
        limit=12,
        include_score=False,
    )
    entry_candidates = _trim_candidates(
        ida_bridge_payload.get("entry_candidates"),
        limit=12,
        include_score=False,
    )
    selected_target_function = (
        str(selection_payload.get("selected_target_function") or "").strip()
        or str(runtime.get("selected_target_function") or "").strip()
        or str(runtime.get("selected_binary_slice_focus") or "").strip()
    )
    if not selected_target_function and focus_candidates:
        selected_target_function = str(focus_candidates[0].get("name") or "").strip()
    if not selected_target_function and parser_candidates:
        selected_target_function = str(parser_candidates[0].get("name") or "").strip()
    selected_binary_slice_focus = (
        str(runtime.get("selected_binary_slice_focus") or "").strip()
        or selected_target_function
        or None
    )
    callgraph_neighbors = _callgraph_neighbors(selected_target_function or None, callgraph_payload)
    contract_hints = _contract_hints(metadata, runtime, contract_payload, selection_payload)
    payload = {
        "task_id": task_id,
        "generated_at": generated_at or runtime.get("binary_seed_completed_at") or runtime.get("binary_analysis_completed_at"),
        "binary_mode": binary_mode,
        "binary_provenance": binary_provenance,
        "provenance_class": provenance_class,
        "analysis_backend": runtime.get("binary_analysis_backend"),
        "selected_target_function": selected_target_function or None,
        "selected_binary_slice_focus": selected_binary_slice_focus,
        "selection_rationale": list(selection_payload.get("selection_rationale") or []),
        "contract": {
            "input_mode": contract_payload.get("selected_input_mode") or runtime.get("binary_input_contract"),
            "confidence": contract_payload.get("selected_confidence") or runtime.get("binary_input_contract_confidence"),
            "reason": contract_payload.get("selected_reason") or runtime.get("binary_input_contract_confidence_reason"),
            "source": runtime.get("binary_input_contract_source") or metadata.get("binary_input_contract_source"),
            "hints": contract_hints,
        },
        "inventory_summary": {
            "function_count": int(function_inventory.get("function_count") or 0),
            "parser_candidate_count": len(function_inventory.get("parser_candidates") or []),
            "entry_candidate_count": len(ida_bridge_payload.get("entry_candidates") or []),
            "callgraph_edge_count": int(callgraph_payload.get("edge_count") or 0),
            "focus_candidate_count": int(selection_payload.get("candidate_count") or len(focus_candidates)),
        },
        "focus_candidates": focus_candidates,
        "parser_candidates": parser_candidates,
        "entry_candidates": entry_candidates,
        "callgraph_neighbors": callgraph_neighbors,
        "artifact_paths": {
            "binary_function_inventory_path": str(binary_function_inventory_path(task_id)),
            "binary_callgraph_manifest_path": str(binary_callgraph_manifest_path(task_id)),
            "binary_contract_inference_manifest_path": str(binary_contract_inference_manifest_path(task_id)),
            "ida_to_binary_context_bridge_path": str(ida_to_binary_context_bridge_path(task_id)),
            "binary_target_selection_manifest_path": str(binary_target_selection_manifest_path(task_id)),
        },
    }
    _write_json(binary_ida_runtime_view_path(task_id), payload)
    return payload

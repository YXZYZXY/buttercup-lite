from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.binary_seed.models import BinarySeedContext
from core.storage.layout import binary_slice_manifest_path


def write_binary_slice(task_id: str, context: BinarySeedContext) -> Path:
    payload: dict[str, Any] = {
        "task_id": task_id,
        "binary_target_name": context.binary_slice.binary_target_name,
        "input_mode": context.binary_slice.input_mode,
        "launcher_semantics_source": context.binary_slice.launcher_semantics_source,
        "entry_candidates": context.binary_slice.entry_candidates,
        "relevant_functions": context.binary_slice.relevant_functions,
        "relevant_strings": context.binary_slice.relevant_strings,
        "relevant_imports": context.binary_slice.relevant_imports,
        "parser_candidates": context.binary_slice.parser_candidates,
        "selected_target_function": context.binary_slice.selected_target_function,
        "selection_rationale": context.binary_slice.selection_rationale,
        "contract_inference": context.binary_slice.contract_inference,
        "context_sources": context.context_sources,
        "artifact_sources": context.artifact_sources,
        "slice_strategy": {
            "entrypoint_seed": "ida entrypoints + parser candidates + exports/functions",
            "function_filter": "ida parser candidates + callgraph + string xrefs",
            "string_filter": "parser-adjacent strings and format hints",
            "import_filter": "memory, file I/O, argv/stdin usage APIs",
        },
    }
    path = binary_slice_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path

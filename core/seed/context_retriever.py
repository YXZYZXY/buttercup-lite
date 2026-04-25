from __future__ import annotations

import json
import zipfile
from pathlib import Path

from core.program_model.context_package import build_context_package
from core.seed.models import HarnessSelection, SeedContext
from core.storage.layout import task_root
from core.utils.settings import settings

def _read_text(path: Path, limit: int = 4000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def _load_build_registry(task_id: str) -> dict:
    task_dir = task_root(task_id)
    registry_path = task_dir / "build" / "build_registry.json"
    return json.loads(registry_path.read_text(encoding="utf-8"))

def _sample_from_directory(directory: Path) -> list[str]:
    samples: list[str] = []
    for candidate in sorted(directory.rglob("*")):
        if not candidate.is_file():
            continue
        text = _read_text(candidate, limit=600)
        if any(token in text for token in ("<", "{", "[", "\"")) and text.strip():
            samples.append(text)
        if len(samples) >= settings.seed_import_sample_limit:
            break
    return samples


def _sample_from_zip(zip_path: Path) -> list[str]:
    samples: list[str] = []
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                data = zf.read(name)[:600]
                text = data.decode("utf-8", "ignore")
                if any(token in text for token in ("<", "{", "[", "\"")) and text.strip():
                    samples.append(text)
                if len(samples) >= 2:
                    break
    except OSError:
        return []
    return samples


def retrieve_context(task_id: str, harness: HarnessSelection, *, task_mode: str = "SEED_INIT") -> SeedContext:
    build_registry = _load_build_registry(task_id)
    harness_source = _read_text(harness.source_path) if harness.source_path else ""
    context_sources: list[str] = []
    context_package_path, context_package = build_context_package(task_id, harness, task_mode=task_mode)

    related_functions = list(context_package.get("related_functions", []))
    target_function = context_package.get("target_function")
    callers = list(context_package.get("callers", []))
    callees = list(context_package.get("callees", []))
    extended_context_functions = list(context_package.get("extended_context_functions", []))
    key_types = list(context_package.get("key_types", []))
    key_constants = list(context_package.get("key_constants", []))
    parser_adjacent_candidates = list(
        context_package.get("typed_parser_adjacent_candidates")
        or (context_package.get("coverage_query_evidence") or {}).get("tree_sitter_parser_adjacent_candidates", [])
    )
    selection_rationale = list(context_package.get("selection_rationale", []))

    sample_inputs: list[str] = []
    resolved_corpus = task_root(task_id) / "imports" / "corpus" / "current"
    if resolved_corpus.exists():
        sample_inputs.extend(_sample_from_directory(resolved_corpus))
        context_sources.append(str(resolved_corpus))

    if harness.seed_corpus_zip and harness.seed_corpus_zip.exists():
        sample_inputs.extend(_sample_from_zip(harness.seed_corpus_zip))
        context_sources.append(str(harness.seed_corpus_zip))

    if harness.dict_path and harness.dict_path.exists():
        context_sources.append(str(harness.dict_path))
    if harness.options_path and harness.options_path.exists():
        context_sources.append(str(harness.options_path))
    if harness.source_path:
        context_sources.append(str(harness.source_path))
    context_sources.extend(context_package.get("evidence_paths", {}).values())
    for fact in [target_function, *related_functions[:4], *callers[:3], *callees[:3]]:
        if fact and fact.get("file"):
            context_sources.append(str(fact["file"]))

    deduped_sources = []
    seen_sources: set[str] = set()
    for item in context_sources:
        if not item or item in seen_sources:
            continue
        seen_sources.add(item)
        deduped_sources.append(item)

    return SeedContext(
        selected_harness=str(context_package.get("selected_harness") or harness.name),
        selected_harness_path=context_package.get("selected_harness_path") or (str(harness.executable_path) if harness.executable_path else None),
        candidate_harnesses=list(context_package.get("candidate_harnesses", [])),
        harness_source=harness_source,
        related_functions=related_functions,
        target_function=target_function,
        selected_target_functions=list(context_package.get("selected_target_functions", [])),
        callers=callers,
        callees=callees,
        extended_context_functions=extended_context_functions,
        key_types=key_types,
        key_constants=key_constants,
        parser_adjacent_candidates=parser_adjacent_candidates,
        sample_inputs=sample_inputs[: settings.seed_import_sample_limit],
        dict_snippet=_read_text(harness.dict_path, limit=1500) if harness.dict_path else None,
        options_snippet=_read_text(harness.options_path, limit=800) if harness.options_path else None,
        context_sources=deduped_sources,
        context_package_path=str(context_package_path),
        context_package=context_package,
        selection_rationale=selection_rationale,
    )

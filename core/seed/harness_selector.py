from __future__ import annotations

import json
from pathlib import Path

from core.seed.models import HarnessSelection
from core.utils.settings import expand_local_path

_CONTAINER_TASK_ROOT = "/data/tasks/"


def _host_path(path: str | Path) -> Path:
    raw = str(path)
    candidate = Path(raw)
    if candidate.exists():
        return candidate
    if raw.startswith(_CONTAINER_TASK_ROOT):
        suffix = Path(raw[len(_CONTAINER_TASK_ROOT) :])
        return expand_local_path(Path("data/tasks") / suffix)
    return candidate


def _load_build_registry(path: str | Path) -> dict:
    registry_path = _host_path(path)
    return json.loads(registry_path.read_text(encoding="utf-8"))


def _token_score(name: str, project_name: str | None) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    lowered = name.lower()
    project = (project_name or "").strip().lower()
    if project and lowered == project:
        score += 25
        reasons.append("project_exact_match")
    elif project and project in lowered:
        score += 15
        reasons.append("project_partial_match")
    generic_tokens = (
        ("fuzzer", 8),
        ("parse", 6),
        ("parser", 6),
        ("read", 4),
        ("test", 2),
    )
    for token, value in generic_tokens:
        if token in lowered:
            score += value
            reasons.append(f"generic_token:{token}")
    return score, reasons


def load_harness_candidates(build_registry_path: str | Path, project_name: str | None = None) -> list[HarnessSelection]:
    registry = _load_build_registry(build_registry_path)
    dict_map = {Path(item["name"]).stem: _host_path(item["path"]) for item in registry.get("dicts", [])}
    options_map = {Path(item["name"]).stem: _host_path(item["path"]) for item in registry.get("options", [])}
    zip_map = {
        item["name"].replace("_seed_corpus.zip", ""): _host_path(item["path"])
        for item in registry.get("seed_corpora", [])
    }
    harness_source_map = {item["name"]: _host_path(item["path"]) for item in registry.get("harnesses", [])}

    candidates: list[HarnessSelection] = []
    for fuzzer in registry.get("fuzzers", []):
        name = fuzzer["name"]
        score, reasons = _token_score(name, project_name)
        if harness_source_map.get(name):
            score += 20
            reasons.append("has_source")
        if dict_map.get(name):
            score += 8
            reasons.append("has_dict")
        if options_map.get(name):
            score += 5
            reasons.append("has_options")
        if zip_map.get(name):
            score += 10
            reasons.append("has_seed_zip")

        candidate = HarnessSelection(
            name=name,
            executable_path=_host_path(fuzzer["path"]),
            source_path=harness_source_map.get(name),
            dict_path=dict_map.get(name),
            options_path=options_map.get(name),
            seed_corpus_zip=zip_map.get(name),
            score=score,
            reasons=reasons,
        )
        candidates.append(candidate)
    return candidates


def select_harness(build_registry_path: str | Path, project_name: str | None = None) -> HarnessSelection:
    candidates = load_harness_candidates(build_registry_path, project_name)
    best: HarnessSelection | None = None
    for candidate in candidates:
        if best is None or candidate.score > best.score:
            best = candidate

    if best is None:
        raise RuntimeError("no harness candidates available in build registry")
    return best


def select_harness_by_name(
    build_registry_path: str | Path,
    requested_name: str,
    project_name: str | None = None,
) -> HarnessSelection | None:
    requested = requested_name.strip().lower()
    for candidate in load_harness_candidates(build_registry_path, project_name):
        if candidate.name.strip().lower() == requested:
            return candidate
    return None

from __future__ import annotations

import json
from pathlib import Path

from core.seed.models import HarnessSelection


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_task_record(task_dir: Path) -> dict:
    return _load_json(task_dir / "task.json")


def load_build_registry(task_dir: Path) -> dict:
    return _load_json(task_dir / "build" / "build_registry.json")


def active_harness_record(task_dir: Path) -> dict:
    task = load_task_record(task_dir)
    runtime = task.get("runtime", {})
    seed_manifest_path = task_dir / "seed" / "seed_manifest.json"
    seed_manifest = _load_json(seed_manifest_path) if seed_manifest_path.exists() else {}
    return {
        "name": runtime.get("active_harness") or seed_manifest.get("selected_harness"),
        "path": runtime.get("active_harness_path") or seed_manifest.get("selected_harness_path"),
        "source_path": runtime.get("harness_source_path") or seed_manifest.get("harness_source_path"),
    }


def resolve_active_harness(task_dir: Path) -> HarnessSelection:
    build_registry = load_build_registry(task_dir)
    active = active_harness_record(task_dir)
    if not active["name"] or not active["path"]:
        raise RuntimeError("active harness is not defined for task")

    dict_path = None
    options_path = None
    seed_corpus_zip = None
    for item in build_registry.get("dicts", []):
        if Path(item["name"]).stem == active["name"]:
            dict_path = Path(item["path"])
            break
    for item in build_registry.get("options", []):
        if Path(item["name"]).stem == active["name"]:
            options_path = Path(item["path"])
            break
    for item in build_registry.get("seed_corpora", []):
        if item["name"].replace("_seed_corpus.zip", "") == active["name"]:
            seed_corpus_zip = Path(item["path"])
            break

    return HarnessSelection(
        name=active["name"],
        executable_path=Path(active["path"]),
        source_path=Path(active["source_path"]) if active["source_path"] else None,
        dict_path=dict_path,
        options_path=options_path,
        seed_corpus_zip=seed_corpus_zip,
        reasons=["active_harness"],
        score=1000,
    )


def classify_crash_source(testcase_path: str | Path) -> str:
    name = Path(testcase_path).name
    if name.startswith("imported_"):
        return "imported_valid"
    return "live_raw"

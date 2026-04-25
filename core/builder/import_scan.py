from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


HARNESS_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
EXECUTABLE_EXCLUDES = {"llvm-symbolizer"}


def _json_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _scan_executables(build_out_dir: Path) -> list[dict[str, Any]]:
    fuzzers: list[dict[str, Any]] = []
    for candidate in sorted(build_out_dir.rglob("*")):
        if not candidate.is_file():
            continue
        if candidate.name in EXECUTABLE_EXCLUDES:
            continue
        if candidate.suffix in {".dict", ".options", ".zip"}:
            continue
        if not os.access(candidate, os.X_OK):
            continue
        fuzzers.append(
            {
                "name": candidate.name,
                "path": str(candidate),
                "relative_path": str(candidate.relative_to(build_out_dir)),
                "size": candidate.stat().st_size,
            }
        )
    return fuzzers


def _scan_named_files(build_out_dir: Path, suffix: str, label: str) -> list[dict[str, Any]]:
    return [
        {
            "name": candidate.name,
            "path": str(candidate),
            "relative_path": str(candidate.relative_to(build_out_dir)),
            "type": label,
        }
        for candidate in sorted(build_out_dir.rglob(f"*{suffix}"))
        if candidate.is_file()
    ]


def _scan_seed_corpora(build_out_dir: Path) -> list[dict[str, Any]]:
    corpora = []
    for candidate in sorted(build_out_dir.rglob("*_seed_corpus.zip")):
        corpora.append(
            {
                "name": candidate.name,
                "path": str(candidate),
                "relative_path": str(candidate.relative_to(build_out_dir)),
            }
        )
    return corpora


def _scan_harnesses(harness_dir: Path | None, fuzzers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if harness_dir is None or not harness_dir.exists() or not harness_dir.is_dir():
        return []

    fuzzer_names = {fuzzer["name"] for fuzzer in fuzzers}
    harnesses = []
    for candidate in sorted(harness_dir.rglob("*")):
        if not candidate.is_file() or candidate.suffix.lower() not in HARNESS_SUFFIXES:
            continue
        stem = candidate.stem
        harnesses.append(
            {
                "name": stem,
                "path": str(candidate),
                "matched_fuzzer": stem if stem in fuzzer_names else None,
            },
        )
    return harnesses


def scan_imported_build(
    *,
    task_id: str,
    build_out_dir: Path,
    harness_dir: Path | None,
    build_dir: Path,
    mode: str = "import_assisted",
) -> dict[str, Any]:
    build_dir.mkdir(parents=True, exist_ok=True)
    fuzzers = _scan_executables(build_out_dir)
    dicts = _scan_named_files(build_out_dir, ".dict", "dict")
    options = _scan_named_files(build_out_dir, ".options", "options")
    seed_corpora = _scan_seed_corpora(build_out_dir)
    harnesses = _scan_harnesses(harness_dir, fuzzers)

    harnesses_path = build_dir / "harnesses.json"
    _json_write(harnesses_path, harnesses)

    registry = {
        "task_id": task_id,
        "mode": mode,
        "build_out_dir": str(build_out_dir),
        "harness_dir": str(harness_dir) if harness_dir else None,
        "fuzzers": fuzzers,
        "dicts": dicts,
        "options": options,
        "seed_corpora": seed_corpora,
        "harnesses": harnesses,
        "artifacts": {
            "harnesses.json": str(harnesses_path),
        },
    }
    registry_path = build_dir / "build_registry.json"
    _json_write(registry_path, registry)
    registry["artifacts"]["build_registry.json"] = str(registry_path)
    _json_write(registry_path, registry)
    return registry

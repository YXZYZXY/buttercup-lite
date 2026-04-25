from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.source_task import repo_identity
from core.storage.layout import source_resolution_manifest_path
from core.utils.settings import settings


def _read_text(path: Path, limit: int = 20000) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")[:limit]


def _extract_repo_urls(text: str) -> list[str]:
    return re.findall(r"https?://[A-Za-z0-9_.:/~?&=%#@!+\\-]+", text)


def _yaml_main_repo(project_yaml: Path) -> str | None:
    text = _read_text(project_yaml)
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("main_repo:"):
            return stripped.split(":", 1)[1].strip().strip("\"'")
    urls = _extract_repo_urls(text)
    return urls[0] if urls else None


def _repo_name_from_url(url: str | None) -> str | None:
    if not url:
        return None
    return repo_identity(url).get("repo_name")


def _discover_harnesses(project_dir: Path) -> list[dict[str, Any]]:
    harnesses: list[dict[str, Any]] = []
    for candidate in sorted(project_dir.glob("*")):
        if candidate.is_file() and candidate.suffix in {".c", ".cc", ".cpp", ".cxx"}:
            text = _read_text(candidate, limit=120000)
            if "LLVMFuzzerTestOneInput" in text:
                harnesses.append(
                    {
                        "name": candidate.stem,
                        "path": str(candidate),
                        "kind": "oss_fuzz_harness_source",
                        "evidence": "LLVMFuzzerTestOneInput",
                    },
                )
    return harnesses


def _source_entry_hints(source_root: Path) -> dict[str, Any]:
    candidates = []
    for relative in ("tests", "test", "examples", "example", "fuzzing", "fuzz", "meson.build", "CMakeLists.txt", "Makefile", "configure.ac"):
        path = source_root / relative
        if path.exists():
            candidates.append(str(path))
    return {
        "source_has_tests_or_examples": any(Path(item).name in {"tests", "test", "examples", "example"} for item in candidates),
        "source_build_files": [item for item in candidates if Path(item).name not in {"tests", "test", "examples", "example", "fuzzing", "fuzz"}],
        "source_entry_candidates": candidates,
    }


def _score_project(
    project_dir: Path,
    *,
    requested_identity: dict[str, Any],
    hint: str | None,
) -> dict[str, Any]:
    project_yaml = project_dir / "project.yaml"
    dockerfile = project_dir / "Dockerfile"
    build_sh = project_dir / "build.sh"
    main_repo = _yaml_main_repo(project_yaml)
    main_repo_identity = repo_identity(main_repo) if main_repo else {}
    requested_repo_name = str(requested_identity.get("repo_name") or "").lower()
    requested_key = str(requested_identity.get("canonical_repo_key") or "").lower()
    main_key = str(main_repo_identity.get("canonical_repo_key") or "").lower()
    main_repo_name = str(main_repo_identity.get("repo_name") or "").lower()
    project_name = project_dir.name.lower()

    score = 0
    reasons: list[str] = []
    if hint and project_name == str(hint).strip().lower():
        score += 100
        reasons.append("explicit_hint_matches_project_dir")
    if requested_key and requested_key == main_key:
        score += 100
        reasons.append("project_yaml_main_repo_exact_match")
    if requested_repo_name and requested_repo_name == project_name:
        score += 70
        reasons.append("repo_name_matches_oss_fuzz_project_dir")
    if requested_repo_name and requested_repo_name == main_repo_name:
        score += 45
        reasons.append("repo_name_matches_project_yaml_main_repo")
    for evidence_path, points, label in (
        (dockerfile, 15, "dockerfile_mentions_repo_name"),
        (build_sh, 10, "build_sh_mentions_repo_name"),
    ):
        text = _read_text(evidence_path).lower()
        if requested_repo_name and requested_repo_name in text:
            score += points
            reasons.append(label)
    harnesses = _discover_harnesses(project_dir)
    if harnesses:
        score += min(20, 5 * len(harnesses))
        reasons.append("oss_fuzz_harness_sources_discovered")

    return {
        "project": project_dir.name,
        "project_root_path": str(project_dir),
        "project_yaml_path": str(project_yaml) if project_yaml.exists() else None,
        "dockerfile_path": str(dockerfile) if dockerfile.exists() else None,
        "build_sh_path": str(build_sh) if build_sh.exists() else None,
        "main_repo": main_repo,
        "main_repo_identity": main_repo_identity,
        "score": score,
        "reasons": reasons,
        "discovered_harnesses": harnesses,
    }


def _oss_fuzz_root() -> Path:
    return Path(settings.oss_fuzz_root).expanduser().resolve()


def resolve_source_project(
    *,
    repo_url: str,
    source_root: str | Path,
    oss_fuzz_project_hint: str | None = None,
) -> dict[str, Any]:
    source_root_path = Path(source_root)
    identity = repo_identity(repo_url)
    root = _oss_fuzz_root()
    projects_root = root / "projects"
    candidates: list[dict[str, Any]] = []
    if projects_root.exists():
        for project_dir in sorted(item for item in projects_root.iterdir() if item.is_dir()):
            scored = _score_project(project_dir, requested_identity=identity, hint=oss_fuzz_project_hint)
            if scored["score"] > 0 or oss_fuzz_project_hint:
                candidates.append(scored)
    candidates.sort(key=lambda item: item["score"], reverse=True)
    selected = candidates[0] if candidates else None
    source_hints = _source_entry_hints(source_root_path)

    if selected and int(selected["score"]) >= 55 and selected.get("project_yaml_path"):
        resolution_class = "direct_oss_fuzz_project_reuse"
        selected_build_strategy = "oss_fuzz_build_assets"
        selected_harness_strategy = "oss_fuzz_harness_scan"
        confidence = "high" if int(selected["score"]) >= 80 else "medium"
    elif source_hints["source_has_tests_or_examples"] or source_hints["source_build_files"]:
        resolution_class = "source_adapter_with_existing_test_or_example_entry"
        selected_build_strategy = "minimal_source_build_from_repo_introspection"
        selected_harness_strategy = "source_entry_or_test_harness_discovery"
        confidence = "medium"
    else:
        resolution_class = "minimal_source_adapter_required"
        selected_build_strategy = "minimal_source_adapter_required"
        selected_harness_strategy = "requires_harness_adapter"
        confidence = "low"

    selected_project = selected.get("project") if selected else None
    selected_project_root = selected.get("project_root_path") if selected else None
    selected_project_yaml = selected.get("project_yaml_path") if selected else None
    discovered_harnesses = selected.get("discovered_harnesses", []) if selected else []

    payload = {
        "repo_url": repo_url,
        "repo_identity": identity,
        "oss_fuzz_root": str(root),
        "oss_fuzz_projects_root_exists": projects_root.exists(),
        "oss_fuzz_project_hint": oss_fuzz_project_hint,
        "oss_fuzz_project_resolution": {
            "resolution_class": resolution_class,
            "selected_oss_fuzz_project": selected_project,
            "selected_oss_fuzz_project_path": selected_project_root,
            "selected_project_yaml_path": selected_project_yaml,
            "candidate_count": len(candidates),
            "top_candidates": candidates[:8],
        },
        "build_strategy_resolution": {
            "selected_build_strategy": selected_build_strategy,
            "selected_harness_strategy": selected_harness_strategy,
            "discovered_harnesses": discovered_harnesses,
            "source_entry_hints": source_hints,
            "tracer_build_strategy": "dedicated_tracer_replay_binary_if_build_outputs_support_it",
            "coverage_build_strategy": "coverage_capable_fuzzer_build_or_llvm_summary_if_available",
        },
        "resolution_class": resolution_class,
        "selected_oss_fuzz_project": selected_project,
        "selected_oss_fuzz_project_path": selected_project_root,
        "selected_project_yaml_path": selected_project_yaml,
        "selected_build_strategy": selected_build_strategy,
        "selected_harness_strategy": selected_harness_strategy,
        "discovered_harnesses": discovered_harnesses,
        "tracer_build_strategy": "dedicated_tracer_replay_binary_if_build_outputs_support_it",
        "coverage_build_strategy": "coverage_capable_fuzzer_build_or_llvm_summary_if_available",
        "confidence": confidence,
        "rationale": (selected or {}).get("reasons", []) or [resolution_class],
        "metadata_patch": {
            "project": selected_project,
            "selected_oss_fuzz_project": selected_project,
            "existing_oss_fuzz_project_path": selected_project_root,
            "existing_project_yaml_path": selected_project_yaml,
            "source_resolution_class": resolution_class,
            "selected_build_strategy": selected_build_strategy,
            "selected_harness_strategy": selected_harness_strategy,
            "discovered_harnesses": discovered_harnesses,
            "tracer_build_strategy": "dedicated_tracer_replay_binary_if_build_outputs_support_it",
            "coverage_build_strategy": "coverage_capable_fuzzer_build_or_llvm_summary_if_available",
        },
    }
    # Drop null path metadata so legacy imports do not try to stage "None".
    payload["metadata_patch"] = {key: value for key, value in payload["metadata_patch"].items() if value is not None}
    return payload


def write_source_resolution_manifest(task_id: str, *, generated_at: str, resolution: dict[str, Any]) -> dict[str, Any]:
    payload = {"task_id": task_id, "generated_at": generated_at, **resolution}
    path = source_resolution_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {**payload, "source_resolution_manifest_path": str(path)}

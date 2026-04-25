from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.models.task import AdapterType, TaskRecord, TaskSource, TaskSpec
from core.storage.layout import source_task_normalization_manifest_path
from core.utils.settings import is_remote_uri


def canonicalize_repo_url(repo_url: str) -> str:
    value = str(repo_url).strip()
    if not value:
        raise ValueError("repo_url is empty")
    if value.startswith("git@"):
        host, repo = value.split(":", 1)
        return f"ssh://{host}/{repo}".removesuffix("/")
    return value.removesuffix("/")


def repo_identity(repo_url: str) -> dict[str, Any]:
    canonical = canonicalize_repo_url(repo_url)
    parsed = urlparse(canonical)
    if parsed.scheme == "ssh" and parsed.netloc.startswith("git@"):
        host = parsed.netloc.split("@", 1)[1]
    else:
        host = parsed.netloc
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    repo_name = parts[-1].removesuffix(".git") if parts else Path(canonical).name.removesuffix(".git")
    owner = parts[-2] if len(parts) >= 2 else None
    return {
        "repo_url": repo_url,
        "canonical_repo_url": canonical,
        "scheme": parsed.scheme or ("local" if Path(canonical).exists() else ""),
        "host": host,
        "owner": owner,
        "repo_name": repo_name,
        "repo_slug": f"{owner}/{repo_name}" if owner else repo_name,
        "canonical_repo_key": f"{host}/{owner}/{repo_name}".lower() if owner else f"{host}/{repo_name}".lower(),
    }


def normalize_task_spec_for_repo_first(task_spec: TaskSpec) -> TaskSpec:
    """Normalize repo-first source tasks into the existing lite TaskSource shape.

    Benchmark profiles remain valid fixtures, but the canonical source lane now
    accepts repo_url/git_ref directly and maps them to a source TaskSource before
    downloader execution.
    """

    metadata = dict(task_spec.metadata or {})
    repo_url = task_spec.repo_url or metadata.get("repo_url") or metadata.get("source_repo_url")
    git_ref = task_spec.git_ref or metadata.get("git_ref") or metadata.get("source_ref")
    if repo_url:
        normalized_repo_url = canonicalize_repo_url(str(repo_url))
        identity = repo_identity(normalized_repo_url)
        metadata.update(
            {
                "repo_first": True,
                "repo_url": normalized_repo_url,
                "source_type": task_spec.source_type or metadata.get("source_type") or "git_repo",
                "normalized_repo_identity": identity,
                "git_ref": git_ref,
                "oss_fuzz_project_hint": task_spec.oss_fuzz_project_hint or metadata.get("oss_fuzz_project_hint"),
                "patch_diff_url": task_spec.patch_diff_url or metadata.get("patch_diff_url"),
                "local_diff_path": task_spec.local_diff_path or metadata.get("local_diff_path"),
                "task_time_budget": task_spec.task_time_budget or metadata.get("task_time_budget"),
                "fuzz_budget": task_spec.fuzz_budget or metadata.get("fuzz_budget"),
                "task_mode": task_spec.mode or metadata.get("task_mode") or metadata.get("mode"),
                "benchmark_profile_role": "fallback_fixture_only",
            },
        )
        return task_spec.model_copy(
            update={
                "source": TaskSource(adapter_type=AdapterType.OSSFUZZ, uri=normalized_repo_url, ref=git_ref),
                "metadata": metadata,
                "source_type": "git_repo",
                "git_ref": git_ref,
            },
        )

    if task_spec.source is None:
        raise ValueError("repo-first source tasks require repo_url, or legacy tasks must provide source.uri")

    metadata.setdefault("repo_first", False)
    metadata.setdefault("benchmark_profile_role", "legacy_or_fixture_input")
    if task_spec.source.uri and is_remote_uri(task_spec.source.uri):
        metadata.setdefault("repo_url", canonicalize_repo_url(task_spec.source.uri))
        metadata.setdefault("git_ref", task_spec.source.ref)
        metadata.setdefault("source_type", "git_repo")
        metadata.setdefault("normalized_repo_identity", repo_identity(task_spec.source.uri))
    else:
        metadata.setdefault("source_type", "local_directory")
    return task_spec.model_copy(update={"metadata": metadata})


def _git_resolved_ref(source_root: str | None) -> dict[str, Any]:
    if not source_root:
        return {"git_ref_resolved": None, "git_head": None, "git_remote": None}
    root = Path(source_root)
    if not (root / ".git").exists():
        return {"git_ref_resolved": None, "git_head": None, "git_remote": None}
    def _git(args: list[str]) -> str | None:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            return None
        return completed.stdout.strip() or None

    return {
        "git_ref_resolved": _git(["rev-parse", "--abbrev-ref", "HEAD"]),
        "git_head": _git(["rev-parse", "HEAD"]),
        "git_remote": _git(["remote", "get-url", "origin"]),
    }


def write_source_task_normalization_manifest(
    task: TaskRecord,
    *,
    generated_at: str,
    layout: dict[str, str],
    runtime: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    resolution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    merged_metadata = {**task.metadata, **(metadata or {})}
    repo_url = merged_metadata.get("repo_url") or task.source.uri
    identity = merged_metadata.get("normalized_repo_identity") or repo_identity(str(repo_url))
    git_info = _git_resolved_ref(runtime.get("source_root") or layout.get("src"))
    payload = {
        "task_id": task.task_id,
        "generated_at": generated_at,
        "contract": "repo_first_source_task_v1",
        "repo_first": bool(merged_metadata.get("repo_first")),
        "repo_url": repo_url,
        "source_type": merged_metadata.get("source_type") or "git_repo",
        "requested_git_ref": merged_metadata.get("git_ref") or task.source.ref,
        "git_ref_resolved": git_info.get("git_ref_resolved"),
        "git_head": git_info.get("git_head"),
        "git_remote": git_info.get("git_remote"),
        "normalized_repo_identity": identity,
        "oss_fuzz_project_hint": merged_metadata.get("oss_fuzz_project_hint"),
        "oss_fuzz_project_resolution": (resolution or {}).get("oss_fuzz_project_resolution"),
        "build_strategy_resolution": (resolution or {}).get("build_strategy_resolution"),
        "task_mode_resolution": {
            "task_mode": merged_metadata.get("task_mode") or merged_metadata.get("mode") or "source_discovery",
            "task_time_budget": merged_metadata.get("task_time_budget"),
            "fuzz_budget": merged_metadata.get("fuzz_budget"),
        },
        "workspace": {
            "task_dir": task.task_dir,
            "src": layout.get("src"),
            "fuzz_tooling": layout.get("fuzz_tooling"),
            "diff": layout.get("diff"),
        },
        "rationale": (
            "repo_url normalized into canonical TaskSource; benchmark profile is only fallback/fixture metadata"
            if merged_metadata.get("repo_first")
            else "legacy source.uri task normalized into the same workspace contract"
        ),
        "confidence": (resolution or {}).get("confidence", "medium"),
    }
    path = source_task_normalization_manifest_path(task.task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {**payload, "source_task_normalization_manifest_path": str(path)}

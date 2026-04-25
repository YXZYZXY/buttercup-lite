from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from core.storage.layout import coverage_artifact_manifest_path, task_root
from core.utils.settings import expand_local_path, settings

_CONTAINER_TASK_ROOT = "/data/tasks/"


def _load_json(path: Path) -> dict[str, Any]:
    if not str(path) or str(path) == "." or not path.exists() or path.is_dir():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _sample_inputs(corpus_dir: Path, limit: int) -> list[Path]:
    samples: list[Path] = []
    for candidate in sorted(corpus_dir.rglob("*")):
        if not candidate.is_file():
            continue
        samples.append(candidate)
        if len(samples) >= limit:
            break
    return samples


def _tool_path(name: str) -> str | None:
    search_paths = []
    for prefix_str in (settings.program_model_toolchain_prefix, settings.build_toolchain_prefix):
        prefix = Path(prefix_str).expanduser()
        for candidate in (prefix / "bin", prefix / "usr" / "bin"):
            if candidate.exists():
                search_paths.append(str(candidate))
    search_path = os.pathsep.join(search_paths) if search_paths else None
    return subprocess.run(
        ["bash", "-lc", f"PATH={search_path}:$PATH command -v {name}"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip() or None


def _is_executable_file(path: Path | None) -> bool:
    return bool(path and path.exists() and path.is_file() and os.access(path, os.X_OK))


def _append_unique_path(paths: list[Path], candidate: Path | None) -> None:
    if candidate is None:
        return
    normalized = candidate.expanduser()
    if normalized not in paths:
        paths.append(normalized)


def _path_variants(raw_value: str | os.PathLike[str] | None, *, task_dir: Path | None = None) -> list[Path]:
    cleaned = str(raw_value or "").strip()
    if not cleaned:
        return []
    variants: list[Path] = []
    raw_path = Path(cleaned).expanduser()
    _append_unique_path(variants, raw_path)
    if not raw_path.is_absolute() and task_dir is not None:
        _append_unique_path(variants, task_dir / raw_path)
    if cleaned.startswith(_CONTAINER_TASK_ROOT):
        suffix = Path(cleaned[len(_CONTAINER_TASK_ROOT) :])
        _append_unique_path(variants, expand_local_path(Path("data/tasks") / suffix))
    return variants


def _record_lookup_attempt(
    lookup_trace: list[dict[str, Any]],
    *,
    stage: str,
    candidate: Path,
    raw_path: str | None = None,
    search_root: Path | None = None,
    relative_path: str | None = None,
) -> None:
    lookup_trace.append(
        {
            "stage": stage,
            "raw_path": raw_path,
            "search_root": str(search_root) if search_root else None,
            "relative_path": relative_path,
            "candidate": str(candidate),
            "exists": candidate.exists(),
            "is_file": candidate.is_file(),
            "is_executable": _is_executable_file(candidate),
        }
    )


def _resolve_binary_candidate(
    *,
    task_dir: Path,
    selected_harness: str | None,
    raw_path: str | None,
    relative_path: str | None,
    prefer_coverage_variant: bool = False,
    extra_search_roots: list[Path] | None = None,
    lookup_trace: list[dict[str, Any]],
    stage: str,
) -> Path | None:
    raw_candidates = _path_variants(raw_path, task_dir=task_dir)
    for candidate in raw_candidates:
        _record_lookup_attempt(lookup_trace, stage=stage, raw_path=raw_path, candidate=candidate)
        if _is_executable_file(candidate):
            return candidate

    search_roots: list[Path] = []
    for root in extra_search_roots or []:
        for variant in _path_variants(str(root), task_dir=task_dir):
            _append_unique_path(search_roots, variant)
    if prefer_coverage_variant:
        preferred_root = task_dir / "build" / "coverage_out"
        _append_unique_path(search_roots, preferred_root)
    else:
        for root in (task_dir / "build" / "out", task_dir / "build" / "coverage_out"):
            _append_unique_path(search_roots, root)

    relative_candidates: list[str] = []
    for value in (relative_path, *(candidate.name for candidate in raw_candidates), selected_harness):
        cleaned = str(value or "").strip()
        if cleaned and cleaned not in relative_candidates:
            relative_candidates.append(cleaned)

    for root in search_roots:
        for rel in relative_candidates:
            resolved = root / rel
            _record_lookup_attempt(
                lookup_trace,
                stage=stage,
                raw_path=raw_path,
                search_root=root,
                relative_path=rel,
                candidate=resolved,
            )
            if _is_executable_file(resolved):
                return resolved
    return None


def _resolve_coverage_binary(task, build_registry: dict[str, Any], selected_harness: str | None) -> dict[str, Any]:
    task_dir = Path(task.task_dir)
    artifacts = build_registry.get("artifacts") or {}
    build_variants = build_registry.get("build_variants") or {}
    coverage_variant = build_variants.get("coverage_build") or {}
    registry_task_id = str(build_registry.get("task_id") or "").strip()
    registry_task_root = task_root(registry_task_id) if registry_task_id else None
    extra_coverage_roots: list[Path] = []
    extra_fuzzer_roots: list[Path] = []
    coverage_build_out_dir = str(artifacts.get("coverage_build_out_dir") or "").strip()
    if coverage_build_out_dir:
        extra_coverage_roots.append(Path(coverage_build_out_dir))
    build_out_dir = str(artifacts.get("build_out_dir") or "").strip()
    if build_out_dir:
        extra_fuzzer_roots.append(Path(build_out_dir))
    if registry_task_root and registry_task_root != task_dir:
        extra_coverage_roots.append(registry_task_root / "build" / "coverage_out")
        extra_fuzzer_roots.append(registry_task_root / "build" / "out")
    lookup_trace: list[dict[str, Any]] = []
    coverage_variant_mode = str(coverage_variant.get("actual_mode") or "").strip().lower()
    coverage_expected = (
        bool(build_registry.get("coverage_fuzzers"))
        or bool(coverage_build_out_dir)
        or "coverage" in coverage_variant_mode
        or coverage_variant_mode == "dedicated_llvm_cov_build"
    )

    for item in build_registry.get("coverage_fuzzers", []):
        if str(item.get("name")) != str(selected_harness):
            continue
        resolved = _resolve_binary_candidate(
            task_dir=task_dir,
            selected_harness=selected_harness,
            raw_path=item.get("path"),
            relative_path=item.get("relative_path"),
            prefer_coverage_variant=True,
            extra_search_roots=extra_coverage_roots,
            lookup_trace=lookup_trace,
            stage="coverage_fuzzers",
        )
        if resolved:
            return {
                "path": resolved,
                "lookup_trace": lookup_trace,
                "resolution_stage": "coverage_fuzzers",
                "coverage_expected": coverage_expected,
                "build_registry_task_id": registry_task_id or None,
            }

    if selected_harness:
        resolved = _resolve_binary_candidate(
            task_dir=task_dir,
            selected_harness=selected_harness,
            raw_path=None,
            relative_path=selected_harness,
            prefer_coverage_variant=True,
            extra_search_roots=extra_coverage_roots,
            lookup_trace=lookup_trace,
            stage="coverage_variant_by_harness_name",
        )
        if resolved:
            return {
                "path": resolved,
                "lookup_trace": lookup_trace,
                "resolution_stage": "coverage_variant_by_harness_name",
                "coverage_expected": coverage_expected,
                "build_registry_task_id": registry_task_id or None,
            }

    if coverage_expected:
        return {
            "path": None,
            "lookup_trace": lookup_trace,
            "resolution_stage": "coverage_variant_missing",
            "coverage_expected": coverage_expected,
            "build_registry_task_id": registry_task_id or None,
        }

    for item in build_registry.get("fuzzers", []):
        if str(item.get("name")) != str(selected_harness):
            continue
        resolved = _resolve_binary_candidate(
            task_dir=task_dir,
            selected_harness=selected_harness,
            raw_path=item.get("path"),
            relative_path=item.get("relative_path"),
            extra_search_roots=extra_fuzzer_roots,
            lookup_trace=lookup_trace,
            stage="fuzzers",
        )
        if resolved:
            return {
                "path": resolved,
                "lookup_trace": lookup_trace,
                "resolution_stage": "fuzzers",
                "coverage_expected": coverage_expected,
                "build_registry_task_id": registry_task_id or None,
            }

    active_harness_path = str(task.runtime.get("active_harness_path") or "").strip()
    if active_harness_path:
        resolved = _resolve_binary_candidate(
            task_dir=task_dir,
            selected_harness=selected_harness,
            raw_path=active_harness_path,
            relative_path=Path(active_harness_path).name,
            extra_search_roots=extra_fuzzer_roots,
            lookup_trace=lookup_trace,
            stage="active_harness_path",
        )
        if resolved:
            return {
                "path": resolved,
                "lookup_trace": lookup_trace,
                "resolution_stage": "active_harness_path",
                "coverage_expected": coverage_expected,
                "build_registry_task_id": registry_task_id or None,
            }
    return {
        "path": None,
        "lookup_trace": lookup_trace,
        "resolution_stage": "not_found",
        "coverage_expected": coverage_expected,
        "build_registry_task_id": registry_task_id or None,
    }


def _process_function_coverage(coverage_data: dict[str, Any]) -> list[dict[str, Any]]:
    covered_functions: list[dict[str, Any]] = []
    for export_obj in coverage_data.get("data", []):
        for function in export_obj.get("functions", []):
            if "name" not in function or "regions" not in function:
                continue
            total_lines: set[int] = set()
            covered_lines: set[int] = set()
            for region in function.get("regions", []):
                if len(region) < 5:
                    continue
                line_start, line_end, execution_count = int(region[0]), int(region[2]), int(region[4])
                for line in range(line_start, line_end + 1):
                    total_lines.add(line)
                    if execution_count > 0:
                        covered_lines.add(line)
            if not total_lines:
                continue
            filenames = function.get("filenames", [])
            covered_functions.append(
                {
                    "name": function["name"],
                    "total_lines": len(total_lines),
                    "covered_lines": len(covered_lines),
                    "coverage_fraction": round(len(covered_lines) / max(len(total_lines), 1), 4),
                    "function_paths": filenames,
                },
            )
    return covered_functions


def _aggregate_files(function_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    file_rows: dict[str, dict[str, Any]] = {}
    for row in function_rows:
        for file_path in row.get("function_paths", []):
            current = file_rows.setdefault(
                file_path,
                {"file": file_path, "covered_lines": 0, "total_lines": 0, "function_count": 0},
            )
            current["covered_lines"] += int(row.get("covered_lines", 0))
            current["total_lines"] += int(row.get("total_lines", 0))
            current["function_count"] += 1
    return [
        {
            **item,
            "coverage_fraction": round(item["covered_lines"] / max(item["total_lines"], 1), 4),
        }
        for item in sorted(file_rows.values(), key=lambda entry: (-entry["covered_lines"], entry["file"]))
    ]


def _coverage_failure_detail(payload: dict[str, Any]) -> dict[str, Any] | None:
    reason = str(payload.get("failure_reason") or "").strip()
    if not reason:
        return None
    replay_results = list(payload.get("replay_results") or [])
    return {
        "failure_reason": reason,
        "coverage_artifacts_level": str(payload.get("coverage_artifacts_level") or "unknown"),
        "sampled_input_count": int(payload.get("sampled_input_count") or 0),
        "profraw_count": len(payload.get("profraw_files") or []),
        "coverage_binary_path": payload.get("coverage_binary_path"),
        "llvm_profdata_path": payload.get("llvm_profdata_path"),
        "llvm_cov_path": payload.get("llvm_cov_path"),
        "merged_profdata_path": payload.get("merged_profdata_path"),
        "coverage_json_path": payload.get("coverage_json_path"),
        "selected_harness": payload.get("selected_harness"),
        "coverage_binary_resolution_stage": payload.get("coverage_binary_resolution_stage"),
        "coverage_binary_expected": bool(payload.get("coverage_binary_expected")),
        "coverage_binary_lookup_trace": list(payload.get("coverage_binary_lookup_trace") or [])[:20],
        "stderr_signal_present": any(str(item.get("stderr_excerpt") or "").strip() for item in replay_results if isinstance(item, dict)),
        "retryable": reason in {"no_corpus_samples_available", "no_profraw_emitted"},
        "replay_results": replay_results[:4],
    }


def collect_source_coverage_artifacts(task) -> dict[str, Any]:
    task_dir = Path(task.task_dir)
    build_registry = _load_json(Path(task.runtime.get("build_registry_path", "")))
    selected_harness = task.runtime.get("active_harness") or task.runtime.get("selected_harness")
    coverage_resolution = _resolve_coverage_binary(task, build_registry, selected_harness)
    coverage_binary = coverage_resolution.get("path")

    corpus_dir = Path(task.layout.get("corpus_active", task_dir / "corpus" / "active"))
    samples = _sample_inputs(corpus_dir, settings.coverage_sample_size)
    llvm_profdata = _tool_path("llvm-profdata")
    llvm_cov = _tool_path("llvm-cov")
    artifacts_dir = task_dir / "coverage" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "task_id": task.task_id,
        "selected_harness": selected_harness,
        "coverage_binary_path": str(coverage_binary) if coverage_binary else None,
        "llvm_profdata_path": llvm_profdata,
        "llvm_cov_path": llvm_cov,
        "sampled_inputs": [str(path) for path in samples],
        "sample_limit": settings.coverage_sample_size,
        "sampled_input_count": len(samples),
        "coverage_binary_resolution_stage": coverage_resolution.get("resolution_stage"),
        "coverage_binary_expected": bool(coverage_resolution.get("coverage_expected")),
        "coverage_binary_lookup_trace": list(coverage_resolution.get("lookup_trace") or [])[:40],
        "coverage_binary_lookup_trace_total": len(coverage_resolution.get("lookup_trace") or []),
        "coverage_binary_build_registry_task_id": coverage_resolution.get("build_registry_task_id"),
    }
    if coverage_binary is None or not coverage_binary.exists():
        payload.update(
            {
                "coverage_artifacts_level": "fallback",
                "failure_reason": "coverage_binary_missing",
                "coverage_degraded_detail": {
                    "resolution_stage": coverage_resolution.get("resolution_stage"),
                    "coverage_expected": bool(coverage_resolution.get("coverage_expected")),
                    "lookup_trace": list(coverage_resolution.get("lookup_trace") or [])[:20],
                },
                "per_function_summary": [],
                "per_file_summary": [],
            },
        )
    elif llvm_profdata is None or llvm_cov is None:
        payload.update(
            {
                "coverage_artifacts_level": "partial",
                "failure_reason": "llvm_coverage_tools_missing",
                "per_function_summary": [],
                "per_file_summary": [],
            },
        )
    elif not samples:
        payload.update(
            {
                "coverage_artifacts_level": "partial",
                "failure_reason": "no_corpus_samples_available",
                "per_function_summary": [],
                "per_file_summary": [],
            },
        )
    else:
        profraw_files: list[str] = []
        replay_results: list[dict[str, Any]] = []
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=0:detect_leaks=0:allocator_may_return_null=1"
        for idx, sample in enumerate(samples, start=1):
            profraw = artifacts_dir / f"sample-{idx}.profraw"
            env["LLVM_PROFILE_FILE"] = str(profraw)
            completed = subprocess.run(
                [str(coverage_binary), str(sample)],
                cwd=str(task_dir),
                capture_output=True,
                text=True,
                env=env,
                timeout=settings.replay_timeout_seconds,
                check=False,
            )
            replay_results.append(
                {
                    "input_path": str(sample),
                    "exit_code": completed.returncode,
                    "stderr_excerpt": completed.stderr[:500],
                },
            )
            if profraw.exists():
                profraw_files.append(str(profraw))
        payload["replay_results"] = replay_results
        payload["profraw_files"] = profraw_files
        if not profraw_files:
            payload.update(
                {
                    "coverage_artifacts_level": "partial",
                    "failure_reason": "no_profraw_emitted",
                    "per_function_summary": [],
                    "per_file_summary": [],
                },
            )
        else:
            merged_profdata = artifacts_dir / "merged.profdata"
            merge = subprocess.run(
                [llvm_profdata, "merge", "-sparse", *profraw_files, "-o", str(merged_profdata)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            payload["merged_profdata_path"] = str(merged_profdata)
            payload["llvm_profdata_merge_stderr"] = merge.stderr[:1000]
            if merge.returncode != 0 or not merged_profdata.exists():
                payload.update(
                    {
                        "coverage_artifacts_level": "partial",
                        "failure_reason": "llvm_profdata_merge_failed",
                        "per_function_summary": [],
                        "per_file_summary": [],
                    },
                )
            else:
                export = subprocess.run(
                    [
                        llvm_cov,
                        "export",
                        "-format=text",
                        f"--instr-profile={merged_profdata}",
                        str(coverage_binary),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                coverage_json_path = artifacts_dir / "coverage.json"
                coverage_json_path.write_text(export.stdout, encoding="utf-8")
                payload["coverage_json_path"] = str(coverage_json_path)
                payload["llvm_cov_export_stderr"] = export.stderr[:1000]
                if export.returncode != 0:
                    payload.update(
                        {
                            "coverage_artifacts_level": "partial",
                            "failure_reason": "llvm_cov_export_failed",
                            "per_function_summary": [],
                            "per_file_summary": [],
                        },
                    )
                else:
                    coverage_data = json.loads(export.stdout)
                    function_rows = _process_function_coverage(coverage_data)
                    payload.update(
                        {
                            "coverage_artifacts_level": "exact",
                            "failure_reason": None,
                            "per_function_summary": function_rows,
                            "per_file_summary": _aggregate_files(function_rows),
                            "covered_function_count": len(function_rows),
                        },
                    )

    level = str(payload.get("coverage_artifacts_level") or "unknown")
    payload["coverage_exact_available"] = level == "exact"
    payload["coverage_control_mode"] = "exact" if level == "exact" else "degraded"
    payload["coverage_degraded_reason"] = payload.get("failure_reason")
    payload["coverage_failure_detail"] = _coverage_failure_detail(payload)
    path = coverage_artifact_manifest_path(task.task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    payload["coverage_artifact_manifest_path"] = str(path)
    return payload

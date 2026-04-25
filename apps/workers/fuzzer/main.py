from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import shutil
import time
from pathlib import Path

from core.analysis.suspicious_candidate import (
    build_suspicious_candidate_queue,
    write_suspicious_candidate_queue,
)
from core.coverage import collect_source_coverage_artifacts
from core.fuzz import run_libfuzzer, write_fuzz_manifest
from core.fuzz.corpus import stage_corpus_helpers
from core.fuzz.crash_collector import stage_imported_valid_crashes
from core.fuzz.harness_binding import resolve_active_harness
from core.models.task import TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.tracer.queue import maybe_enqueue_trace
from core.utils.settings import resolve_bool_setting, settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("fuzzer-worker")

COUNTERS_PATTERN = re.compile(r"Loaded\s+\d+\s+modules\s+\((\d+)\s+inline 8-bit counters\)")
PCS_PATTERN = re.compile(r"Loaded\s+\d+\s+PC tables\s+\((\d+)\s+PCs\)")
COV_PATTERN = re.compile(r"\bcov:\s*(\d+)")
FT_PATTERN = re.compile(r"\bft:\s*(\d+)")
CORP_PATTERN = re.compile(r"\bcorp:\s*(\d+)")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _unique_overflow_path(overflow_dir: Path, source_path: Path) -> Path:
    target = overflow_dir / source_path.name
    suffix = 1
    while target.exists():
        target = overflow_dir / f"{source_path.stem}_{suffix}{source_path.suffix}"
        suffix += 1
    return target


def _curate_crashes_for_trace(
    crash_paths: list[str],
    *,
    overflow_dir: Path,
    max_to_trace: int,
    sample_seed: str,
) -> dict:
    existing_paths = [Path(path) for path in crash_paths if Path(path).exists()]
    canonical_by_hash: dict[str, Path] = {}
    deduped_paths: list[Path] = []
    overflow_candidates: list[Path] = []

    for path in sorted(existing_paths, key=lambda item: item.name):
        digest = _sha256_file(path)
        if digest in canonical_by_hash:
            overflow_candidates.append(path)
            continue
        canonical_by_hash[digest] = path
        deduped_paths.append(path)

    selected_paths = list(deduped_paths)
    selection_mode = "content_hash_dedupe_only"
    if len(deduped_paths) > max_to_trace:
        rng = random.Random(sample_seed)
        selected_paths = sorted(rng.sample(deduped_paths, max_to_trace), key=lambda item: item.name)
        selected_lookup = set(selected_paths)
        overflow_candidates.extend(path for path in deduped_paths if path not in selected_lookup)
        selection_mode = "content_hash_dedupe_and_random_sample"

    overflow_records: list[dict[str, str]] = []
    if overflow_candidates:
        overflow_dir.mkdir(parents=True, exist_ok=True)
        for source_path in sorted(overflow_candidates, key=lambda item: item.name):
            target_path = _unique_overflow_path(overflow_dir, source_path)
            shutil.move(str(source_path), str(target_path))
            overflow_records.append(
                {
                    "source_path": str(source_path),
                    "overflow_path": str(target_path),
                }
            )

    return {
        "selected_paths": [str(path) for path in selected_paths if path.exists()],
        "original_count": len(existing_paths),
        "deduped_count": len(deduped_paths),
        "sampled_count": len(selected_paths),
        "overflow_count": len(overflow_records),
        "overflow_dir": str(overflow_dir),
        "overflow_records": overflow_records,
        "selection_mode": selection_mode,
        "max_to_trace": max_to_trace,
    }


def _write_coverage_summary(task, coverage_artifacts: dict, *, generated_at: str) -> str:
    per_file_summary = coverage_artifacts.get("per_file_summary", []) or []
    per_function_summary = coverage_artifacts.get("per_function_summary", []) or []
    lines_covered = sum(int(item.get("covered_lines", 0) or 0) for item in per_file_summary)
    lines_total = sum(int(item.get("total_lines", 0) or 0) for item in per_file_summary)
    functions_total = len(per_function_summary)
    functions_covered = sum(1 for item in per_function_summary if int(item.get("covered_lines", 0) or 0) > 0)
    summary_path = Path(task.task_dir) / "coverage" / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "coverage_artifacts_level": coverage_artifacts.get("coverage_artifacts_level"),
                "coverage_artifact_manifest_path": coverage_artifacts.get("coverage_artifact_manifest_path"),
                "lines_covered": lines_covered,
                "lines_total": lines_total,
                "line_coverage_fraction": round(lines_covered / max(lines_total, 1), 4) if lines_total else 0.0,
                "functions_covered": functions_covered,
                "functions_total": functions_total,
                "function_coverage_fraction": round(functions_covered / max(functions_total, 1), 4)
                if functions_total
                else 0.0,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return str(summary_path)


def _parse_progress_metrics(stderr: str) -> dict[str, int | None]:
    def _max_int(pattern: re.Pattern[str]) -> int | None:
        matches = [int(match) for match in pattern.findall(stderr)]
        return max(matches) if matches else None

    return {
        "inline_8bit_counters": _max_int(COUNTERS_PATTERN),
        "pc_table_entries": _max_int(PCS_PATTERN),
        "coverage_feature_count": _max_int(FT_PATTERN),
        "coverage_pc_count": _max_int(COV_PATTERN),
        "corpus_unit_count": _max_int(CORP_PATTERN),
    }


def _stderr_signal_summary(stderr: str) -> dict:
    unique_lines: list[str] = []
    crash_like_lines: list[str] = []
    for raw_line in stderr.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith("info:") or lowered.startswith("running:") or lowered.startswith("executed "):
            continue
        if line not in unique_lines:
            unique_lines.append(line)
        if any(
            token in lowered
            for token in (
                "addresssanitizer",
                "undefinedbehaviorsanitizer",
                "segmentation fault",
                "deadly signal",
                "timeout",
                "abort",
                "assert",
                "error:",
            )
        ) and line not in crash_like_lines:
            crash_like_lines.append(line)
    return {
        "unique_signal_count": len(unique_lines),
        "unique_signal_lines": unique_lines[:10],
        "crash_like_signal_count": len(crash_like_lines),
        "crash_like_signal_lines": crash_like_lines[:10],
    }


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("fuzzer received task %s", task_id)
    task_store.update_status(
        task_id,
        TaskStatus.FUZZING,
        runtime_patch={"fuzz_started_at": task_store.now()},
    )

    task = task_store.load_task(task_id)
    task_dir = Path(task.task_dir)
    active_harness = resolve_active_harness(task_dir)
    seed_manifest_path = Path(task.layout["seed"]) / "seed_manifest.json"
    seed_task_manifest_path = Path(task.layout["seed"]) / "seed_task_manifest.json"
    seed_manifest = (
        json.loads(seed_manifest_path.read_text(encoding="utf-8"))
        if seed_manifest_path.exists()
        else {}
    )
    seed_task_manifest = (
        json.loads(seed_task_manifest_path.read_text(encoding="utf-8"))
        if seed_task_manifest_path.exists()
        else {}
    )
    helper_seed_inputs = []
    allow_imported_helper_inputs = resolve_bool_setting(
        task.metadata,
        "FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES",
        settings.fuzz_seed_from_imported_valid_crashes,
    )
    if allow_imported_helper_inputs:
        helper_seed_inputs = stage_corpus_helpers(
            Path(task.layout["corpus_active"]),
            task.runtime.get("resolved_imports", {}).get("existing_valid_crashes_path"),
            limit=settings.fuzz_imported_valid_seed_limit,
        )

    result = run_libfuzzer(task_dir, task.metadata)
    coverage_artifacts = collect_source_coverage_artifacts(
        task,
        requested_by="fuzz_worker_post_run",
        force_retry=True,
    )
    coverage_summary_path = _write_coverage_summary(task, coverage_artifacts, generated_at=task_store.now())
    progress_metrics = _parse_progress_metrics(result.stderr)
    signal_summary = _stderr_signal_summary(result.stderr)
    imported_crashes = []
    allow_imported_crash_fallback = resolve_bool_setting(
        task.metadata,
        "ALLOW_IMPORTED_CRASH_FALLBACK",
        settings.allow_imported_crash_fallback,
    )
    if not result.raw_crashes and allow_imported_crash_fallback:
        imported_crashes = stage_imported_valid_crashes(
            task.runtime.get("resolved_imports", {}).get("existing_valid_crashes_path"),
            Path(task.layout["crashes_raw"]),
            limit=1,
        )
    raw_overflow_dir = Path(task.layout["crashes"]) / "raw_overflow"
    crash_curation = _curate_crashes_for_trace(
        list(result.raw_crashes),
        overflow_dir=raw_overflow_dir,
        max_to_trace=max(settings.fuzz_max_crashes_to_trace, 1),
        sample_seed=task_id,
    )
    live_crashes = list(crash_curation["selected_paths"])
    raw_crashes = live_crashes + [item["staged_path"] for item in imported_crashes]
    crash_source = "live_raw" if live_crashes else ("imported_valid" if imported_crashes else None)
    closure_mode = "strict_live" if live_crashes else ("imported_fallback" if imported_crashes else None)
    logger.info(
        "[%s] crash 采样：原始 %s 个，去重后 %s 个，采样后 %s 个进入 trace",
        task_id,
        crash_curation["original_count"],
        crash_curation["deduped_count"],
        crash_curation["sampled_count"],
    )
    selected_target_functions = seed_manifest.get("selected_target_functions", []) or []
    if not selected_target_functions and seed_manifest.get("target_function_name"):
        selected_target_functions = [
            {
                "name": seed_manifest.get("target_function_name"),
                "reason": "seed_manifest_target_function_name",
            },
        ]

    per_seed_family_contribution = [
        {
            "seed_mode": seed_task_manifest.get("seed_mode") or task.runtime.get("seed_task_mode_default"),
            "seed_provenance": seed_manifest.get("seed_provenance"),
            "generated_seed_count": seed_manifest.get("generated_seed_count", 0),
            "observed_new_corpus_files": len(result.new_corpus_files),
            "observed_raw_crashes": len(raw_crashes),
            "observed_unique_signal_count": signal_summary["unique_signal_count"],
            "attribution_mode": "whole_run_attributed_to_active_seed_family",
        },
    ]
    per_target_function_contribution = [
        {
            "target_function": item.get("name") if isinstance(item, dict) else str(item),
            "reason": item.get("reason") if isinstance(item, dict) else None,
            "observed_new_corpus_files": len(result.new_corpus_files),
            "observed_raw_crashes": len(raw_crashes),
            "observed_unique_signal_count": signal_summary["unique_signal_count"],
            "selected_harness": active_harness.name,
        }
        for item in selected_target_functions
        if (item.get("name") if isinstance(item, dict) else str(item))
    ]
    fuzz_completed_at = task_store.now()
    suspicious_candidate_payload = None
    suspicious_candidate_queue_file = None
    if not raw_crashes:
        suspicious_candidate_payload = build_suspicious_candidate_queue(
            task_id=task_id,
            task_dir=task_dir,
            now_iso=fuzz_completed_at,
            selected_harness=active_harness.name,
            selected_target_function=seed_manifest.get("target_function_name"),
            selected_target_functions=selected_target_functions,
            new_corpus_files=list(result.new_corpus_files),
            runtime=task.runtime,
            signal_summary=signal_summary,
            task_metadata=task.metadata,
        )
        suspicious_candidate_queue_file = write_suspicious_candidate_queue(
            task_dir,
            suspicious_candidate_payload,
        )

    manifest_payload = {
        "task_id": task_id,
        "status": TaskStatus.FUZZING.value,
        "harness_name": result.harness_name,
        "selected_harness": active_harness.name,
        "selected_harness_path": str(active_harness.executable_path),
        "selected_target_function": seed_manifest.get("target_function_name"),
        "selected_target_functions": seed_manifest.get("selected_target_functions", []),
        "binary_path": result.binary_path,
        "dict_path": result.dict_path,
        "options_path": result.options_path,
        "command": result.command,
        "exit_code": result.exit_code,
        "new_corpus_files": result.new_corpus_files,
        "raw_crashes": raw_crashes,
        "raw_crash_count_total": crash_curation["original_count"],
        "raw_crash_count_deduped": crash_curation["deduped_count"],
        "raw_crash_count_sampled_for_trace": crash_curation["sampled_count"],
        "raw_crash_overflow_count": crash_curation["overflow_count"],
        "raw_crash_overflow_dir": crash_curation["overflow_dir"],
        "crash_curation_mode": crash_curation["selection_mode"],
        "fuzz_max_crashes_to_trace": crash_curation["max_to_trace"],
        "crash_count_live_raw": len(live_crashes),
        "crash_source": crash_source,
        "imported_crashes": imported_crashes,
        "imported_crash_count_used_for_seeding": len(helper_seed_inputs),
        "helper_seed_inputs": helper_seed_inputs,
        "allow_imported_helper_inputs": allow_imported_helper_inputs,
        "allow_imported_crash_fallback": allow_imported_crash_fallback,
        "closure_candidate": bool(live_crashes),
        "seed_task_mode": seed_task_manifest.get("seed_mode") or task.runtime.get("seed_task_mode_default"),
        "seed_task_manifest_path": str(seed_task_manifest_path) if seed_task_manifest_path.exists() else None,
        "seed_provenance": seed_manifest.get("seed_provenance"),
        "llm_real_call_verified": seed_manifest.get("llm_real_call_verified"),
        "coverage_metrics": progress_metrics,
        "coverage_artifacts_level": coverage_artifacts.get("coverage_artifacts_level"),
        "coverage_artifact_manifest_path": coverage_artifacts.get("coverage_artifact_manifest_path"),
        "coverage_summary_path": coverage_summary_path,
        "stderr_signal_summary": signal_summary,
        "suspicious_candidate_queue_path": suspicious_candidate_queue_file,
        "suspicious_candidate_count": int((suspicious_candidate_payload or {}).get("candidate_count") or 0),
        "suspicious_candidate_trace_worthy_count": int(
            (suspicious_candidate_payload or {}).get("trace_worthy_candidate_count") or 0
        ),
        "suspicious_candidate_reason_summary": (suspicious_candidate_payload or {}).get("reason_summary") or [],
        "per_seed_family_contribution": per_seed_family_contribution,
        "per_target_function_contribution": per_target_function_contribution,
        "stdout_excerpt": result.stdout[:4000],
        "stderr_excerpt": result.stderr[:4000],
    }
    manifest_path = write_fuzz_manifest(task_id, manifest_payload)
    task_store.update_runtime(
        task_id,
        {
            "fuzz_completed_at": fuzz_completed_at,
            "fuzz_manifest_path": str(manifest_path),
            "selected_harness": active_harness.name,
            "selected_harness_path": str(active_harness.executable_path),
            "selected_target_function": seed_manifest.get("target_function_name"),
            "selected_target_functions": seed_manifest.get("selected_target_functions", []),
            "active_harness": active_harness.name,
            "active_harness_path": str(active_harness.executable_path),
            "raw_crash_count": len(raw_crashes),
            "raw_crash_count_total": crash_curation["original_count"],
            "raw_crash_count_deduped": crash_curation["deduped_count"],
            "raw_crash_count_sampled_for_trace": crash_curation["sampled_count"],
            "raw_crash_overflow_count": crash_curation["overflow_count"],
            "raw_crash_overflow_dir": crash_curation["overflow_dir"],
            "crash_count_live_raw": len(live_crashes),
            "crash_curation_mode": crash_curation["selection_mode"],
            "fuzz_max_crashes_to_trace": crash_curation["max_to_trace"],
            "fuzz_command": result.command,
            "coverage_metrics": progress_metrics,
            "coverage_artifacts_level": coverage_artifacts.get("coverage_artifacts_level"),
            "coverage_artifact_manifest_path": coverage_artifacts.get("coverage_artifact_manifest_path"),
            "coverage_summary_path": coverage_summary_path,
            "stderr_signal_summary": signal_summary,
            "suspicious_candidate_queue_path": suspicious_candidate_queue_file,
            "suspicious_candidate_count": int((suspicious_candidate_payload or {}).get("candidate_count") or 0),
            "suspicious_candidate_trace_worthy_count": int(
                (suspicious_candidate_payload or {}).get("trace_worthy_candidate_count") or 0
            ),
            "suspicious_candidate_reason_summary": (suspicious_candidate_payload or {}).get("reason_summary") or [],
            "per_seed_family_contribution": per_seed_family_contribution,
            "per_target_function_contribution": per_target_function_contribution,
            "crash_source_policy": settings.crash_source_policy,
            "closure_mode": closure_mode,
        },
    )
    queued_for_trace = maybe_enqueue_trace(task_id, task_store, queue)
    if queued_for_trace:
        task_store.update_runtime(
            task_id,
            {
                "fuzz_trace_enqueued": True,
                "fuzz_final_status": TaskStatus.QUEUED_TRACE.value,
            },
        )
    else:
        with task_store.task_lock(task_id):
            current_task = task_store._load_task_unlocked(task_id)
            if current_task.status == TaskStatus.FUZZING:
                current_task.status = TaskStatus.FUZZ_COMPLETED
                current_task.runtime.update(
                    {
                        "fuzz_trace_enqueued": False,
                        "fuzz_final_status": TaskStatus.FUZZ_COMPLETED.value,
                        "fuzz_terminal_reason": current_task.runtime.get("trace_gate_reason")
                        or "trace_not_queued_after_fuzz_completion",
                    },
                )
                task_store._save_task_unlocked(current_task)
                logger.info(
                    "task %s fuzz completed without trace enqueue reason=%s",
                    task_id,
                    current_task.runtime.get("fuzz_terminal_reason"),
                )
    queue.ack(QueueNames.FUZZ, task_id)
    logger.info(
        "task %s fuzzed harness=%s raw_crashes_total=%s raw_crashes_for_trace=%s overflow=%s imported_crashes=%s",
        task_id,
        result.harness_name,
        crash_curation["original_count"],
        crash_curation["sampled_count"],
        crash_curation["overflow_count"],
        len(imported_crashes),
    )


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("fuzzer worker started")
    while True:
        task_id = queue.pop(QueueNames.FUZZ, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("fuzzer failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.FUZZ_FAILED,
                runtime_patch={"fuzz_error": str(exc), "fuzz_failed_at": task_store.now()},
            )
            queue.ack(QueueNames.FUZZ, task_id)


if __name__ == "__main__":
    main()

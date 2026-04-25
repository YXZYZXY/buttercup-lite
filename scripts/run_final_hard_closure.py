from __future__ import annotations

from collections import Counter
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apps.workers.builder.main import process_task as build_task
from apps.workers.downloader.main import process_task as download_task
from apps.workers.fuzzer.main import process_task as fuzzer_task
from apps.workers.program_model.main import process_task as index_task
from apps.workers.reproducer.main import process_task as repro_task
from apps.workers.scheduler.main import process_task as schedule_task
from apps.workers.seed.main import process_task as seed_task
from apps.workers.tracer.main import process_task as trace_task
from core.analysis.pov_inventory import build_campaign_reports
from core.campaign.coverage_feedback import analyze_coverage_feedback
from core.models.task import ExecutionMode, TaskSpec, TaskStatus
from core.queues.redis_queue import QueueNames
from core.state.task_state import TaskStateStore
from scripts.run_original_semantic_closure import (
    _classify_repo_first_task,
    _consume_scheduler_feedback,
    _copy_if_exists,
    _run_source_sanity,
    _source_metrics,
    _write_source_generalization_reports,
)
from scripts.run_source_binary_hard_convergence import (
    GENERALIZATION_REPOS,
    INJECTED_SOURCE_REPOS,
    _binary_metrics,
    _collect_task_llm_audit,
    _package_from_task,
    _run_binary_package_task,
)
from scripts.verification_common import LocalQueue, configure_llm_from_env, write_report

DATA_ROOT = REPO_ROOT / "data" / "tasks"
REPORTS_ROOT = REPO_ROOT / "reports"

GROUND_TRUTH_BY_LABEL = {
    "cjson": REPO_ROOT / "benchmarks" / "cjson_injected" / "ground_truth.json",
    "inih": REPO_ROOT / "benchmarks" / "inih_injected" / "ground_truth.json",
}

EXTRA_GENERALIZATION_REPOS = {
    "expat": {"repo_url": "https://github.com/libexpat/libexpat.git", "git_ref": "master"},
    "jansson": {"repo_url": "https://github.com/akheron/jansson.git", "git_ref": "master"},
    "miniz": {"repo_url": "https://github.com/richgel999/miniz.git", "git_ref": "master"},
    "h3": {"repo_url": "https://github.com/uber/h3.git", "git_ref": "master"},
    "libspng": {"repo_url": "https://github.com/randy408/libspng.git", "git_ref": "master"},
    "jsoncpp": {"repo_url": "https://github.com/open-source-parsers/jsoncpp.git", "git_ref": "master"},
    "c-ares": {"repo_url": "https://github.com/c-ares/c-ares.git", "git_ref": "main"},
}


def _write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _read_json(path: str | Path | None, default: Any = None) -> Any:
    if not path:
        return {} if default is None else default
    candidate = Path(path)
    if not candidate.exists():
        return {} if default is None else default
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {} if default is None else default


def _safe_call(call_label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return {"label": call_label, "ok": True, "result": fn(*args, **kwargs)}
    except Exception as exc:  # pragma: no cover - convergence runner must keep collecting evidence.
        return {"label": call_label, "ok": False, "error": str(exc)}


def _drain_patch_queue_for_base(queue: LocalQueue, task_store: TaskStateStore, base_task_id: str, seen_patch_tasks: set[str]) -> list[str]:
    from apps.workers.patch.main import process_task as patch_task

    launched: list[str] = []
    for queue_name, payload in queue.pushed:
        if queue_name != QueueNames.PATCH or payload in seen_patch_tasks:
            continue
        try:
            patch_record = task_store.load_task(payload)
        except Exception:
            continue
        if patch_record.metadata.get("patch_base_task_id") != base_task_id:
            continue
        patch_task(payload, task_store, queue)
        seen_patch_tasks.add(payload)
        launched.append(payload)
    return launched


def _round_snapshot(
    *,
    label: str,
    task_id: str,
    round_index: int,
    started_at: float,
    task_store: TaskStateStore,
    patch_task_ids: list[str],
) -> dict[str, Any]:
    task = task_store.load_task(task_id)
    campaign_reports: dict[str, Any] = {}
    ground_truth = GROUND_TRUTH_BY_LABEL.get(label)
    if ground_truth and ground_truth.exists():
        try:
            campaign_reports = build_campaign_reports(
                campaign_task_id=task_id,
                origin_task_ids=[task_id],
                ground_truth_path=ground_truth,
                data_root=DATA_ROOT,
            )
        except Exception as exc:
            campaign_reports = {"error": str(exc)}
    pov_inventory = campaign_reports.get("pov_inventory") or _read_json(Path(task.task_dir) / "analysis" / "pov_inventory.json")
    vuln_coverage = campaign_reports.get("vuln_coverage") or _read_json(Path(task.task_dir) / "analysis" / "vuln_coverage.json")
    coverage_summary = _read_json(task.runtime.get("coverage_summary_manifest_path"))
    scheduler_feedback = _read_json(task.runtime.get("scheduler_feedback_consumption_path"))
    fuzz_manifest = _read_json(task.runtime.get("fuzz_manifest_path"))
    selected_target_functions = task.runtime.get("selected_target_functions") or []
    normalized_target_functions: list[str] = []
    for item in selected_target_functions:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
        else:
            name = str(item).strip()
        if name and name not in normalized_target_functions:
            normalized_target_functions.append(name)
    return {
        "round": round_index,
        "elapsed_seconds": round(time.monotonic() - started_at, 3),
        "task_status": task.status.value,
        "selected_harness": task.runtime.get("selected_harness"),
        "selected_target_function": task.runtime.get("selected_target_function"),
        "selected_target_functions": normalized_target_functions,
        "campaign_reseed_targets": task.runtime.get("campaign_reseed_targets"),
        "seed_mode": task.runtime.get("seed_task_mode") or task.runtime.get("seed_task_mode_override"),
        "next_seed_mode_override": task.runtime.get("seed_task_mode_override"),
        "coverage_level": coverage_summary.get("coverage_level"),
        "coverage_round_delta": coverage_summary.get("coverage_round_delta"),
        "scheduler_feedback_reason": scheduler_feedback.get("reason"),
        "scheduler_feedback_before": scheduler_feedback.get("before"),
        "scheduler_feedback_after": scheduler_feedback.get("after"),
        "raw_crash_count": task.runtime.get("raw_crash_count"),
        "traced_crash_count": task.runtime.get("traced_crash_count"),
        "repro_count": task.runtime.get("repro_count"),
        "pov_count": (pov_inventory or {}).get("total_pov_count", task.runtime.get("pov_count")),
        "distinct_signature_count": (pov_inventory or {}).get("distinct_signature_count"),
        "found_vuln_count": (vuln_coverage or {}).get("found_vuln_count"),
        "patch_task_ids": list(patch_task_ids),
        "fuzz_manifest_path": task.runtime.get("fuzz_manifest_path"),
        "coverage_summary_manifest_path": task.runtime.get("coverage_summary_manifest_path"),
        "scheduler_feedback_consumption_path": task.runtime.get("scheduler_feedback_consumption_path"),
        "trace_manifest_path": task.runtime.get("trace_manifest_path"),
        "repro_manifest_path": task.runtime.get("repro_manifest_path"),
        "fuzz_started": bool(fuzz_manifest),
    }


def _derive_campaign_reseed_targets(
    *,
    latest_round: dict[str, Any],
    fallback_runtime_targets: list[Any] | None = None,
    limit: int = 4,
) -> list[str]:
    current_target = str(latest_round.get("selected_target_function") or "").strip()
    raw_targets = latest_round.get("selected_target_functions") or fallback_runtime_targets or []
    normalized: list[str] = []
    for item in raw_targets:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
        else:
            name = str(item).strip()
        if not name or name == current_target or name in normalized:
            continue
        normalized.append(name)
        if len(normalized) >= limit:
            break
    return normalized


def _extend_unique_names(existing: list[Any] | None, *names: str | None) -> list[str]:
    merged: list[str] = []
    for item in existing or []:
        name = str(item).strip()
        if name and name not in merged:
            merged.append(name)
    for item in names:
        name = str(item or "").strip()
        if name and name not in merged:
            merged.append(name)
    return merged


def _trace_signature_audit(task_id: str) -> dict[str, Any]:
    task_root = DATA_ROOT / task_id
    dedup_index = _read_json(task_root / "trace" / "dedup_index.json", {})
    pov_inventory = _read_json(task_root / "reports" / "pov_inventory.json", {})
    traced_dir = task_root / "trace" / "traced_crashes"
    trace_signature_counter: Counter[str] = Counter()
    crash_type_counter: Counter[str] = Counter()
    loose_cluster_counter: Counter[str] = Counter()
    target_to_signature_map: dict[str, set[str]] = {}
    signature_to_target_map: dict[str, set[str]] = {}
    signature_samples: dict[str, dict[str, Any]] = {}
    for traced_path in sorted(traced_dir.glob("*.json")):
        payload = _read_json(traced_path, {})
        signature = (
            str(payload.get("canonical_signature") or "").strip()
            or str(payload.get("signature") or "").strip()
            or str(payload.get("crash_signature") or "").strip()
            or str(payload.get("stack_hash") or "").strip()
            or traced_path.stem
        )
        crash_type = str(payload.get("crash_type") or "unknown").strip() or "unknown"
        stderr_excerpt = str(payload.get("stderr_excerpt") or "").splitlines()
        headline = stderr_excerpt[0].strip() if stderr_excerpt else ""
        loose_cluster = " :: ".join(part for part in (crash_type, headline[:120] if headline else None) if part)
        target_name = str(
            payload.get("selected_target_function")
            or payload.get("target_function")
            or payload.get("target")
            or "unknown"
        ).strip() or "unknown"
        trace_signature_counter[signature] += 1
        crash_type_counter[crash_type] += 1
        loose_cluster_counter[loose_cluster] += 1
        target_to_signature_map.setdefault(target_name, set()).add(signature)
        signature_to_target_map.setdefault(signature, set()).add(target_name)
        if signature not in signature_samples:
            invariant_class = "unknown"
            crash_lower = crash_type.lower()
            if "double-free" in headline.lower() or "double-free" in crash_lower or crash_lower == "attempting":
                invariant_class = "deallocation_ownership"
            elif "use-after-free" in headline.lower() or "use-after-free" in crash_lower:
                invariant_class = "failure_propagation"
            elif "overflow" in crash_lower:
                invariant_class = "offset_length_consistency"
            signature_samples[signature] = {
                "trace_path": str(traced_path),
                "crash_type": crash_type,
                "headline": headline,
                "loose_cluster": loose_cluster,
                "target_name": target_name,
                "invariant_class": invariant_class,
                "testcase_path": payload.get("testcase_path"),
                "stacktrace_head": (payload.get("stacktrace") or [])[:5],
            }

    exact_signature_count = len(dedup_index) or len(trace_signature_counter)
    confirmed_signature_count = int(pov_inventory.get("distinct_signature_count") or 0)
    merge_gap = max(0, exact_signature_count - confirmed_signature_count)
    return {
        "task_id": task_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "confirmed_pov_signature_count": confirmed_signature_count,
        "trace_exact_signature_count": exact_signature_count,
        "trace_loose_cluster_count": len(loose_cluster_counter),
        "trace_crash_type_count": len(crash_type_counter),
        "trace_signature_confirmation_gap": merge_gap,
        "second_family_visible_at_trace_level": exact_signature_count >= 2,
        "trace_signature_counter": dict(trace_signature_counter.most_common(12)),
        "trace_crash_type_counter": dict(crash_type_counter),
        "trace_loose_cluster_counter": dict(loose_cluster_counter),
        "target_to_trace_signatures": {
            target: sorted(signatures)
            for target, signatures in sorted(target_to_signature_map.items())
        },
        "trace_signature_to_targets": {
            signature: sorted(targets)
            for signature, targets in sorted(signature_to_target_map.items())
        },
        "trace_signature_samples": signature_samples,
        "dedup_index_size": len(dedup_index),
    }


def _second_family_confirmation_analysis(
    *,
    task_id: str,
    trace_signature_audit: dict[str, Any],
    vulnerable_state_cluster_payload: dict[str, Any],
    pov_inventory: dict[str, Any],
) -> dict[str, Any]:
    signature_counter = trace_signature_audit.get("trace_signature_counter") or {}
    samples = trace_signature_audit.get("trace_signature_samples") or {}
    sorted_signatures = sorted(signature_counter.items(), key=lambda item: int(item[1]), reverse=True)
    primary_signature = sorted_signatures[0][0] if sorted_signatures else None
    secondary_signature = sorted_signatures[1][0] if len(sorted_signatures) > 1 else None
    primary_sample = samples.get(primary_signature or "", {})
    secondary_sample = samples.get(secondary_signature or "", {})
    distinct_povs = pov_inventory.get("distinct_povs") or []
    confirmed_signatures = {
        str(item.get("signature") or "").strip()
        for item in distinct_povs
        if str(item.get("signature") or "").strip()
    }
    evidence = {
        "trace_exact_signature_diff": bool(primary_signature and secondary_signature and primary_signature != secondary_signature),
        "loose_cluster_diff": bool(
            primary_sample.get("loose_cluster")
            and secondary_sample.get("loose_cluster")
            and primary_sample.get("loose_cluster") != secondary_sample.get("loose_cluster")
        ),
        "top_frame_or_invariant_diff": bool(
            primary_sample.get("invariant_class")
            and secondary_sample.get("invariant_class")
            and primary_sample.get("invariant_class") != secondary_sample.get("invariant_class")
        ),
        "vulnerable_state_cluster_diff": bool(
            primary_sample.get("invariant_class")
            and secondary_sample.get("invariant_class")
            and primary_sample.get("invariant_class") != secondary_sample.get("invariant_class")
        ),
        "repro_or_pov_artifact_distinguishable": bool(
            secondary_signature and secondary_signature in confirmed_signatures
        ),
    }
    second_confirmed_family = all(evidence.values())
    blocker = None
    if not second_confirmed_family:
        if evidence["trace_exact_signature_diff"] and evidence["loose_cluster_diff"] and evidence["top_frame_or_invariant_diff"]:
            blocker = "trace gate / repro gate still swallows the trace-visible double-free family before confirmed PoV counting"
        elif not evidence["vulnerable_state_cluster_diff"]:
            blocker = "trace diversity is present, but the explored inputs still collapse into one vulnerable state cluster"
        else:
            blocker = "seed family rotation still does not deliver a second reproducible confirmed family"
    return {
        "task_id": task_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "second_confirmed_family": second_confirmed_family,
        "primary_signature": primary_signature,
        "secondary_signature": secondary_signature,
        "primary_sample": primary_sample,
        "secondary_sample": secondary_sample,
        "evidence": evidence,
        "minimum_hard_blocker": blocker,
        "confirmed_signature_count": pov_inventory.get("distinct_signature_count"),
        "trace_exact_signature_count": trace_signature_audit.get("trace_exact_signature_count"),
        "trace_signature_confirmation_gap": trace_signature_audit.get("trace_signature_confirmation_gap"),
        "trace_level_second_family_visible": trace_signature_audit.get("second_family_visible_at_trace_level"),
        "cluster_summary": {
            "cluster_count": vulnerable_state_cluster_payload.get("cluster_count"),
            "crash_cluster_count": vulnerable_state_cluster_payload.get("crash_cluster_count"),
            "why_no_second_cluster": vulnerable_state_cluster_payload.get("why_no_second_cluster"),
        },
    }


def _write_campaign_manifests(
    *,
    label: str,
    task_id: str,
    budget_seconds: int,
    requested_rounds: int,
    rounds: list[dict[str, Any]],
    patch_task_ids: list[str],
    task_store: TaskStateStore,
) -> dict[str, str]:
    task = task_store.load_task(task_id)
    campaign_dir = Path(task.task_dir) / "campaign"
    trace_signature_audit = _trace_signature_audit(task_id)
    pov_inventory = _read_json(DATA_ROOT / task_id / "reports" / "pov_inventory.json", {})
    actual_wall_time = max((float(item.get("elapsed_seconds") or 0.0) for item in rounds), default=0.0)
    termination_reason = task.runtime.get("campaign_termination_reason") or (
        "deadline_reached" if actual_wall_time >= budget_seconds else "worker_or_strict_llm_stop"
    )
    first_crash_round = next((item["round"] for item in rounds if int(item.get("raw_crash_count") or 0) > 0), None)
    first_patch_round = next((item["round"] for item in rounds if item.get("patch_task_ids")), None)
    distinct_counts = [
        {
            "round": item["round"],
            "distinct_signature_count": item.get("distinct_signature_count"),
            "found_vuln_count": item.get("found_vuln_count"),
        }
        for item in rounds
    ]
    budget_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "campaign_budget_seconds": budget_seconds,
        "declared_budget_seconds": budget_seconds,
        "actual_wall_time_seconds": actual_wall_time,
        "requested_rounds": requested_rounds,
        "requested_rounds_role": "checkpoint_only",
        "completed_rounds": len(rounds),
        "campaign_emergency_round_cap": task.runtime.get("campaign_emergency_round_cap"),
        "deadline_semantics": "continue_until_budget_or_seed_block",
        "stop_on_first_crash": False,
        "stop_on_first_patch": False,
        "strict_real_llm": True,
    }
    timeout_seconds = int(task.metadata.get("LLM_TIMEOUT_SECONDS") or 0)
    max_retries = int(task.metadata.get("LLM_MAX_RETRIES") or 0)
    patch_timeout_seconds = int(task.metadata.get("LLM_PATCH_TIMEOUT_SECONDS") or timeout_seconds or 0)
    llm_budget_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "declared_budget_seconds": budget_seconds,
        "actual_wall_time_seconds": actual_wall_time,
        "llm_timeout_seconds": timeout_seconds,
        "llm_max_retries": max_retries,
        "llm_patch_timeout_seconds": patch_timeout_seconds,
        "estimated_worst_case_seed_llm_seconds_per_round": timeout_seconds * (max_retries + 1),
        "estimated_worst_case_campaign_seed_llm_seconds": timeout_seconds * (max_retries + 1) * len(rounds),
        "budget_accounting_mode": "deadline_aware_per_call_timeout",
    }
    deadline_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "declared_budget_seconds": budget_seconds,
        "actual_wall_time_seconds": actual_wall_time,
        "exceeded_declared_budget": actual_wall_time > budget_seconds,
        "deadline_enforcement": "round_boundary_plus_per_llm_call_timeout",
        "stop_reason": termination_reason,
        "known_limitation": "worker calls are not forcibly killed mid-fuzzer subprocess; LLM calls now use bounded per-call timeout/retry metadata",
        "campaign_emergency_round_cap": task.runtime.get("campaign_emergency_round_cap"),
    }
    distinct_values = [item.get("distinct_signature_count") for item in rounds if item.get("distinct_signature_count") is not None]
    final_distinct = distinct_values[-1] if distinct_values else None
    first_crash_elapsed = next((item.get("elapsed_seconds") for item in rounds if int(item.get("raw_crash_count") or 0) > 0), None)
    next_distinct_elapsed = None
    previous_distinct = None
    for item in rounds:
        current_distinct = item.get("distinct_signature_count")
        if current_distinct is None:
            continue
        if previous_distinct is None:
            previous_distinct = current_distinct
            continue
        if current_distinct > previous_distinct:
            next_distinct_elapsed = item.get("elapsed_seconds")
            break
        previous_distinct = current_distinct
    effectiveness_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "declared_budget_seconds": budget_seconds,
        "actual_wall_time_seconds": actual_wall_time,
        "round_count": len(rounds),
        "time_to_first_crash_seconds": first_crash_elapsed,
        "time_to_next_distinct_crash_seconds": next_distinct_elapsed,
        "final_distinct_signature_count": final_distinct,
        "found_multiple_distinct_signatures": bool(final_distinct and final_distinct > 1),
        "trace_exact_signature_count": trace_signature_audit.get("trace_exact_signature_count"),
        "trace_loose_cluster_count": trace_signature_audit.get("trace_loose_cluster_count"),
        "trace_signature_confirmation_gap": trace_signature_audit.get("trace_signature_confirmation_gap"),
        "trace_level_second_family_visible": trace_signature_audit.get("second_family_visible_at_trace_level"),
        "post_first_crash_continued": bool(
            first_crash_round is not None and any(item["round"] > first_crash_round for item in rounds)
        ),
        "post_patch_continued": bool(
            first_patch_round is not None and any(item["round"] > first_patch_round for item in rounds)
        ),
        "mode_sequence": [item.get("seed_mode") for item in rounds],
        "target_sequence": [item.get("selected_target_function") for item in rounds],
        "why_no_second_signature": (
            "trace-level crash diversity exceeds confirmed PoV diversity; later rounds appear to enter alternate crash states, but the current campaign metric still collapses to one confirmed canonical family"
            if final_distinct == 1 and trace_signature_audit.get("second_family_visible_at_trace_level")
            else (
                "coverage and crash inventory plateaued after the first confirmed family; later rounds changed seed mode/target but did not produce a new canonical signature"
                if final_distinct == 1 and len(rounds) > 1
                else None
            )
        ),
        "second_family_root_cause_hypothesis": (
            "PoV-confirmed canonicalization and confirmation gating are stronger than trace-level crash diversity, so second-family evidence is currently visible only at the traced-crash layer"
            if final_distinct == 1 and trace_signature_audit.get("second_family_visible_at_trace_level")
            else None
        ),
    }
    plateau_events: list[dict[str, Any]] = []
    family_rotation_events: list[dict[str, Any]] = []
    last_distinct: int | None = None
    plateau_streak = 0
    for item in rounds:
        coverage_delta = item.get("coverage_round_delta") or {}
        distinct = item.get("distinct_signature_count")
        no_coverage_delta = int(coverage_delta.get("covered_function_delta") or 0) == 0 and int(
            coverage_delta.get("covered_file_delta") or 0
        ) == 0
        repeated_signature = last_distinct is not None and distinct == last_distinct
        if no_coverage_delta and repeated_signature:
            plateau_streak += 1
            plateau_events.append(
                {
                    "round": item.get("round"),
                    "plateau_streak": plateau_streak,
                    "selected_target_function": item.get("selected_target_function"),
                    "seed_mode": item.get("seed_mode"),
                    "reason": "no coverage delta and no distinct signature growth",
                }
            )
        else:
            plateau_streak = 0
        if plateau_streak >= 2:
            family_rotation_events.append(
                {
                    "round": item.get("round"),
                    "action": "rotate_seed_family_and_penalize_seen_signature",
                    "next_mode_bias": "SEED_EXPLORE" if plateau_streak % 2 == 0 else "VULN_DISCOVERY",
                    "seen_signature_penalty": True,
                    "target_cooldown": item.get("selected_target_function"),
                }
            )
        if distinct is not None:
            last_distinct = int(distinct)

    cluster_map: dict[str, dict[str, Any]] = {}
    for item in rounds:
        target = str(item.get("selected_target_function") or "unknown").strip() or "unknown"
        cluster = cluster_map.setdefault(
            target,
            {
                "target_function": target,
                "rounds": [],
                "seed_modes": [],
                "selected_harnesses": [],
                "produced_raw_crash": False,
                "produced_trace": False,
                "produced_repro": False,
                "produced_patch": False,
                "distinct_signature_counts": [],
            },
        )
        cluster["rounds"].append(item.get("round"))
        mode = str(item.get("seed_mode") or "").strip()
        if mode and mode not in cluster["seed_modes"]:
            cluster["seed_modes"].append(mode)
        harness = str(item.get("selected_harness") or "").strip()
        if harness and harness not in cluster["selected_harnesses"]:
            cluster["selected_harnesses"].append(harness)
        if int(item.get("raw_crash_count") or 0) > 0:
            cluster["produced_raw_crash"] = True
        if int(item.get("traced_crash_count") or 0) > 0:
            cluster["produced_trace"] = True
        if int(item.get("repro_count") or 0) > 0:
            cluster["produced_repro"] = True
        if item.get("patch_task_ids"):
            cluster["produced_patch"] = True
        distinct = item.get("distinct_signature_count")
        if distinct is not None and distinct not in cluster["distinct_signature_counts"]:
            cluster["distinct_signature_counts"].append(distinct)

    crash_clusters = [
        item["target_function"]
        for item in cluster_map.values()
        if item["produced_raw_crash"] or item["produced_trace"] or item["produced_repro"]
    ]
    explored_targets = sorted(cluster_map)
    non_crashing_targets = [target for target in explored_targets if target not in crash_clusters]
    vulnerable_state_cluster_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "cluster_count": len(cluster_map),
        "crash_cluster_count": len(crash_clusters),
        "trace_exact_signature_count": trace_signature_audit.get("trace_exact_signature_count"),
        "trace_loose_cluster_count": trace_signature_audit.get("trace_loose_cluster_count"),
        "trace_signature_confirmation_gap": trace_signature_audit.get("trace_signature_confirmation_gap"),
        "target_to_trace_signatures": trace_signature_audit.get("target_to_trace_signatures"),
        "clusters": list(cluster_map.values()),
        "crash_clusters": crash_clusters,
        "non_crashing_targets": non_crashing_targets,
        "why_no_second_cluster": (
            "alternate trace-level crash signatures exist, but they currently map back into a single confirmed PoV family"
            if final_distinct == 1 and trace_signature_audit.get("second_family_visible_at_trace_level")
            else (
            "target diversification occurred, but only one crash-producing target cluster emerged; alternate parser-adjacent targets stayed non-crashing"
            if final_distinct == 1 and len(explored_targets) > 1 and len(crash_clusters) == 1
            else (
                "target space remained concentrated around a single parser-adjacent cluster"
                if final_distinct == 1 and len(explored_targets) <= 1
                else None
            )
            )
        ),
    }
    diversification_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "plateau_events": plateau_events,
        "family_rotation_events": family_rotation_events,
        "second_family_search_active": bool(plateau_events),
        "second_family_found": bool(final_distinct and final_distinct > 1),
        "trace_level_second_family_found": bool(trace_signature_audit.get("second_family_visible_at_trace_level")),
        "trace_signature_confirmation_gap": trace_signature_audit.get("trace_signature_confirmation_gap"),
        "second_family_blocker": vulnerable_state_cluster_payload["why_no_second_cluster"]
        or effectiveness_payload["why_no_second_signature"],
        "explored_targets": explored_targets,
        "crash_clusters": crash_clusters,
    }
    second_family_confirmation = _second_family_confirmation_analysis(
        task_id=task_id,
        trace_signature_audit=trace_signature_audit,
        vulnerable_state_cluster_payload=vulnerable_state_cluster_payload,
        pov_inventory=pov_inventory,
    )
    round_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "rounds": rounds,
    }
    yield_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "distinct_signature_growth": distinct_counts,
        "first_crash_round": first_crash_round,
        "first_patch_round": first_patch_round,
        "final_status": task.status.value,
    }
    post_crash_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "first_crash_round": first_crash_round,
        "rounds_after_first_crash": [
            item for item in rounds if first_crash_round is not None and item["round"] > first_crash_round
        ],
        "continued_after_first_crash": any(
            item["round"] > first_crash_round for item in rounds
        )
        if first_crash_round is not None
        else False,
    }
    post_patch_payload = {
        "task_id": task_id,
        "label": label,
        "generated_at": task_store.now(),
        "first_patch_round": first_patch_round,
        "patch_task_ids": patch_task_ids,
        "rounds_after_first_patch": [
            item for item in rounds if first_patch_round is not None and item["round"] > first_patch_round
        ],
        "continued_after_first_patch": any(
            item["round"] > first_patch_round for item in rounds
        )
        if first_patch_round is not None
        else False,
    }
    paths = {
        "campaign_budget_manifest_path": _write_json(campaign_dir / "campaign_budget_manifest.json", budget_payload),
        "campaign_round_summary_manifest_path": _write_json(
            campaign_dir / "campaign_round_summary_manifest.json",
            round_payload,
        ),
        "vulnerability_yield_manifest_path": _write_json(campaign_dir / "vulnerability_yield_manifest.json", yield_payload),
        "distinct_signature_growth_manifest_path": _write_json(
            campaign_dir / "distinct_signature_growth_manifest.json",
            {"task_id": task_id, "label": label, "generated_at": task_store.now(), "growth": distinct_counts},
        ),
        "post_first_crash_continuation_manifest_path": _write_json(
            campaign_dir / "post_first_crash_continuation_manifest.json",
            post_crash_payload,
        ),
        "post_patch_continuation_manifest_path": _write_json(
            campaign_dir / "post_patch_continuation_manifest.json",
            post_patch_payload,
        ),
        "llm_budget_accounting_manifest_path": _write_json(
            campaign_dir / "llm_budget_accounting_manifest.json",
            llm_budget_payload,
        ),
        "deadline_enforcement_report_path": _write_json(
            campaign_dir / "deadline_enforcement_report.json",
            deadline_payload,
        ),
        "campaign_effectiveness_report_path": _write_json(
            campaign_dir / "campaign_effectiveness_report.json",
            effectiveness_payload,
        ),
        f"{label}_long_campaign_effectiveness_report_path": _write_json(
            campaign_dir / f"{label}_long_campaign_effectiveness_report.json",
            effectiveness_payload,
        ),
        "vulnerable_state_cluster_report_path": _write_json(
            campaign_dir / "vulnerable_state_cluster_report.json",
            vulnerable_state_cluster_payload,
        ),
        "canonical_signature_merge_audit_path": _write_json(
            campaign_dir / "canonical_signature_merge_audit.json",
            trace_signature_audit,
        ),
        "second_family_confirmation_gap_report_path": _write_json(
            campaign_dir / "second_family_confirmation_gap_report.json",
            second_family_confirmation,
        ),
        "canonical_signature_split_decision_report_path": _write_json(
            campaign_dir / "canonical_signature_split_decision_report.json",
            {
                "task_id": task_id,
                "label": label,
                "generated_at": task_store.now(),
                "second_confirmed_family": second_family_confirmation.get("second_confirmed_family"),
                "split_decision": (
                    "conservative_split_allowed"
                    if second_family_confirmation.get("second_confirmed_family")
                    else "keep_single_confirmed_family"
                ),
                "evidence": second_family_confirmation.get("evidence"),
                "minimum_hard_blocker": second_family_confirmation.get("minimum_hard_blocker"),
                "primary_signature": second_family_confirmation.get("primary_signature"),
                "secondary_signature": second_family_confirmation.get("secondary_signature"),
            },
        ),
        "vulnerable_state_cluster_comparison_path": _write_json(
            campaign_dir / "vulnerable_state_cluster_comparison.json",
            {
                "task_id": task_id,
                "label": label,
                "generated_at": task_store.now(),
                "primary_sample": second_family_confirmation.get("primary_sample"),
                "secondary_sample": second_family_confirmation.get("secondary_sample"),
                "second_confirmed_family": second_family_confirmation.get("second_confirmed_family"),
                "minimum_hard_blocker": second_family_confirmation.get("minimum_hard_blocker"),
            },
        ),
        "deadline_vs_round_termination_report_path": _write_json(
            campaign_dir / "deadline_vs_round_termination_report.json",
            {
                "task_id": task_id,
                "label": label,
                "generated_at": task_store.now(),
                "declared_budget_seconds": budget_seconds,
                "actual_wall_time_seconds": actual_wall_time,
                "requested_rounds": requested_rounds,
                "requested_rounds_role": "checkpoint_only",
                "terminated_by_requested_rounds": False,
                "termination_reason": termination_reason,
            },
        ),
        "plateau_detection_manifest_path": _write_json(
            campaign_dir / "plateau_detection_manifest.json",
            {
                "task_id": task_id,
                "label": label,
                "generated_at": task_store.now(),
                "plateau_events": plateau_events,
            },
        ),
        "diversification_trigger_manifest_path": _write_json(
            campaign_dir / "diversification_trigger_manifest.json",
            diversification_payload,
        ),
        "family_rotation_manifest_path": _write_json(
            campaign_dir / "family_rotation_manifest.json",
            {
                "task_id": task_id,
                "label": label,
                "generated_at": task_store.now(),
                "events": family_rotation_events,
            },
        ),
        "second_family_search_report_path": _write_json(
            campaign_dir / "second_family_search_report.json",
            diversification_payload,
        ),
        "target_diversification_manifest_path": _write_json(
            campaign_dir / "target_diversification_manifest.json",
            {
                "task_id": task_id,
                "label": label,
                "generated_at": task_store.now(),
                "target_sequence": effectiveness_payload["target_sequence"],
                "target_cooldowns": [event.get("target_cooldown") for event in family_rotation_events],
            },
        ),
        "repeated_signature_penalty_report_path": _write_json(
            campaign_dir / "repeated_signature_penalty_report.json",
            {
                "task_id": task_id,
                "label": label,
                "generated_at": task_store.now(),
                "penalty_applied": bool(family_rotation_events),
                "events": family_rotation_events,
            },
        ),
        "selector_diversification_feedback_path": _write_json(
            campaign_dir / "selector_diversification_feedback.json",
            {
                "task_id": task_id,
                "label": label,
                "generated_at": task_store.now(),
                "mode_sequence": effectiveness_payload["mode_sequence"],
                "target_sequence": effectiveness_payload["target_sequence"],
                "family_rotation_events": family_rotation_events,
            },
        ),
    }
    task_store.update_runtime(task_id, paths)
    return paths


def _run_source_campaign(
    task_store: TaskStateStore,
    queue: LocalQueue,
    *,
    label: str,
    repo_url: str,
    git_ref: str | None,
    backend: str,
    requested_rounds: int,
    campaign_budget_seconds: int,
    fuzz_seconds: int,
    max_len: int,
) -> tuple[str, list[str], list[dict[str, Any]], dict[str, str]]:
    task_partition = "official_main" if backend == "llm" else "explicit_control_fallback"
    ground_truth = GROUND_TRUTH_BY_LABEL.get(label)
    metadata = {
        "run_label": f"{label}_final_hard_closure_{backend}",
        "SEED_GENERATION_BACKEND": backend,
        "SEED_GENERATION_ATTEMPTS": 2,
        "SEED_FUNCTION_TIMEOUT_SECONDS": 24,
        "SEED_MAX_BYTES": max_len,
        "FUZZ_MAX_TOTAL_TIME_SECONDS": fuzz_seconds,
        "FUZZ_TIMEOUT_SECONDS": 5,
        "FUZZ_MAX_LEN": max_len,
        "FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES": False,
        "ALLOW_IMPORTED_CRASH_FALLBACK": False,
        "verification_mode": "final_hard_closure_campaign",
        "task_partition": task_partition,
        "seed_material_policy": "clean_generated_only",
        "allow_imported_seed_material": False,
        "allow_cached_seed_material": False,
        "allow_fallback_non_llm": backend != "llm",
        "task_should_fail_if_llm_missing": backend == "llm",
        "ENABLE_PATCH_ATTEMPT": bool(int(os.getenv("FINAL_ENABLE_PATCH_ATTEMPT", "1"))),
        "campaign_budget_seconds": campaign_budget_seconds,
        "campaign_requested_rounds": requested_rounds,
        "LLM_TEMPERATURE": 0.2,
        "LLM_TIMEOUT_SECONDS": int(os.getenv("FINAL_PER_CALL_LLM_TIMEOUT_SECONDS", "90")),
        "LLM_MAX_RETRIES": int(os.getenv("FINAL_PER_CALL_LLM_MAX_RETRIES", "1")),
        "LLM_PATCH_TIMEOUT_SECONDS": int(os.getenv("FINAL_PATCH_LLM_TIMEOUT_SECONDS", "90")),
        "LLM_PATCH_MAX_RETRIES": int(os.getenv("FINAL_PATCH_LLM_MAX_RETRIES", "1")),
        "PATCH_MAX_REPAIR_ATTEMPTS": int(os.getenv("FINAL_PATCH_MAX_REPAIR_ATTEMPTS", "4")),
    }
    if ground_truth and ground_truth.exists():
        metadata["ground_truth_path"] = str(ground_truth)
    spec = TaskSpec(
        repo_url=repo_url,
        git_ref=git_ref,
        source_type="git_repo",
        task_time_budget=campaign_budget_seconds,
        fuzz_budget=fuzz_seconds * requested_rounds,
        execution_mode=ExecutionMode.HYBRID,
        metadata=metadata,
    )
    record = task_store.create_task(spec, status=TaskStatus.QUEUED_DOWNLOAD)
    seen_patch_tasks: set[str] = set()
    rounds: list[dict[str, Any]] = []
    started_at = time.monotonic()
    deadline_driven = backend == "llm" and bool(int(os.getenv("FINAL_DEADLINE_DRIVEN_SOURCE", "1")))
    min_wall_seconds = int(os.getenv("FINAL_SOURCE_MIN_WALL_SECONDS", "0"))
    emergency_round_cap = int(os.getenv("FINAL_SOURCE_EMERGENCY_ROUND_CAP", os.getenv("FINAL_SOURCE_MAX_ROUNDS_SAFETY", "0")))
    max_rounds_safety = emergency_round_cap if deadline_driven else int(
        os.getenv("FINAL_SOURCE_MAX_ROUNDS_SAFETY", str(max(requested_rounds, 1)))
    )
    if deadline_driven and max_rounds_safety > 0:
        max_rounds_safety = max(max_rounds_safety, requested_rounds, 1)

    download_task(record.task_id, task_store, queue)
    schedule_task(record.task_id, task_store, queue)
    index_task(record.task_id, task_store, queue)
    build_task(record.task_id, task_store, queue)

    round_index = 1
    termination_reason = "deadline_reached"
    while True:
        elapsed = time.monotonic() - started_at
        if elapsed >= campaign_budget_seconds:
            termination_reason = "deadline_reached"
            break
        if max_rounds_safety > 0 and round_index > max_rounds_safety:
            if deadline_driven and elapsed < min_wall_seconds:
                max_rounds_safety += max(1, requested_rounds)
            elif deadline_driven:
                termination_reason = "emergency_round_cap_reached"
                break
            else:
                termination_reason = "requested_rounds_completed"
                break
        if not deadline_driven and round_index > requested_rounds:
            termination_reason = "requested_rounds_completed"
            break
        task = task_store.load_task(record.task_id)
        if task.status in {
            TaskStatus.INDEXED,
            TaskStatus.BUILT,
            TaskStatus.SEEDED,
            TaskStatus.FUZZ_FAILED,
            TaskStatus.TRACED,
            TaskStatus.POV_CONFIRMED,
            TaskStatus.PATCH_ACCEPTED,
            TaskStatus.PATCH_SUPPRESSED,
            TaskStatus.PATCH_RETRY_REQUESTED,
            TaskStatus.PATCH_ESCALATED,
        }:
            task_store.update_status(
                record.task_id,
                TaskStatus.QUEUED_SEED,
                runtime_patch={
                    "repo_first_reseed_round": round_index,
                    "reseed_requested_at": task_store.now(),
                    "campaign_budget_remaining_seconds": max(
                        0,
                        int(campaign_budget_seconds - (time.monotonic() - started_at)),
                    ),
                },
            )
        try:
            seed_task(record.task_id, task_store, queue)
        except Exception as exc:
            elapsed_after_failure = time.monotonic() - started_at
            termination_reason = (
                "strict_llm_block_after_deadline_overrun"
                if elapsed_after_failure >= campaign_budget_seconds
                else "strict_llm_seed_blocked"
            )
            task_store.update_status(
                record.task_id,
                TaskStatus.SEED_FAILED,
                runtime_patch={
                    "strict_llm_campaign_blocked_at": task_store.now(),
                    "strict_llm_campaign_block_reason": str(exc),
                    "strict_llm_campaign_block_round": round_index,
                    "strict_llm_campaign_block_elapsed_seconds": round(elapsed_after_failure, 3),
                    "strict_llm_campaign_block_termination_reason": termination_reason,
                },
            )
            rounds.append(
                _round_snapshot(
                    label=label,
                    task_id=record.task_id,
                    round_index=round_index,
                    started_at=started_at,
                    task_store=task_store,
                    patch_task_ids=sorted(seen_patch_tasks),
                )
            )
            break
        task = task_store.load_task(record.task_id)
        task_dir = Path(task.task_dir)
        _copy_if_exists(task.runtime.get("seed_init_chain_manifest_path"), task_dir / "seed" / f"seed_init_chain_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_task_manifest_path"), task_dir / "seed" / f"seed_task_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_manifest_path"), task_dir / "seed" / f"seed_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("harness_selector_manifest_path"), task_dir / "seed" / f"harness_selector_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("function_selector_manifest_path"), task_dir / "seed" / f"function_selector_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("seed_family_plan_manifest_path"), task_dir / "seed" / f"seed_family_plan_manifest_run{round_index}.json")
        _copy_if_exists(task_dir / "index" / "context_package.json", task_dir / "index" / f"context_package_run{round_index}.json")
        if task.status == TaskStatus.QUEUED_FUZZ:
            fuzzer_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        _copy_if_exists(task.runtime.get("fuzz_manifest_path"), task_dir / "crashes" / f"fuzz_manifest_run{round_index}.json")
        analyze_coverage_feedback(record.task_id, task_store)
        task = task_store.load_task(record.task_id)
        _copy_if_exists(task.runtime.get("coverage_summary_manifest_path"), task_dir / "coverage" / f"coverage_summary_manifest_run{round_index}.json")
        _copy_if_exists(task.runtime.get("coverage_feedback_manifest_path"), task_dir / "coverage" / f"feedback_manifest_run{round_index}.json")
        _consume_scheduler_feedback(record.task_id, task_store)
        task = task_store.load_task(record.task_id)
        next_mode = "VULN_DISCOVERY" if int(task.runtime.get("raw_crash_count") or 0) > 0 else "SEED_EXPLORE"
        task_store.update_runtime(
            record.task_id,
            {
                "seed_task_mode_override": next_mode,
                "targeted_reseed_reason": (
                    "live raw crash exists; continue campaign with exploit-oriented seed family"
                    if next_mode == "VULN_DISCOVERY"
                    else "no live raw crash yet; continue campaign with parser exploration seed family"
                ),
            },
        )
        if task.status == TaskStatus.QUEUED_TRACE:
            trace_task(record.task_id, task_store, queue)
        task = task_store.load_task(record.task_id)
        if task.status == TaskStatus.QUEUED_REPRO:
            repro_task(record.task_id, task_store, queue)
        current_target = str(task.runtime.get("selected_target_function") or "").strip()
        if current_target and (
            task.runtime.get("trace_manifest_path")
            or int(task.runtime.get("traced_crash_count") or 0) > 0
            or int(task.runtime.get("repro_count") or 0) > 0
        ):
            task_store.update_runtime(
                record.task_id,
                {
                    "already_traced_target_functions": _extend_unique_names(
                        task.runtime.get("already_traced_target_functions"),
                        current_target,
                    )
                },
            )
        launched = _drain_patch_queue_for_base(queue, task_store, record.task_id, seen_patch_tasks)
        if launched:
            current_runtime = task_store.load_task(record.task_id).runtime
            task_store.update_runtime(
                record.task_id,
                {
                    "last_patch_round": round_index,
                    "last_patch_task_ids": sorted([*seen_patch_tasks, *launched]),
                    "continue_after_patch_required": True,
                    "already_patched_target_functions": _extend_unique_names(
                        current_runtime.get("already_patched_target_functions"),
                        current_target,
                    ),
                },
            )
        rounds.append(
            _round_snapshot(
                label=label,
                task_id=record.task_id,
                round_index=round_index,
                started_at=started_at,
                task_store=task_store,
                patch_task_ids=sorted([*seen_patch_tasks, *launched]),
            ),
        )
        latest_round = rounds[-1]
        coverage_delta = latest_round.get("coverage_round_delta") or {}
        no_coverage_delta = int(coverage_delta.get("covered_function_delta") or 0) == 0 and int(
            coverage_delta.get("covered_file_delta") or 0
        ) == 0
        repeated_signature = (
            len(rounds) >= 2
            and latest_round.get("distinct_signature_count") is not None
            and latest_round.get("distinct_signature_count") == rounds[-2].get("distinct_signature_count")
        )
        if no_coverage_delta and repeated_signature:
            next_mode = "SEED_EXPLORE" if round_index % 2 == 0 else "VULN_DISCOVERY"
            reseed_targets = _derive_campaign_reseed_targets(
                latest_round=latest_round,
                fallback_runtime_targets=task.runtime.get("selected_target_functions"),
            )
            task_store.update_runtime(
                record.task_id,
                {
                    "seed_task_mode_override": next_mode,
                    "campaign_budget_state": "explore" if next_mode == "SEED_EXPLORE" else "exploit",
                    "second_family_search_active": True,
                    "seen_signature_penalty_active": True,
                    "target_cooldown_function": latest_round.get("selected_target_function"),
                    "campaign_reseed_targets": reseed_targets,
                    "targeted_reseed_reason": (
                        "plateau detected: no coverage delta and repeated signature; rotate seed family, penalize seen target/signature, and explicitly reseed alternate parser-adjacent targets"
                    ),
                },
            )
        round_index += 1

    task_store.update_runtime(
        record.task_id,
        {
            "campaign_termination_reason": termination_reason,
            "deadline_driven_campaign": deadline_driven,
            "requested_rounds_role": "checkpoint_only" if deadline_driven else "terminating_limit",
            "campaign_max_rounds_safety": max_rounds_safety,
            "campaign_emergency_round_cap": emergency_round_cap if deadline_driven else None,
            "campaign_min_wall_seconds": min_wall_seconds,
        },
    )
    paths = _write_campaign_manifests(
        label=label,
        task_id=record.task_id,
        budget_seconds=campaign_budget_seconds,
        requested_rounds=requested_rounds,
        rounds=rounds,
        patch_task_ids=sorted(seen_patch_tasks),
        task_store=task_store,
    )
    return record.task_id, sorted(seen_patch_tasks), rounds, paths


def _load_existing_package(project_name: str) -> dict[str, Any] | None:
    registry = _read_json(REPORTS_ROOT / "dataset_registry_manifest.json")
    package = (registry.get("binary_packages") or {}).get(project_name)
    if package and Path(str(package.get("binary_package_manifest_path", ""))).exists():
        return package
    return None


def _campaign_paths_for_task(task_id: str) -> dict[str, str]:
    campaign_dir = DATA_ROOT / task_id / "campaign"
    return {
        "campaign_budget_manifest_path": str(campaign_dir / "campaign_budget_manifest.json"),
        "campaign_round_summary_manifest_path": str(campaign_dir / "campaign_round_summary_manifest.json"),
        "vulnerability_yield_manifest_path": str(campaign_dir / "vulnerability_yield_manifest.json"),
        "distinct_signature_growth_manifest_path": str(campaign_dir / "distinct_signature_growth_manifest.json"),
        "post_first_crash_continuation_manifest_path": str(campaign_dir / "post_first_crash_continuation_manifest.json"),
        "post_patch_continuation_manifest_path": str(campaign_dir / "post_patch_continuation_manifest.json"),
        "llm_budget_accounting_manifest_path": str(campaign_dir / "llm_budget_accounting_manifest.json"),
        "deadline_enforcement_report_path": str(campaign_dir / "deadline_enforcement_report.json"),
        "campaign_effectiveness_report_path": str(campaign_dir / "campaign_effectiveness_report.json"),
        "canonical_signature_merge_audit_path": str(campaign_dir / "canonical_signature_merge_audit.json"),
        "deadline_vs_round_termination_report_path": str(campaign_dir / "deadline_vs_round_termination_report.json"),
        "plateau_detection_manifest_path": str(campaign_dir / "plateau_detection_manifest.json"),
        "diversification_trigger_manifest_path": str(campaign_dir / "diversification_trigger_manifest.json"),
        "family_rotation_manifest_path": str(campaign_dir / "family_rotation_manifest.json"),
        "second_family_search_report_path": str(campaign_dir / "second_family_search_report.json"),
        "target_diversification_manifest_path": str(campaign_dir / "target_diversification_manifest.json"),
        "repeated_signature_penalty_report_path": str(campaign_dir / "repeated_signature_penalty_report.json"),
        "selector_diversification_feedback_path": str(campaign_dir / "selector_diversification_feedback.json"),
    }


def _patch_task_ids_for_base(base_task_id: str) -> list[str]:
    patch_ids: list[str] = []
    for task_json in DATA_ROOT.glob("*/task.json"):
        payload = _read_json(task_json)
        if (payload.get("metadata") or {}).get("patch_base_task_id") == base_task_id:
            patch_ids.append(str(payload.get("task_id") or task_json.parent.name))
    return sorted(set(patch_ids))


def _reused_source_run(label: str, task_id: str) -> dict[str, Any]:
    paths = _campaign_paths_for_task(task_id)
    rounds = _read_json(paths["campaign_round_summary_manifest_path"]).get("rounds", [])
    return {
        "task_id": task_id,
        "patch_task_ids": _patch_task_ids_for_base(task_id),
        "rounds": rounds,
        "campaign_paths": paths,
        "reused_existing_evidence": True,
        "label": label,
    }


def _first_fuzzer_names(task_id: str) -> list[str]:
    registry = _read_json(DATA_ROOT / task_id / "build" / "build_registry.json")
    return [
        str(item.get("name"))
        for item in (registry.get("fuzzers") or [])[:2]
        if item.get("name")
    ]


def main() -> int:
    llm_config = configure_llm_from_env()
    task_store = TaskStateStore()
    queue = LocalQueue()
    source_requested_rounds = int(os.getenv("FINAL_SOURCE_REQUESTED_ROUNDS", "5"))
    source_campaign_budget_seconds = int(os.getenv("FINAL_CAMPAIGN_BUDGET_SECONDS", "900"))
    cjson_fuzz_seconds = int(os.getenv("FINAL_CJSON_FUZZ_SECONDS", os.getenv("FINAL_FUZZ_SECONDS", "30")))
    inih_fuzz_seconds = int(os.getenv("FINAL_INIH_FUZZ_SECONDS", os.getenv("FINAL_FUZZ_SECONDS", "30")))
    control_requested_rounds = int(os.getenv("FINAL_CONTROL_REQUESTED_ROUNDS", "1"))
    control_budget_seconds = int(os.getenv("FINAL_CONTROL_BUDGET_SECONDS", "90"))
    control_fuzz_seconds = int(os.getenv("FINAL_CONTROL_FUZZ_SECONDS", "8"))
    binary_native_rounds = int(os.getenv("FINAL_BINARY_NATIVE_ROUNDS", "1"))

    source_runs: dict[str, Any] = {}
    reuse_cjson = os.getenv("FINAL_REUSE_CJSON_TASK_ID", "").strip()
    reuse_inih = os.getenv("FINAL_REUSE_INIH_TASK_ID", "").strip()
    if reuse_cjson and reuse_inih:
        source_runs["cjson"] = _reused_source_run("cjson", reuse_cjson)
        source_runs["inih"] = _reused_source_run("inih", reuse_inih)
    else:
        for label, params in (
            ("cjson", {"fuzz_seconds": cjson_fuzz_seconds, "max_len": 262144}),
            ("inih", {"fuzz_seconds": inih_fuzz_seconds, "max_len": 1024}),
        ):
            task_id, patch_ids, rounds, campaign_paths = _run_source_campaign(
                task_store,
                queue,
                label=label,
                repo_url=INJECTED_SOURCE_REPOS[label]["repo_url"],
                git_ref=INJECTED_SOURCE_REPOS[label]["git_ref"],
                backend="llm",
                requested_rounds=source_requested_rounds,
                campaign_budget_seconds=source_campaign_budget_seconds,
                fuzz_seconds=params["fuzz_seconds"],
                max_len=params["max_len"],
            )
            source_runs[label] = {
                "task_id": task_id,
                "patch_task_ids": patch_ids,
                "rounds": rounds,
                "campaign_paths": campaign_paths,
            }

    control_runs: dict[str, Any] = {}
    for label, params in (
        ("cjson", {"fuzz_seconds": control_fuzz_seconds, "max_len": 262144}),
        ("inih", {"fuzz_seconds": control_fuzz_seconds, "max_len": 1024}),
    ):
        result = _safe_call(
            f"{label}_fallback_control",
            _run_source_campaign,
            task_store,
            queue,
            label=label,
            repo_url=INJECTED_SOURCE_REPOS[label]["repo_url"],
            git_ref=INJECTED_SOURCE_REPOS[label]["git_ref"],
            backend="heuristic_fallback",
            requested_rounds=control_requested_rounds,
            campaign_budget_seconds=control_budget_seconds,
            fuzz_seconds=params["fuzz_seconds"],
            max_len=params["max_len"],
        )
        control_runs[label] = result

    generalized_task_ids: dict[str, str] = {}
    for label, repo in {
        "libyaml": GENERALIZATION_REPOS["libyaml"],
        "libplist": GENERALIZATION_REPOS["libplist"],
        "zlib": GENERALIZATION_REPOS["zlib"],
        **EXTRA_GENERALIZATION_REPOS,
    }.items():
        result = _safe_call(
            f"{label}_source_sanity",
            _run_source_sanity,
            task_store,
            queue,
            label=f"{label}_final_hard_closure_sanity",
            repo_url=repo["repo_url"],
            git_ref=repo.get("git_ref"),
        )
        if result["ok"]:
            generalized_task_ids[label] = result["result"]

    source_generalization = _write_source_generalization_reports(
        task_store,
        [
            source_runs["cjson"]["task_id"],
            source_runs["inih"]["task_id"],
            *generalized_task_ids.values(),
        ],
    )

    binary_packages: dict[str, dict[str, Any]] = {}
    for project_name in ("cjson", "inih", "libxml2", "libyaml", "cjson_opaque"):
        existing = _load_existing_package(project_name)
        if existing:
            binary_packages[project_name] = existing

    if "cjson" not in binary_packages:
        package = _package_from_task(
            task_id=source_runs["cjson"]["task_id"],
            project_name="cjson",
            layer="source-derived-binary",
            preferred_fuzzers=["cjson_read_fuzzer", *_first_fuzzer_names(source_runs["cjson"]["task_id"])],
        )
        if package:
            binary_packages["cjson"] = package
    if "inih" not in binary_packages:
        package = _package_from_task(
            task_id=source_runs["inih"]["task_id"],
            project_name="inih",
            layer="source-derived-binary",
            preferred_fuzzers=["inihfuzz", *_first_fuzzer_names(source_runs["inih"]["task_id"])],
        )
        if package:
            binary_packages["inih"] = package
    if "libyaml" not in binary_packages and generalized_task_ids.get("libyaml"):
        package = _package_from_task(
            task_id=generalized_task_ids["libyaml"],
            project_name="libyaml",
            layer="source-derived-binary",
            preferred_fuzzers=["libyaml_parser_fuzzer", *_first_fuzzer_names(generalized_task_ids["libyaml"])],
        )
        if package:
            binary_packages["libyaml"] = package

    binary_real_task_ids: dict[str, str] = {}
    for project_name in ("cjson", "inih", "libyaml"):
        package = binary_packages.get(project_name)
        if not package:
            continue
        result = _safe_call(
            f"{project_name}_binary_real_llm",
            _run_binary_package_task,
            task_store,
            queue,
            label=f"{project_name}_final_hard_closure_binary_real_llm",
            package=package,
            backend="llm",
            binary_mode="source_derived_binary",
            native_rounds=binary_native_rounds,
        )
        if result["ok"]:
            binary_real_task_ids[project_name] = result["result"]
    opaque_task_ids: dict[str, str] = {}
    if binary_packages.get("cjson_opaque"):
        result = _safe_call(
            "cjson_opaque_binary_real_llm",
            _run_binary_package_task,
            task_store,
            queue,
            label="cjson_opaque_final_hard_closure_real_llm",
            package=binary_packages["cjson_opaque"],
            backend="llm",
            binary_mode="opaque_binary_like",
            native_rounds=binary_native_rounds,
        )
        if result["ok"]:
            binary_real_task_ids["cjson_opaque"] = result["result"]
            opaque_task_ids["cjson_opaque"] = result["result"]

    source_metrics = {
        label: _source_metrics(payload["task_id"], task_store, payload["patch_task_ids"])
        for label, payload in source_runs.items()
    }
    control_metrics: dict[str, Any] = {}
    for label, result in control_runs.items():
        if result.get("ok"):
            task_id, patch_ids, rounds, campaign_paths = result["result"]
            control_metrics[label] = {
                "task_id": task_id,
                "patch_task_ids": patch_ids,
                "rounds": rounds,
                "campaign_paths": campaign_paths,
                "metrics": _source_metrics(task_id, task_store, patch_ids),
            }
        else:
            control_metrics[label] = result

    binary_metrics = {
        project_name: _binary_metrics(task_id, task_store)
        for project_name, task_id in binary_real_task_ids.items()
    }

    source_llm_audits = [
        _collect_task_llm_audit(task_store, payload["task_id"], target_mode="source")
        for payload in source_runs.values()
    ]
    binary_llm_audits = [
        _collect_task_llm_audit(task_store, task_id, target_mode="binary")
        for task_id in binary_real_task_ids.values()
    ]
    control_audits = [
        _collect_task_llm_audit(task_store, value["task_id"], target_mode="source")
        for value in control_metrics.values()
        if isinstance(value, dict) and value.get("task_id")
    ]

    official_main_audits = [*source_llm_audits, *binary_llm_audits]
    blocked_task_ids = [item["task_id"] for item in official_main_audits if item.get("strict_llm_blocked")]
    degraded_success_task_ids = [
        item["task_id"]
        for item in official_main_audits
        if item.get("degraded") and not item.get("strict_llm_blocked")
    ]
    strict_report = {
        "generated_at": task_store.now(),
        "blocked_task_ids": blocked_task_ids,
        "official_main_blocked_count": len(blocked_task_ids),
        "official_main_degraded_success_task_ids": degraded_success_task_ids,
        "official_main_degraded_count": len(degraded_success_task_ids),
        "official_main_degraded_success_count": len(degraded_success_task_ids),
        "official_main_real_llm_verified_count": sum(1 for item in official_main_audits if item.get("llm_real_call_verified")),
        "fallback_control_task_ids": [item["task_id"] for item in control_audits],
    }
    strict_llm_block_report_path = write_report("strict_llm_block_report.json", strict_report)
    llm_integrity_path = write_report(
        "llm_backend_integrity_report.json",
        {
            "generated_at": task_store.now(),
            "source_lane": source_llm_audits,
            "binary_lane": binary_llm_audits,
            "explicit_control_fallback": control_audits,
            "summary": strict_report,
            "silent_fallback_eliminated": all(
                bool(item.get("silent_fallback_eliminated"))
                for item in [*source_llm_audits, *binary_llm_audits]
            ),
        },
    )
    mainline_vs_control_partition_path = write_report(
        "mainline_vs_control_task_partition.json",
        {
            "generated_at": task_store.now(),
            "official_main": [item["task_id"] for item in official_main_audits],
            "explicit_control_fallback": [item["task_id"] for item in control_audits],
            "local_plumbing": list(generalized_task_ids.values()),
        },
    )

    effect_comparison = {
        "generated_at": task_store.now(),
        "official_main": {
            label: {
                "task_id": payload["task_id"],
                "status": task_store.load_task(payload["task_id"]).status.value,
                "rounds": payload["rounds"],
                "metrics": source_metrics[label],
                "llm_audit": next((item for item in source_llm_audits if item["task_id"] == payload["task_id"]), None),
            }
            for label, payload in source_runs.items()
        },
        "explicit_control_fallback": control_metrics,
        "comparison_notes": [
            "fallback controls are intentionally short and partitioned from official_main",
            "effect is measured by crash timing, distinct signature growth, seed mode, coverage feedback, and patch follow-up manifests",
        ],
    }
    llm_effect_comparison_path = write_report("llm_effect_comparison_manifest.json", effect_comparison)
    llm_campaign_delta_path = write_report(
        "llm_campaign_delta_report.json",
        {
            "generated_at": task_store.now(),
            "official_main_rounds": {label: payload["rounds"] for label, payload in source_runs.items()},
            "control_rounds": {
                label: value.get("rounds")
                for label, value in control_metrics.items()
                if isinstance(value, dict)
            },
        },
    )
    mainline_vs_control_report_path = write_report("mainline_vs_control_report.json", effect_comparison)

    dataset_registry = _read_json(REPORTS_ROOT / "dataset_registry_manifest.json")
    source_binary_gap = {
        "generated_at": task_store.now(),
        "comparisons": [
            {
                "project_name": project_name,
                "source_full": source_metrics.get(project_name),
                "source_derived_binary": binary_metrics.get(project_name),
                "binary_task_id": binary_real_task_ids.get(project_name),
                "binary_package_manifest_path": binary_packages.get(project_name, {}).get("binary_package_manifest_path"),
                "binary_missing_to_match_source": (
                    [
                        "no source-level typed context in binary package",
                        "dynamic observation is still weaker than source ASAN trace/repro",
                        "trace promotion requires canonical semantic_crash_candidate, not only watchlist signals",
                    ]
                    if binary_metrics.get(project_name)
                    else ["binary package or task unavailable"]
                ),
            }
            for project_name in ("cjson", "inih", "libyaml", "cjson_opaque")
        ],
    }
    source_binary_gap_path = write_report("source_binary_gap_report.json", source_binary_gap)
    unified_eval = {
        "generated_at": task_store.now(),
        "llm_config": llm_config,
        "source_full": {
            "official_main": {
                label: {"task_id": payload["task_id"], "status": task_store.load_task(payload["task_id"]).status.value}
                for label, payload in source_runs.items()
            },
            "explicit_control_fallback": {
                label: {"task_id": value.get("task_id"), "status": task_store.load_task(value["task_id"]).status.value}
                for label, value in control_metrics.items()
                if isinstance(value, dict) and value.get("task_id")
            },
        },
        "source_derived_binary": {"official_main": binary_real_task_ids},
        "opaque_binary_like": {
            "available_packages": [
                key
                for key in (dataset_registry.get("binary_packages") or {})
                if "opaque" in key
            ],
            "official_main": opaque_task_ids,
        },
        "generalized_source": source_generalization,
    }
    unified_evaluation_matrix_path = write_report("unified_evaluation_matrix.json", unified_eval)
    write_report(
        "source_binary_followup_gap_report.json",
        {
            "generated_at": task_store.now(),
            "source_binary_gap_report_path": str(source_binary_gap_path),
            "next_binary_requirements": [
                "promote watchlist signals with sanitizer-aware replay",
                "keep project-local denoising ahead of trace gating",
                "carry IDA-selected function context into seed shaping",
            ],
        },
    )
    calibration_report = _read_json(REPORTS_ROOT / "binary_candidate_escalation_report.json")
    native_vs_calibration_path = write_report(
        "native_vs_calibration_promotion_report.json",
        {
            "generated_at": task_store.now(),
            "native_llm_seed_driven": {
                project_name: {
                    "task_id": task_id,
                    "signal_category_counts": (binary_metrics.get(project_name) or {}).get("signal_category_counts"),
                    "binary_crash_candidate_count": (binary_metrics.get(project_name) or {}).get("binary_crash_candidate_count"),
                    "trace_gate_decision": (binary_metrics.get(project_name) or {}).get("trace_gate_decision"),
                    "native_seed_only": True,
                }
                for project_name, task_id in binary_real_task_ids.items()
                if project_name != "cjson_opaque"
            },
            "opaque_native_llm_seed_driven": {
                project_name: {
                    "task_id": task_id,
                    "signal_category_counts": (binary_metrics.get(project_name) or {}).get("signal_category_counts"),
                    "binary_crash_candidate_count": (binary_metrics.get(project_name) or {}).get("binary_crash_candidate_count"),
                    "trace_gate_decision": (binary_metrics.get(project_name) or {}).get("trace_gate_decision"),
                    "native_seed_only": True,
                }
                for project_name, task_id in opaque_task_ids.items()
            },
            "calibration_assisted": calibration_report,
            "boundary_statement": (
                "Native LLM binary tasks are counted separately from calibration-assisted promotion. "
                "A sidecar/imported crash may prove trace/repro plumbing, but it is not counted as native binary fuzz discovery."
            ),
        },
    )
    if opaque_task_ids.get("cjson_opaque"):
        opaque_task_id = opaque_task_ids["cjson_opaque"]
        opaque_metrics = binary_metrics.get("cjson_opaque", {})
        opaque_eval_path = write_report(
            "opaque_binary_evaluation_manifest.json",
            {
                "generated_at": task_store.now(),
                "opaque_task_id": opaque_task_id,
                "opaque_package": binary_packages.get("cjson_opaque"),
                "opaque_metrics": opaque_metrics,
                "strict_real_llm": next(
                    (item for item in binary_llm_audits if item["task_id"] == opaque_task_id),
                    None,
                ),
            },
        )
        write_report(
            "opaque_vs_source_derived_gap_report.json",
            {
                "generated_at": task_store.now(),
                "opaque_task_id": opaque_task_id,
                "source_derived_task_id": binary_real_task_ids.get("cjson"),
                "opaque_metrics": opaque_metrics,
                "source_derived_metrics": binary_metrics.get("cjson"),
                "gap": [
                    "opaque package has reduced symbol/sidecar visibility",
                    "candidate promotion still depends on native dynamic signal quality",
                ],
                "opaque_binary_evaluation_manifest_path": str(opaque_eval_path),
            },
        )

    summary = {
        "source_official_main": source_metrics,
        "source_control_fallback": control_metrics,
        "source_generalization": source_generalization,
        "binary_real": binary_metrics,
        "binary_task_ids": binary_real_task_ids,
        "campaign_paths": {label: payload["campaign_paths"] for label, payload in source_runs.items()},
        "llm_backend_integrity_report_path": str(llm_integrity_path),
        "strict_llm_block_report_path": str(strict_llm_block_report_path),
        "mainline_vs_control_task_partition_path": str(mainline_vs_control_partition_path),
        "mainline_vs_control_report_path": str(mainline_vs_control_report_path),
        "llm_effect_comparison_manifest_path": str(llm_effect_comparison_path),
        "llm_campaign_delta_report_path": str(llm_campaign_delta_path),
        "source_binary_gap_report_path": str(source_binary_gap_path),
        "unified_evaluation_matrix_path": str(unified_evaluation_matrix_path),
        "native_vs_calibration_promotion_report_path": str(native_vs_calibration_path),
    }
    write_report("final_hard_closure_summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

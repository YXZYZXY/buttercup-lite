from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from core.analysis.suspicious_candidate import record_suspicious_candidate_repro_status
from core.analysis.family_confirmation import (
    classify_reproduction_attempts,
    load_campaign_family_context,
    plan_reproduction_candidates,
    write_repro_family_manifest,
)
from core.binary.repro_bridge import enrich_binary_pov
from core.binary.trace_bridge import is_binary_task
from core.fuzz.harness_binding import active_harness_record
from core.models.task import TaskStatus
from core.patch_plane import maybe_enqueue_patch_followup
from core.patch_priority import write_patch_priority_manifest
from core.queues.redis_queue import QueueNames, RedisQueue
from core.reproducer import build_pov_record, replay_traced_crash, write_repro_manifest
from core.state.task_state import TaskStateStore
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("reproducer-worker")


def _cluster_summary_map(family_plan: dict) -> dict[str, dict]:
    return {
        str(item.get("loose_cluster_key") or "").strip(): dict(item)
        for item in (family_plan.get("cluster_summaries") or [])
        if isinstance(item, dict) and str(item.get("loose_cluster_key") or "").strip()
    }


def _build_patch_family_priority(entry: dict, cluster_summary: dict) -> dict:
    requires_reconfirmation = bool(entry.get("requires_reconfirmation"))
    cluster_crash_count = int(
        cluster_summary.get("crash_count")
        or len(cluster_summary.get("member_candidate_ids") or [])
        or 1
    )
    cluster_priority_rank = int(cluster_summary.get("priority_rank") or 0)
    selection_score = float(entry.get("selection_score") or 0.0)
    priority_score = round(
        (1000.0 if requires_reconfirmation else 0.0)
        + cluster_crash_count * 25.0
        + max(selection_score, 0.0) * 10.0
        - cluster_priority_rank,
        4,
    )
    priority_reason = (
        "requires_reconfirmation_then_cluster_crash_count"
        if requires_reconfirmation
        else "cluster_crash_count_then_selection_score"
    )
    return {
        "requires_reconfirmation": requires_reconfirmation,
        "reconfirmation_trigger": entry.get("reconfirmation_trigger"),
        "reconfirmation_round_gap": int(entry.get("reconfirmation_round_gap") or 0),
        "reconfirmation_threshold_rounds": entry.get("reconfirmation_threshold_rounds"),
        "loose_cluster_key": entry.get("family_loose_cluster_key"),
        "confirmed_family_key": entry.get("family_confirmed_family_key"),
        "cluster_crash_count": cluster_crash_count,
        "cluster_priority_rank": cluster_priority_rank,
        "selection_score": selection_score,
        "priority_score": priority_score,
        "priority_reason": priority_reason,
    }


def _patch_reference_sort_key(entry: dict) -> tuple:
    family_priority = dict(entry.get("family_priority") or {})
    return (
        0 if bool(family_priority.get("requires_reconfirmation")) else 1,
        -int(family_priority.get("cluster_crash_count") or 0),
        int(family_priority.get("cluster_priority_rank") or 0),
        -float(entry.get("selection_score") or 0.0),
        str(entry.get("candidate_id") or ""),
    )


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("reproducer received task %s", task_id)
    task_store.update_status(
        task_id,
        TaskStatus.REPRODUCING,
        runtime_patch={"repro_started_at": task_store.now()},
    )
    task = task_store.load_task(task_id)
    traced_dir = Path(task.layout["trace_traced_crashes"])
    traced_files = sorted(traced_dir.glob("*.json"))
    if not traced_files:
        raise RuntimeError("no traced crashes available for reproduction")
    task_dir = Path(task.task_dir)
    binary_mode = is_binary_task(task_dir)
    active = active_harness_record(task_dir)
    traced_candidates = [json.loads(path.read_text(encoding="utf-8")) for path in traced_files]
    confirmed_dir = Path(task.layout["pov_confirmed"])
    confirmed_dir.mkdir(parents=True, exist_ok=True)
    campaign_state = load_campaign_family_context(task_dir)
    family_plan = plan_reproduction_candidates(
        traced_candidates,
        active_harness_name=active.get("name"),
        campaign_state=campaign_state,
    )
    cluster_summaries = _cluster_summary_map(family_plan)

    confirmed_entries: list[dict] = []
    blocked_entries: list[dict] = []
    pov_paths: list[str] = []
    all_attempts: list[dict] = []
    pending_candidate_repro_updates: list[dict] = []
    weak_repro_attempted_count = 0
    weak_repro_result_distribution: dict[str, int] = {}

    for selected in family_plan.get("selected_candidates") or []:
        traced = dict(selected.get("traced_candidate") or {})
        attempts = replay_traced_crash(traced, Path(task.task_dir))
        attempt_dicts = [attempt.__dict__ for attempt in attempts]
        all_attempts.extend(attempt_dicts)
        outcome = classify_reproduction_attempts(traced, attempts, selection_context=selected)
        weak_repro_attempted = bool(
            traced.get("candidate_origin_kind") == "suspicious_candidate"
            and (
                bool(traced.get("weak_signal_detected"))
                or str(traced.get("replay_signal_classification") or "") == "weak_actionable_signal"
            )
        )
        weak_repro_result = (
            "confirmed_family"
            if outcome.get("confirmed")
            else str(outcome.get("blocker_reason") or "weak_repro_not_confirmed")
        )
        if weak_repro_attempted:
            weak_repro_attempted_count += 1
            weak_repro_result_distribution[weak_repro_result] = (
                weak_repro_result_distribution.get(weak_repro_result, 0) + 1
            )
        closure_mode = (
            "strict_live"
            if traced.get("crash_source") == "live_raw" and traced.get("trace_mode") == "live_asan"
            else (
                "pure_binary_replay"
                if traced.get("target_mode") == "binary"
                and traced.get("binary_provenance") == "pure_binary_input"
                and traced.get("crash_source") == "live_raw"
                else "imported_fallback"
            )
        )
        candidate_result = {
            "candidate_id": selected.get("candidate_id"),
            "selection_reason": selected.get("selection_reason"),
            "already_confirmed_family": bool(selected.get("already_confirmed_family")),
            "requires_reconfirmation": bool(selected.get("requires_reconfirmation")),
            "reconfirmation_trigger": selected.get("reconfirmation_trigger"),
            "reconfirmation_round_gap": int(selected.get("reconfirmation_round_gap") or 0),
            "reconfirmation_threshold_rounds": selected.get("reconfirmation_threshold_rounds"),
            "known_confirmed_signatures": selected.get("known_confirmed_signatures") or [],
            "selection_score": selected.get("selection_score"),
            "family_exact_signature": traced.get("family_exact_signature") or traced.get("signature"),
            "family_loose_cluster_key": traced.get("family_loose_cluster_key"),
            "family_confirmed_family_key": traced.get("family_confirmed_family_key"),
            "primary_function": (traced.get("family_features") or {}).get("primary_function"),
            "primary_file": (traced.get("family_features") or {}).get("primary_file"),
            "harness_name": traced.get("harness_name"),
            "testcase_path": traced.get("testcase_path"),
            "crash_source": traced.get("crash_source"),
            "classification": outcome.get("classification"),
            "blocker_kind": outcome.get("blocker_kind"),
            "blocker_reason": outcome.get("blocker_reason"),
            "stable_replays": outcome.get("stable_replays"),
            "observed_signatures": outcome.get("observed_signatures"),
            "observed_cluster_keys": outcome.get("observed_cluster_keys") or [],
            "observed_cluster_match_reasons": outcome.get("observed_cluster_match_reasons") or [],
            "attempt_cluster_evidence": outcome.get("attempt_cluster_evidence") or [],
            "confirmation_level": outcome.get("confirmation_level"),
            "promotion_rule": outcome.get("promotion_rule"),
            "family_lineage": outcome.get("lineage") or {},
            "weak_repro_attempted": weak_repro_attempted,
            "weak_repro_result": weak_repro_result if weak_repro_attempted else None,
            "attempts": attempt_dicts,
        }
        cluster_summary = cluster_summaries.get(str(traced.get("family_loose_cluster_key") or "").strip(), {})
        candidate_result["family_priority"] = _build_patch_family_priority(candidate_result, cluster_summary)
        if outcome.get("confirmed"):
            pov_record = build_pov_record(traced)
            if binary_mode:
                pov_record = enrich_binary_pov(task_dir, traced, pov_record)
            pov_record["closure_mode"] = closure_mode
            pov_record["crash_source"] = traced.get("crash_source")
            pov_record["repro_attempts"] = attempt_dicts
            pov_record["source_loose_cluster_key"] = traced.get("family_loose_cluster_key")
            pov_record["confirmed_family_key"] = traced.get("family_confirmed_family_key")
            pov_record["family_exact_signature"] = traced.get("family_exact_signature") or traced.get("signature")
            pov_record["family_confirmation_reason"] = selected.get("selection_reason")
            pov_record["family_confirmation_level"] = outcome.get("confirmation_level")
            pov_record["family_promotion_rule"] = outcome.get("promotion_rule")
            pov_record["family_lineage"] = outcome.get("lineage") or {}
            pov_record["family_primary_function"] = (traced.get("family_features") or {}).get("primary_function")
            pov_record["family_primary_file"] = (traced.get("family_features") or {}).get("primary_file")
            pov_path = confirmed_dir / f"{Path(traced['testcase_path']).stem}.json"
            pov_path.write_text(json.dumps(pov_record, indent=2), encoding="utf-8")
            pov_paths.append(str(pov_path))
            confirmed_entries.append(
                {
                    **candidate_result,
                    "classification": (
                        "confirmed_existing_family_loose_cluster"
                        if outcome.get("confirmation_level") == "loose_cluster"
                        else (
                            "confirmed_existing_family"
                            if selected.get("already_confirmed_family")
                            else "confirmed_new_family"
                        )
                    ),
                    "closure_mode": closure_mode,
                    "pov_path": str(pov_path),
                    "source_traced_crash": str(traced_dir / f"{Path(traced['testcase_path']).stem}.json"),
                }
            )
            if traced.get("candidate_origin_kind") == "suspicious_candidate":
                pending_candidate_repro_updates.append(
                    {
                        "candidate_id": selected.get("candidate_id"),
                        "repro_gate_decision": "confirmed",
                        "repro_gate_reason": "generalized_candidate_confirmed_family",
                        "pov_path": str(pov_path),
                        "weak_repro_attempted": weak_repro_attempted,
                        "weak_repro_result": weak_repro_result if weak_repro_attempted else None,
                    }
                )
        else:
            blocked_entries.append(candidate_result)
            if traced.get("candidate_origin_kind") == "suspicious_candidate":
                pending_candidate_repro_updates.append(
                    {
                        "candidate_id": selected.get("candidate_id"),
                        "repro_gate_decision": "blocked",
                        "repro_gate_reason": outcome.get("blocker_reason") or "generalized_candidate_repro_blocked",
                        "pov_path": None,
                        "weak_repro_attempted": weak_repro_attempted,
                        "weak_repro_result": weak_repro_result if weak_repro_attempted else None,
                    }
                )

    unresolved_loose_clusters = [
        {
            "loose_cluster_key": entry.get("family_loose_cluster_key"),
            "confirmed_family_key": entry.get("family_confirmed_family_key"),
            "candidate_id": entry.get("candidate_id"),
            "harness_name": entry.get("harness_name"),
            "primary_function": entry.get("primary_function"),
            "primary_file": entry.get("primary_file"),
            "requires_reconfirmation": bool(entry.get("requires_reconfirmation")),
            "confirmation_level": entry.get("confirmation_level"),
            "promotion_rule": entry.get("promotion_rule"),
            "blocker_kind": entry.get("blocker_kind"),
            "blocker_reason": entry.get("blocker_reason"),
            "family_lineage": entry.get("family_lineage") or {},
        }
        for entry in blocked_entries
        if entry.get("family_loose_cluster_key")
    ]
    family_manifest_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "manifest_version": 1,
        "selection_mode": family_plan.get("selection_mode"),
        "campaign_confirmed_family_keys": family_plan.get("campaign_confirmed_family_keys") or [],
        "campaign_unresolved_loose_clusters": family_plan.get("campaign_unresolved_loose_clusters") or [],
        "cluster_summaries": family_plan.get("cluster_summaries") or [],
        "selected_candidates": [
            {
                "candidate_id": entry.get("candidate_id"),
                "selection_reason": entry.get("selection_reason"),
                "already_confirmed_family": bool(entry.get("already_confirmed_family")),
                "requires_reconfirmation": bool(entry.get("requires_reconfirmation")),
                "known_confirmed_signatures": entry.get("known_confirmed_signatures") or [],
                "selection_score": entry.get("selection_score"),
                "family_loose_cluster_key": (entry.get("traced_candidate") or {}).get("family_loose_cluster_key"),
                "family_confirmed_family_key": (entry.get("traced_candidate") or {}).get("family_confirmed_family_key"),
                "family_exact_signature": (entry.get("traced_candidate") or {}).get("family_exact_signature") or (entry.get("traced_candidate") or {}).get("signature"),
                "primary_function": ((entry.get("traced_candidate") or {}).get("family_features") or {}).get("primary_function"),
                "primary_file": ((entry.get("traced_candidate") or {}).get("family_features") or {}).get("primary_file"),
            }
            for entry in (family_plan.get("selected_candidates") or [])
        ],
        "skipped_candidates": family_plan.get("skipped_candidates") or [],
        "confirmed_families": confirmed_entries,
        "promotion_blockers": blocked_entries,
        "unresolved_loose_clusters": unresolved_loose_clusters,
        "promotion_lineage": [
            {
                "candidate_id": entry.get("candidate_id"),
                "classification": entry.get("classification"),
                "selection_reason": entry.get("selection_reason"),
                "confirmation_level": entry.get("confirmation_level"),
                "promotion_rule": entry.get("promotion_rule"),
                "family_lineage": entry.get("family_lineage") or {},
            }
            for entry in (confirmed_entries + blocked_entries)
        ],
    }
    family_manifest_path = write_repro_family_manifest(task_id, family_manifest_payload)
    selected_reference_candidates = confirmed_entries or blocked_entries
    selected_reference = (
        sorted(selected_reference_candidates, key=_patch_reference_sort_key)[0]
        if selected_reference_candidates
        else {}
    )
    selected_traced = dict(
        next(
            (
                entry.get("traced_candidate")
                for entry in (family_plan.get("selected_candidates") or [])
                if entry.get("candidate_id") == selected_reference.get("candidate_id")
            ),
            {},
        )
    )
    manifest_payload = {
        "task_id": task_id,
        "status": (
            TaskStatus.POV_CONFIRMED.value
            if confirmed_entries
            else TaskStatus.REPRO_FAILED.value
        ),
        "selected_harness": (
            selected_traced.get("harness_name")
            or selected_reference.get("harness_name")
            or active.get("name")
        ),
        "crash_source": selected_traced.get("crash_source") or selected_reference.get("crash_source"),
        "replay_attempts": len(all_attempts),
        "stable_replays": sum(int(entry.get("stable_replays") or 0) for entry in confirmed_entries),
        "closure_mode": selected_reference.get("closure_mode"),
        "target_mode": selected_traced.get("target_mode"),
        "binary_provenance": selected_traced.get("binary_provenance"),
        "binary_origin_task_id": selected_traced.get("binary_origin_task_id"),
        "binary_analysis_backend": selected_traced.get("binary_analysis_backend"),
        "launcher_semantics_source": selected_traced.get("launcher_semantics_source"),
        "seed_provenance": selected_traced.get("seed_provenance"),
        "corpus_provenance": selected_traced.get("corpus_provenance"),
        "binary_execution_command": selected_traced.get("binary_execution_command"),
        "input_mode": selected_traced.get("input_mode"),
        "testcase_path": selected_traced.get("testcase_path"),
        "source_traced_crash": selected_reference.get("source_traced_crash"),
        "source_traced_crashes": [entry.get("source_traced_crash") for entry in confirmed_entries if entry.get("source_traced_crash")],
        "pov_paths": pov_paths,
        "attempts": all_attempts,
        "candidate_results": confirmed_entries + blocked_entries,
        "patch_selected_candidate_id": selected_reference.get("candidate_id"),
        "patch_selected_family_priority": selected_reference.get("family_priority") or {},
        "confirmed_family_keys": sorted(
            {
                str(entry.get("family_confirmed_family_key") or "").strip()
                for entry in confirmed_entries
                if str(entry.get("family_confirmed_family_key") or "").strip()
            }
        ),
        "family_loose_cluster_count": len(family_plan.get("cluster_summaries") or []),
        "family_selected_candidate_count": len(family_plan.get("selected_candidates") or []),
        "family_confirmed_count": len(confirmed_entries),
        "family_blocked_count": len(blocked_entries),
        "family_selected_reconfirmation_count": int(family_plan.get("selected_reconfirmation_count") or 0),
        "family_confirmation_manifest_path": str(family_manifest_path),
        "weak_repro_attempted_count": weak_repro_attempted_count,
        "weak_repro_result_distribution": weak_repro_result_distribution,
        "fallback_trigger_reason": selected_traced.get("fallback_trigger_reason"),
        "fallback_from": selected_traced.get("fallback_from"),
        "fallback_to": selected_traced.get("fallback_to"),
        "fallback_effect": selected_traced.get("fallback_effect"),
    }
    manifest_path = write_repro_manifest(task_id, manifest_payload)
    for update in pending_candidate_repro_updates:
        record_suspicious_candidate_repro_status(
            task_dir,
            candidate_id=str(update.get("candidate_id")),
            repro_gate_decision=str(update.get("repro_gate_decision")),
            repro_gate_reason=str(update.get("repro_gate_reason")),
            repro_attempt_path=str(manifest_path),
            pov_path=update.get("pov_path"),
            weak_repro_attempted=(
                bool(update.get("weak_repro_attempted"))
                if update.get("weak_repro_attempted") is not None
                else None
            ),
            weak_repro_result=update.get("weak_repro_result"),
        )
    if not confirmed_entries:
        task_store.update_status(
            task_id,
            TaskStatus.REPRO_FAILED,
            runtime_patch={
                "repro_failed_at": task_store.now(),
                "repro_manifest_path": str(manifest_path),
                "repro_family_manifest_path": str(family_manifest_path),
                "repro_error": "no loose-cluster candidate reached confirmed family",
                "family_unresolved_loose_cluster_count": len(unresolved_loose_clusters),
                "family_confirmed_family_count": 0,
                "weak_repro_attempted_count": weak_repro_attempted_count,
                "weak_repro_result_distribution": weak_repro_result_distribution,
                "active_harness": active.get("name"),
            },
        )
        queue.ack(QueueNames.REPRO, task_id)
        logger.info("task %s produced no confirmed family candidates", task_id)
        return
    patch_priority_path = write_patch_priority_manifest(
        task_id,
        generated_at=task_store.now(),
        pov_paths=pov_paths,
        trace_manifest_path=task.runtime.get("trace_manifest_path"),
        repro_manifest_path=str(manifest_path),
        target_mode=selected_traced.get("target_mode") or task.runtime.get("target_mode"),
        adapter_resolution=task.runtime.get("adapter_resolution"),
    )
    task_store.update_status(
        task_id,
        TaskStatus.POV_CONFIRMED,
        runtime_patch={
            "repro_completed_at": task_store.now(),
            "repro_manifest_path": str(manifest_path),
            "repro_family_manifest_path": str(family_manifest_path),
            "pov_path": selected_reference.get("pov_path") or (pov_paths[0] if pov_paths else None),
            "patch_priority_manifest_path": str(patch_priority_path),
            "active_harness": selected_traced.get("harness_name"),
            "active_harness_path": selected_traced.get("binary_path"),
            "target_mode": selected_traced.get("target_mode"),
            "binary_provenance": selected_traced.get("binary_provenance"),
            "binary_origin_task_id": selected_traced.get("binary_origin_task_id"),
            "binary_analysis_backend": selected_traced.get("binary_analysis_backend"),
            "trace_mode": selected_traced.get("trace_mode"),
            "closure_mode": selected_reference.get("closure_mode"),
            "family_confirmed_family_keys": manifest_payload.get("confirmed_family_keys"),
            "family_confirmed_family_count": len(manifest_payload.get("confirmed_family_keys") or []),
            "family_unresolved_loose_cluster_count": len(unresolved_loose_clusters),
            "weak_repro_attempted_count": weak_repro_attempted_count,
            "weak_repro_result_distribution": weak_repro_result_distribution,
            "patch_selected_candidate_id": manifest_payload.get("patch_selected_candidate_id"),
            "patch_selected_family_priority": manifest_payload.get("patch_selected_family_priority"),
        },
    )
    patch_followup_task_id = maybe_enqueue_patch_followup(task_id, task_store, queue)
    if patch_followup_task_id:
        task_store.update_runtime(
            task_id,
            {
                "patch_followup_task_id": patch_followup_task_id,
                "patch_followup_status": TaskStatus.QUEUED_PATCH.value,
            },
        )
    queue.ack(QueueNames.REPRO, task_id)
    logger.info("task %s confirmed povs=%s families=%s", task_id, len(pov_paths), len(manifest_payload.get("confirmed_family_keys") or []))


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("reproducer worker started")
    while True:
        task_id = queue.pop(QueueNames.REPRO, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("reproducer failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.REPRO_FAILED,
                runtime_patch={"repro_error": str(exc), "repro_failed_at": task_store.now()},
            )
            queue.ack(QueueNames.REPRO, task_id)


if __name__ == "__main__":
    main()

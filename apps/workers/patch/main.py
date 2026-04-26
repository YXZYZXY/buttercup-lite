import json
import logging
import shutil
import time
from pathlib import Path

from core.models.task import TaskStatus
from core.patch_plane import (
    build_accepted_pov_record,
    write_context_retrieval,
    write_patch_apply,
    write_patch_build,
    write_patch_creation,
    write_patch_request,
    write_qe,
    write_reflection,
    write_root_cause,
)
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.storage.layout import (
    deterministic_patch_dependency_report_path,
    llm_patch_audit_manifest_path,
    llm_patch_candidate_ranking_manifest_path,
    patch_generalization_report_path,
    patch_priority_manifest_path,
    patch_reflection_retry_manifest_path,
)
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("patch-worker")
DEFAULT_PATCH_QUEUE_RETRY_LIMIT = 3

PATCH_RETRY_STRATEGIES = (
    {
        "name": "same_family_refinement_retry",
        "instruction": (
            "Refine the previous patch within the same semantic family. Preserve the intended invariant, "
            "but repair the concrete build/QE failure."
        ),
    },
    {
        "name": "alternative_family_retry",
        "instruction": (
            "Try an alternative invariant family if the previous patch still reproduces the PoV. Prefer a "
            "different root-cause guard over repeating the same surface edit."
        ),
    },
    {
        "name": "buildability_regression_preserving_rewrite",
        "instruction": (
            "Rewrite for a minimal buildable diff that preserves parser behavior for non-crashing inputs, "
            "then add only the smallest root-cause guard needed for the PoV."
        ),
    },
)


def _priority_action(task_id: str) -> str | None:
    path = patch_priority_manifest_path(task_id)
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload.get("priority_decision", {}).get("action")


def _llm_runtime_fields() -> dict[str, object]:
    return {
        "llm_enabled_config": settings.llm_enabled,
        "llm_base_url": settings.llm_base_url.rstrip("/"),
        "llm_model": settings.llm_model,
        "llm_request_attempted": False,
        "llm_http_status": None,
        "llm_response_received": False,
        "llm_real_call_verified": False,
        "llm_failure_reason": "patch plane currently uses deterministic local logic, not a real LLM call",
        "llm_provenance": "fallback_non_llm",
        "prompt_sha256": None,
        "response_sha256": None,
        "generated_by": "patch_worker.state_machine",
    }


def _patch_truth_runtime_fields(*, provenance: str, semantic_strength: str) -> dict[str, object]:
    return {
        "patch_generation_provenance": provenance,
        "patch_llm_request_attempted": False,
        "patch_llm_real_call_verified": False,
        "patch_semantic_strength": semantic_strength,
    }


def _patch_creation_runtime_fields(creation_payload: dict[str, object]) -> dict[str, object]:
    return {
        "llm_enabled_config": creation_payload.get("llm_enabled_config"),
        "llm_base_url": creation_payload.get("llm_base_url"),
        "llm_model": creation_payload.get("llm_model"),
        "llm_provider": creation_payload.get("llm_provider"),
        "llm_request_attempted": creation_payload.get("llm_request_attempted"),
        "llm_http_status": creation_payload.get("llm_http_status"),
        "llm_response_received": creation_payload.get("llm_response_received"),
        "llm_real_call_verified": creation_payload.get("llm_real_call_verified"),
        "llm_failure_reason": creation_payload.get("llm_failure_reason"),
        "llm_provenance": creation_payload.get("llm_provenance"),
        "prompt_sha256": creation_payload.get("prompt_sha256"),
        "response_sha256": creation_payload.get("response_sha256"),
        "generated_by": creation_payload.get("generated_by"),
        "patch_generation_provenance": creation_payload.get("patch_generation_provenance"),
        "patch_llm_request_attempted": creation_payload.get("patch_llm_request_attempted"),
        "patch_llm_real_call_verified": creation_payload.get("patch_llm_real_call_verified"),
        "patch_semantic_strength": creation_payload.get("patch_semantic_strength"),
        "patch_ground_truth_mode": creation_payload.get("patch_ground_truth_mode"),
        "attempted_repair_family": creation_payload.get("attempted_repair_family"),
        "attempted_context_source": creation_payload.get("attempted_context_source"),
        "observed_crash_type": creation_payload.get("observed_crash_type"),
        "repair_family_priority": creation_payload.get("repair_family_priority"),
        "patch_synthesis_type": creation_payload.get("patch_synthesis_type"),
        "patch_synthesis_reason": creation_payload.get("patch_synthesis_reason"),
        "prompt_template_id": creation_payload.get("prompt_template_id"),
        "known_fix_path_reached": creation_payload.get("known_fix_path_reached"),
        "deterministic_template_applied": creation_payload.get("deterministic_template_applied"),
        "llm_selection_confidence": creation_payload.get("llm_selection_confidence"),
        "llm_selection_fallback_triggered": creation_payload.get("llm_selection_fallback_triggered"),
        "llm_vs_rule_agreement": creation_payload.get("llm_vs_rule_agreement"),
        "verifier_gates_passed": creation_payload.get("verifier_gates_passed"),
    }


def _snapshot_patch_attempt(task_store: TaskStateStore, task_id: str, attempt_index: int) -> dict[str, str]:
    patch_dir = Path(task_store.load_task(task_id).task_dir) / "patch"
    snapshots: dict[str, str] = {}
    for name in (
        "patch_creation_manifest.json",
        "patch_apply_manifest.json",
        "patch_build_manifest.json",
        "qe_manifest.json",
        "reflection_manifest.json",
        "patch_freeform_materialization_manifest.json",
        "patch_llm_vs_template_comparison.json",
        "candidate.diff",
        "llm_freeform_candidate.diff",
    ):
        src = patch_dir / name
        if not src.exists():
            continue
        dst = patch_dir / f"attempt{attempt_index}_{name}"
        shutil.copy2(src, dst)
        snapshots[name] = str(dst)
    return snapshots


def _sync_patch_creation_observability(
    creation_path: Path,
    creation_payload: dict[str, object],
    qe_payload: dict[str, object],
) -> dict[str, object]:
    synced_payload = dict(creation_payload)
    synced_payload["verifier_gates_passed"] = list(qe_payload.get("verifier_gates_passed") or [])
    creation_path.write_text(json.dumps(synced_payload, indent=2), encoding="utf-8")
    return synced_payload


def _log_patch_observability(
    task_id: str,
    creation_payload: dict[str, object],
    qe_payload: dict[str, object],
) -> None:
    logger.info(
        "[%s] patch LLM selection: fallback=%s, agreement=%s, confidence=%s",
        task_id,
        creation_payload.get("llm_selection_fallback_triggered"),
        creation_payload.get("llm_vs_rule_agreement"),
        creation_payload.get("llm_selection_confidence"),
    )
    logger.info(
        "[%s] patch verifier: gates_passed=%s",
        task_id,
        qe_payload.get("verifier_gates_passed", []),
    )


def _retry_context(
    *,
    creation_payload: dict[str, object],
    build_payload: dict[str, object],
    qe_payload: dict[str, object],
    qe_verdict: str,
    retry_strategy: dict[str, str],
    previous_attempt: dict[str, object] | None,
    reflection_payload: dict[str, object],
) -> dict[str, object]:
    return {
        "retry_strategy": retry_strategy.get("name"),
        "previous_materialization_mode": creation_payload.get("patch_materialization_mode"),
        "previous_selected_candidate": creation_payload.get("selected_candidate"),
        "previous_llm_payload": creation_payload.get("llm_patch_payload"),
        "previous_freeform_materialization": creation_payload.get("freeform_materialization"),
        "previous_build_status": build_payload.get("status"),
        "previous_build_error": build_payload.get("error"),
        "previous_qe_verdict": qe_verdict,
        "previous_qe_reason": qe_payload.get("reason"),
        "previous_attempted_repair_family": (previous_attempt or {}).get("attempted_repair_family"),
        "previous_attempted_context_source": (previous_attempt or {}).get("attempted_context_source"),
        "previous_prompt_template_id": (previous_attempt or {}).get("prompt_template_id"),
        "previous_failure_reason": (previous_attempt or {}).get("failure_reason"),
        "previous_failure_detail": (previous_attempt or {}).get("failure_detail"),
        "next_repair_family": reflection_payload.get("next_repair_family"),
        "next_context_source": reflection_payload.get("next_context_source"),
        "next_prompt_template_id": reflection_payload.get("next_prompt_template_id"),
        "switch_reason": reflection_payload.get("switch_reason"),
        "repair_instruction": (
            "Generate a corrected freeform unified diff. If the previous patch compiled incorrectly, fix the concrete syntax/build error first, "
            "then keep the root-cause semantic guard. Avoid partial uncommenting, stale commented braces, duplicate blocks, or truncated hunks. "
            + retry_strategy.get("instruction", "")
        ),
    }


def _attempt_record(
    *,
    attempt_index: int,
    strategy: str,
    snapshots: dict[str, str],
    creation_path: Path,
    apply_path: Path,
    build_path: Path,
    qe_path: Path,
    reflection_path: Path,
    creation_payload: dict[str, object],
    apply_payload: dict[str, object],
    build_payload: dict[str, object],
    qe_payload: dict[str, object],
    qe_verdict: str,
    action: str,
    reflection_payload: dict[str, object],
    retry_context: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "attempt_index": attempt_index,
        "strategy": strategy,
        "snapshots": snapshots,
        "retry_context": retry_context,
        "creation_manifest_path": str(creation_path),
        "apply_manifest_path": str(apply_path),
        "build_manifest_path": str(build_path),
        "qe_manifest_path": str(qe_path),
        "reflection_manifest_path": str(reflection_path),
        "qe_verdict": qe_verdict,
        "action": action,
        "materialization_mode": creation_payload.get("patch_materialization_mode"),
        "llm_real_call_verified": creation_payload.get("patch_llm_real_call_verified"),
        "result_classification": qe_payload.get(
            "patch_result_classification",
            build_payload.get("patch_result_classification", apply_payload.get("patch_result_classification")),
        ),
        "attempted_repair_family": creation_payload.get("attempted_repair_family"),
        "attempted_context_source": creation_payload.get("attempted_context_source"),
        "prompt_template_id": creation_payload.get("prompt_template_id"),
        "failure_reason": reflection_payload.get("failure_reason"),
        "failure_detail": reflection_payload.get("failure_detail"),
        "applied_switch_reason": (retry_context or {}).get("switch_reason"),
        "switch_reason": reflection_payload.get("switch_reason"),
        "next_repair_family": reflection_payload.get("next_repair_family"),
        "next_context_source": reflection_payload.get("next_context_source"),
        "next_prompt_template_id": reflection_payload.get("next_prompt_template_id"),
        "observed_crash_type": creation_payload.get("observed_crash_type"),
    }


def _write_reflection_diff_artifact(
    *,
    task_store: TaskStateStore,
    task_id: str,
    attempts: list[dict[str, object]],
) -> Path:
    task_dir = Path(task_store.load_task(task_id).task_dir)
    patch_dir = task_dir / "patch"
    transitions: list[dict[str, object]] = []
    for previous, current in zip(attempts, attempts[1:]):
        transitions.append(
            {
                "from_attempt": previous.get("attempt_index"),
                "to_attempt": current.get("attempt_index"),
                "from_family": previous.get("attempted_repair_family"),
                "to_family": current.get("attempted_repair_family"),
                "from_context_source": previous.get("attempted_context_source"),
                "to_context_source": current.get("attempted_context_source"),
                "from_template_id": previous.get("prompt_template_id"),
                "to_template_id": current.get("prompt_template_id"),
                "switch_reason": current.get("applied_switch_reason") or current.get("switch_reason"),
            }
        )
    payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "transition_count": len(transitions),
        "transitions": transitions,
    }
    path = patch_dir / "reflection_diff_artifact.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _load_optional_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_patch_search_reports(
    *,
    task_id: str,
    task_store: TaskStateStore,
    attempts: list[dict[str, object]],
    creation_payload: dict[str, object],
    qe_payload: dict[str, object],
    reflection_payload: dict[str, object],
) -> dict[str, str]:
    task_dir = Path(task_store.load_task(task_id).task_dir)
    patch_dir = task_dir / "patch"
    invariant_report = _load_optional_json(patch_dir / "vulnerable_invariant_report.json")
    alignment_report = _load_optional_json(patch_dir / "vulnerable_invariant_alignment_report.json")
    selected_candidate = creation_payload.get("selected_candidate") or {}
    alignment_rows = alignment_report.get("candidate_alignment") or []
    selected_candidate_alignment = next(
        (
            item
            for item in alignment_rows
            if item.get("candidate_id") == selected_candidate.get("candidate_id")
        ),
        {},
    )
    llm_reflection_retry_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "reflection_engine": "real_llm" if reflection_payload.get("llm_real_call_verified") else "deterministic_fallback",
        "reflection_action": reflection_payload.get("reflection_action"),
        "primary_blocker": reflection_payload.get("primary_blocker"),
        "invariant_family": reflection_payload.get("invariant_family"),
        "next_strategy": reflection_payload.get("next_strategy"),
        "attempt_count": len(attempts),
        "attempt_history": attempts,
        "llm_reflection_payload": reflection_payload.get("llm_reflection_payload"),
        "llm_failure_reason": reflection_payload.get("llm_failure_reason"),
        "llm_reflection_error": reflection_payload.get("llm_reflection_error"),
    }
    scorecard_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "primary_invariant": invariant_report.get("primary_invariant"),
        "selected_candidate_id": selected_candidate.get("candidate_id"),
        "selected_candidate_strategy_family": selected_candidate.get("strategy_family"),
        "selected_candidate_alignment_score": selected_candidate_alignment.get("alignment_score"),
        "selected_candidate_aligned_invariants": selected_candidate_alignment.get("aligned_invariants"),
        "reflection_invariant_family": reflection_payload.get("invariant_family"),
        "reflection_root_cause_alignment_score": reflection_payload.get("root_cause_alignment_score"),
        "qe_verdict": qe_payload.get("verdict"),
        "qe_reason": qe_payload.get("reason"),
    }
    family_matrix_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "selected_candidate": selected_candidate,
        "attempts": [
            {
                "attempt_index": item.get("attempt_index"),
                "strategy": item.get("strategy"),
                "attempted_repair_family": item.get("attempted_repair_family"),
                "attempted_context_source": item.get("attempted_context_source"),
                "prompt_template_id": item.get("prompt_template_id"),
                "qe_verdict": item.get("qe_verdict"),
                "failure_reason": item.get("failure_reason"),
                "action": item.get("action"),
                "materialization_mode": item.get("materialization_mode"),
                "result_classification": item.get("result_classification"),
            }
            for item in attempts
        ],
        "final_reflection_action": reflection_payload.get("reflection_action"),
        "recommended_next_strategy": reflection_payload.get("next_strategy"),
    }
    qe_feedback_payload = {
        "task_id": task_id,
        "generated_at": task_store.now(),
        "qe_verdict": qe_payload.get("verdict"),
        "qe_reason": qe_payload.get("reason"),
        "verifier_gates_passed": qe_payload.get("verifier_gates_passed"),
        "mapped_primary_blocker": reflection_payload.get("primary_blocker"),
        "mapped_invariant_family": reflection_payload.get("invariant_family"),
        "selected_candidate_alignment": selected_candidate_alignment,
        "attempt_history_count": len(attempts),
    }
    paths = {
        "llm_reflection_retry_report_path": str(patch_dir / "llm_reflection_retry_report.json"),
        "root_cause_alignment_scorecard_path": str(patch_dir / "root_cause_alignment_scorecard.json"),
        "patch_family_decision_matrix_path": str(patch_dir / "patch_family_decision_matrix.json"),
        "qe_failure_to_invariant_feedback_report_path": str(patch_dir / "qe_failure_to_invariant_feedback_report.json"),
    }
    Path(paths["llm_reflection_retry_report_path"]).write_text(
        json.dumps(llm_reflection_retry_payload, indent=2),
        encoding="utf-8",
    )
    Path(paths["root_cause_alignment_scorecard_path"]).write_text(
        json.dumps(scorecard_payload, indent=2),
        encoding="utf-8",
    )
    Path(paths["patch_family_decision_matrix_path"]).write_text(
        json.dumps(family_matrix_payload, indent=2),
        encoding="utf-8",
    )
    Path(paths["qe_failure_to_invariant_feedback_report_path"]).write_text(
        json.dumps(qe_feedback_payload, indent=2),
        encoding="utf-8",
    )
    return paths


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("patch state machine received task %s", task_id)
    task = task_store.load_task(task_id)
    patch_retry_count = int(task.runtime.get("patch_retry_count") or 0)
    max_patch_queue_retries = int(task.metadata.get("PATCH_MAX_QUEUE_RETRIES", DEFAULT_PATCH_QUEUE_RETRY_LIMIT))
    now = task_store.now()
    request_path = write_patch_request(task_id, now=now, metadata=task.metadata, runtime=task.runtime)
    task_store.update_status(
        task_id,
        TaskStatus.PATCH_ROOT_CAUSE,
        runtime_patch={
            "patch_request_manifest_path": str(request_path),
            **_llm_runtime_fields(),
            **_patch_truth_runtime_fields(provenance="deterministic_rule", semantic_strength="placeholder"),
        },
    )

    root_cause_path = write_root_cause(
        task_id,
        now=task_store.now(),
        metadata=task.metadata,
        runtime=task_store.load_task(task_id).runtime,
    )
    task_store.update_status(
        task_id,
        TaskStatus.PATCH_CONTEXT_RETRIEVAL,
        runtime_patch={
            "patch_root_cause_manifest_path": str(root_cause_path),
            "patch_root_cause_alignment_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_root_cause_alignment_manifest.json"),
        },
    )

    context_path = write_context_retrieval(
        task_id,
        now=task_store.now(),
        metadata=task.metadata,
        runtime=task_store.load_task(task_id).runtime,
    )
    task_store.update_status(task_id, TaskStatus.PATCH_QE, runtime_patch={"patch_context_manifest_path": str(context_path)})

    creation_path, creation_payload = write_patch_creation(
        task_id,
        now=task_store.now(),
        metadata=task.metadata,
        runtime=task_store.load_task(task_id).runtime,
    )
    apply_path, apply_payload = write_patch_apply(
        task_id,
        now=task_store.now(),
        creation_payload=creation_payload,
    )
    build_path, build_payload = write_patch_build(
        task_id,
        now=task_store.now(),
        metadata=task.metadata,
        runtime=task_store.load_task(task_id).runtime,
        creation_payload=creation_payload,
    )

    priority_action = _priority_action(task_id)
    qe_path, qe_verdict = write_qe(
        task_id,
        now=task_store.now(),
        metadata=task.metadata,
        runtime=task_store.load_task(task_id).runtime,
        build_payload=build_payload,
    )
    qe_payload = json.loads(Path(qe_path).read_text(encoding="utf-8"))
    creation_payload = _sync_patch_creation_observability(Path(creation_path), creation_payload, qe_payload)
    _log_patch_observability(task_id, creation_payload, qe_payload)
    task_store.update_status(
        task_id,
        TaskStatus.PATCH_REFLECTION,
        runtime_patch={
            "patch_creation_manifest_path": str(creation_path),
            "patch_candidate_ranking_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_candidate_ranking_manifest.json"),
            "llm_patch_candidate_ranking_manifest_path": str(llm_patch_candidate_ranking_manifest_path(task_id)),
            "llm_patch_audit_manifest_path": str(llm_patch_audit_manifest_path(task_id)),
            "generalized_patch_strategy_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "generalized_patch_strategy_manifest.json"),
            "semantic_patch_synthesis_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "semantic_patch_synthesis_manifest.json"),
            "patch_strategy_family_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_strategy_family_manifest.json"),
            "ground_truth_dependency_report_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "ground_truth_dependency_report.json"),
            "patch_generalization_report_path": str(patch_generalization_report_path(task_id)),
            "deterministic_patch_dependency_report_path": str(deterministic_patch_dependency_report_path(task_id)),
            "patch_apply_manifest_path": str(apply_path),
            "patch_build_manifest_path": str(build_path),
            "patch_qe_manifest_path": str(qe_path),
            "patch_semantic_validation_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_semantic_validation_manifest.json"),
            "patch_failure_analysis_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_failure_analysis.json"),
            "patch_qe_verdict": qe_verdict,
            "patch_priority_action": priority_action,
            "patch_result_classification": qe_payload.get(
                "patch_result_classification",
                build_payload.get("patch_result_classification", apply_payload.get("patch_result_classification")),
            ),
            **_patch_creation_runtime_fields(creation_payload),
        },
    )

    reflection_path, action = write_reflection(
        task_id,
        now=task_store.now(),
        qe_verdict=qe_verdict,
        priority_action=priority_action,
        metadata=task.metadata,
        runtime=task_store.load_task(task_id).runtime,
        creation_payload=creation_payload,
        build_payload=build_payload,
        qe_payload=qe_payload,
        attempt_history=[],
    )
    reflection_payload = json.loads(Path(reflection_path).read_text(encoding="utf-8"))
    retry_manifest_payload: dict[str, object] | None = None
    multi_strategy_manifest_payload: dict[str, object] | None = None
    reflection_diff_artifact_path: Path | None = None
    retry_enabled = bool(task.metadata.get("PATCH_ENABLE_REFLECTION_RETRY", True))
    max_repair_attempts = int(task.metadata.get("PATCH_MAX_REPAIR_ATTEMPTS", len(PATCH_RETRY_STRATEGIES) + 1))
    retryable_qe_verdicts = {"build_failed", "pov_failed", "regression_failed"}
    retry_worthwhile = (
        retry_enabled
        and action in {"retry", "suppress"}
        and qe_verdict in retryable_qe_verdicts
        and bool(creation_payload.get("patch_llm_real_call_verified"))
        and max_repair_attempts > 1
    )
    if retry_worthwhile:
        attempts: list[dict[str, object]] = [
            _attempt_record(
                attempt_index=1,
                strategy="initial_freeform",
                snapshots=_snapshot_patch_attempt(task_store, task_id, 1),
                creation_path=Path(creation_path),
                apply_path=Path(apply_path),
                build_path=Path(build_path),
                qe_path=Path(qe_path),
                reflection_path=Path(reflection_path),
                creation_payload=creation_payload,
                apply_payload=apply_payload,
                build_payload=build_payload,
                qe_payload=qe_payload,
                qe_verdict=qe_verdict,
                action=action,
                reflection_payload=reflection_payload,
            )
        ]
        attempt_index = 1
        while (
            attempt_index < max_repair_attempts
            and action in {"retry", "suppress"}
            and qe_verdict in retryable_qe_verdicts
            and bool(creation_payload.get("patch_llm_real_call_verified"))
            and attempt_index <= len(PATCH_RETRY_STRATEGIES)
        ):
            strategy = PATCH_RETRY_STRATEGIES[attempt_index - 1]
            previous_attempt = attempts[-1]
            retry_metadata = {
                **task.metadata,
                "PATCH_RETRY_ATTEMPT_INDEX": attempt_index + 1,
                "PATCH_RETRY_STRATEGY_FAMILY": reflection_payload.get("next_strategy") or strategy["name"],
                "PATCH_RETRY_TARGET_FAMILY": reflection_payload.get("next_repair_family"),
                "PATCH_RETRY_CONTEXT_SOURCE": reflection_payload.get("next_context_source"),
                "PATCH_RETRY_TEMPLATE_ID": reflection_payload.get("next_prompt_template_id"),
                "PATCH_RETRY_FAILURE_REASON": reflection_payload.get("failure_reason"),
                "patch_retry_context": _retry_context(
                    creation_payload=creation_payload,
                    build_payload=build_payload,
                    qe_payload=qe_payload,
                    qe_verdict=qe_verdict,
                    retry_strategy=strategy,
                    previous_attempt=previous_attempt,
                    reflection_payload=reflection_payload,
                ),
            }
            retry_creation_path, retry_creation_payload = write_patch_creation(
                task_id,
                now=task_store.now(),
                metadata=retry_metadata,
                runtime=task_store.load_task(task_id).runtime,
            )
            retry_apply_path, retry_apply_payload = write_patch_apply(
                task_id,
                now=task_store.now(),
                creation_payload=retry_creation_payload,
            )
            retry_build_path, retry_build_payload = write_patch_build(
                task_id,
                now=task_store.now(),
                metadata=retry_metadata,
                runtime=task_store.load_task(task_id).runtime,
                creation_payload=retry_creation_payload,
            )
            retry_qe_path, retry_qe_verdict = write_qe(
                task_id,
                now=task_store.now(),
                metadata=retry_metadata,
                runtime=task_store.load_task(task_id).runtime,
                build_payload=retry_build_payload,
            )
            retry_qe_payload = json.loads(Path(retry_qe_path).read_text(encoding="utf-8"))
            retry_creation_payload = _sync_patch_creation_observability(
                Path(retry_creation_path),
                retry_creation_payload,
                retry_qe_payload,
            )
            _log_patch_observability(task_id, retry_creation_payload, retry_qe_payload)
            retry_reflection_path, retry_action = write_reflection(
                task_id,
                now=task_store.now(),
                qe_verdict=retry_qe_verdict,
                priority_action=priority_action,
                metadata=retry_metadata,
                runtime=task_store.load_task(task_id).runtime,
                creation_payload=retry_creation_payload,
                build_payload=retry_build_payload,
                qe_payload=retry_qe_payload,
                attempt_history=attempts,
            )
            retry_reflection_payload = json.loads(Path(retry_reflection_path).read_text(encoding="utf-8"))
            attempt_index += 1
            attempts.append(
                _attempt_record(
                    attempt_index=attempt_index,
                    strategy=strategy["name"],
                    snapshots=_snapshot_patch_attempt(task_store, task_id, attempt_index),
                    creation_path=Path(retry_creation_path),
                    apply_path=Path(retry_apply_path),
                    build_path=Path(retry_build_path),
                    qe_path=Path(retry_qe_path),
                    reflection_path=Path(retry_reflection_path),
                    creation_payload=retry_creation_payload,
                    apply_payload=retry_apply_payload,
                    build_payload=retry_build_payload,
                    qe_payload=retry_qe_payload,
                    qe_verdict=retry_qe_verdict,
                    action=retry_action,
                    reflection_payload=retry_reflection_payload,
                    retry_context=retry_metadata["patch_retry_context"],
                )
            )
            reflection_diff_artifact_path = _write_reflection_diff_artifact(
                task_store=task_store,
                task_id=task_id,
                attempts=attempts,
            )
            creation_path, creation_payload = retry_creation_path, retry_creation_payload
            apply_path, apply_payload = retry_apply_path, retry_apply_payload
            build_path, build_payload = retry_build_path, retry_build_payload
            qe_path, qe_verdict, qe_payload = retry_qe_path, retry_qe_verdict, retry_qe_payload
            reflection_path, action = retry_reflection_path, retry_action
            reflection_payload = retry_reflection_payload

        retry_manifest_payload = {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "retry_attempted": True,
            "retry_reason": "LLM patch entered build/QE reflection path",
            "max_repair_attempts": max_repair_attempts,
            "attempt_count": len(attempts),
            "strategies_attempted": [item.get("strategy") for item in attempts],
            "attempts": attempts,
            "reflection_diff_artifact_path": str(reflection_diff_artifact_path) if reflection_diff_artifact_path else None,
            "final_qe_verdict": qe_verdict,
            "final_action": action,
        }
        multi_strategy_manifest_payload = {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "search_mode": "llm_freeform_multi_strategy_repair",
            "strategy_families": [strategy["name"] for strategy in PATCH_RETRY_STRATEGIES],
            "attempt_count": len(attempts),
            "attempts": attempts,
            "selected_final_strategy": attempts[-1].get("strategy") if attempts else None,
            "final_qe_verdict": qe_verdict,
            "final_action": action,
            "deterministic_template_role": "not_used_in_blind_mainline",
        }
        retry_manifest_path = patch_reflection_retry_manifest_path(task_id)
        retry_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        retry_manifest_path.write_text(json.dumps(retry_manifest_payload, indent=2), encoding="utf-8")
        multi_strategy_path = Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_multi_strategy_search_manifest.json"
        multi_strategy_path.write_text(json.dumps(multi_strategy_manifest_payload, indent=2), encoding="utf-8")

    reflection_payload = json.loads(Path(reflection_path).read_text(encoding="utf-8"))
    patch_search_report_paths = _write_patch_search_reports(
        task_id=task_id,
        task_store=task_store,
        attempts=retry_manifest_payload.get("attempts", []) if retry_manifest_payload else [
            {
                "attempt_index": 1,
                "strategy": "initial_freeform",
                "qe_verdict": qe_verdict,
                "action": action,
                "materialization_mode": creation_payload.get("patch_materialization_mode"),
                "attempted_repair_family": creation_payload.get("attempted_repair_family"),
                "attempted_context_source": creation_payload.get("attempted_context_source"),
                "prompt_template_id": creation_payload.get("prompt_template_id"),
                "failure_reason": reflection_payload.get("failure_reason"),
                "failure_detail": reflection_payload.get("failure_detail"),
                "result_classification": qe_payload.get(
                    "patch_result_classification",
                    build_payload.get("patch_result_classification", apply_payload.get("patch_result_classification")),
                ),
            }
        ],
        creation_payload=creation_payload,
        qe_payload=qe_payload,
        reflection_payload=reflection_payload,
    )

    accepted_pov_path = build_accepted_pov_record(task_id, qe_payload)
    final_status = {
        "accept": TaskStatus.PATCH_ACCEPTED,
        "retry": TaskStatus.PATCH_RETRY_REQUESTED,
        "suppress": TaskStatus.PATCH_SUPPRESSED,
        "escalate": TaskStatus.PATCH_ESCALATED,
    }[action]
    next_patch_retry_count = patch_retry_count
    patch_retry_limit_reached = False
    patch_error = None
    if action == "retry":
        if patch_retry_count >= max_patch_queue_retries:
            final_status = TaskStatus.PATCH_FAILED
            patch_retry_limit_reached = True
            patch_error = (
                f"patch retry limit reached ({patch_retry_count}/{max_patch_queue_retries}); "
                "not requeuing patch task"
            )
        else:
            next_patch_retry_count = patch_retry_count + 1
    task_store.update_status(
        task_id,
        final_status,
        runtime_patch={
            "patch_reflection_manifest_path": str(reflection_path),
            "patch_reflection_retry_manifest_path": str(patch_reflection_retry_manifest_path(task_id))
            if retry_manifest_payload
            else None,
            "patch_reflection_retry_attempted": bool(retry_manifest_payload),
            "patch_reflection_diff_artifact_path": str(reflection_diff_artifact_path) if reflection_diff_artifact_path else None,
            "patch_multi_strategy_search_manifest_path": str(
                Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_multi_strategy_search_manifest.json"
            )
            if multi_strategy_manifest_payload
            else None,
            "patch_multi_strategy_search_attempted": bool(multi_strategy_manifest_payload),
            "patch_reflection_action": action,
            "llm_reflection_retry_report_path": patch_search_report_paths["llm_reflection_retry_report_path"],
            "root_cause_alignment_scorecard_path": patch_search_report_paths["root_cause_alignment_scorecard_path"],
            "patch_family_decision_matrix_path": patch_search_report_paths["patch_family_decision_matrix_path"],
            "qe_failure_to_invariant_feedback_report_path": patch_search_report_paths["qe_failure_to_invariant_feedback_report_path"],
            "patch_creation_manifest_path": str(creation_path),
            "patch_candidate_ranking_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_candidate_ranking_manifest.json"),
            "llm_patch_candidate_ranking_manifest_path": str(llm_patch_candidate_ranking_manifest_path(task_id)),
            "llm_patch_audit_manifest_path": str(llm_patch_audit_manifest_path(task_id)),
            "generalized_patch_strategy_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "generalized_patch_strategy_manifest.json"),
            "semantic_patch_synthesis_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "semantic_patch_synthesis_manifest.json"),
            "patch_strategy_family_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_strategy_family_manifest.json"),
            "ground_truth_dependency_report_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "ground_truth_dependency_report.json"),
            "patch_generalization_report_path": str(patch_generalization_report_path(task_id)),
            "deterministic_patch_dependency_report_path": str(deterministic_patch_dependency_report_path(task_id)),
            "patch_apply_manifest_path": str(apply_path),
            "patch_build_manifest_path": str(build_path),
            "patch_build_status": build_payload.get("status"),
            "patch_semantic_validation_manifest_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_semantic_validation_manifest.json"),
            "patch_failure_analysis_path": str(Path(task_store.load_task(task_id).task_dir) / "patch" / "patch_failure_analysis.json"),
            "patch_qe_supported_verdicts": qe_payload.get("supported_verdicts"),
            "patch_result_classification": qe_payload.get(
                "patch_result_classification",
                build_payload.get("patch_result_classification", apply_payload.get("patch_result_classification")),
            ),
            "patch_accepted_pov_path": str(accepted_pov_path) if accepted_pov_path else None,
            "patch_state_machine_completed_at": task_store.now(),
            "patch_retry_count": next_patch_retry_count,
            "patch_max_queue_retries": max_patch_queue_retries,
            "patch_retry_limit_reached": patch_retry_limit_reached,
            "patch_retry_queue_name": QueueNames.PATCH if action == "retry" and not patch_retry_limit_reached else None,
            "patch_retry_requested_at": task_store.now() if action == "retry" and not patch_retry_limit_reached else None,
            "patch_error": patch_error,
            "patch_failed_at": task_store.now() if final_status == TaskStatus.PATCH_FAILED else None,
            **_patch_creation_runtime_fields(creation_payload),
        },
    )
    if action == "retry":
        if patch_retry_limit_reached:
            logger.warning("[%s] patch retry reached limit %s; marking task as PATCH_FAILED", task_id, max_patch_queue_retries)
        else:
            queue.push(QueueNames.PATCH, task_id)
            logger.info(
                "[%s] patch retry triggered, requeued %s, current retry count=%s",
                task_id,
                QueueNames.PATCH,
                next_patch_retry_count,
            )
    queue.ack(QueueNames.PATCH, task_id)
    logger.info("task %s patch state machine complete action=%s", task_id, action)


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("patch worker started")
    while True:
        task_id = queue.pop(QueueNames.PATCH, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("patch worker failed for task %s: %s", task_id, exc)
            task_store.update_status(task_id, TaskStatus.PATCH_FAILED, runtime_patch={"patch_error": str(exc), "patch_failed_at": task_store.now()})
            queue.ack(QueueNames.PATCH, task_id)


if __name__ == "__main__":
    main()

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path


MAX_SUSPICIOUS_CANDIDATES = 8
GENERALIZED_CANDIDATE_QUEUE_VERSION = 3
DEFAULT_TRACE_CLAIM_LIMIT = 5

GENERALIZED_TRACE_ADMISSION_RESULT_CLAIM_REJECTED = "candidate_claimed_rejected"
GENERALIZED_TRACE_ADMISSION_RESULT_ADMITTED = "candidate_admitted_to_trace"
GENERALIZED_TRACE_ADMISSION_RESULT_NO_SIGNAL = "trace_no_actionable_signal"
GENERALIZED_TRACE_ADMISSION_RESULT_ACTIONABLE = "trace_produced_actionable_signal"
GENERALIZED_TRACE_ADMISSION_RESULTS = (
    GENERALIZED_TRACE_ADMISSION_RESULT_CLAIM_REJECTED,
    GENERALIZED_TRACE_ADMISSION_RESULT_ADMITTED,
    GENERALIZED_TRACE_ADMISSION_RESULT_NO_SIGNAL,
    GENERALIZED_TRACE_ADMISSION_RESULT_ACTIONABLE,
)

CANDIDATE_REASON_PRIORITY = {
    "stderr_crash_like_signal_present": 1000,
    "asan_output_detected": 900,
    "ubsan_output_detected": 880,
    "timeout_with_suspicious_stderr": 760,
    "partial_coverage_spike": 620,
    "low_growth": 500,
    "corpus_growth_without_raw_crash": 100,
    "stderr_unique_signal_present": 90,
    "campaign_candidate_bridge_targets_present": 80,
    "coverage_queue_kind:candidate_bridge": 70,
    "uncovered_functions_present": 60,
    "cross_harness_corpus_staging_present": 50,
    "family_stagnation_count_ge_2": 40,
}

REASON_TOKEN_ALIASES = {
    "low_growth_functions_present": "low_growth",
    "partial_coverage_mode": "partial_coverage_spike",
    "partial_degraded_targets_present": "partial_coverage_spike",
}


def suspicious_candidate_queue_path(task_dir: Path) -> Path:
    return task_dir / "runtime" / "suspicious_candidate_queue.json"


def suspicious_candidate_trace_results_dir(task_dir: Path) -> Path:
    return task_dir / "trace" / "candidate_results"


def suspicious_candidate_trace_result_path(task_dir: Path, candidate_id: str) -> Path:
    return suspicious_candidate_trace_results_dir(task_dir) / f"{candidate_id}.json"


def _empty_trace_admission_distribution() -> dict[str, int]:
    return {name: 0 for name in GENERALIZED_TRACE_ADMISSION_RESULTS}


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f"{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        json.dump(payload, handle, indent=2)
        handle.flush()
        temp_path = Path(handle.name)
    temp_path.replace(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_target_names(values: list[dict] | list[str] | None) -> list[str]:
    names: list[str] = []
    for value in values or []:
        if isinstance(value, dict):
            candidate = value.get("name") or value.get("target_function") or value.get("selected_target_function")
        else:
            candidate = str(value)
        text = str(candidate or "").strip()
        if not text or text in names:
            continue
        names.append(text)
    return names[:6]


def _normalize_reason_token(value: str | None) -> str:
    token = str(value or "").strip()
    return REASON_TOKEN_ALIASES.get(token, token)


def _dedupe_reason_tokens(values: list[str] | None) -> list[str]:
    reasons: list[str] = []
    for value in values or []:
        token = _normalize_reason_token(value)
        if not token or token in reasons:
            continue
        reasons.append(token)
    return reasons


def _sorted_reason_tokens(values: list[str] | None) -> list[str]:
    reasons = _dedupe_reason_tokens(values)
    reasons.sort(key=lambda reason: (-int(CANDIDATE_REASON_PRIORITY.get(reason) or 0), reason))
    return reasons


def _primary_candidate_reason(values: list[str] | None) -> str | None:
    reasons = _sorted_reason_tokens(values)
    return reasons[0] if reasons else None


def _candidate_priority_value(candidate_reason: str | None) -> int:
    return int(CANDIDATE_REASON_PRIORITY.get(str(candidate_reason or "").strip()) or 0)


def _candidate_sort_key(item: dict) -> tuple[int, float, int, str, str]:
    candidate_reason = str(
        item.get("candidate_reason")
        or _primary_candidate_reason(item.get("candidate_reasons") or [])
        or ""
    )
    candidate_priority = int(item.get("candidate_priority") or _candidate_priority_value(candidate_reason))
    candidate_confidence = float(item.get("candidate_confidence") or 0.0)
    source_kind = 1 if str(item.get("candidate_source_kind") or "") == "new_corpus" else 0
    created_at = str(item.get("created_at") or "")
    candidate_id = str(item.get("candidate_id") or "")
    return (candidate_priority, candidate_confidence, source_kind, created_at, candidate_id)


def _normalized_admission_events(values: list[str] | None) -> list[str]:
    events: list[str] = []
    for value in values or []:
        token = str(value or "").strip()
        if token not in GENERALIZED_TRACE_ADMISSION_RESULTS or token in events:
            continue
        events.append(token)
    return events


def _infer_admission_events(item: dict) -> list[str]:
    events = _normalized_admission_events(item.get("admission_events"))
    if events:
        return events
    classification = str(item.get("trace_result_classification") or "").strip()
    trace_artifact_path = str(item.get("trace_artifact_path") or "").strip()
    repro_eligibility = str(item.get("repro_admission_eligibility") or "").strip()
    trace_state = str(item.get("trace_state") or item.get("admission_state") or "").strip()
    if classification == "no_replay_targets_available":
        return [GENERALIZED_TRACE_ADMISSION_RESULT_CLAIM_REJECTED]
    if trace_artifact_path or repro_eligibility == "eligible":
        return [
            GENERALIZED_TRACE_ADMISSION_RESULT_ADMITTED,
            GENERALIZED_TRACE_ADMISSION_RESULT_ACTIONABLE,
        ]
    if trace_state in {"trace_completed", "trace_rejected"} or classification:
        return [
            GENERALIZED_TRACE_ADMISSION_RESULT_ADMITTED,
            GENERALIZED_TRACE_ADMISSION_RESULT_NO_SIGNAL,
        ]
    if str(item.get("trace_claimed_at") or "").strip():
        return [GENERALIZED_TRACE_ADMISSION_RESULT_ADMITTED]
    return []


def _infer_final_admission_result(item: dict) -> str | None:
    admission_result = str(item.get("admission_result") or "").strip()
    if admission_result in GENERALIZED_TRACE_ADMISSION_RESULTS:
        return admission_result
    events = _infer_admission_events(item)
    return events[-1] if events else None


def summarize_suspicious_candidate_admission(task_dir: Path) -> dict:
    queue_payload = load_suspicious_candidate_queue(task_dir)
    result_payloads = [
        item
        for item in load_candidate_trace_results(task_dir)
        if str(item.get("candidate_origin_kind") or "") == "suspicious_candidate"
    ]
    distribution = _empty_trace_admission_distribution()
    final_distribution = _empty_trace_admission_distribution()
    trace_admission_attempt_count = 0
    actionable_count = 0
    no_signal_count = 0
    claimed_rejected_count = 0
    weak_repro_attempted_count = 0
    weak_repro_result_distribution: dict[str, int] = {}
    for item in result_payloads:
        events = _infer_admission_events(item)
        final_result = _infer_final_admission_result(item)
        for event in events:
            distribution[event] = distribution.get(event, 0) + 1
        if GENERALIZED_TRACE_ADMISSION_RESULT_ADMITTED in events:
            trace_admission_attempt_count += 1
        if final_result:
            final_distribution[final_result] = final_distribution.get(final_result, 0) + 1
        if final_result == GENERALIZED_TRACE_ADMISSION_RESULT_ACTIONABLE:
            actionable_count += 1
        elif final_result == GENERALIZED_TRACE_ADMISSION_RESULT_NO_SIGNAL:
            no_signal_count += 1
        elif final_result == GENERALIZED_TRACE_ADMISSION_RESULT_CLAIM_REJECTED:
            claimed_rejected_count += 1
        if bool(item.get("weak_repro_attempted")):
            weak_repro_attempted_count += 1
            weak_repro_result = str(item.get("weak_repro_result") or "attempted_without_result").strip()
            weak_repro_result_distribution[weak_repro_result] = (
                weak_repro_result_distribution.get(weak_repro_result, 0) + 1
            )
    admission_rate = round(actionable_count / max(trace_admission_attempt_count, 1), 6)
    return {
        "candidate_queue_claim_count": int(queue_payload.get("candidate_claim_count") or 0),
        "trace_admission_attempt_count": trace_admission_attempt_count,
        "trace_admission_result_distribution": distribution,
        "trace_admission_final_result_distribution": final_distribution,
        "trace_admission_actionable_count": actionable_count,
        "trace_admission_no_signal_count": no_signal_count,
        "trace_admission_claimed_rejected_count": claimed_rejected_count,
        "trace_admission_result_count": len(result_payloads),
        "weak_repro_attempted_count": weak_repro_attempted_count,
        "weak_repro_result_distribution": weak_repro_result_distribution,
        "admission_rate": admission_rate,
    }


def _signal_lines(signal_summary: dict, key: str) -> list[str]:
    return [str(line).strip().lower() for line in signal_summary.get(key) or [] if str(line).strip()]


def _collect_reason_tokens(
    *,
    runtime: dict,
    signal_summary: dict,
    new_corpus_files: list[str],
) -> list[str]:
    reasons: list[str] = []
    crash_like_lines = _signal_lines(signal_summary, "crash_like_signal_lines")
    unique_signal_lines = _signal_lines(signal_summary, "unique_signal_lines")
    family_stagnation_count = int(runtime.get("campaign_family_stagnation_count") or 0)
    high_quality_reason_present = False

    if int(signal_summary.get("crash_like_signal_count") or 0) > 0:
        reasons.append("stderr_crash_like_signal_present")
        high_quality_reason_present = True
    if any("addresssanitizer" in line for line in crash_like_lines):
        reasons.append("asan_output_detected")
        high_quality_reason_present = True
    if any("undefinedbehaviorsanitizer" in line for line in crash_like_lines):
        reasons.append("ubsan_output_detected")
        high_quality_reason_present = True
    if any("timeout" in line for line in crash_like_lines) and unique_signal_lines:
        reasons.append("timeout_with_suspicious_stderr")
        high_quality_reason_present = True
    if str(runtime.get("campaign_exact_or_partial") or "") == "partial" and (
        runtime.get("campaign_partial_degraded_targets")
        or runtime.get("campaign_uncovered_functions")
        or runtime.get("campaign_low_growth_functions")
    ):
        reasons.append("partial_coverage_spike")
        high_quality_reason_present = True
    if runtime.get("campaign_low_growth_functions") and family_stagnation_count >= 3:
        reasons.append("low_growth")
        high_quality_reason_present = True

    if runtime.get("campaign_candidate_bridge_targets"):
        reasons.append("campaign_candidate_bridge_targets_present")
    queue_kind = str(runtime.get("campaign_coverage_queue_kind") or "").strip()
    if queue_kind:
        reasons.append(f"coverage_queue_kind:{queue_kind}")
    if family_stagnation_count >= 2:
        reasons.append("family_stagnation_count_ge_2")
    if runtime.get("campaign_uncovered_functions"):
        reasons.append("uncovered_functions_present")
    if int(runtime.get("campaign_stage_cross_harness_selected_count") or 0) > 0:
        reasons.append("cross_harness_corpus_staging_present")
    if int(signal_summary.get("unique_signal_count") or 0) > 0:
        reasons.append("stderr_unique_signal_present")
    if new_corpus_files and not high_quality_reason_present:
        reasons.append("corpus_growth_without_raw_crash")
    return _sorted_reason_tokens(reasons)


def _candidate_confidence_and_priority(
    *,
    reasons: list[str],
    new_corpus_files: list[str],
    signal_summary: dict,
    candidate_targets: list[str],
) -> tuple[float, int]:
    primary_reason = _primary_candidate_reason(reasons)
    base_confidence = {
        "stderr_crash_like_signal_present": 0.95,
        "asan_output_detected": 0.88,
        "ubsan_output_detected": 0.86,
        "timeout_with_suspicious_stderr": 0.8,
        "partial_coverage_spike": 0.68,
        "low_growth": 0.56,
        "corpus_growth_without_raw_crash": 0.28,
    }.get(primary_reason, 0.35)
    score = base_confidence
    if "stderr_unique_signal_present" in reasons and primary_reason != "corpus_growth_without_raw_crash":
        score += 0.03
    if candidate_targets:
        score += min(len(candidate_targets), 3) * 0.03
    if int(signal_summary.get("crash_like_signal_count") or 0) > 0 and primary_reason != "stderr_crash_like_signal_present":
        score += 0.02
    if new_corpus_files and primary_reason != "corpus_growth_without_raw_crash":
        score += min(len(new_corpus_files), 2) * 0.01
    confidence = round(min(score, 0.99), 2)
    priority = _candidate_priority_value(primary_reason) + int(round(confidence * 10))
    return confidence, priority


def _recent_corpus_candidates(
    corpus_dir: Path,
    *,
    limit: int,
    excluded_paths: set[str],
) -> list[Path]:
    if not corpus_dir.exists():
        return []
    candidates = [path for path in corpus_dir.iterdir() if path.is_file() and str(path) not in excluded_paths]
    candidates.sort(key=lambda path: (-path.stat().st_mtime_ns, path.name))
    return candidates[:limit]


def build_suspicious_candidate_queue(
    *,
    task_id: str,
    task_dir: Path,
    now_iso: str,
    selected_harness: str,
    selected_target_function: str | None,
    selected_target_functions: list[dict] | list[str] | None,
    new_corpus_files: list[str],
    runtime: dict,
    signal_summary: dict,
    task_metadata: dict | None = None,
) -> dict | None:
    task_metadata = task_metadata or {}
    reasons = _collect_reason_tokens(
        runtime=runtime,
        signal_summary=signal_summary,
        new_corpus_files=new_corpus_files,
    )
    if not reasons:
        return None

    candidate_targets = _normalize_target_names(runtime.get("campaign_candidate_bridge_targets"))
    if not candidate_targets:
        candidate_targets = _normalize_target_names(selected_target_functions)
    if not candidate_targets and selected_target_function:
        candidate_targets = [str(selected_target_function)]

    confidence, priority = _candidate_confidence_and_priority(
        reasons=reasons,
        new_corpus_files=new_corpus_files,
        signal_summary=signal_summary,
        candidate_targets=candidate_targets,
    )
    candidate_reason = _primary_candidate_reason(reasons)
    source_campaign_task_id = (
        str(task_metadata.get("campaign_parent_task_id") or runtime.get("campaign_parent_task_id") or "").strip()
        or None
    )
    campaign_round = task_metadata.get("campaign_round") or runtime.get("campaign_round")
    campaign_session_index = runtime.get("campaign_session_index")
    project = str(task_metadata.get("project") or "").strip() or None
    benchmark = str(task_metadata.get("benchmark") or "").strip() or None
    target_mode = str(task_metadata.get("target_mode") or runtime.get("target_mode") or "source").strip() or None

    selected_pairs: list[tuple[Path, str]] = []
    excluded_paths: set[str] = set()
    for raw_path in new_corpus_files:
        candidate = Path(raw_path)
        if not candidate.exists() or not candidate.is_file():
            continue
        selected_pairs.append((candidate, "new_corpus"))
        excluded_paths.add(str(candidate))
        if len(selected_pairs) >= MAX_SUSPICIOUS_CANDIDATES:
            break

    if len(selected_pairs) < MAX_SUSPICIOUS_CANDIDATES:
        for candidate in _recent_corpus_candidates(
            task_dir / "corpus" / "active",
            limit=MAX_SUSPICIOUS_CANDIDATES - len(selected_pairs),
            excluded_paths=excluded_paths,
        ):
            selected_pairs.append((candidate, "corpus_active_recent"))

    items: list[dict] = []
    seen_digests: set[str] = set()
    for candidate_path, source_kind in selected_pairs:
        digest = _sha256_file(candidate_path)
        if digest in seen_digests:
            continue
        seen_digests.add(digest)
        item = {
            "candidate_id": f"suspicious-{digest[:12]}",
            "candidate_origin_kind": "suspicious_candidate",
            "candidate_kind": "suspicious_no_crash",
            "candidate_reason": candidate_reason,
            "candidate_reasons": reasons,
            "candidate_confidence": confidence,
            "candidate_priority": priority,
            "testcase_path": str(candidate_path),
            "testcase_name": candidate_path.name,
            "candidate_source_kind": source_kind,
            "selected_harness": selected_harness,
            "selected_target_function": selected_target_function,
            "candidate_targets": candidate_targets,
            "trace_worthy": True,
            "replayable": candidate_path.exists(),
            "trace_admission_eligibility": "eligible" if candidate_path.exists() else "blocked",
            "trace_admission_block_reason": None if candidate_path.exists() else "testcase_missing",
            "repro_admission_eligibility": "defer_until_trace_result",
            "repro_admission_reason": "await_trace_result",
            "admission_state": "pending_trace",
            "sha256": digest,
            "size_bytes": candidate_path.stat().st_size,
            "created_at": now_iso,
            "source_task_id": task_id,
            "originating_task_id": task_id,
            "originating_round_task_id": task_id,
            "source_campaign_task_id": source_campaign_task_id,
            "campaign_round": int(campaign_round) if str(campaign_round or "").isdigit() else campaign_round,
            "campaign_session_index": int(campaign_session_index) if str(campaign_session_index or "").isdigit() else campaign_session_index,
            "project": project,
            "benchmark": benchmark,
            "target_mode": target_mode,
            "trace_claim_token": None,
            "trace_claimed_at": None,
            "trace_claimed_by": None,
            "trace_result_path": None,
            "trace_artifact_path": None,
            "trace_rejection_reason": None,
            "trace_result_classification": None,
            "admission_events": [],
            "admission_result": None,
            "trace_completed_at": None,
            "weak_signal_detected": False,
            "weak_signal_type": None,
            "repro_gate_decision": None,
            "repro_gate_reason": None,
            "repro_attempt_path": None,
            "weak_repro_attempted": False,
            "weak_repro_result": None,
            "pov_path": None,
        }
        items.append(item)

    items.sort(key=_candidate_sort_key, reverse=True)

    payload = {
        "queue_version": GENERALIZED_CANDIDATE_QUEUE_VERSION,
        "task_id": task_id,
        "generated_at": now_iso,
        "candidate_origin_kind": "suspicious_candidate",
        "selected_harness": selected_harness,
        "selected_target_function": selected_target_function,
        "candidate_targets": candidate_targets,
        "reason_tokens": reasons,
        "reason_summary": reasons[:4],
        "project": project,
        "benchmark": benchmark,
        "target_mode": target_mode,
        "source_campaign_task_id": source_campaign_task_id,
        "campaign_round": int(campaign_round) if str(campaign_round or "").isdigit() else campaign_round,
        "campaign_session_index": int(campaign_session_index) if str(campaign_session_index or "").isdigit() else campaign_session_index,
        "new_corpus_file_count": len(new_corpus_files),
        "stderr_crash_like_signal_count": int(signal_summary.get("crash_like_signal_count") or 0),
        "stderr_unique_signal_count": int(signal_summary.get("unique_signal_count") or 0),
        "candidate_count": len(items),
        "replayable_candidate_count": sum(1 for item in items if item.get("replayable")),
        "trace_worthy_candidate_count": sum(1 for item in items if item.get("trace_worthy")),
        "trace_eligible_candidate_count": sum(
            1 for item in items if item.get("trace_admission_eligibility") == "eligible"
        ),
        "candidate_claim_count": 0,
        "candidate_trace_result_count": 0,
        "candidate_trace_artifact_count": 0,
        "candidate_rejected_count": 0,
        "candidate_repro_eligible_count": 0,
        "candidate_results_dir": str(suspicious_candidate_trace_results_dir(task_dir)),
        "queue_blocked_reason": None if items else "no_replayable_corpus_inputs_available",
        "items": items,
    }
    return payload


def write_suspicious_candidate_queue(task_dir: Path, payload: dict | None) -> str | None:
    if payload is None:
        return None
    path = suspicious_candidate_queue_path(task_dir)
    _write_json(path, payload)
    return str(path)


def load_suspicious_candidate_queue(task_dir: Path) -> dict:
    payload = _load_json(suspicious_candidate_queue_path(task_dir))
    return _upgrade_legacy_candidate_queue(task_dir, payload)


def replayable_suspicious_candidates(
    task_dir: Path,
    *,
    require_trace_worthy: bool = True,
) -> list[dict]:
    payload = load_suspicious_candidate_queue(task_dir)
    replayable: list[dict] = []
    for item in payload.get("items") or []:
        path = Path(str(item.get("testcase_path") or ""))
        if not path.exists() or not path.is_file():
            continue
        if not item.get("replayable", True):
            continue
        if item.get("trace_admission_eligibility") not in {None, "eligible"}:
            continue
        if str(item.get("admission_state") or "pending_trace") not in {"pending_trace", "requeued_for_trace"}:
            continue
        if require_trace_worthy and not item.get("trace_worthy", False):
            continue
        replayable.append(dict(item))
    replayable.sort(key=_candidate_sort_key, reverse=True)
    return replayable


def claim_suspicious_candidates_for_trace(
    task_dir: Path,
    *,
    owner_task_id: str,
    claimed_by: str,
    now_iso: str,
    max_items: int | None = None,
) -> list[dict]:
    payload = load_suspicious_candidate_queue(task_dir)
    items = payload.get("items") or []
    claimed: list[dict] = []
    effective_max_items = DEFAULT_TRACE_CLAIM_LIMIT if max_items is None else max_items
    eligible_items: list[dict] = []
    for item in items:
        if item.get("trace_admission_eligibility") != "eligible":
            continue
        if str(item.get("admission_state") or "pending_trace") not in {"pending_trace", "requeued_for_trace"}:
            continue
        testcase_path = Path(str(item.get("testcase_path") or ""))
        if not testcase_path.exists() or not testcase_path.is_file():
            item["trace_admission_eligibility"] = "blocked"
            item["trace_admission_block_reason"] = "testcase_missing"
            item["admission_state"] = "blocked"
            continue
        eligible_items.append(item)

    eligible_items.sort(key=_candidate_sort_key, reverse=True)
    highest_priority = (
        int(eligible_items[0].get("candidate_priority") or 0)
        if eligible_items
        else None
    )
    for item in eligible_items:
        if effective_max_items is not None and len(claimed) >= effective_max_items:
            break
        if highest_priority is not None and int(item.get("candidate_priority") or 0) < highest_priority:
            continue
        claim_token = f"trace-{owner_task_id}-{item.get('candidate_id')}"
        item["trace_claim_token"] = claim_token
        item["trace_claimed_at"] = now_iso
        item["trace_claimed_by"] = claimed_by
        item["admission_state"] = "claimed_for_trace"
        item["trace_owner_task_id"] = owner_task_id
        claimed.append(dict(item))
    if items:
        _refresh_candidate_queue_counters(payload)
        _write_json(suspicious_candidate_queue_path(task_dir), payload)
    return claimed


def record_suspicious_candidate_trace_result(
    task_dir: Path,
    *,
    candidate_id: str,
    result_payload: dict,
) -> str:
    path = suspicious_candidate_trace_result_path(task_dir, candidate_id)
    _write_json(path, result_payload)
    return str(path)


def load_candidate_trace_results(task_dir: Path) -> list[dict]:
    results_dir = suspicious_candidate_trace_results_dir(task_dir)
    if not results_dir.exists():
        return []
    results: list[dict] = []
    for path in sorted(results_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        payload.setdefault("trace_result_path", str(path))
        payload.setdefault("admission_events", _infer_admission_events(payload))
        payload.setdefault("admission_result", _infer_final_admission_result(payload))
        payload.setdefault("weak_signal_detected", bool(payload.get("weak_signal_type")))
        payload.setdefault("weak_signal_type", payload.get("signal_type"))
        payload.setdefault("weak_repro_attempted", False)
        payload.setdefault("weak_repro_result", None)
        results.append(payload)
    return results


def requeue_claimed_suspicious_candidates_for_trace(
    task_dir: Path,
    *,
    candidate_ids: list[str],
    now_iso: str,
    reason: str,
) -> None:
    if not candidate_ids:
        return
    payload = load_suspicious_candidate_queue(task_dir)
    selected = {str(candidate_id).strip() for candidate_id in candidate_ids if str(candidate_id).strip()}
    if not selected:
        return
    for item in payload.get("items") or []:
        if str(item.get("candidate_id") or "").strip() not in selected:
            continue
        if str(item.get("admission_state") or "").strip() != "claimed_for_trace":
            continue
        item["admission_state"] = "requeued_for_trace"
        item["trace_rejection_reason"] = reason
        item["trace_requeued_at"] = now_iso
    _refresh_candidate_queue_counters(payload)
    _write_json(suspicious_candidate_queue_path(task_dir), payload)


def finalize_suspicious_candidate_trace(
    task_dir: Path,
    *,
    candidate_id: str,
    trace_state: str,
    now_iso: str,
    trace_result_path: str,
    trace_result_classification: str,
    trace_artifact_path: str | None,
    trace_rejection_reason: str | None,
    repro_admission_eligibility: str,
    repro_admission_reason: str,
    admission_events: list[str] | None = None,
    admission_result: str | None = None,
    weak_signal_detected: bool | None = None,
    weak_signal_type: str | None = None,
) -> None:
    payload = load_suspicious_candidate_queue(task_dir)
    for item in payload.get("items") or []:
        if item.get("candidate_id") != candidate_id:
            continue
        item["admission_state"] = trace_state
        item["trace_result_path"] = trace_result_path
        item["trace_artifact_path"] = trace_artifact_path
        item["trace_rejection_reason"] = trace_rejection_reason
        item["trace_result_classification"] = trace_result_classification
        item["admission_events"] = _normalized_admission_events(admission_events) or _infer_admission_events(
            {
                "trace_result_classification": trace_result_classification,
                "trace_artifact_path": trace_artifact_path,
                "repro_admission_eligibility": repro_admission_eligibility,
                "trace_state": trace_state,
            }
        )
        normalized_result = str(admission_result or "").strip()
        item["admission_result"] = (
            normalized_result
            if normalized_result in GENERALIZED_TRACE_ADMISSION_RESULTS
            else _infer_final_admission_result(item)
        )
        item["trace_completed_at"] = now_iso
        item["weak_signal_detected"] = (
            bool(weak_signal_detected)
            if weak_signal_detected is not None
            else bool(weak_signal_type)
        )
        item["weak_signal_type"] = weak_signal_type
        item["repro_admission_eligibility"] = repro_admission_eligibility
        item["repro_admission_reason"] = repro_admission_reason
        break
    _refresh_candidate_queue_counters(payload)
    _write_json(suspicious_candidate_queue_path(task_dir), payload)


def record_suspicious_candidate_repro_status(
    task_dir: Path,
    *,
    candidate_id: str,
    repro_gate_decision: str,
    repro_gate_reason: str,
    repro_attempt_path: str | None = None,
    pov_path: str | None = None,
    weak_repro_attempted: bool | None = None,
    weak_repro_result: str | None = None,
) -> None:
    result_path = suspicious_candidate_trace_result_path(task_dir, candidate_id)
    if result_path.exists():
        payload = _load_json(result_path)
        payload["repro_gate_decision"] = repro_gate_decision
        payload["repro_gate_reason"] = repro_gate_reason
        payload["repro_attempt_path"] = repro_attempt_path
        payload["pov_path"] = pov_path
        if weak_repro_attempted is not None:
            payload["weak_repro_attempted"] = bool(weak_repro_attempted)
        if weak_repro_result is not None:
            payload["weak_repro_result"] = weak_repro_result
        _write_json(result_path, payload)

    queue_payload = load_suspicious_candidate_queue(task_dir)
    for item in queue_payload.get("items") or []:
        if item.get("candidate_id") != candidate_id:
            continue
        item["repro_gate_decision"] = repro_gate_decision
        item["repro_gate_reason"] = repro_gate_reason
        item["repro_attempt_path"] = repro_attempt_path
        item["pov_path"] = pov_path
        if weak_repro_attempted is not None:
            item["weak_repro_attempted"] = bool(weak_repro_attempted)
        if weak_repro_result is not None:
            item["weak_repro_result"] = weak_repro_result
        break
    if queue_payload:
        _refresh_candidate_queue_counters(queue_payload)
        _write_json(suspicious_candidate_queue_path(task_dir), queue_payload)


def _refresh_candidate_queue_counters(payload: dict) -> None:
    items = payload.get("items") or []
    payload["candidate_count"] = len(items)
    payload["replayable_candidate_count"] = sum(1 for item in items if item.get("replayable"))
    payload["trace_worthy_candidate_count"] = sum(1 for item in items if item.get("trace_worthy"))
    payload["trace_eligible_candidate_count"] = sum(
        1
        for item in items
        if item.get("trace_admission_eligibility") == "eligible"
        and str(item.get("admission_state") or "pending_trace") in {"pending_trace", "requeued_for_trace"}
    )
    payload["candidate_claim_count"] = sum(1 for item in items if item.get("trace_claimed_at"))
    payload["candidate_trace_result_count"] = sum(1 for item in items if item.get("trace_result_path"))
    payload["candidate_trace_artifact_count"] = sum(1 for item in items if item.get("trace_artifact_path"))
    payload["candidate_rejected_count"] = sum(1 for item in items if item.get("admission_state") == "trace_rejected")
    payload["candidate_repro_eligible_count"] = sum(
        1 for item in items if item.get("repro_admission_eligibility") == "eligible"
    )
    admission_summary = {
        "distribution": _empty_trace_admission_distribution(),
        "final_distribution": _empty_trace_admission_distribution(),
    }
    for item in items:
        for event in _infer_admission_events(item):
            admission_summary["distribution"][event] = admission_summary["distribution"].get(event, 0) + 1
        final_result = _infer_final_admission_result(item)
        if final_result:
            admission_summary["final_distribution"][final_result] = (
                admission_summary["final_distribution"].get(final_result, 0) + 1
            )
    payload["trace_admission_result_distribution"] = admission_summary["distribution"]
    payload["trace_admission_final_result_distribution"] = admission_summary["final_distribution"]


def _upgrade_legacy_candidate_queue(task_dir: Path, payload: dict) -> dict:
    if not payload:
        return payload
    payload["queue_version"] = max(
        int(payload.get("queue_version") or 0),
        GENERALIZED_CANDIDATE_QUEUE_VERSION,
    )
    payload.setdefault("candidate_results_dir", str(suspicious_candidate_trace_results_dir(task_dir)))
    payload.setdefault("candidate_claim_count", 0)
    payload.setdefault("candidate_trace_result_count", 0)
    payload.setdefault("candidate_trace_artifact_count", 0)
    payload.setdefault("candidate_rejected_count", 0)
    payload.setdefault("candidate_repro_eligible_count", 0)
    selected_harness = payload.get("selected_harness")
    selected_target_function = payload.get("selected_target_function")
    candidate_targets = payload.get("candidate_targets") or []
    project = payload.get("project")
    benchmark = payload.get("benchmark")
    target_mode = payload.get("target_mode")
    source_campaign_task_id = payload.get("source_campaign_task_id")
    campaign_round = payload.get("campaign_round")
    campaign_session_index = payload.get("campaign_session_index")
    for item in payload.get("items") or []:
        testcase_path = Path(str(item.get("testcase_path") or ""))
        replayable = bool(item.get("replayable", testcase_path.exists() and testcase_path.is_file()))
        item["replayable"] = replayable
        normalized_reasons = _sorted_reason_tokens(
            list(item.get("candidate_reasons") or ([item.get("candidate_reason")] if item.get("candidate_reason") else []))
        )
        confidence, priority = _candidate_confidence_and_priority(
            reasons=normalized_reasons,
            new_corpus_files=[],
            signal_summary={},
            candidate_targets=list(item.get("candidate_targets") or candidate_targets),
        )
        item["candidate_reasons"] = normalized_reasons
        item["candidate_reason"] = _primary_candidate_reason(normalized_reasons)
        item["candidate_confidence"] = float(item.get("candidate_confidence") or confidence)
        item["candidate_priority"] = int(item.get("candidate_priority") or priority)
        item.setdefault("selected_harness", selected_harness)
        item.setdefault("selected_target_function", selected_target_function)
        item.setdefault("candidate_targets", candidate_targets)
        item.setdefault("originating_task_id", item.get("source_task_id"))
        item.setdefault("originating_round_task_id", item.get("source_task_id"))
        item.setdefault("source_campaign_task_id", source_campaign_task_id)
        item.setdefault("campaign_round", campaign_round)
        item.setdefault("campaign_session_index", campaign_session_index)
        item.setdefault("project", project)
        item.setdefault("benchmark", benchmark)
        item.setdefault("target_mode", target_mode)
        item.setdefault(
            "trace_admission_eligibility",
            "eligible" if replayable and item.get("trace_worthy", False) else "blocked",
        )
        item.setdefault(
            "trace_admission_block_reason",
            None
            if item.get("trace_admission_eligibility") == "eligible"
            else "candidate_not_trace_eligible",
        )
        item.setdefault("repro_admission_eligibility", "defer_until_trace_result")
        item.setdefault("repro_admission_reason", "await_trace_result")
        item.setdefault("admission_state", "pending_trace")
        item.setdefault("trace_claim_token", None)
        item.setdefault("trace_claimed_at", None)
        item.setdefault("trace_claimed_by", None)
        item.setdefault("trace_result_path", None)
        item.setdefault("trace_artifact_path", None)
        item.setdefault("trace_rejection_reason", None)
        item.setdefault("trace_result_classification", None)
        item.setdefault("admission_events", _infer_admission_events(item))
        item.setdefault("admission_result", _infer_final_admission_result(item))
        item.setdefault("trace_completed_at", None)
        item.setdefault("weak_signal_detected", bool(item.get("weak_signal_type")))
        item.setdefault("weak_signal_type", item.get("signal_type"))
        item.setdefault("repro_gate_decision", None)
        item.setdefault("repro_gate_reason", None)
        item.setdefault("repro_attempt_path", None)
        item.setdefault("weak_repro_attempted", False)
        item.setdefault("weak_repro_result", None)
        item.setdefault("pov_path", None)
    payload["items"] = sorted(payload.get("items") or [], key=_candidate_sort_key, reverse=True)
    _refresh_candidate_queue_counters(payload)
    return payload

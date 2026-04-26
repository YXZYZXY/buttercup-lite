from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.analysis.loose_cluster import (
    assign_loose_cluster_key,
    compare_loose_cluster_features,
    derive_loose_cluster_features,
    derive_replay_loose_cluster_features,
)
from core.storage.layout import repro_family_manifest_path, trace_family_manifest_path

DEFAULT_RECONFIRMATION_ROUND_GAP = 5


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _candidate_id(payload: dict[str, Any], *, fallback_path: Path | None = None) -> str:
    testcase_path = str(payload.get("testcase_path") or "").strip()
    if testcase_path:
        return Path(testcase_path).stem
    if fallback_path is not None:
        return fallback_path.stem
    return str(payload.get("signature") or "candidate")


def _candidate_has_source_frame(payload: dict[str, Any]) -> bool:
    features = payload.get("family_features") or {}
    if features.get("primary_function") and features.get("primary_file"):
        return True
    return str(payload.get("symbolization_status") or "") == "success"


def _selection_score(payload: dict[str, Any], *, active_harness_name: str | None) -> float:
    score = 0.0
    if str(payload.get("harness_name") or "") == str(active_harness_name or ""):
        score += 4.0
    if str(payload.get("crash_source") or "") == "live_raw":
        score += 3.0
    if _candidate_has_source_frame(payload):
        score += 2.5
    if str(payload.get("symbolization_status") or "") == "success":
        score += 1.5
    if str(payload.get("crash_state") or "").strip().lower() == str(payload.get("crash_type") or "").strip().lower():
        score -= 0.75
    if str(payload.get("crash_state") or "").strip().lower() == "attempting":
        score -= 1.25
    return score


def _sorted_strings(values: set[str] | list[str] | tuple[str, ...]) -> list[str]:
    return sorted(str(item).strip() for item in values if str(item).strip())


def _reconfirmation_round_threshold(campaign_state: dict[str, Any]) -> int:
    family_inventory = dict(campaign_state.get("family_inventory") or {})
    threshold = int(
        family_inventory.get("reconfirmation_threshold_rounds")
        or campaign_state.get("family_reconfirmation_round_threshold")
        or DEFAULT_RECONFIRMATION_ROUND_GAP
        or 1
    )
    return max(1, threshold)


def _family_lineage(
    *,
    exact_signature: str | None,
    loose_cluster_key: str | None,
    confirmed_family_key: str | None,
    promotion_state: str,
    already_confirmed_family: bool = False,
    requires_reconfirmation: bool = False,
    selection_reason: str | None = None,
    confirmation_level: str | None = None,
    promotion_rule: str | None = None,
    blocker_kind: str | None = None,
    blocker_reason: str | None = None,
    observed_signatures: list[str] | None = None,
    observed_cluster_match_reasons: list[str] | None = None,
    reconfirmation_trigger: str | None = None,
    reconfirmation_round_gap: int | None = None,
    reconfirmation_threshold_rounds: int | None = None,
) -> dict[str, Any]:
    generated_at = _now_iso()
    return {
        "from_trace_exact_signature": str(exact_signature or "").strip() or None,
        "from_loose_cluster_key": str(loose_cluster_key or "").strip() or None,
        "to_confirmed_family_key": str(confirmed_family_key or "").strip() or None,
        "generated_at": generated_at,
        "promotion_state": promotion_state,
        "already_confirmed_family": bool(already_confirmed_family),
        "requires_reconfirmation": bool(requires_reconfirmation),
        "selection_reason": str(selection_reason or "").strip() or None,
        "confirmation_level": str(confirmation_level or "").strip() or None,
        "promotion_rule": str(promotion_rule or "").strip() or None,
        "blocker_kind": str(blocker_kind or "").strip() or None,
        "blocker_reason": str(blocker_reason or "").strip() or None,
        "observed_signatures": list(observed_signatures or []),
        "observed_cluster_match_reasons": list(observed_cluster_match_reasons or []),
        "reconfirmation_trigger": str(reconfirmation_trigger or "").strip() or None,
        "reconfirmation_round_gap": int(reconfirmation_round_gap or 0),
        "reconfirmation_threshold_rounds": (
            int(reconfirmation_threshold_rounds)
            if reconfirmation_threshold_rounds is not None
            else None
        ),
        "transitions": {
            "trace_exact": {
                "exact_signature": str(exact_signature or "").strip() or None,
                "recorded_at": generated_at,
            },
            "loose_cluster": {
                "loose_cluster_key": str(loose_cluster_key or "").strip() or None,
                "recorded_at": generated_at,
                "cluster_match_reasons": list(observed_cluster_match_reasons or []),
            },
            "confirmed_family": {
                "confirmed_family_key": str(confirmed_family_key or "").strip() or None,
                "recorded_at": generated_at,
                "promotion_state": promotion_state,
                "confirmation_level": str(confirmation_level or "").strip() or None,
                "promotion_rule": str(promotion_rule or "").strip() or None,
                "blocker_kind": str(blocker_kind or "").strip() or None,
                "blocker_reason": str(blocker_reason or "").strip() or None,
                "requires_reconfirmation": bool(requires_reconfirmation),
                "reconfirmation_trigger": str(reconfirmation_trigger or "").strip() or None,
                "reconfirmation_round_gap": int(reconfirmation_round_gap or 0),
                "reconfirmation_threshold_rounds": (
                    int(reconfirmation_threshold_rounds)
                    if reconfirmation_threshold_rounds is not None
                    else None
                ),
            },
        },
    }


def _confirmed_signature_index(family_inventory: dict[str, Any]) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    details = dict(family_inventory.get("confirmed_family_details") or {})
    for family_key, detail in details.items():
        normalized_family_key = str(family_key or "").strip()
        if not normalized_family_key or not isinstance(detail, dict):
            continue
        signatures: set[str] = set()
        for value in [detail.get("family_exact_signature"), detail.get("signature")]:
            candidate = str(value or "").strip()
            if candidate:
                signatures.add(candidate)
        for collection_key in ["observed_signatures", "exact_signatures"]:
            for value in (detail.get(collection_key) or []):
                candidate = str(value or "").strip()
                if candidate:
                    signatures.add(candidate)
        index[normalized_family_key] = signatures
    return index


def build_trace_family_manifest(
    task_id: str,
    traced_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    clusters: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    exact_signatures: set[str] = set()
    for artifact in traced_artifacts:
        artifact_path = Path(str(artifact["artifact_path"]))
        payload = dict(artifact["payload"])
        exact_signature = str(payload.get("signature") or "").strip()
        features = derive_loose_cluster_features(payload)
        loose_cluster_key, cluster_match_reason = assign_loose_cluster_key(features, clusters)
        confirmed_family_key = loose_cluster_key
        crash_id = _candidate_id(payload, fallback_path=artifact_path)
        lineage = _family_lineage(
            exact_signature=exact_signature,
            loose_cluster_key=loose_cluster_key,
            confirmed_family_key=confirmed_family_key,
            promotion_state="traced_unconfirmed",
        )
        payload["family_exact_signature"] = exact_signature
        payload["family_loose_cluster_key"] = loose_cluster_key
        payload["family_confirmed_family_key"] = confirmed_family_key
        payload["family_cluster_match_reason"] = cluster_match_reason
        payload["family_features"] = features
        payload["family_lineage"] = lineage
        artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        exact_signatures.add(exact_signature)

        cluster = next((item for item in clusters if item["loose_cluster_key"] == loose_cluster_key), None)
        if cluster is None:
            cluster = {
                "loose_cluster_key": loose_cluster_key,
                "confirmed_family_key": confirmed_family_key,
                "cluster_match_reason": cluster_match_reason,
                "features": features,
                "crash_ids": [],
                "artifact_paths": [],
                "exact_signatures": [],
                "exact_signature_count": 0,
                "representative_crash_id": crash_id,
                "representative_artifact_path": str(artifact_path),
                "representative_harness_name": payload.get("harness_name"),
                "lineage_template": lineage,
            }
            clusters.append(cluster)
        cluster["crash_ids"].append(crash_id)
        cluster["artifact_paths"].append(str(artifact_path))
        if exact_signature and exact_signature not in cluster["exact_signatures"]:
            cluster["exact_signatures"].append(exact_signature)
        cluster["exact_signature_count"] = len(cluster["exact_signatures"])

        candidates.append(
            {
                "crash_id": crash_id,
                "artifact_path": str(artifact_path),
                "testcase_path": payload.get("testcase_path"),
                "harness_name": payload.get("harness_name"),
                "crash_source": payload.get("crash_source"),
                "symbolization_status": payload.get("symbolization_status"),
                "family_exact_signature": exact_signature,
                "family_loose_cluster_key": loose_cluster_key,
                "family_confirmed_family_key": confirmed_family_key,
                "family_cluster_match_reason": cluster_match_reason,
                "family_features": features,
                "family_lineage": lineage,
            }
        )

    manifest = {
        "task_id": task_id,
        "generated_at": _now_iso(),
        "manifest_version": 2,
        "exact_signature_count": len([item for item in exact_signatures if item]),
        "loose_cluster_count": len(clusters),
        "candidates": candidates,
        "clusters": clusters,
        "lineage_summary": [
            {
                "trace_exact_signature": item.get("family_exact_signature"),
                "loose_cluster_key": item.get("family_loose_cluster_key"),
                "confirmed_family_key": item.get("family_confirmed_family_key"),
                "cluster_match_reason": item.get("family_cluster_match_reason"),
            }
            for item in candidates
        ],
    }
    path = trace_family_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def load_campaign_family_context(task_dir: Path) -> dict[str, Any]:
    task_payload = _read_json(task_dir / "task.json")
    runtime = task_payload.get("runtime") or {}
    state_path = str(runtime.get("campaign_runtime_state_path") or "").strip()
    if not state_path:
        return {"family_inventory": {}}
    return _read_json(Path(state_path))


def plan_reproduction_candidates(
    traced_candidates: list[dict[str, Any]],
    *,
    active_harness_name: str | None,
    campaign_state: dict[str, Any],
) -> dict[str, Any]:
    family_inventory = dict(campaign_state.get("family_inventory") or {})
    current_session_index = int(campaign_state.get("session_count") or 0) + 1
    reconfirmation_threshold_rounds = _reconfirmation_round_threshold(campaign_state)
    confirmed_family_keys = {
        str(item).strip()
        for item in (family_inventory.get("confirmed_families") or [])
        if str(item).strip()
    }
    confirmed_signature_index = _confirmed_signature_index(family_inventory)
    confirmed_family_details = dict(family_inventory.get("confirmed_family_details") or {})
    unresolved_backlog = {
        str(item.get("loose_cluster_key") or "").strip()
        for item in (family_inventory.get("unresolved_loose_clusters") or [])
        if isinstance(item, dict) and str(item.get("loose_cluster_key") or "").strip()
    }
    grouped: dict[str, list[dict[str, Any]]] = {}
    cluster_summaries: dict[str, dict[str, Any]] = {}
    for candidate in traced_candidates:
        payload = dict(candidate)
        if not payload.get("family_loose_cluster_key"):
            features = derive_loose_cluster_features(payload)
            payload["family_exact_signature"] = str(payload.get("signature") or "").strip()
            payload["family_loose_cluster_key"] = str(features.get("cluster_display") or payload.get("family_exact_signature") or "unknown_cluster")
            payload["family_confirmed_family_key"] = payload["family_loose_cluster_key"]
            payload["family_cluster_match_reason"] = "fallback_runtime_derivation"
            payload["family_features"] = features
        loose_cluster_key = str(payload.get("family_loose_cluster_key") or "").strip()
        confirmed_family_key = str(payload.get("family_confirmed_family_key") or loose_cluster_key).strip()
        candidate_exact_signature = str(payload.get("family_exact_signature") or payload.get("signature") or "").strip()
        already_confirmed_family = confirmed_family_key in confirmed_family_keys
        known_confirmed_signatures = _sorted_strings(confirmed_signature_index.get(confirmed_family_key, set()))
        family_detail = dict(confirmed_family_details.get(confirmed_family_key) or {})
        signature_drift_requires_reconfirmation = bool(
            already_confirmed_family
            and candidate_exact_signature
            and known_confirmed_signatures
            and candidate_exact_signature not in known_confirmed_signatures
        )
        last_reconfirmed_session_index = int(
            family_detail.get("last_reconfirmed_session_index")
            or family_detail.get("last_confirmed_session_index")
            or family_detail.get("first_confirmed_session_index")
            or 0
        )
        reconfirmation_round_gap = max(0, current_session_index - last_reconfirmed_session_index)
        round_age_requires_reconfirmation = bool(
            already_confirmed_family
            and last_reconfirmed_session_index > 0
            and reconfirmation_round_gap >= reconfirmation_threshold_rounds
        )
        requires_reconfirmation = bool(
            signature_drift_requires_reconfirmation or round_age_requires_reconfirmation
        )
        reconfirmation_trigger = (
            "signature_drift+round_age"
            if signature_drift_requires_reconfirmation and round_age_requires_reconfirmation
            else (
                "signature_drift"
                if signature_drift_requires_reconfirmation
                else ("round_age" if round_age_requires_reconfirmation else None)
            )
        )
        selection_score = _selection_score(payload, active_harness_name=active_harness_name)
        candidate_entry = {
            "candidate_id": _candidate_id(payload),
            "selection_score": selection_score,
            "already_confirmed_family": already_confirmed_family,
            "requires_reconfirmation": requires_reconfirmation,
            "reconfirmation_trigger": reconfirmation_trigger,
            "reconfirmation_round_gap": reconfirmation_round_gap,
            "reconfirmation_threshold_rounds": reconfirmation_threshold_rounds,
            "known_confirmed_signatures": known_confirmed_signatures,
            "backlog_priority": loose_cluster_key in unresolved_backlog,
            "traced_candidate": payload,
            "summary": {
                "candidate_id": _candidate_id(payload),
                "testcase_path": payload.get("testcase_path"),
                "harness_name": payload.get("harness_name"),
                "crash_source": payload.get("crash_source"),
                "symbolization_status": payload.get("symbolization_status"),
                "family_exact_signature": payload.get("family_exact_signature") or payload.get("signature"),
                "family_loose_cluster_key": loose_cluster_key,
                "family_confirmed_family_key": confirmed_family_key,
                "family_cluster_match_reason": payload.get("family_cluster_match_reason"),
                "primary_function": (payload.get("family_features") or {}).get("primary_function"),
                "primary_file": (payload.get("family_features") or {}).get("primary_file"),
                "selection_score": selection_score,
                "requires_reconfirmation": requires_reconfirmation,
                "reconfirmation_trigger": reconfirmation_trigger,
                "reconfirmation_round_gap": reconfirmation_round_gap,
                "reconfirmation_threshold_rounds": reconfirmation_threshold_rounds,
                "known_confirmed_signatures": known_confirmed_signatures,
            },
        }
        grouped.setdefault(loose_cluster_key, []).append(candidate_entry)
        cluster_summaries.setdefault(
            loose_cluster_key,
            {
                "loose_cluster_key": loose_cluster_key,
                "confirmed_family_key": confirmed_family_key,
                "already_confirmed_family": already_confirmed_family,
                "backlog_priority": loose_cluster_key in unresolved_backlog,
                "member_candidate_ids": [],
                "member_exact_signatures": [],
                "requires_reconfirmation": False,
                "reconfirmation_trigger": None,
                "reconfirmation_round_gap": 0,
                "reconfirmation_threshold_rounds": reconfirmation_threshold_rounds,
                "known_confirmed_signatures": known_confirmed_signatures,
                "representative_primary_function": (payload.get("family_features") or {}).get("primary_function"),
                "representative_primary_file": (payload.get("family_features") or {}).get("primary_file"),
            },
        )
        cluster_summaries[loose_cluster_key]["member_candidate_ids"].append(candidate_entry["candidate_id"])
        cluster_summaries[loose_cluster_key]["crash_count"] = len(cluster_summaries[loose_cluster_key]["member_candidate_ids"])
        if candidate_exact_signature and candidate_exact_signature not in cluster_summaries[loose_cluster_key]["member_exact_signatures"]:
            cluster_summaries[loose_cluster_key]["member_exact_signatures"].append(candidate_exact_signature)
        if requires_reconfirmation:
            cluster_summaries[loose_cluster_key]["requires_reconfirmation"] = True
            cluster_summaries[loose_cluster_key]["reconfirmation_trigger"] = reconfirmation_trigger
            cluster_summaries[loose_cluster_key]["reconfirmation_round_gap"] = max(
                int(cluster_summaries[loose_cluster_key].get("reconfirmation_round_gap") or 0),
                reconfirmation_round_gap,
            )

    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    unresolved_selected = False
    ordered_clusters = sorted(
        grouped.items(),
        key=lambda item: (
            0 if bool(cluster_summaries[item[0]].get("requires_reconfirmation")) else 1,
            0 if bool(cluster_summaries[item[0]].get("backlog_priority")) else 1,
            -int(cluster_summaries[item[0]].get("crash_count") or len(item[1])),
            0 if not bool(cluster_summaries[item[0]].get("already_confirmed_family")) else 1,
            -max(float(entry.get("selection_score") or 0.0) for entry in item[1]),
            item[0],
        ),
    )
    for cluster_rank, (loose_cluster_key, entries) in enumerate(ordered_clusters, start=1):
        ordered = sorted(
            entries,
            key=lambda item: (
                0 if item["requires_reconfirmation"] else 1,
                0 if item["backlog_priority"] else 1,
                0 if not item["already_confirmed_family"] else 1,
                -float(item["selection_score"]),
                item["candidate_id"],
            ),
        )
        primary = ordered[0]
        cluster_summary = cluster_summaries[loose_cluster_key]
        cluster_summary["priority_rank"] = cluster_rank
        if primary["requires_reconfirmation"]:
            unresolved_selected = True
            primary["selection_reason"] = (
                "confirmed_family_round_age_reconfirmation"
                if primary.get("reconfirmation_trigger") == "round_age"
                else (
                    "confirmed_family_signature_drift_reconfirmation"
                    if primary.get("reconfirmation_trigger") == "signature_drift"
                    else "confirmed_family_reconfirmation"
                )
            )
            selected.append(
                {
                    **primary,
                    "cluster_summary": cluster_summary,
                }
            )
        elif primary["already_confirmed_family"]:
            primary["selection_reason"] = "already_confirmed_family_fallback"
            skipped.append(
                {
                    **primary["summary"],
                    "selection_status": "already_confirmed_family",
                }
            )
        else:
            unresolved_selected = True
            primary["selection_reason"] = (
                "existing_unresolved_loose_cluster"
                if primary["backlog_priority"]
                else "new_unresolved_loose_cluster"
            )
            selected.append(
                {
                    **primary,
                    "cluster_summary": cluster_summary,
                }
            )
        for duplicate in ordered[1:]:
            skipped.append(
                {
                    **duplicate["summary"],
                    "selection_status": "same_loose_cluster_lower_priority",
                }
            )
    if not selected and grouped:
        fallback = sorted(
            [entries[0] for entries in grouped.values()],
            key=lambda item: (-float(item["selection_score"]), item["candidate_id"]),
        )[0]
        fallback["selection_reason"] = "all_clusters_already_confirmed"
        selected.append(
            {
                **fallback,
                "cluster_summary": cluster_summaries[str(fallback["summary"]["family_loose_cluster_key"])],
            }
        )
        skipped = [
            item
            for item in skipped
            if item.get("candidate_id") != fallback["candidate_id"]
        ]

    return {
        "generated_at": _now_iso(),
        "campaign_confirmed_family_keys": sorted(confirmed_family_keys),
        "campaign_unresolved_loose_clusters": sorted(unresolved_backlog),
        "selected_candidates": selected,
        "skipped_candidates": skipped,
        "cluster_summaries": sorted(
            cluster_summaries.values(),
            key=lambda item: (
                int(item.get("priority_rank") or 999999),
                str(item.get("loose_cluster_key") or ""),
            ),
        ),
        "selected_unresolved_cluster_count": len(
            [
                item
                for item in selected
                if (not bool(item.get("already_confirmed_family"))) or bool(item.get("requires_reconfirmation"))
            ]
        ),
        "selected_reconfirmation_count": len([item for item in selected if bool(item.get("requires_reconfirmation"))]),
        "selection_mode": "one_per_loose_cluster_or_reconfirmation" if unresolved_selected else "confirmed_family_fallback",
    }


def classify_reproduction_attempts(
    traced_candidate: dict[str, Any],
    attempts: list[Any],
    *,
    selection_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selection_context = dict(selection_context or {})
    traced_features = dict(traced_candidate.get("family_features") or derive_loose_cluster_features(traced_candidate))
    traced_signature = str(
        traced_candidate.get("family_exact_signature")
        or traced_candidate.get("signature")
        or ""
    ).strip()
    traced_loose_cluster_key = str(traced_candidate.get("family_loose_cluster_key") or "").strip() or None
    confirmed_family_key = str(
        traced_candidate.get("family_confirmed_family_key")
        or traced_loose_cluster_key
        or ""
    ).strip() or None
    already_confirmed_family = bool(selection_context.get("already_confirmed_family"))
    requires_reconfirmation = bool(selection_context.get("requires_reconfirmation"))
    reconfirmation_trigger = str(selection_context.get("reconfirmation_trigger") or "").strip() or None
    reconfirmation_round_gap = int(selection_context.get("reconfirmation_round_gap") or 0)
    reconfirmation_threshold_rounds = (
        int(selection_context.get("reconfirmation_threshold_rounds"))
        if selection_context.get("reconfirmation_threshold_rounds") is not None
        else None
    )
    environment_failures = [
        attempt
        for attempt in attempts
        if getattr(attempt, "environment_classification", None)
    ]
    observed_signatures = _sorted_strings(
        {
            str(getattr(attempt, "signature", "")).strip()
            for attempt in attempts
            if str(getattr(attempt, "signature", "")).strip()
        }
    )
    if environment_failures:
        blocker_reason = ", ".join(
            f"{attempt.environment_classification}:{attempt.environment_reason}"
            for attempt in environment_failures
        )
        return {
            "confirmed": False,
            "classification": "environment_failure",
            "blocker_kind": "environment_failure",
            "blocker_reason": blocker_reason,
            "stable_replays": 0,
            "observed_signatures": observed_signatures,
            "observed_cluster_keys": [],
            "observed_cluster_match_reasons": [],
            "attempt_cluster_evidence": [],
            "confirmation_level": None,
            "promotion_rule": None,
            "lineage": _family_lineage(
                exact_signature=traced_signature,
                loose_cluster_key=traced_loose_cluster_key,
                confirmed_family_key=confirmed_family_key,
                promotion_state="blocked",
                already_confirmed_family=already_confirmed_family,
                requires_reconfirmation=requires_reconfirmation,
                blocker_kind="environment_failure",
                blocker_reason=blocker_reason,
                observed_signatures=observed_signatures,
                reconfirmation_trigger=reconfirmation_trigger,
                reconfirmation_round_gap=reconfirmation_round_gap,
                reconfirmation_threshold_rounds=reconfirmation_threshold_rounds,
            ),
        }

    signatures = set(observed_signatures)
    attempt_cluster_evidence: list[dict[str, Any]] = []
    cluster_match_reasons: list[str] = []
    cluster_mismatch_reasons: list[str] = []
    observed_cluster_keys: set[str] = set()
    for attempt in attempts:
        attempt_features = derive_replay_loose_cluster_features(
            stderr_excerpt=getattr(attempt, "stderr_excerpt", None),
            signature=getattr(attempt, "signature", None),
            harness_name=traced_candidate.get("harness_name"),
            trace_mode=traced_candidate.get("trace_mode"),
            fallback_crash_type=traced_features.get("crash_type"),
            fallback_crash_state=traced_features.get("crash_state"),
        )
        similar, reason = compare_loose_cluster_features(attempt_features, traced_features)
        observed_cluster_key = str(
            attempt_features.get("cluster_invariant_key")
            or attempt_features.get("cluster_display")
            or ""
        ).strip()
        if observed_cluster_key:
            observed_cluster_keys.add(observed_cluster_key)
        if similar and reason not in cluster_match_reasons:
            cluster_match_reasons.append(reason)
        if not similar and reason not in cluster_mismatch_reasons:
            cluster_mismatch_reasons.append(reason)
        attempt_cluster_evidence.append(
            {
                "attempt": getattr(attempt, "attempt", None),
                "signature": str(getattr(attempt, "signature", "")).strip() or None,
                "cluster_matches_traced": similar,
                "cluster_match_reason": reason,
                "replay_cluster_display": attempt_features.get("cluster_display"),
                "replay_stack_anchor": attempt_features.get("stack_anchor"),
                "replay_source_anchor": attempt_features.get("source_anchor"),
            }
        )

    if len(signatures) == 1 and traced_signature in signatures:
        lineage = _family_lineage(
            exact_signature=traced_signature,
            loose_cluster_key=traced_loose_cluster_key,
            confirmed_family_key=confirmed_family_key,
            promotion_state="confirmed",
            already_confirmed_family=already_confirmed_family,
            requires_reconfirmation=requires_reconfirmation,
            confirmation_level="exact_signature",
            promotion_rule="exact_signature_stable",
            observed_signatures=observed_signatures,
            observed_cluster_match_reasons=cluster_match_reasons,
            reconfirmation_trigger=reconfirmation_trigger,
            reconfirmation_round_gap=reconfirmation_round_gap,
            reconfirmation_threshold_rounds=reconfirmation_threshold_rounds,
        )
        return {
            "confirmed": True,
            "classification": "confirmed_exact_signature",
            "blocker_kind": None,
            "blocker_reason": None,
            "stable_replays": len(attempts),
            "observed_signatures": observed_signatures,
            "observed_cluster_keys": _sorted_strings(observed_cluster_keys),
            "observed_cluster_match_reasons": cluster_match_reasons,
            "attempt_cluster_evidence": attempt_cluster_evidence,
            "confirmation_level": "exact_signature",
            "promotion_rule": "exact_signature_stable",
            "lineage": lineage,
        }

    if not cluster_mismatch_reasons and observed_signatures and (already_confirmed_family or requires_reconfirmation):
        lineage = _family_lineage(
            exact_signature=traced_signature,
            loose_cluster_key=traced_loose_cluster_key,
            confirmed_family_key=confirmed_family_key,
            promotion_state="confirmed",
            already_confirmed_family=already_confirmed_family,
            requires_reconfirmation=requires_reconfirmation,
            confirmation_level="loose_cluster",
            promotion_rule="confirmed_family_reconfirmation_by_loose_cluster",
            observed_signatures=observed_signatures,
            observed_cluster_match_reasons=cluster_match_reasons,
            reconfirmation_trigger=reconfirmation_trigger,
            reconfirmation_round_gap=reconfirmation_round_gap,
            reconfirmation_threshold_rounds=reconfirmation_threshold_rounds,
        )
        return {
            "confirmed": True,
            "classification": "confirmed_loose_cluster_existing_family",
            "blocker_kind": None,
            "blocker_reason": None,
            "stable_replays": len(attempts),
            "observed_signatures": observed_signatures,
            "observed_cluster_keys": _sorted_strings(observed_cluster_keys),
            "observed_cluster_match_reasons": cluster_match_reasons,
            "attempt_cluster_evidence": attempt_cluster_evidence,
            "confirmation_level": "loose_cluster",
            "promotion_rule": "confirmed_family_reconfirmation_by_loose_cluster",
            "lineage": lineage,
        }

    if not cluster_mismatch_reasons and observed_signatures:
        blocker_reason = "new loose cluster stayed semantically stable but did not earn first confirmation because exact signature remained unstable"
        return {
            "confirmed": False,
            "classification": "loose_cluster_pending_exact_confirmation",
            "blocker_kind": "await_exact_signature_for_first_confirmation",
            "blocker_reason": blocker_reason,
            "stable_replays": 0,
            "observed_signatures": observed_signatures,
            "observed_cluster_keys": _sorted_strings(observed_cluster_keys),
            "observed_cluster_match_reasons": cluster_match_reasons,
            "attempt_cluster_evidence": attempt_cluster_evidence,
            "confirmation_level": None,
            "promotion_rule": "conservative_first_family_gate",
            "lineage": _family_lineage(
                exact_signature=traced_signature,
                loose_cluster_key=traced_loose_cluster_key,
                confirmed_family_key=confirmed_family_key,
                promotion_state="blocked",
                already_confirmed_family=already_confirmed_family,
                requires_reconfirmation=requires_reconfirmation,
                promotion_rule="conservative_first_family_gate",
                blocker_kind="await_exact_signature_for_first_confirmation",
                blocker_reason=blocker_reason,
                observed_signatures=observed_signatures,
                observed_cluster_match_reasons=cluster_match_reasons,
                reconfirmation_trigger=reconfirmation_trigger,
                reconfirmation_round_gap=reconfirmation_round_gap,
                reconfirmation_threshold_rounds=reconfirmation_threshold_rounds,
            ),
        }

    blocker_reason = (
        "reproduction drift crossed conservative loose-cluster split rules: "
        + ", ".join(cluster_mismatch_reasons)
        if cluster_mismatch_reasons
        else "traced crash was not stable across reproduction attempts"
    )
    return {
        "confirmed": False,
        "classification": "loose_cluster_split",
        "blocker_kind": cluster_mismatch_reasons[0] if cluster_mismatch_reasons else "signature_instability",
        "blocker_reason": blocker_reason,
        "stable_replays": 0,
        "observed_signatures": observed_signatures,
        "observed_cluster_keys": _sorted_strings(observed_cluster_keys),
        "observed_cluster_match_reasons": cluster_match_reasons,
        "attempt_cluster_evidence": attempt_cluster_evidence,
        "confirmation_level": None,
        "promotion_rule": "conservative_split_guard",
        "lineage": _family_lineage(
            exact_signature=traced_signature,
            loose_cluster_key=traced_loose_cluster_key,
            confirmed_family_key=confirmed_family_key,
            promotion_state="blocked",
            already_confirmed_family=already_confirmed_family,
            requires_reconfirmation=requires_reconfirmation,
            promotion_rule="conservative_split_guard",
            blocker_kind=cluster_mismatch_reasons[0] if cluster_mismatch_reasons else "signature_instability",
            blocker_reason=blocker_reason,
            observed_signatures=observed_signatures,
            observed_cluster_match_reasons=cluster_match_reasons,
            reconfirmation_trigger=reconfirmation_trigger,
            reconfirmation_round_gap=reconfirmation_round_gap,
            reconfirmation_threshold_rounds=reconfirmation_threshold_rounds,
        ),
    }


def write_repro_family_manifest(task_id: str, payload: dict[str, Any]) -> Path:
    path = repro_family_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path

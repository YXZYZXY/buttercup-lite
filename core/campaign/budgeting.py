from __future__ import annotations

from copy import deepcopy
from typing import Any


def apply_budget_multiplier(base_attempts: int, multiplier: float) -> int:
    if multiplier <= 1.0:
        return int(base_attempts)
    boosted = int(round(base_attempts * multiplier))
    return max(base_attempts + 1, boosted)


def redistribute_candidate_weights(
    candidates: list[dict],
    *,
    selected_candidate_id: str | None,
    budget_multiplier: float,
    stalled: bool,
) -> list[dict]:
    redistributed = deepcopy(candidates)
    for candidate in redistributed:
        before_weight = float(candidate.get("weight", 1.0))
        candidate["weight_before"] = before_weight
        if selected_candidate_id and candidate.get("candidate_id") == selected_candidate_id:
            candidate["weight_after"] = round(before_weight * max(1.0, budget_multiplier), 3)
            candidate["priority_after"] = "high" if budget_multiplier > 1.0 else candidate.get("priority", "normal")
            candidate["decision"] = "selected"
        elif stalled:
            candidate["weight_after"] = round(max(0.1, before_weight * 0.6), 3)
            candidate["priority_after"] = "deprioritized"
            candidate["decision"] = "deprioritized"
        else:
            candidate["weight_after"] = before_weight
            candidate["priority_after"] = candidate.get("priority", "normal")
            candidate["decision"] = "unchanged"
    return redistributed


def score_workload_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    scored = deepcopy(candidate)
    score = float(candidate.get("budget_before", 1.0))
    reasons: list[str] = []
    adapter = str(candidate.get("adapter", "source"))
    workload_type = str(candidate.get("workload_type", "seed"))
    priority = str(candidate.get("priority", "normal"))
    weight = float(candidate.get("weight", 1.0))
    stalled = bool(candidate.get("stalled"))
    crash_count = int(candidate.get("crash_count", 0) or 0)
    pov_count = int(candidate.get("pov_count", 0) or 0)
    patch_priority_action = candidate.get("patch_priority_action")
    reflection_action = candidate.get("reflection_action")

    if adapter == "source":
        score += 0.15
        reasons.append("source_adapter_bonus")
    elif adapter == "binary":
        score += 0.10
        reasons.append("pure_binary_adapter_bonus")

    score += max(0.0, weight - 1.0) * 0.5
    if weight > 1.0:
        reasons.append("existing_weight_bias")

    if priority == "high":
        score += 0.45
        reasons.append("high_priority_signal")
    elif priority == "critical":
        score += 0.8
        reasons.append("critical_priority_signal")

    if workload_type == "seed" and stalled:
        score += 0.9
        reasons.append("coverage_recovery_seed")
    if workload_type in {"fuzz", "binary_execution"} and crash_count > 0:
        score += 0.9
        reasons.append("active_crash_signal")
    if workload_type == "patch" and patch_priority_action == "escalate":
        score += 1.4
        reasons.append("patch_priority_escalation")
    if workload_type == "patch" and pov_count > 0:
        score += 0.7
        reasons.append("confirmed_pov_patchable")
    if reflection_action in {"accept", "suppress"}:
        score -= 1.2
        reasons.append("patch_path_already_resolved")
    elif reflection_action == "retry":
        score += 0.35
        reasons.append("patch_retry_requested")

    scored["score"] = round(score, 3)
    scored["score_reasons"] = reasons
    return scored


def arbitrate_workloads(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [score_workload_candidate(candidate) for candidate in candidates]
    scored.sort(key=lambda item: item.get("score", 0.0), reverse=True)
    selected_ids = {item["candidate_id"] for item in scored[:2]}
    after: list[dict[str, Any]] = []
    for index, candidate in enumerate(scored):
        updated = deepcopy(candidate)
        budget_before = float(candidate.get("budget_before", 1.0))
        if candidate.get("reflection_action") in {"accept", "suppress"}:
            budget_after = 0.0
            decision = "suppress"
        elif candidate["candidate_id"] in selected_ids and index == 0:
            budget_after = round(max(budget_before, 1.0) * 1.8, 3)
            decision = "boost"
        elif candidate["candidate_id"] in selected_ids:
            budget_after = round(max(budget_before, 1.0) * 1.35, 3)
            decision = "support"
        elif candidate.get("stalled") and int(candidate.get("crash_count", 0) or 0) <= 0:
            budget_after = round(max(0.1, budget_before * 0.45), 3)
            decision = "deprioritize"
        else:
            budget_after = round(max(0.2, budget_before * 0.8), 3)
            decision = "hold"
        updated["budget_after"] = budget_after
        updated["decision"] = decision
        after.append(updated)

    return {
        "candidates_before": candidates,
        "candidates_after": after,
        "selected_candidates": [item for item in after if item["decision"] in {"boost", "support"}],
        "suppressed_candidates": [item for item in after if item["decision"] == "suppress"],
        "deprioritized_candidates": [item for item in after if item["decision"] == "deprioritize"],
    }

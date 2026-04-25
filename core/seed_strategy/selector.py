from __future__ import annotations

from typing import Any

from core.seed_strategy.task_modes import SeedTaskDecision, SeedTaskMode


def _count_traced_crashes(task: Any) -> int:
    runtime = getattr(task, "runtime", {}) or {}
    value = runtime.get("traced_crash_count") or runtime.get("binary_traced_crash_count")
    if value:
        return int(value)
    return 0


def _mode_counts(task: Any) -> dict[str, int]:
    runtime = getattr(task, "runtime", {}) or {}
    raw_counts = runtime.get("seed_mode_counts") or {}
    return {
        "SEED_INIT": int(raw_counts.get("SEED_INIT") or 0),
        "VULN_DISCOVERY": int(raw_counts.get("VULN_DISCOVERY") or 0),
        "SEED_EXPLORE": int(raw_counts.get("SEED_EXPLORE") or 0),
    }


def _coverage_target_pressure(task: Any, coverage_manifest: dict[str, Any] | None) -> dict[str, int]:
    runtime = getattr(task, "runtime", {}) or {}
    current = dict((coverage_manifest or {}).get("current") or {})
    return {
        "selected": len(runtime.get("campaign_coverage_selected_entries") or []),
        "low_growth": len(runtime.get("campaign_low_growth_functions") or current.get("low_growth_functions") or []),
        "uncovered": len(runtime.get("campaign_uncovered_functions") or current.get("uncovered_functions") or []),
        "partial": len(runtime.get("campaign_partial_degraded_targets") or []),
        "candidate_bridge": len(runtime.get("campaign_candidate_bridge_targets") or []),
    }


def select_seed_task_mode(task: Any, coverage_manifest: dict[str, Any] | None = None) -> SeedTaskDecision:
    metadata = getattr(task, "metadata", {}) or {}
    runtime = getattr(task, "runtime", {}) or {}

    explicit = metadata.get("seed_task_mode") or runtime.get("seed_task_mode_override")
    if explicit:
        return SeedTaskDecision(
            mode=str(explicit),
            reason="explicit seed_task_mode override",
            budget_multiplier=1.0,
            priority="manual",
        )

    manifest = coverage_manifest or {}
    current = manifest.get("current", {})
    stalled = bool(manifest.get("stalled"))
    raw_crash_count = int(current.get("raw_crash_count") or 0)
    traced_crash_count = _count_traced_crashes(task)
    patch_priority_action = runtime.get("patch_priority_action")
    budget_pressure = str(metadata.get("campaign_budget_state") or runtime.get("campaign_budget_state") or "normal")
    mode_counts = _mode_counts(task)
    coverage_pressure = _coverage_target_pressure(task, coverage_manifest)
    coverage_target_pressure = sum(coverage_pressure.values())

    if patch_priority_action == "escalate":
        return SeedTaskDecision(
            mode=SeedTaskMode.VULN_DISCOVERY,
            reason="patch priority escalation requests exploit-oriented seed generation",
            budget_multiplier=2.0,
            priority="critical",
        )

    if mode_counts["SEED_INIT"] < 3:
        return SeedTaskDecision(
            mode=SeedTaskMode.SEED_INIT,
            reason="original-like seed-init minimum has not been reached yet",
            budget_multiplier=1.0,
            priority="normal",
        )

    if mode_counts["VULN_DISCOVERY"] < 1:
        return SeedTaskDecision(
            mode=SeedTaskMode.VULN_DISCOVERY,
            reason="original-like vuln-discovery minimum has not been reached yet",
            budget_multiplier=1.4,
            priority="high",
        )

    if stalled and (raw_crash_count > 0 or traced_crash_count > 0):
        return SeedTaskDecision(
            mode=SeedTaskMode.VULN_DISCOVERY,
            reason="coverage stalled while crashes already exist; bias toward exploit-oriented seed generation",
            budget_multiplier=1.75,
            priority="high",
        )

    if budget_pressure == "explore":
        return SeedTaskDecision(
            mode=SeedTaskMode.SEED_EXPLORE,
            reason="campaign budget state requests exploration",
            budget_multiplier=1.5,
            priority="high",
        )

    if coverage_target_pressure > 0:
        dominant_queue = max(
            coverage_pressure.items(),
            key=lambda item: (item[1], item[0]),
        )[0]
        return SeedTaskDecision(
            mode=SeedTaskMode.SEED_EXPLORE,
            reason=(
                "durable coverage target pressure requests exploration "
                f"(selected={coverage_pressure['selected']}, uncovered={coverage_pressure['uncovered']}, "
                f"low_growth={coverage_pressure['low_growth']}, partial={coverage_pressure['partial']}, "
                f"candidate_bridge={coverage_pressure['candidate_bridge']}, dominant={dominant_queue})"
            ),
            budget_multiplier=1.7 if coverage_pressure["uncovered"] or coverage_pressure["low_growth"] else 1.5,
            priority="high",
        )

    if raw_crash_count == 0 and traced_crash_count == 0 and mode_counts["SEED_EXPLORE"] < 1:
        return SeedTaskDecision(
            mode=SeedTaskMode.SEED_EXPLORE,
            reason="no crash has been found yet and explore quota has not been exercised",
            budget_multiplier=1.45,
            priority="high",
        )

    if stalled or runtime.get("coverage_feedback_triggered"):
        return SeedTaskDecision(
            mode=SeedTaskMode.SEED_EXPLORE,
            reason="coverage stalled or growth is weak; bias toward exploratory seed generation",
            budget_multiplier=1.35,
            priority="high",
        )

    if raw_crash_count > 0 or traced_crash_count > 0:
        return SeedTaskDecision(
            mode=SeedTaskMode.VULN_DISCOVERY,
            reason="crash history exists; bias toward exploit-oriented seeds over new initialization",
            budget_multiplier=1.5,
            priority="high",
        )

    return SeedTaskDecision(
        mode=SeedTaskMode.SEED_EXPLORE,
        reason="original-like steady-state selector favors exploration after initialization quotas are met",
        budget_multiplier=1.25,
        priority="normal",
    )

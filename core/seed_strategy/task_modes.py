from __future__ import annotations

from dataclasses import dataclass


class SeedTaskMode:
    SEED_INIT = "SEED_INIT"
    SEED_EXPLORE = "SEED_EXPLORE"
    VULN_DISCOVERY = "VULN_DISCOVERY"


@dataclass(frozen=True)
class SeedTaskDecision:
    mode: str
    reason: str
    budget_multiplier: float = 1.0
    priority: str = "normal"


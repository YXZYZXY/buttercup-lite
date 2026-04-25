from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PatchPriorityDecision:
    action: str
    reason: str
    score: int
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "score": self.score,
            "evidence": self.evidence,
        }


def decide_patch_priority(*, pov_confirmed: bool, distinct_signature_count: int = 1, repeated_signature_count: int = 0) -> PatchPriorityDecision:
    if not pov_confirmed:
        return PatchPriorityDecision(
            action="suppress",
            reason="no confirmed PoV available",
            score=0,
            evidence={"pov_confirmed": False},
        )
    if distinct_signature_count > 0 and repeated_signature_count > 10:
        return PatchPriorityDecision(
            action="escalate",
            reason="confirmed PoV with repeated crash signature evidence",
            score=90,
            evidence={
                "pov_confirmed": True,
                "distinct_signature_count": distinct_signature_count,
                "repeated_signature_count": repeated_signature_count,
            },
        )
    return PatchPriorityDecision(
        action="neutral",
        reason="confirmed PoV exists but no additional campaign pressure signal",
        score=50,
        evidence={
            "pov_confirmed": True,
            "distinct_signature_count": distinct_signature_count,
            "repeated_signature_count": repeated_signature_count,
        },
    )


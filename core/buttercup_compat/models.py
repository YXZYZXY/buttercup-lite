from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class OriginalMapping:
    """One original-Buttercup semantic concept as represented in lite."""

    original_component: str
    original_semantics: str
    lite_component: str
    lite_artifact: str | None
    alignment: str
    live_dependency_edges: list[str] = field(default_factory=list)
    missing_dependency_edges: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ButtercupRequest:
    """Queue request shape mirroring the original orchestrator message fanout."""

    request_type: str
    queue: str | None
    worker: str | None
    execute: bool
    inputs: list[Any] = field(default_factory=list)
    build_type: str | None = None
    sanitizer: str | None = None
    apply_diff: bool | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

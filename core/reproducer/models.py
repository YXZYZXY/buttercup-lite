from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ReproAttempt:
    attempt: int
    exit_code: int
    signature: str
    stderr_excerpt: str
    command: list[str]
    input_mode: str | None
    testcase_path: str | None
    environment_classification: str | None = None
    environment_reason: str | None = None

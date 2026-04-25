from __future__ import annotations

from pathlib import Path

from core.reproducer.models import ReproAttempt
from core.tracer import compute_signature, parse_replay_result, replay_testcase
from core.utils.settings import settings


def replay_traced_crash(traced_crash: dict, task_dir: Path) -> list[ReproAttempt]:
    attempts: list[ReproAttempt] = []
    for index in range(settings.repro_attempts):
        result = replay_testcase(
            traced_crash["binary_path"],
            traced_crash["harness_name"],
            traced_crash["testcase_path"],
            task_dir,
        )
        parsed = parse_replay_result(result, traced_crash.get("crash_source", "live_raw"))
        attempts.append(
            ReproAttempt(
                attempt=index + 1,
                exit_code=result.exit_code,
                signature=compute_signature(parsed.crash_type, parsed.crash_state),
                stderr_excerpt=parsed.stderr_excerpt[:1000],
                command=list(result.command),
                input_mode=traced_crash.get("input_mode"),
                testcase_path=traced_crash.get("testcase_path"),
                environment_classification=parsed.environment_classification,
                environment_reason=parsed.environment_reason,
            ),
        )
    return attempts

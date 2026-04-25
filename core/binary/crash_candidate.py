from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from core.binary.models import BinaryCrashCandidate, BinaryExecutionInput


def detect_crash_candidate(exit_code: int, stdout: str, stderr: str) -> tuple[bool, str]:
    combined = f"{stdout}\n{stderr}"
    if "AddressSanitizer:" in combined:
        return True, "address"
    if "UndefinedBehaviorSanitizer:" in combined:
        return True, "undefined"
    if "Segmentation fault" in combined:
        return True, "segmentation_fault"
    if "deadly signal" in combined or "Aborted" in combined:
        return True, "abort_signal"
    if exit_code in {-11, 139}:
        return True, f"segv_exit:{exit_code}"
    if exit_code in {-6, 134}:
        return True, f"abort_exit:{exit_code}"
    return False, ""


def materialize_crash_candidate(
    *,
    task_id: str,
    execution_input: BinaryExecutionInput,
    output_dir: Path,
    reason: str,
    exit_code: int,
) -> BinaryCrashCandidate:
    output_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(
        f"{task_id}:{execution_input.path}:{reason}:{exit_code}".encode("utf-8"),
    ).hexdigest()[:12]
    destination = output_dir / f"{execution_input.path.stem}_{digest}{execution_input.path.suffix or '.bin'}"
    shutil.copy2(execution_input.path, destination)
    return BinaryCrashCandidate(
        candidate_path=str(destination),
        input_path=str(execution_input.path),
        source_kind=execution_input.source_kind,
        source_path=execution_input.source_path,
        size=destination.stat().st_size,
        reason=reason,
        exit_code=exit_code,
    )

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from core.binary.models import BinaryToolResult
from core.utils.settings import settings


def invoke_ida_mcp(binary_path: Path, output_dir: Path) -> tuple[dict[str, Any], BinaryToolResult]:
    if not settings.ida_mcp_configured():
        raise RuntimeError("IDA_MCP_COMMAND is not configured in the current environment")

    argv = settings.ida_mcp_command_argv() + [str(binary_path.resolve()), str(output_dir)]
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=settings.ida_mcp_timeout_seconds,
        check=False,
    )
    result = BinaryToolResult(
        command=argv,
        return_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        available=True,
    )
    if completed.returncode != 0:
        stdout_excerpt = completed.stdout.strip()[:500]
        stderr_excerpt = completed.stderr.strip()[:500]
        raise RuntimeError(
            f"IDA MCP command failed exit_code={completed.returncode} "
            f"stdout={stdout_excerpt!r} stderr={stderr_excerpt!r}"
        )

    stdout = completed.stdout.strip()
    if stdout:
        try:
            return json.loads(stdout), result
        except json.JSONDecodeError:
            return {"stdout": stdout}, result
    return {}, result

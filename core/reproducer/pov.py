from __future__ import annotations

import base64
import platform
from pathlib import Path


def build_pov_record(traced_crash: dict) -> dict:
    testcase_bytes = Path(traced_crash["testcase_path"]).read_bytes()
    engine = "binary_execution" if traced_crash.get("target_mode") == "binary" else "libFuzzer"
    return {
        "architecture": platform.machine(),
        "engine": engine,
        "fuzzer_name": traced_crash["harness_name"],
        "sanitizer": traced_crash["sanitizer"],
        "testcase": base64.b64encode(testcase_bytes).decode("ascii"),
        "source_crash_signature": traced_crash["signature"],
    }

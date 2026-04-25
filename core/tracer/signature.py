from __future__ import annotations

import hashlib


def compute_signature(crash_type: str, crash_state: str) -> str:
    return hashlib.sha256(f"{crash_type}\n{crash_state}".encode("utf-8")).hexdigest()

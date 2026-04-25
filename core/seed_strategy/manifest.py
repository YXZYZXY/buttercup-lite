from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.storage.layout import binary_seed_task_manifest_path, seed_task_manifest_path


def write_seed_task_manifest(
    task_id: str,
    *,
    target_mode: str,
    payload: dict[str, Any],
) -> Path:
    if target_mode == "binary":
        path = binary_seed_task_manifest_path(task_id)
    else:
        path = seed_task_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


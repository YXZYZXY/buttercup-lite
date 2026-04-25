from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.storage.layout import campaign_manifest_path


def write_campaign_manifest(task_id: str, payload: dict[str, Any]) -> Path:
    path = campaign_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path

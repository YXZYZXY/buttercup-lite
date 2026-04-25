from __future__ import annotations

import json
from typing import Any

from core.storage.layout import seed_init_chain_manifest_path


def write_seed_init_chain_manifest(
    task_id: str,
    *,
    generated_at: str,
    context_phase: dict[str, Any],
    generation_phase: dict[str, Any],
    execution_phase: dict[str, Any],
) -> str:
    payload = {
        "task_id": task_id,
        "generated_at": generated_at,
        "compat_source": "original_buttercup.seed_gen.SeedInitTask",
        "original_chain": [
            "get_context",
            "generate_seeds",
            "execute_seeds",
        ],
        "lite_chain": {
            "get_context": context_phase,
            "generate_seeds": generation_phase,
            "execute_seeds": execution_phase,
        },
        "alignment_note": (
            "Lite keeps its local worker/task_dir plumbing but now records the same SeedInit phase boundary "
            "used by original Buttercup."
        ),
    }
    path = seed_init_chain_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)

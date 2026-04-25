from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.patch_priority.models import decide_patch_priority
from core.storage.layout import patch_priority_manifest_path, patch_priority_consumption_path, patch_reflection_consumption_path


def write_patch_priority_manifest(
    task_id: str,
    *,
    generated_at: str,
    pov_paths: list[str],
    trace_manifest_path: str | None,
    repro_manifest_path: str | None,
    target_mode: str | None,
    adapter_resolution: str | None,
    repeated_signature_count: int = 0,
) -> Path:
    decision = decide_patch_priority(
        pov_confirmed=bool(pov_paths),
        distinct_signature_count=1 if pov_paths else 0,
        repeated_signature_count=repeated_signature_count,
    )
    payload = {
        "task_id": task_id,
        "generated_at": generated_at,
        "producer": "reproducer-worker",
        "target_mode": target_mode,
        "adapter_resolution": adapter_resolution,
        "trace_manifest_path": trace_manifest_path,
        "repro_manifest_path": repro_manifest_path,
        "pov_paths": pov_paths,
        "priority_decision": decision.to_dict(),
        "downstream_consumers": ["scheduler", "campaign"],
    }
    path = patch_priority_manifest_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def consume_patch_priority_manifest(task_id: str, *, consumer: str, now: str, manifest_path: str | Path) -> Path:
    source_path = Path(manifest_path)
    payload: dict[str, Any] = json.loads(source_path.read_text(encoding="utf-8")) if source_path.exists() else {}
    decision = payload.get("priority_decision", {})
    consumed = {
        "task_id": task_id,
        "consumer": consumer,
        "consumed_at": now,
        "source_manifest_path": str(source_path),
        "priority_action": decision.get("action", "neutral"),
        "priority_score": decision.get("score", 50),
        "priority_reason": decision.get("reason", "missing patch priority manifest"),
        "scheduler_or_campaign_effect": {
            "suppress": "do_not_start_patch_or_extra_campaign_work",
            "neutral": "no_priority_change",
            "escalate": "raise_patch_or_campaign_priority",
        }.get(decision.get("action", "neutral"), "no_priority_change"),
    }
    path = patch_priority_consumption_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(consumed, indent=2), encoding="utf-8")
    return path


def consume_patch_reflection_manifest(task_id: str, *, consumer: str, now: str, manifest_path: str | Path) -> Path:
    source_path = Path(manifest_path)
    payload: dict[str, Any] = json.loads(source_path.read_text(encoding="utf-8")) if source_path.exists() else {}
    action = payload.get("reflection_action", "suppress")
    consumed = {
        "task_id": task_id,
        "consumer": consumer,
        "consumed_at": now,
        "source_manifest_path": str(source_path),
        "reflection_action": action,
        "qe_verdict": payload.get("qe_verdict"),
        "reflection_reason": payload.get("reason"),
        "scheduler_or_campaign_effect": {
            "accept": "suppress_additional_patch_attempts_for_signature",
            "retry": "schedule_new_patch_attempt",
            "suppress": "suppress_patch_path_for_signature",
            "escalate": "raise_campaign_or_patch_priority",
        }.get(action, "suppress_patch_path_for_signature"),
    }
    path = patch_reflection_consumption_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(consumed, indent=2), encoding="utf-8")
    return path

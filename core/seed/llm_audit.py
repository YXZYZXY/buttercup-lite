from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.storage.layout import (
    llm_backend_integrity_report_path,
    llm_seed_audit_manifest_path,
    seed_backend_degradation_report_path,
    strict_llm_block_report_path,
)


def _write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def write_llm_seed_audit(
    task_id: str,
    *,
    target_mode: str,
    task_partition: str,
    requested_seed_backend: str,
    actual_seed_backend: str,
    llm_metadata: dict[str, Any],
    seed_provenance: str,
    prompt_template_id: str,
    task_should_fail_if_llm_missing: bool,
    fallback_used: bool,
    fallback_reason: str | None,
) -> dict[str, str]:
    requested_real_llm = requested_seed_backend == "llm"
    actual_real_llm = actual_seed_backend == "llm" and bool(llm_metadata.get("llm_real_call_verified"))
    degraded = requested_real_llm and not actual_real_llm
    strict_llm_blocked = bool(task_should_fail_if_llm_missing and task_partition == "official_main" and degraded)
    audit_payload = {
        "task_id": task_id,
        "target_mode": target_mode,
        "task_partition": task_partition,
        "requested_seed_backend": requested_seed_backend,
        "actual_seed_backend": actual_seed_backend,
        "llm_real_call_verified": llm_metadata.get("llm_real_call_verified"),
        "provider": llm_metadata.get("llm_provider"),
        "model": llm_metadata.get("llm_model"),
        "request_count": llm_metadata.get("llm_request_count"),
        "request_id_or_response_id_hash": llm_metadata.get("llm_request_id_hash"),
        "prompt_hash": llm_metadata.get("prompt_sha256"),
        "response_hash": llm_metadata.get("response_sha256"),
        "token_usage": llm_metadata.get("llm_token_usage"),
        "fallback_used": fallback_used,
        "fallback_reason": fallback_reason,
        "seed_provenance": seed_provenance,
        "prompt_template_id": prompt_template_id,
        "task_should_fail_if_llm_missing": task_should_fail_if_llm_missing,
        "degraded": degraded,
        "strict_llm_blocked": strict_llm_blocked,
        "llm_provenance": llm_metadata.get("llm_provenance"),
    }
    integrity_payload = {
        "task_id": task_id,
        "target_mode": target_mode,
        "task_partition": task_partition,
        "requested_real_llm": requested_real_llm,
        "actual_real_llm": actual_real_llm,
        "degraded": degraded,
        "strict_llm_blocked": strict_llm_blocked,
        "silent_fallback_eliminated": True,
        "fallback_used": fallback_used,
        "fallback_reason": fallback_reason,
        "verdict": (
            "blocked_mainline_llm_failure"
            if strict_llm_blocked
            else "degraded"
            if degraded
            else "real_llm_verified"
            if actual_real_llm
            else "non_llm_requested"
        ),
    }
    degradation_payload = {
        "task_id": task_id,
        "target_mode": target_mode,
        "task_partition": task_partition,
        "degraded": degraded,
        "strict_llm_blocked": strict_llm_blocked,
        "requested_seed_backend": requested_seed_backend,
        "actual_seed_backend": actual_seed_backend,
        "task_should_fail_if_llm_missing": task_should_fail_if_llm_missing,
        "fallback_used": fallback_used,
        "fallback_reason": fallback_reason,
        "llm_failure_reason": llm_metadata.get("llm_failure_reason"),
        "degradation_effect": (
            "task_requested_real_llm_but_backend_did_not_remain_real_llm"
            if degraded
            else None
        ),
    }
    strict_block_payload = {
        "task_id": task_id,
        "target_mode": target_mode,
        "task_partition": task_partition,
        "requested_seed_backend": requested_seed_backend,
        "actual_seed_backend": actual_seed_backend,
        "strict_llm_blocked": strict_llm_blocked,
        "task_should_fail_if_llm_missing": task_should_fail_if_llm_missing,
        "downstream_allowed": not strict_llm_blocked,
        "block_reason": llm_metadata.get("llm_failure_reason") if strict_llm_blocked else None,
        "verdict": "BLOCKED" if strict_llm_blocked else "NOT_BLOCKED",
    }
    return {
        "llm_seed_audit_manifest_path": _write_json(llm_seed_audit_manifest_path(task_id), audit_payload),
        "llm_backend_integrity_report_path": _write_json(
            llm_backend_integrity_report_path(task_id),
            integrity_payload,
        ),
        "seed_backend_degradation_report_path": _write_json(
            seed_backend_degradation_report_path(task_id),
            degradation_payload,
        ),
        "strict_llm_block_report_path": _write_json(
            strict_llm_block_report_path(task_id),
            strict_block_payload,
        ),
    }

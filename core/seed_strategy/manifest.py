from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.storage.layout import binary_seed_task_manifest_path, seed_task_manifest_path
from core.utils.settings import settings


def _normalize_provider(provider: str, base_url: str) -> str:
    candidate = provider.strip()
    if candidate:
        lowered = candidate.lower()
        if "deepseek" in lowered:
            return "deepseek"
        return candidate
    hostname = (urlparse(base_url).hostname or "").strip().lower()
    if "deepseek" in hostname:
        return "deepseek"
    return hostname


def _normalize_llm_manifest_fields(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    base_url = str(
        normalized.get("base_url")
        or normalized.get("llm_base_url")
        or settings.llm_base_url
        or ""
    ).strip()
    provider = _normalize_provider(
        str(
        normalized.get("provider")
        or normalized.get("llm_provider")
        or urlparse(base_url).hostname
        or ""
    ),
        base_url,
    )
    model = str(
        normalized.get("model")
        or normalized.get("llm_model")
        or settings.llm_model
        or ""
    ).strip()
    request_count = int(
        normalized.get("llm_request_count")
        or normalized.get("llm_request_count_total")
        or 0
    )
    success_count = normalized.get("llm_success_count")
    if success_count is None:
        success_count = 1 if (
            normalized.get("llm_real_call_verified")
            and normalized.get("llm_response_received")
            and not normalized.get("llm_failure_reason")
        ) else 0
    failure_count = normalized.get("llm_failure_count")
    if failure_count is None:
        failure_count = 1 if (
            normalized.get("llm_request_attempted")
            and not int(success_count or 0)
            and (normalized.get("llm_failure_reason") or request_count > 0)
        ) else 0
    api_calls_per_hour = normalized.get("api_calls_per_hour")
    if api_calls_per_hour is None:
        api_calls_per_hour = 0.0

    normalized["provider"] = provider or None
    normalized["base_url"] = base_url or None
    normalized["model"] = model or None
    normalized["llm_request_count"] = request_count
    normalized["llm_success_count"] = int(success_count or 0)
    normalized["llm_failure_count"] = int(failure_count or 0)
    normalized["api_calls_per_hour"] = api_calls_per_hour
    return normalized


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
    path.write_text(
        json.dumps(_normalize_llm_manifest_fields(payload), indent=2),
        encoding="utf-8",
    )
    return path

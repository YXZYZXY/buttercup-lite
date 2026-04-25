from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import Any
from urllib import error, parse, request

from core.utils.settings import settings

logger = logging.getLogger("seed-llm-client")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class LLMCallMetadata:
    llm_enabled_config: bool
    llm_base_url: str
    llm_model: str
    llm_provider: str | None
    llm_request_attempted: bool
    llm_request_count: int
    llm_http_status: int | None
    llm_response_received: bool
    llm_real_call_verified: bool
    llm_failure_reason: str | None
    llm_provenance: str
    llm_request_id_hash: str | None
    llm_token_usage: dict[str, Any] | None
    prompt_sha256: str | None
    response_sha256: str | None
    generated_by: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LLMCallError(RuntimeError):
    def __init__(self, message: str, metadata: LLMCallMetadata):
        super().__init__(message)
        self.metadata = metadata


def build_non_llm_metadata(
    *,
    generated_by: str,
    failure_reason: str | None,
    provenance: str = "fallback_non_llm",
    prompt_sha256: str | None = None,
) -> LLMCallMetadata:
    return LLMCallMetadata(
        llm_enabled_config=settings.llm_enabled,
        llm_base_url=settings.llm_base_url.rstrip("/"),
        llm_model=settings.llm_model,
        llm_provider=parse.urlparse(settings.llm_base_url).hostname,
        llm_request_attempted=False,
        llm_request_count=0,
        llm_http_status=None,
        llm_response_received=False,
        llm_real_call_verified=False,
        llm_failure_reason=failure_reason,
        llm_provenance=provenance,
        llm_request_id_hash=None,
        llm_token_usage=None,
        prompt_sha256=prompt_sha256,
        response_sha256=None,
        generated_by=generated_by,
    )


class LLMClient:
    def __init__(self) -> None:
        self.base_url = settings.llm_base_url.rstrip("/")
        self.api_key = settings.llm_api_key
        self.model = settings.llm_model

    def enabled(self) -> bool:
        return settings.llm_enabled and bool(self.api_key)

    def _endpoint(self) -> str:
        return parse.urljoin(f"{self.base_url}/", "chat/completions")

    def chat_with_metadata(
        self,
        messages: list[dict[str, Any]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout_seconds: int | None = None,
        max_retries: int | None = None,
        generated_by: str = "unknown",
    ) -> tuple[dict[str, Any], LLMCallMetadata]:
        prompt_sha256 = _sha256_text(json.dumps(messages, ensure_ascii=False, sort_keys=True))
        metadata = build_non_llm_metadata(
            generated_by=generated_by,
            failure_reason=None,
            provenance="fallback_non_llm",
            prompt_sha256=prompt_sha256,
        )
        if not self.enabled():
            metadata.llm_failure_reason = "LLM is disabled or API key is missing"
            raise LLMCallError(metadata.llm_failure_reason, metadata)

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": settings.llm_temperature if temperature is None else temperature,
        }
        effective_max_tokens = settings.llm_max_tokens if max_tokens is None else max_tokens
        if effective_max_tokens is not None:
            payload["max_tokens"] = effective_max_tokens
        else:
            logger.info("seed LLM request model=%s max_tokens omitted", self.model)
        body = json.dumps(payload).encode("utf-8")
        endpoint = self._endpoint()
        effective_timeout_seconds = (
            settings.llm_timeout_seconds if timeout_seconds is None else max(1, int(timeout_seconds))
        )
        effective_max_retries = (
            settings.llm_max_retries if max_retries is None else max(0, int(max_retries))
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        metadata.llm_request_attempted = True

        for attempt in range(effective_max_retries + 1):
            metadata.llm_request_count += 1
            try:
                req = request.Request(endpoint, data=body, headers=headers, method="POST")
                with request.urlopen(req, timeout=effective_timeout_seconds) as response:
                    raw = response.read().decode("utf-8")
                    metadata.llm_http_status = response.status
                    metadata.llm_response_received = True
                    metadata.llm_real_call_verified = True
                    metadata.llm_provenance = "real_llm"
                    metadata.response_sha256 = _sha256_text(raw)
                    try:
                        parsed_payload = json.loads(raw)
                    except json.JSONDecodeError:
                        parsed_payload = {}
                    response_id = parsed_payload.get("id")
                    metadata.llm_request_id_hash = (
                        _sha256_text(str(response_id)) if response_id else None
                    )
                    usage = parsed_payload.get("usage")
                    metadata.llm_token_usage = usage if isinstance(usage, dict) else None
                    logger.info(
                        "seed LLM request succeeded model=%s status=%s attempt=%s",
                        self.model,
                        response.status,
                        attempt + 1,
                    )
                    return parsed_payload, metadata
            except error.HTTPError as exc:
                status = exc.code
                raw_error = exc.read().decode("utf-8", "ignore")[:500]
                metadata.llm_http_status = status
                metadata.llm_response_received = True
                metadata.llm_real_call_verified = True
                metadata.llm_provenance = "real_llm"
                metadata.response_sha256 = _sha256_text(raw_error)
                metadata.llm_failure_reason = f"LLM HTTP error status={status} body={raw_error}"
                logger.warning(
                    "seed LLM request failed model=%s status=%s attempt=%s",
                    self.model,
                    status,
                    attempt + 1,
                )
                if status in {429, 500, 502, 503, 504} and attempt < effective_max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise LLMCallError(metadata.llm_failure_reason, metadata) from exc
            except TimeoutError as exc:
                metadata.llm_failure_reason = (
                    f"LLM timeout error after {effective_timeout_seconds}s: {exc}"
                )
                metadata.llm_response_received = False
                logger.warning("seed LLM timeout model=%s attempt=%s", self.model, attempt + 1)
                if attempt < effective_max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise LLMCallError(metadata.llm_failure_reason, metadata) from exc
            except error.URLError as exc:
                metadata.llm_failure_reason = f"LLM network error: {exc}"
                logger.warning("seed LLM network error model=%s attempt=%s", self.model, attempt + 1)
                if attempt < effective_max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise LLMCallError(metadata.llm_failure_reason, metadata) from exc
            except OSError as exc:
                metadata.llm_failure_reason = (
                    f"LLM transport error: {exc.__class__.__name__}: {exc}"
                )
                logger.warning("seed LLM transport error model=%s attempt=%s", self.model, attempt + 1)
                if attempt < effective_max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise LLMCallError(metadata.llm_failure_reason, metadata) from exc

        metadata.llm_failure_reason = "LLM request exhausted retries"
        raise LLMCallError(metadata.llm_failure_reason, metadata)

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        generated_by: str = "unknown",
    ) -> dict[str, Any]:
        payload, _metadata = self.chat_with_metadata(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            generated_by=generated_by,
        )
        return payload


def extract_content(response_payload: dict[str, Any]) -> str:
    choices = response_payload.get("choices", [])
    if not choices:
        raise RuntimeError("LLM response did not contain choices")
    message = choices[0].get("message", {})
    content = message.get("content", "")
    if isinstance(content, list):
        texts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(item.get("text", ""))
        content = "\n".join(texts)
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("LLM response content was empty")
    return content

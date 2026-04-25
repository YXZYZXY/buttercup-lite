from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Final
from urllib.parse import ParseResult, urlparse, urlunparse
from uuid import uuid4

from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


class QueueNames:
    DOWNLOAD: Final[str] = "q.tasks.download"
    READY: Final[str] = "q.tasks.ready"
    COVERAGE_FEEDBACK: Final[str] = "q.tasks.coverage_feedback"
    CAMPAIGN: Final[str] = "q.tasks.campaign"
    BINARY_ANALYSIS: Final[str] = "q.tasks.binary_analysis"
    BINARY_SEED: Final[str] = "q.tasks.binary_seed"
    BINARY_EXECUTION: Final[str] = "q.tasks.binary_execution"
    PROTOCOL_EXECUTION: Final[str] = "q.tasks.protocol_execution"
    PATCH: Final[str] = "q.tasks.patch"
    INDEX: Final[str] = "q.tasks.index"
    BUILD: Final[str] = "q.tasks.build"
    SEED: Final[str] = "q.tasks.seed"
    FUZZ: Final[str] = "q.tasks.fuzz"
    TRACE: Final[str] = "q.tasks.trace"
    REPRO: Final[str] = "q.tasks.repro"


class RedisQueue:
    def __init__(
        self,
        redis_url: str,
        *,
        default_lease_ttl: int = 300,
        max_retry: int = 3,
    ) -> None:
        self.redis_url = redis_url
        self.default_lease_ttl = max(60, int(default_lease_ttl))
        self.max_retry = max(0, int(max_retry))
        self._candidate_urls = self._build_candidate_urls(redis_url)
        self._client: Redis | None = None
        self._active_url: str | None = None
        self._claim_cache: dict[str, dict[str, list[str]]] = {}

    def _build_candidate_urls(self, redis_url: str) -> list[str]:
        candidates = [redis_url]
        parsed = urlparse(redis_url)
        if parsed.hostname != "redis":
            return candidates
        for fallback_host in ("127.0.0.1", "localhost"):
            fallback = self._replace_url_host(parsed, fallback_host)
            if fallback not in candidates:
                candidates.append(fallback)
        return candidates

    def _replace_url_host(self, parsed: ParseResult, host: str) -> str:
        auth = ""
        if parsed.username:
            auth = parsed.username
            if parsed.password:
                auth = f"{auth}:{parsed.password}"
            auth = f"{auth}@"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunparse(parsed._replace(netloc=f"{auth}{host}{port}"))

    def _get_client(self) -> Redis:
        if self._client is not None:
            return self._client
        last_error: Exception | None = None
        for url in self._candidate_urls:
            client = Redis.from_url(url, decode_responses=True)
            try:
                client.ping()
            except RedisConnectionError as exc:
                last_error = exc
                continue
            self._client = client
            self._active_url = url
            return client
        if last_error is not None:
            raise last_error
        self._client = Redis.from_url(self.redis_url, decode_responses=True)
        self._active_url = self.redis_url
        return self._client

    def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        try:
            client = self._get_client()
            return getattr(client, method)(*args, **kwargs)
        except RedisConnectionError:
            self._client = None
            self._active_url = None
            client = self._get_client()
            return getattr(client, method)(*args, **kwargs)

    def _processing_queue_key(self, queue_name: str) -> str:
        return f"{queue_name}:processing"

    def _lease_hash_key(self, queue_name: str) -> str:
        return f"{queue_name}:processing:leases"

    def _dead_letter_queue_key(self, queue_name: str) -> str:
        return f"{queue_name}:dead"

    def _deserialize_item(self, queue_name: str, raw_item: str) -> dict[str, Any]:
        try:
            payload = json.loads(raw_item)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict) and "item_id" in payload and "payload" in payload:
            normalized = dict(payload)
            normalized.setdefault("queue_name", queue_name)
            normalized.setdefault("created_at", _now_iso())
            normalized.setdefault("retry_count", 0)
            return normalized
        return {
            "item_id": str(uuid4()),
            "payload": raw_item,
            "queue_name": queue_name,
            "created_at": _now_iso(),
            "retry_count": 0,
        }

    def _serialize_item(
        self,
        *,
        queue_name: str,
        payload: str,
        item_id: str | None = None,
        created_at: str | None = None,
        retry_count: int = 0,
        ack_state: str = "pending",
        lease_owner: str | None = None,
        lease_until: str | None = None,
        last_claimed_at: str | None = None,
        dead_lettered_at: str | None = None,
    ) -> str:
        return _json_dumps(
            {
                "item_id": item_id or str(uuid4()),
                "payload": payload,
                "queue_name": queue_name,
                "created_at": created_at or _now_iso(),
                "retry_count": int(retry_count),
                "ack_state": ack_state,
                "lease_owner": lease_owner,
                "lease_until": lease_until,
                "last_claimed_at": last_claimed_at,
                "dead_lettered_at": dead_lettered_at,
            }
        )

    def _remember_claim(self, queue_name: str, payload: str, item_id: str) -> None:
        queue_cache = self._claim_cache.setdefault(queue_name, {})
        payload_cache = queue_cache.setdefault(payload, [])
        payload_cache.append(item_id)
        if len(payload_cache) > 8:
            del payload_cache[:-8]

    def _forget_claim(self, queue_name: str, payload: str, item_id: str) -> None:
        queue_cache = self._claim_cache.get(queue_name) or {}
        payload_cache = queue_cache.get(payload) or []
        queue_cache[payload] = [candidate for candidate in payload_cache if candidate != item_id]
        if not queue_cache[payload]:
            queue_cache.pop(payload, None)
        if not queue_cache:
            self._claim_cache.pop(queue_name, None)

    def _resolve_claim_record(self, queue_name: str, item_or_payload: str) -> tuple[str | None, dict[str, Any] | None]:
        candidate = str(item_or_payload or "").strip()
        if not candidate:
            return None, None
        leases_key = self._lease_hash_key(queue_name)
        direct = self._call("hget", leases_key, candidate)
        if direct:
            return candidate, json.loads(direct)
        queue_cache = self._claim_cache.get(queue_name) or {}
        cached_ids = list(queue_cache.get(candidate) or [])
        for item_id in reversed(cached_ids):
            cached_raw = self._call("hget", leases_key, item_id)
            if cached_raw:
                return item_id, json.loads(cached_raw)
        for item_id, raw_record in (self._call("hgetall", leases_key) or {}).items():
            record = json.loads(raw_record)
            if str(record.get("payload") or "") == candidate:
                return item_id, record
        return None, None

    def ping(self) -> bool:
        return bool(self._call("ping"))

    def push(self, queue_name: str, payload: str) -> int:
        raw_input = str(payload)
        envelope = self._deserialize_item(queue_name, raw_input)
        if (
            envelope.get("payload") == raw_input
            and str(envelope.get("item_id") or "").strip()
            and raw_input[:1] != "{"
        ):
            raw_payload = self._serialize_item(
                queue_name=queue_name,
                payload=str(envelope.get("payload") or ""),
                item_id=str(envelope.get("item_id") or ""),
                created_at=str(envelope.get("created_at") or _now_iso()),
                retry_count=int(envelope.get("retry_count") or 0),
                ack_state=str(envelope.get("ack_state") or "pending"),
                lease_owner=str(envelope.get("lease_owner") or "") or None,
                lease_until=str(envelope.get("lease_until") or "") or None,
                last_claimed_at=str(envelope.get("last_claimed_at") or "") or None,
                dead_lettered_at=str(envelope.get("dead_lettered_at") or "") or None,
            )
        else:
            raw_payload = _json_dumps(envelope)
        return int(self._call("rpush", queue_name, raw_payload))

    def claim(
        self,
        queue_name: str,
        *,
        lease_ttl: int = 300,
        timeout: int = 2,
        lease_owner: str | None = None,
    ) -> dict[str, Any] | None:
        self.recover_stale_leases(queue_name)
        ttl = max(60, int(lease_ttl or self.default_lease_ttl))
        pending_key = queue_name
        processing_key = self._processing_queue_key(queue_name)
        if int(timeout) > 0:
            raw_item = self._call("brpoplpush", pending_key, processing_key, timeout=int(timeout))
        else:
            raw_item = self._call("rpoplpush", pending_key, processing_key)
        if raw_item is None:
            return None
        envelope = self._deserialize_item(queue_name, str(raw_item))
        claimed_at = _now_iso()
        lease_until = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() + ttl,
            timezone.utc,
        ).isoformat()
        record = {
            **envelope,
            "queue_name": queue_name,
            "ack_state": "processing",
            "lease_owner": lease_owner,
            "lease_until": lease_until,
            "last_claimed_at": claimed_at,
            "raw_item": str(raw_item),
        }
        self._call("hset", self._lease_hash_key(queue_name), record["item_id"], _json_dumps(record))
        self._remember_claim(queue_name, str(record.get("payload") or ""), str(record.get("item_id") or ""))
        return dict(record)

    def pop(self, queue_name: str, timeout: int = 2) -> str | None:
        record = self.claim(queue_name, lease_ttl=self.default_lease_ttl, timeout=timeout)
        if not record:
            return None
        return str(record.get("payload") or "")

    def ack(self, queue_name: str, payload: str) -> None:
        item_id, record = self._resolve_claim_record(queue_name, payload)
        if not item_id or not record:
            return None
        processing_key = self._processing_queue_key(queue_name)
        raw_item = str(record.get("raw_item") or "")
        pipe = self._get_client().pipeline()
        if raw_item:
            pipe.lrem(processing_key, 1, raw_item)
        pipe.hdel(self._lease_hash_key(queue_name), item_id)
        pipe.execute()
        self._forget_claim(queue_name, str(record.get("payload") or ""), item_id)
        return None

    def nack(self, queue_name: str, item_id: str) -> dict[str, Any] | None:
        resolved_item_id, record = self._resolve_claim_record(queue_name, item_id)
        if not resolved_item_id or not record:
            return None
        return self._requeue_or_dead_letter(
            queue_name,
            resolved_item_id,
            record,
            recovery_reason="nack",
        )

    def recover_stale_leases(self, queue_name: str) -> dict[str, Any]:
        leases = self._call("hgetall", self._lease_hash_key(queue_name)) or {}
        if not leases:
            return {"recovered": [], "dead_lettered": []}
        now = datetime.now(timezone.utc)
        recovered: list[dict[str, Any]] = []
        dead_lettered: list[dict[str, Any]] = []
        for item_id, raw_record in leases.items():
            record = json.loads(raw_record)
            lease_until = _parse_iso(record.get("lease_until"))
            if lease_until is None or lease_until >= now:
                continue
            outcome = self._requeue_or_dead_letter(
                queue_name,
                item_id,
                record,
                recovery_reason="lease_expired",
            )
            if not outcome:
                continue
            if str(outcome.get("ack_state") or "") == "dead":
                dead_lettered.append(outcome)
            else:
                recovered.append(outcome)
        return {
            "recovered": recovered,
            "dead_lettered": dead_lettered,
        }

    def _requeue_or_dead_letter(
        self,
        queue_name: str,
        item_id: str,
        record: dict[str, Any],
        *,
        recovery_reason: str,
    ) -> dict[str, Any]:
        payload = str(record.get("payload") or "")
        retry_count = int(record.get("retry_count") or 0) + 1
        raw_item = str(record.get("raw_item") or "")
        processing_key = self._processing_queue_key(queue_name)
        lease_key = self._lease_hash_key(queue_name)
        if retry_count > self.max_retry:
            dead_payload = self._serialize_item(
                queue_name=queue_name,
                payload=payload,
                item_id=item_id,
                created_at=str(record.get("created_at") or _now_iso()),
                retry_count=retry_count,
                ack_state="dead",
                dead_lettered_at=_now_iso(),
            )
            pipe = self._get_client().pipeline()
            if raw_item:
                pipe.lrem(processing_key, 1, raw_item)
            pipe.hdel(lease_key, item_id)
            pipe.rpush(self._dead_letter_queue_key(queue_name), dead_payload)
            pipe.execute()
            self._forget_claim(queue_name, payload, item_id)
            return {
                **record,
                "retry_count": retry_count,
                "ack_state": "dead",
                "dead_letter_queue": self._dead_letter_queue_key(queue_name),
                "recovery_reason": recovery_reason,
            }
        pending_payload = self._serialize_item(
            queue_name=queue_name,
            payload=payload,
            item_id=item_id,
            created_at=str(record.get("created_at") or _now_iso()),
            retry_count=retry_count,
            ack_state="pending",
        )
        pipe = self._get_client().pipeline()
        if raw_item:
            pipe.lrem(processing_key, 1, raw_item)
        pipe.hdel(lease_key, item_id)
        pipe.rpush(queue_name, pending_payload)
        pipe.execute()
        self._forget_claim(queue_name, payload, item_id)
        return {
            **record,
            "retry_count": retry_count,
            "ack_state": "pending",
            "recovery_reason": recovery_reason,
        }

    def renew_lease(
        self,
        queue_name: str,
        item_id: str,
        *,
        lease_ttl: int | None = None,
        lease_owner: str | None = None,
    ) -> dict[str, Any] | None:
        resolved_item_id, record = self._resolve_claim_record(queue_name, item_id)
        if not resolved_item_id or not record:
            return None
        ttl = max(60, int(lease_ttl or self.default_lease_ttl))
        updated = {
            **record,
            "ack_state": "processing",
            "lease_owner": lease_owner if lease_owner is not None else record.get("lease_owner"),
            "lease_until": datetime.fromtimestamp(
                datetime.now(timezone.utc).timestamp() + ttl,
                timezone.utc,
            ).isoformat(),
        }
        self._call("hset", self._lease_hash_key(queue_name), resolved_item_id, _json_dumps(updated))
        return updated

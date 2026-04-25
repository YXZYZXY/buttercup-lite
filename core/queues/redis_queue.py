from typing import Final

from redis import Redis


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
    def __init__(self, redis_url: str):
        self.client = Redis.from_url(redis_url, decode_responses=True)

    def ping(self) -> bool:
        return bool(self.client.ping())

    def push(self, queue_name: str, payload: str) -> int:
        return int(self.client.rpush(queue_name, payload))

    def pop(self, queue_name: str, timeout: int = 2) -> str | None:
        item = self.client.blpop(queue_name, timeout=timeout)
        if item is None:
            return None
        _, payload = item
        return payload

    def ack(self, queue_name: str, payload: str) -> None:
        _ = (queue_name, payload)
        return None

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from core.models.task import TaskRecord, TaskSpec, TaskStatus
from core.state.task_state import TaskStateStore
from core.storage.layout import create_task_layout, task_root
from core.utils.settings import parse_bool_env, parse_float_value, parse_int_value, parse_optional_int_value, settings

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_ROOT = REPO_ROOT / "reports"
BENCHMARKS_ROOT = Path("/home/buttercup2/Project/benchmarks")
OSS_FUZZ_ROOT = Path("/home/buttercup2/Project/oss-fuzz/oss-fuzz")
SOURCE_DONOR_TASK_ID = "d15e7148-1f38-4536-9487-d6346e07afb6"
PURE_BINARY_DONOR_TASK_ID = "ee48d355-ce4c-4417-87a4-81fb415c4fd2"


class LocalQueue:
    def __init__(self) -> None:
        self.pushed: list[tuple[str, str]] = []
        self.acked: list[tuple[str, str]] = []

    def push(self, queue_name: str, payload: str) -> int:
        self.pushed.append((queue_name, payload))
        return len(self.pushed)

    def ack(self, queue_name: str, payload: str) -> None:
        self.acked.append((queue_name, payload))


def configure_llm_from_env() -> dict[str, Any]:
    api_key = os.getenv("LLM_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("LLM_API_KEY is required in the environment for real LLM verification")

    settings.llm_enabled = parse_bool_env(os.getenv("LLM_ENABLED"), default=True)
    settings.llm_base_url = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1").rstrip("/")
    settings.llm_api_key = api_key
    settings.llm_model = os.getenv("LLM_MODEL", "deepseek-chat")
    settings.llm_timeout_seconds = parse_int_value(os.getenv("LLM_TIMEOUT_SECONDS"), settings.llm_timeout_seconds)
    settings.llm_max_retries = parse_int_value(os.getenv("LLM_MAX_RETRIES"), settings.llm_max_retries)
    settings.llm_temperature = parse_float_value(os.getenv("LLM_TEMPERATURE"), settings.llm_temperature)
    settings.llm_max_tokens = parse_optional_int_value(os.getenv("LLM_MAX_TOKENS"))
    return {
        "llm_enabled": settings.llm_enabled,
        "llm_base_url": settings.llm_base_url,
        "llm_model": settings.llm_model,
        "llm_max_tokens": settings.llm_max_tokens,
    }


def create_task_with_layout(task_spec: TaskSpec, *, status: TaskStatus) -> tuple[TaskStateStore, TaskRecord]:
    task_store = TaskStateStore()
    record = task_store.create_task(task_spec, status=status)
    layout = create_task_layout(record.task_id)
    record = task_store.update_task(record.task_id, layout=layout)
    return task_store, record


def write_report(name: str, payload: dict[str, Any]) -> Path:
    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    path = REPORTS_ROOT / name
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def donor_task_root(task_id: str) -> Path:
    return task_root(task_id)


def host_path(path_str: str) -> Path:
    path = Path(path_str)
    if path.exists():
        return path
    prefix = "/data/tasks/"
    if path_str.startswith(prefix):
        return REPO_ROOT / "data" / "tasks" / path_str[len(prefix) :]
    return path

import json
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
from pathlib import Path
from typing import Any

from core.models.task import ExecutionMode, TaskRecord, TaskSpec, TaskStatus
from core.source_task import normalize_task_spec_for_repo_first
from core.storage.layout import ensure_task_root, task_json_path, task_root


class TaskStateStore:
    def now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    @contextmanager
    def task_lock(self, task_id: str):
        path = task_json_path(task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.with_suffix(".lock")
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _save_task_unlocked(self, record: TaskRecord) -> TaskRecord:
        record.updated_at = self.now()
        path = task_json_path(record.task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(record.model_dump(mode="json"), indent=2), encoding="utf-8")
        temp_path.replace(path)
        return record

    def _load_task_unlocked(self, task_id: str) -> TaskRecord:
        path = task_json_path(task_id)
        if not path.exists():
            raise FileNotFoundError(task_id)
        return TaskRecord.model_validate_json(path.read_text(encoding="utf-8"))

    def create_task(self, task_spec: TaskSpec, status: TaskStatus) -> TaskRecord:
        normalized_spec = normalize_task_spec_for_repo_first(task_spec)
        record = TaskRecord.new(normalized_spec, task_dir="", status=status)
        real_root = ensure_task_root(record.task_id)
        record.task_dir = str(real_root)
        self.save_task(record)
        return record

    def save_task(self, record: TaskRecord) -> TaskRecord:
        with self.task_lock(record.task_id):
            return self._save_task_unlocked(record)

    def load_task(self, task_id: str) -> TaskRecord:
        with self.task_lock(task_id):
            return self._load_task_unlocked(task_id)

    def update_task(
        self,
        task_id: str,
        *,
        status: TaskStatus | None = None,
        execution_mode: ExecutionMode | None = None,
        layout: dict[str, str] | None = None,
        runtime: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TaskRecord:
        with self.task_lock(task_id):
            record = self._load_task_unlocked(task_id)
            if status is not None:
                record.status = status
            if execution_mode is not None:
                record.execution_mode = execution_mode
            if layout is not None:
                record.layout.update(layout)
            if runtime is not None:
                record.runtime.update(runtime)
            if metadata is not None:
                record.metadata.update(metadata)
            record.task_dir = str(task_root(task_id))
            return self._save_task_unlocked(record)

    def update_runtime(self, task_id: str, runtime_patch: dict[str, Any]) -> TaskRecord:
        with self.task_lock(task_id):
            record = self._load_task_unlocked(task_id)
            record.runtime.update(runtime_patch)
            return self._save_task_unlocked(record)

    def update_status(
        self,
        task_id: str,
        status: TaskStatus,
        runtime_patch: dict[str, Any] | None = None,
    ) -> TaskRecord:
        with self.task_lock(task_id):
            record = self._load_task_unlocked(task_id)
            record.status = status
            if runtime_patch:
                record.runtime.update(runtime_patch)
            return self._save_task_unlocked(record)

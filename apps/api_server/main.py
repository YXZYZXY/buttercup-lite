from fastapi import FastAPI, HTTPException

from core.models.task import TaskRecord, TaskSpec, TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.state.task_state import TaskStateStore
from core.utils.settings import settings

app = FastAPI(title="buttercup-lite api")

task_store = TaskStateStore()
queue = RedisQueue(settings.redis_url)


@app.get("/health")
def health() -> dict[str, str]:
    queue.ping()
    return {"status": "ok"}


@app.post("/tasks", response_model=TaskRecord)
def create_task(task_spec: TaskSpec) -> TaskRecord:
    record = task_store.create_task(task_spec, status=TaskStatus.QUEUED_DOWNLOAD)
    queue.push(QueueNames.DOWNLOAD, record.task_id)
    updated = task_store.update_task(
        record.task_id,
        runtime={
            **record.runtime,
            "download_queue_name": QueueNames.DOWNLOAD,
            "download_queued_at": record.updated_at,
        },
    )
    return updated


@app.get("/tasks/{task_id}", response_model=TaskRecord)
def get_task(task_id: str) -> TaskRecord:
    try:
        return task_store.load_task(task_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"task {task_id} not found") from exc

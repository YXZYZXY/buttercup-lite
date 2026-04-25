import logging
import time

from core.models.task import TaskStatus
from core.buttercup_compat.program_model import LiteCodeQueryView
from core.program_model.code_index import build_index
from core.program_model.index_request import IndexRequest
from core.program_model_backends import (
    write_program_model_backend_manifest,
    write_program_model_query_validation_manifests,
)
from core.queues.redis_queue import QueueNames, RedisQueue
from core.seed.queue import maybe_enqueue_seed
from core.state.task_state import TaskStateStore
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("program-model-worker")


def _base_index_runtime_patch(*, request: IndexRequest, manifest: dict, generated_at: str) -> dict:
    return {
        "index_completed_at": generated_at,
        "index_dir": str(request.index_dir),
        "index_mode": manifest["mode"],
        "index_artifacts": manifest["artifacts"],
        "index_manifest_path": str(request.index_dir / "manifest.json"),
        "source_file_count": manifest["source_file_count"],
        "symbol_count": manifest["symbol_count"],
        "function_fact_count": manifest.get("function_fact_count", 0),
        "type_fact_count": manifest.get("type_fact_count", 0),
    }


def _program_model_enrichment_runtime_patch(
    *,
    query_manifest_path,
    backend_manifest: dict,
    validation_manifest: dict,
    generated_at: str,
) -> dict:
    return {
        "program_model_enrichment_completed_at": generated_at,
        "program_model_query_manifest_path": str(query_manifest_path),
        "program_model_backend_manifest_path": backend_manifest["program_model_backend_manifest_path"],
        "program_model_query_validation_manifest_path": validation_manifest["program_model_query_validation_manifest_path"],
        "query_capability_matrix_path": validation_manifest["query_capability_matrix_path"],
        "sample_query_results_path": validation_manifest["sample_query_results_path"],
        "tree_sitter_backend_manifest_path": backend_manifest.get("tree_sitter_backend_manifest_path"),
        "typed_query_results_path": backend_manifest.get("typed_query_results_path"),
        "program_model_backend": backend_manifest["backend"],
        "program_model_semantics": "CodeQueryPersistent-oriented query backend with explicit artifact provenance",
    }


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("program-model received task %s", task_id)
    task_store.update_status(
        task_id,
        TaskStatus.INDEXING,
        runtime_patch={"index_started_at": task_store.now()},
    )

    task = task_store.load_task(task_id)
    request = IndexRequest.from_task(task)
    manifest = build_index(request)
    indexed_at = task_store.now()
    task_store.update_status(
        task_id,
        TaskStatus.INDEXED,
        runtime_patch=_base_index_runtime_patch(
            request=request,
            manifest=manifest,
            generated_at=indexed_at,
        ),
    )
    if maybe_enqueue_seed(task_id, task_store, queue):
        logger.info("task %s base index ready and seed queued", task_id)
    else:
        logger.info("task %s base index ready; seed still waiting on other prerequisites", task_id)

    enrichment_started_at = task_store.now()
    task_store.update_runtime(
        task_id,
        {"program_model_enrichment_started_at": enrichment_started_at},
    )

    try:
        query_view = LiteCodeQueryView.from_task(task_id)
        backend_manifest = write_program_model_backend_manifest(
            task_id,
            generated_at=task_store.now(),
            source_manifest=manifest,
            function_facts=query_view.function_facts,
            type_facts=query_view.type_facts,
        )
        validation_manifest = write_program_model_query_validation_manifests(
            task_id,
            generated_at=task_store.now(),
            function_facts=query_view.function_facts,
            type_facts=query_view.type_facts,
            backend_manifest=backend_manifest,
        )
        query_manifest_path = query_view.write_manifest(
            generated_at=task_store.now(),
            source_manifest=manifest,
            backend_manifest=backend_manifest,
        )
    except Exception as exc:
        logger.warning("task %s index enrichment degraded: %s", task_id, exc, exc_info=True)
        task_store.update_runtime(
            task_id,
            {
                "program_model_enrichment_status": "DEGRADED",
                "program_model_enrichment_error": str(exc),
                "program_model_enrichment_failed_at": task_store.now(),
            },
        )
        queue.ack(QueueNames.INDEX, task_id)
        return

    task_store.update_runtime(
        task_id,
        _program_model_enrichment_runtime_patch(
            query_manifest_path=query_manifest_path,
            backend_manifest=backend_manifest,
            validation_manifest=validation_manifest,
            generated_at=task_store.now(),
        ),
    )
    queue.ack(QueueNames.INDEX, task_id)
    logger.info("task %s indexed successfully with enrichment manifests", task_id)


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("program-model worker started")
    while True:
        task_id = queue.pop(QueueNames.INDEX, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("program-model failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.INDEX_FAILED,
                runtime_patch={"index_error": str(exc), "index_failed_at": task_store.now()},
            )
            queue.ack(QueueNames.INDEX, task_id)


if __name__ == "__main__":
    main()

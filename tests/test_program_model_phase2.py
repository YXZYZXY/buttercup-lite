import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.workers.builder.main import process_task as process_build_task
from apps.workers.program_model.main import process_task as process_index_task
from apps.workers.scheduler.main import process_task as process_scheduler_task
from core.models.task import AdapterType, ExecutionMode, TaskSource, TaskSpec, TaskStatus
from core.queues.redis_queue import QueueNames
from core.state.task_state import TaskStateStore
from core.storage.layout import create_task_layout
from core.utils.settings import settings


class FakeQueue:
    def __init__(self) -> None:
        self.pushed: list[tuple[str, str]] = []
        self.acked: list[tuple[str, str]] = []

    def push(self, queue_name: str, payload: str) -> int:
        self.pushed.append((queue_name, payload))
        return len(self.pushed)

    def ack(self, queue_name: str, payload: str) -> None:
        self.acked.append((queue_name, payload))


class Phase2ProgramModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_root_original = settings.data_root
        self.scheduler_hold_original = settings.scheduler_ready_hold_seconds
        settings.data_root = str(Path(self.temp_dir.name) / "tasks")
        settings.scheduler_ready_hold_seconds = 0
        self.task_store = TaskStateStore()

    def tearDown(self) -> None:
        settings.data_root = self.data_root_original
        settings.scheduler_ready_hold_seconds = self.scheduler_hold_original
        self.temp_dir.cleanup()

    def _create_task(self, *, metadata: dict | None = None, source_uri: str = "memory://task"):
        spec = TaskSpec(
            source=TaskSource(adapter_type=AdapterType.OSSFUZZ, uri=source_uri),
            metadata=metadata or {},
        )
        record = self.task_store.create_task(spec, status=TaskStatus.READY)
        layout = create_task_layout(record.task_id)
        self.task_store.update_task(record.task_id, layout=layout, status=TaskStatus.READY)
        return self.task_store.load_task(record.task_id)

    def test_scheduler_enqueues_index_and_build(self) -> None:
        with tempfile.TemporaryDirectory() as external_src_dir, tempfile.TemporaryDirectory() as build_out_dir:
            external_src = Path(external_src_dir)
            build_out = Path(build_out_dir)
            (external_src / "demo.c").write_text("int demo(void) { return 1; }\n", encoding="utf-8")
            executable = build_out / "demo_fuzzer"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            record = self._create_task(
                metadata={
                    "existing_src_path": str(external_src),
                    "existing_index_path": str(external_src),
                    "existing_build_out_path": str(build_out),
                    "existing_corpus_path": str(external_src),
                    "existing_valid_crashes_path": str(external_src),
                },
            )
            queue = FakeQueue()

            process_scheduler_task(record.task_id, self.task_store, queue)

            updated = self.task_store.load_task(record.task_id)
            execution_plan_path = Path(updated.runtime["execution_plan_path"])
            import_manifest_path = Path(updated.runtime["import_manifest_path"])
            self.assertEqual(updated.status, TaskStatus.QUEUED_INDEX)
            self.assertEqual(updated.execution_mode, ExecutionMode.IMPORT_ASSISTED)
            self.assertIn((QueueNames.INDEX, record.task_id), queue.pushed)
            self.assertIn((QueueNames.BUILD, record.task_id), queue.pushed)
            self.assertTrue(execution_plan_path.exists())
            self.assertTrue(import_manifest_path.exists())

    def test_program_model_generates_manifest(self) -> None:
        record = self._create_task()
        source_file = Path(record.layout["src"]) / "demo.c"
        source_file.write_text("int demo(void) {\n  return 1;\n}\n", encoding="utf-8")
        self.task_store.update_status(record.task_id, TaskStatus.QUEUED_INDEX)
        queue = FakeQueue()

        process_index_task(record.task_id, self.task_store, queue)

        updated = self.task_store.load_task(record.task_id)
        manifest_path = Path(updated.runtime["index_manifest_path"])
        self.assertEqual(updated.status, TaskStatus.INDEXED)
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["mode"], "fresh")
        self.assertGreaterEqual(manifest["source_file_count"], 1)

    def test_existing_src_path_is_imported(self) -> None:
        with tempfile.TemporaryDirectory() as external_src_dir:
            external_src = Path(external_src_dir)
            (external_src / "imported.c").write_text("int imported(void) {\n  return 7;\n}\n", encoding="utf-8")
            record = self._create_task(metadata={"existing_src_path": str(external_src)})
            scheduler_queue = FakeQueue()
            process_scheduler_task(record.task_id, self.task_store, scheduler_queue)
            queue = FakeQueue()

            process_index_task(record.task_id, self.task_store, queue)

            updated = self.task_store.load_task(record.task_id)
            imported_copy = Path(updated.layout["src"]) / "imported.c"
            manifest = json.loads(Path(updated.runtime["index_manifest_path"]).read_text(encoding="utf-8"))
            self.assertTrue(imported_copy.exists())
            self.assertEqual(updated.status, TaskStatus.INDEXED)
            self.assertEqual(manifest["mode"], "hybrid")
            self.assertIn("current", manifest["imported_from"]["src"])

    def test_existing_index_path_is_imported(self) -> None:
        with tempfile.TemporaryDirectory() as external_index_dir:
            external_index = Path(external_index_dir)
            (external_index / "tags").write_text(
                "!_TAG_FILE_FORMAT\t2\t/extended format/\n"
                "imported_fn\tdemo.c\t/^int imported_fn(void) {$/;\"\tf\tline:1\n",
                encoding="utf-8",
            )
            (external_index / "cscope.files").write_text("/tmp/demo.c\n", encoding="utf-8")
            (external_index / "codequery.db").write_text("placeholder", encoding="utf-8")
            record = self._create_task(metadata={"existing_index_path": str(external_index)})
            scheduler_queue = FakeQueue()
            process_scheduler_task(record.task_id, self.task_store, scheduler_queue)
            queue = FakeQueue()

            process_index_task(record.task_id, self.task_store, queue)

            updated = self.task_store.load_task(record.task_id)
            manifest = json.loads(Path(updated.runtime["index_manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(updated.status, TaskStatus.INDEXED)
            self.assertTrue((Path(updated.layout["index"]) / "codequery.db").exists())
            self.assertEqual(manifest["mode"], "import_assisted")
            self.assertIn("current", manifest["imported_from"]["index"])

    def test_missing_tools_still_generates_degraded_manifest(self) -> None:
        record = self._create_task()
        source_file = Path(record.layout["src"]) / "fallback.c"
        source_file.write_text("int fallback(void) {\n  return 0;\n}\n", encoding="utf-8")
        self.task_store.update_status(record.task_id, TaskStatus.QUEUED_INDEX)
        queue = FakeQueue()

        with patch("core.program_model.code_index.shutil.which", return_value=None):
            process_index_task(record.task_id, self.task_store, queue)

        updated = self.task_store.load_task(record.task_id)
        manifest = json.loads(Path(updated.runtime["index_manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(updated.status, TaskStatus.INDEXED)
        self.assertFalse(manifest["tools"]["ctags"]["available"])
        self.assertTrue((Path(updated.layout["index"]) / "symbols.json").exists())

    def test_builder_scans_imported_build_out(self) -> None:
        with tempfile.TemporaryDirectory() as build_out_dir, tempfile.TemporaryDirectory() as harness_dir:
            build_out = Path(build_out_dir)
            harnesses = Path(harness_dir)
            executable = build_out / "reader"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            (build_out / "reader.options").write_text("[libfuzzer]\n", encoding="utf-8")
            (build_out / "xml.dict").write_text("token\n", encoding="utf-8")
            (build_out / "reader_seed_corpus.zip").write_text("zip", encoding="utf-8")
            (harnesses / "reader.c").write_text("int LLVMFuzzerTestOneInput(void){return 0;}\n", encoding="utf-8")

            record = self._create_task(
                metadata={
                    "existing_build_out_path": str(build_out),
                    "existing_harness_dir": str(harnesses),
                },
            )
            scheduler_queue = FakeQueue()
            process_scheduler_task(record.task_id, self.task_store, scheduler_queue)
            queue = FakeQueue()

            process_build_task(record.task_id, self.task_store, queue)

            updated = self.task_store.load_task(record.task_id)
            registry_path = Path(updated.runtime["build_registry_path"])
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            self.assertEqual(updated.runtime["build_status"], "BUILT")
            self.assertEqual(len(registry["fuzzers"]), 1)
            self.assertEqual(len(registry["harnesses"]), 1)
            self.assertEqual(len(registry["seed_corpora"]), 1)


if __name__ == "__main__":
    unittest.main()

from dataclasses import dataclass
from pathlib import Path

from core.models.task import ExecutionMode, TaskRecord


@dataclass
class IndexRequest:
    task_id: str
    task_dir: Path
    source_dir: Path
    index_dir: Path
    imports_src_dir: Path
    imports_index_dir: Path
    source_uri: str
    adapter_type: str
    execution_mode: str = ExecutionMode.FRESH.value
    existing_src_path: str | None = None
    existing_index_path: str | None = None

    @classmethod
    def from_task(cls, task: TaskRecord) -> "IndexRequest":
        layout = task.layout
        task_dir = Path(task.task_dir)
        resolved_imports = task.runtime.get("resolved_imports", {})
        return cls(
            task_id=task.task_id,
            task_dir=task_dir,
            source_dir=Path(layout.get("src", str(task_dir / "src"))),
            index_dir=Path(layout.get("index", str(task_dir / "index"))),
            imports_src_dir=Path(layout.get("imports_src", str(task_dir / "imports" / "src"))),
            imports_index_dir=Path(layout.get("imports_index", str(task_dir / "imports" / "index"))),
            source_uri=task.source.uri,
            adapter_type=task.source.adapter_type.value,
            execution_mode=(task.execution_mode or ExecutionMode.FRESH).value,
            existing_src_path=resolved_imports.get("existing_src_path"),
            existing_index_path=resolved_imports.get("existing_index_path"),
        )

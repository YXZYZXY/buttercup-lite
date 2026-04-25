from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class AdapterType(str, Enum):
    OSSFUZZ = "ossfuzz"
    BINARY = "binary"
    PROTOCOL = "protocol"

    @classmethod
    def canonicalize(cls, value: Any) -> "AdapterType":
        if isinstance(value, cls):
            return value
        normalized = str(value or "").strip().lower()
        if normalized == "network_protocol":
            return cls.PROTOCOL
        return cls(normalized)


class ExecutionMode(str, Enum):
    FRESH = "fresh"
    IMPORT_ASSISTED = "import_assisted"
    HYBRID = "hybrid"


class TaskStatus(str, Enum):
    QUEUED_DOWNLOAD = "QUEUED_DOWNLOAD"
    DOWNLOADING = "DOWNLOADING"
    READY = "READY"
    QUEUED_COVERAGE_FEEDBACK = "QUEUED_COVERAGE_FEEDBACK"
    COVERAGE_ANALYZING = "COVERAGE_ANALYZING"
    COVERAGE_FEEDBACK_READY = "COVERAGE_FEEDBACK_READY"
    CAMPAIGN_QUEUED = "CAMPAIGN_QUEUED"
    CAMPAIGN_RUNNING = "CAMPAIGN_RUNNING"
    CAMPAIGN_COMPLETED = "CAMPAIGN_COMPLETED"
    CAMPAIGN_FAILED = "CAMPAIGN_FAILED"
    QUEUED_BINARY_ANALYSIS = "QUEUED_BINARY_ANALYSIS"
    BINARY_ANALYZING = "BINARY_ANALYZING"
    BINARY_ANALYZED = "BINARY_ANALYZED"
    BINARY_ANALYSIS_FAILED = "BINARY_ANALYSIS_FAILED"
    QUEUED_BINARY_SEED = "QUEUED_BINARY_SEED"
    BINARY_SEEDING = "BINARY_SEEDING"
    BINARY_SEEDED = "BINARY_SEEDED"
    BINARY_SEED_FAILED = "BINARY_SEED_FAILED"
    QUEUED_BINARY_EXECUTION = "QUEUED_BINARY_EXECUTION"
    BINARY_EXECUTING = "BINARY_EXECUTING"
    BINARY_EXECUTED = "BINARY_EXECUTED"
    BINARY_CRASH_CANDIDATE_FOUND = "BINARY_CRASH_CANDIDATE_FOUND"
    BINARY_EXECUTION_FAILED = "BINARY_EXECUTION_FAILED"
    QUEUED_PROTOCOL_EXECUTION = "QUEUED_PROTOCOL_EXECUTION"
    PROTOCOL_EXECUTING = "PROTOCOL_EXECUTING"
    PROTOCOL_EXECUTED = "PROTOCOL_EXECUTED"
    PROTOCOL_NOT_IMPLEMENTED = "PROTOCOL_NOT_IMPLEMENTED"
    PROTOCOL_EXECUTION_FAILED = "PROTOCOL_EXECUTION_FAILED"
    QUEUED_PATCH = "QUEUED_PATCH"
    PATCH_ROOT_CAUSE = "PATCH_ROOT_CAUSE"
    PATCH_CONTEXT_RETRIEVAL = "PATCH_CONTEXT_RETRIEVAL"
    PATCH_QE = "PATCH_QE"
    PATCH_REFLECTION = "PATCH_REFLECTION"
    PATCH_SUPPRESSED = "PATCH_SUPPRESSED"
    PATCH_ESCALATED = "PATCH_ESCALATED"
    PATCH_ACCEPTED = "PATCH_ACCEPTED"
    PATCH_RETRY_REQUESTED = "PATCH_RETRY_REQUESTED"
    PATCH_FAILED = "PATCH_FAILED"
    QUEUED_INDEX = "QUEUED_INDEX"
    INDEXING = "INDEXING"
    INDEXED = "INDEXED"
    INDEX_FAILED = "INDEX_FAILED"
    QUEUED_BUILD = "QUEUED_BUILD"
    BUILDING = "BUILDING"
    BUILT = "BUILT"
    QUEUED_SEED = "QUEUED_SEED"
    SEEDING = "SEEDING"
    SEEDED = "SEEDED"
    SEED_FAILED = "SEED_FAILED"
    QUEUED_FUZZ = "QUEUED_FUZZ"
    FUZZING = "FUZZING"
    FUZZ_COMPLETED = "FUZZ_COMPLETED"
    FUZZ_FAILED = "FUZZ_FAILED"
    QUEUED_TRACE = "QUEUED_TRACE"
    TRACING = "TRACING"
    TRACED = "TRACED"
    TRACE_FAILED = "TRACE_FAILED"
    QUEUED_REPRO = "QUEUED_REPRO"
    REPRODUCING = "REPRODUCING"
    POV_CONFIRMED = "POV_CONFIRMED"
    REPRO_FAILED = "REPRO_FAILED"
    SCHEDULED = "SCHEDULED"
    FAILED = "FAILED"


class TaskSource(BaseModel):
    adapter_type: AdapterType
    uri: str
    ref: str | None = None

    @field_validator("adapter_type", mode="before")
    @classmethod
    def validate_adapter_type(cls, value: Any) -> AdapterType:
        return AdapterType.canonicalize(value)


class TaskSpec(BaseModel):
    source: TaskSource | None = None
    repo_url: str | None = None
    git_ref: str | None = None
    source_type: str | None = None
    oss_fuzz_project_hint: str | None = None
    patch_diff_url: str | None = None
    local_diff_path: str | None = None
    task_time_budget: int | None = None
    fuzz_budget: int | None = None
    mode: str | None = None
    execution_mode: ExecutionMode | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaskRecord(BaseModel):
    task_id: str
    source: TaskSource
    execution_mode: ExecutionMode | None = None
    status: TaskStatus
    metadata: dict[str, Any] = Field(default_factory=dict)
    task_dir: str
    created_at: str
    updated_at: str
    layout: dict[str, str] = Field(default_factory=dict)
    runtime: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def new(cls, task_spec: TaskSpec, task_dir: str, status: TaskStatus) -> "TaskRecord":
        if task_spec.source is None:
            raise ValueError("TaskSpec.source must be normalized before creating a TaskRecord")
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            task_id=str(uuid4()),
            source=task_spec.source,
            execution_mode=task_spec.execution_mode,
            status=status,
            metadata=task_spec.metadata,
            task_dir=task_dir,
            created_at=now,
            updated_at=now,
        )

from __future__ import annotations

import json
from typing import Any

from core.buttercup_compat.models import ButtercupRequest
from core.models.task import TaskRecord
from core.storage.layout import scheduler_fanout_manifest_path


def _request_from_stage(request_type: str, stage: dict[str, Any], *, reason: str | None = None) -> dict[str, Any]:
    request = ButtercupRequest(
        request_type=request_type,
        queue=stage.get("queue"),
        worker=stage.get("worker"),
        execute=bool(stage.get("execute")),
        inputs=[item for item in stage.get("inputs", []) if item],
        reason=reason,
    )
    payload = request.to_dict()
    payload["trigger_condition"] = stage.get("trigger_condition") or reason
    payload["upstream_dependencies"] = stage.get("upstream_dependencies", [])
    payload["transition_rationale"] = stage.get("selection_rationale") or reason
    payload["actual_launched_worker"] = stage.get("worker") if stage.get("execute") else None
    return payload


def build_scheduler_fanout(task: TaskRecord, plan: dict[str, Any], import_manifest: dict[str, Any], now: str) -> dict[str, Any]:
    stages = plan.get("stages", {})
    build_contract = stages.get("build", {}).get("contract", {})
    build_decision = build_contract.get("build_decision", {})
    requested_build_kinds = build_contract.get("requested_build_kinds", [])
    build_requests: list[dict[str, Any]] = []
    for build_kind in requested_build_kinds:
        build_requests.append(
            {
                **ButtercupRequest(
                    request_type="BuildRequest",
                    queue=stages.get("build", {}).get("queue"),
                    worker=stages.get("build", {}).get("worker"),
                    execute=bool(stages.get("build", {}).get("execute")),
                    inputs=[item for item in stages.get("build", {}).get("inputs", []) if item],
                    build_type=build_kind,
                    sanitizer="address" if build_kind in {"fuzzer_build", "tracer_build"} else None,
                    apply_diff=False,
                    reason=build_decision.get("reason"),
                ).to_dict(),
                "trigger_condition": "READY source task with build contract",
                "upstream_dependencies": ["source_task_normalization", "source_resolution"],
                "transition_rationale": build_decision.get("reason"),
                "actual_launched_worker": stages.get("build", {}).get("worker")
                if stages.get("build", {}).get("execute")
                else None,
            },
        )

    requests = [
        _request_from_stage(
            "BinaryAnalysisRequest",
            stages.get("binary_analysis", {}),
            reason="pure-binary adapter fanout to binary analysis",
        ),
        _request_from_stage(
            "BinarySeedRequest",
            stages.get("binary_seed", {}),
            reason="pure-binary adapter fanout to binary-native seed generation",
        ),
        _request_from_stage(
            "BinaryExecutionRequest",
            stages.get("binary_execution", {}),
            reason="pure-binary adapter fanout to execution/repro signal collection",
        ),
        _request_from_stage(
            "IndexRequest",
            stages.get("index", {}),
            reason="READY task fanout to program model, matching original scheduler",
        ),
        *build_requests,
        _request_from_stage("SeedInitRequest", stages.get("seed", {}), reason="seed-init bootstrap after index/build"),
        _request_from_stage("FuzzRequest", stages.get("fuzz", {}), reason="fuzz after corpus is available"),
        _request_from_stage("TraceRequest", stages.get("trace", {}), reason="trace only when crash candidate is present"),
        _request_from_stage("ReproRequest", stages.get("repro", {}), reason="repro only consumes traced candidates"),
        {
            **ButtercupRequest(
                request_type="PatchReservedRequest",
                queue=None,
                worker=None,
                execute=False,
                reason="patch plane reserved only in buttercup-lite front-half scope",
            ).to_dict(),
            "trigger_condition": "confirmed vuln or patch priority request",
            "upstream_dependencies": ["trace", "repro", "pov"],
            "transition_rationale": "reserved only; patch agent out of current lite scope",
            "actual_launched_worker": None,
        },
    ]
    return {
        "task_id": task.task_id,
        "generated_at": now,
        "compat_source": "original_buttercup.orchestrator.scheduler.process_ready_task",
        "adapter_resolution": plan.get("adapter_resolution"),
        "execution_mode": plan.get("execution_mode"),
        "ready_to_fanout": task.status.value,
        "original_semantics": {
            "ready_task_fanout": "READY -> IndexRequest + BuildRequest fanout",
            "build_type_fanout": "coverage/fuzzer/tracer build requests are explicit",
            "crash_followup": "crash candidates gate TraceRequest -> ReproRequest",
            "patch": "reserved placeholder, not executed",
        },
        "resolved_imports": import_manifest.get("resolved_paths", {}),
        "source_task_normalization": plan.get("source_task_normalization", {}),
        "source_resolution": plan.get("source_resolution", {}),
        "requests": requests,
        "workers_to_run": plan.get("workers_to_run", []),
        "coverage_feedback_consumed": bool(plan.get("scheduler_consumed_feedback")),
    }


def write_scheduler_fanout_manifest(
    task: TaskRecord,
    plan: dict[str, Any],
    import_manifest: dict[str, Any],
    now: str,
) -> dict[str, Any]:
    payload = build_scheduler_fanout(task, plan, import_manifest, now)
    path = scheduler_fanout_manifest_path(task.task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {**payload, "scheduler_fanout_manifest_path": str(path)}

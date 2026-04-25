import logging
import time
from pathlib import Path
import json

from core.builder.contracts import (
    resolve_build_decision,
    resolve_oss_fuzz_project_contract_from_resolved_imports,
)
from core.builder.fresh_build import build_ossfuzz_project
from core.builder.import_scan import scan_imported_build
from core.models.task import TaskStatus
from core.queues.redis_queue import QueueNames, RedisQueue
from core.seed.queue import maybe_enqueue_seed
from core.state.task_state import TaskStateStore
from core.storage.layout import (
    build_matrix_manifest_path,
    build_to_fuzzer_registry_bridge_path,
    fuzzer_registry_manifest_path,
    optional_assets_handling_manifest_path,
    oss_fuzz_asset_import_manifest_path,
)
from core.utils.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("builder-worker")


def _write_json(path: Path, payload: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _write_registry_bridge_manifests(*, task_id: str, now: str, registry: dict, build_decision, source_resolution: dict) -> dict[str, str]:
    fuzzer_payload = {
        "task_id": task_id,
        "generated_at": now,
        "registry_mode": registry.get("mode"),
        "runnable_fuzzers": registry.get("fuzzers", []),
        "coverage_fuzzers": registry.get("coverage_fuzzers", []),
        "tracer_replay_binaries": registry.get("tracer_replay_binaries", []),
        "harness_inventory": registry.get("harnesses", []),
        "dicts": registry.get("dicts", []),
        "options": registry.get("options", []),
        "seed_corpora": registry.get("seed_corpora", []),
        "build_source": registry.get("build_source") or build_decision.decision,
        "runnable_fuzzer_count": len(registry.get("fuzzers", [])),
    }
    asset_payload = {
        "task_id": task_id,
        "generated_at": now,
        "selected_oss_fuzz_project": source_resolution.get("selected_oss_fuzz_project"),
        "staged_harness_sources": registry.get("staged_harness_sources", []),
        "staged_oss_fuzz_assets_src_root": registry.get("staged_oss_fuzz_assets_src_root", []),
        "build_log_path": registry.get("artifacts", {}).get("build_log"),
        "asset_import_mode": registry.get("mode"),
    }
    optional_payload = {
        "task_id": task_id,
        "generated_at": now,
        "selected_oss_fuzz_project": source_resolution.get("selected_oss_fuzz_project"),
        "missing_optional_assets": ((registry.get("optional_assets_handling") or {}).get("missing_optional_assets") or []),
        "graceful_degradation": bool((registry.get("optional_assets_handling") or {}).get("graceful_degradation")),
        "build_script_adaptations": ((registry.get("optional_assets_handling") or {}).get("build_script_adaptations") or []),
        "build_still_succeeded": bool(registry.get("fuzzers") or registry.get("coverage_fuzzers")),
    }
    bridge_payload = {
        "task_id": task_id,
        "generated_at": now,
        "selected_build_strategy": source_resolution.get("selected_build_strategy"),
        "selected_harness_strategy": source_resolution.get("selected_harness_strategy"),
        "auto_resolved": build_decision.auto_resolved,
        "registry_fallback_used": build_decision.registry_fallback_used,
        "discovered_harnesses": source_resolution.get("discovered_harnesses", []),
        "harness_inventory": registry.get("harnesses", []),
        "runnable_fuzzers": registry.get("fuzzers", []),
        "bridge_status": (
            "runnable_fuzzers_available"
            if registry.get("fuzzers")
            else "harnesses_discovered_but_no_runnable_fuzzers"
            if registry.get("harnesses")
            else "no_harnesses_discovered"
        ),
        "bridge_reason": (
            "build outputs include executable fuzzers"
            if registry.get("fuzzers")
            else "harness sources were discovered but no executable fuzzers were emitted into /out"
            if registry.get("harnesses")
            else "no harness sources or executables were discovered"
        ),
    }
    return {
        "fuzzer_registry_manifest_path": _write_json(fuzzer_registry_manifest_path(task_id), fuzzer_payload),
        "oss_fuzz_asset_import_manifest_path": _write_json(oss_fuzz_asset_import_manifest_path(task_id), asset_payload),
        "optional_assets_handling_manifest_path": _write_json(optional_assets_handling_manifest_path(task_id), optional_payload),
        "build_to_fuzzer_registry_bridge_path": _write_json(build_to_fuzzer_registry_bridge_path(task_id), bridge_payload),
    }


def _build_matrix_entry(
    *,
    kind: str,
    requested: bool,
    requested_mode: str,
    decision: str,
    supported: bool,
    produced_artifacts: list[str],
    actual_mode: str | None = None,
    failure_reason: str | None = None,
    fallback_reason: str | None = None,
    fallback_effect: str | None = None,
    semantic_limitations: list[str] | None = None,
) -> dict:
    return {
        "requested": requested,
        "requested_mode": requested_mode,
        "decision": decision,
        "supported": supported,
        "produced_artifacts": produced_artifacts,
        "actual_mode": actual_mode or decision,
        "failure_reason": failure_reason,
        "fallback_reason": fallback_reason,
        "fallback_effect": fallback_effect,
        "semantic_limitations": semantic_limitations or [],
        "build_kind": kind,
    }


def _write_build_matrix_manifest(
    *,
    task_id: str,
    now: str,
    build_decision,
    oss_fuzz_contract,
    registry: dict | None,
    failure_reason: str | None = None,
    source_resolution: dict | None = None,
) -> str:
    artifacts = registry.get("artifacts", {}) if registry else {}
    fuzzers = [item.get("path") for item in (registry or {}).get("fuzzers", []) if item.get("path")]
    coverage_fuzzers = [item.get("path") for item in (registry or {}).get("coverage_fuzzers", []) if item.get("path")]
    tracer_replay_binaries = [
        item.get("path")
        for item in (registry or {}).get("tracer_replay_binaries", [])
        if item.get("path")
    ]
    produced_common = [path for path in {artifacts.get("build_registry.json"), *fuzzers} if path]
    supported = bool(registry) and build_decision.supported
    decision_name = build_decision.decision if supported else "unsupported"
    build_variants = registry.get("build_variants", {}) if registry else {}

    def _variant(kind: str, *, default_decision: str) -> dict:
        variant = build_variants.get(kind, {})
        return _build_matrix_entry(
            kind=kind,
            requested=True,
            requested_mode=str(
                variant.get("requested_mode")
                or {
                    "coverage_build": "dedicated_coverage_build",
                    "fuzzer_build": "dedicated_fuzzer_build",
                    "tracer_build": "dedicated_tracer_build",
                    "patch_qe_build": "patch_qe_usable_build",
                }[kind]
            ),
            decision=default_decision,
            supported=supported,
            produced_artifacts=(
                coverage_fuzzers
                if kind == "coverage_build" and coverage_fuzzers
                else fuzzers
                if kind == "fuzzer_build"
                else tracer_replay_binaries
                if kind == "tracer_build" and tracer_replay_binaries
                else produced_common
            ),
            actual_mode=variant.get("actual_mode") or default_decision,
            failure_reason=None if supported else failure_reason,
            fallback_reason=variant.get("fallback_reason"),
            fallback_effect=variant.get("fallback_effect"),
            semantic_limitations=list(variant.get("semantic_limitations") or []),
        )

    payload = {
        "task_id": task_id,
        "generated_at": now,
        "build_decision": build_decision.to_dict(),
        "auto_resolved": build_decision.auto_resolved,
        "registry_fallback_used": build_decision.registry_fallback_used,
        "oss_fuzz_project_contract": oss_fuzz_contract.to_dict(),
        "build_capability": build_decision.capability.to_dict() if build_decision.capability else None,
        "source_resolution": source_resolution or {},
        "auto_discovered_harnesses": (source_resolution or {}).get("discovered_harnesses", []),
        "selected_build_strategy": (source_resolution or {}).get("selected_build_strategy"),
        "selected_harness_strategy": (source_resolution or {}).get("selected_harness_strategy"),
        "tracer_build_strategy": (source_resolution or {}).get("tracer_build_strategy"),
        "coverage_build_strategy": (source_resolution or {}).get("coverage_build_strategy"),
        "build_environment": registry.get("build_environment") if registry else None,
        "builds": {
            "coverage_build": _variant(
                "coverage_build",
                default_decision="coverage_capable_fuzzer_build" if supported else decision_name,
            ),
            "fuzzer_build": _variant(
                "fuzzer_build",
                default_decision=build_decision.decision if build_decision.supported else decision_name,
            ),
            "tracer_build": _variant(
                "tracer_build",
                default_decision="reuse_fuzzer_build_for_replay" if supported else decision_name,
            ),
            "patch_qe_build": _variant(
                "patch_qe_build",
                default_decision="reuse_build_output_for_qe" if supported else decision_name,
            ),
        },
    }
    output_path = build_matrix_manifest_path(task_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(output_path)


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("builder received task %s", task_id)
    task_store.update_runtime(
        task_id,
        {
            "build_started_at": task_store.now(),
            "build_status": "BUILDING",
        },
    )

    task = task_store.load_task(task_id)
    resolved_imports = task.runtime.get("resolved_imports", {})
    build_out = resolved_imports.get("existing_build_out_path")
    harness_dir = resolved_imports.get("existing_harness_dir")
    build_dir = Path(task.layout["build"])
    project = (
        task.metadata.get("project")
        or task.runtime.get("selected_oss_fuzz_project")
        or task.metadata.get("selected_oss_fuzz_project")
        or ""
    ).lower()
    source_resolution = {
        "source_resolution_manifest_path": task.runtime.get("source_resolution_manifest_path"),
        "resolution_class": task.runtime.get("source_resolution_class") or task.metadata.get("source_resolution_class"),
        "selected_oss_fuzz_project": task.runtime.get("selected_oss_fuzz_project") or task.metadata.get("selected_oss_fuzz_project"),
        "selected_build_strategy": task.runtime.get("selected_build_strategy") or task.metadata.get("selected_build_strategy"),
        "selected_harness_strategy": task.runtime.get("selected_harness_strategy") or task.metadata.get("selected_harness_strategy"),
        "discovered_harnesses": task.runtime.get("discovered_harnesses") or task.metadata.get("discovered_harnesses") or [],
        "tracer_build_strategy": task.runtime.get("tracer_build_strategy") or task.metadata.get("tracer_build_strategy"),
        "coverage_build_strategy": task.runtime.get("coverage_build_strategy") or task.metadata.get("coverage_build_strategy"),
    }
    oss_fuzz_contract = resolve_oss_fuzz_project_contract_from_resolved_imports(resolved_imports)
    build_decision = resolve_build_decision(
        project_name=project,
        imported_build_path=build_out,
        oss_fuzz_project_contract=oss_fuzz_contract,
        source_dir=task.layout.get("src"),
        source_resolution=source_resolution,
        task_id=task_id,
    )
    capability = build_decision.capability
    if build_out:
        registry = scan_imported_build(
            task_id=task_id,
            build_out_dir=Path(build_out),
            harness_dir=Path(harness_dir) if harness_dir else None,
            build_dir=build_dir,
            mode="import_assisted",
        )
        registry["build_environment"] = {
            "environment_kind": "host_imported_build",
            "toolchain_prefix": None,
            "tools": {},
        }
    else:
        source_dir = Path(task.layout["src"])
        if build_decision.decision == "unsupported":
            build_matrix_path = _write_build_matrix_manifest(
                task_id=task_id,
                now=task_store.now(),
                build_decision=build_decision,
                oss_fuzz_contract=oss_fuzz_contract,
                registry=None,
                failure_reason=build_decision.reason,
                source_resolution=source_resolution,
            )
            task_store.update_status(
                task_id,
                TaskStatus.FAILED,
                runtime_patch={
                    "build_completed_at": task_store.now(),
                    "build_status": "UNSUPPORTED",
                    "build_error": f"build decision is unsupported: {build_decision.reason}",
                    "build_decision": build_decision.to_dict(),
                    "build_capability": None,
                    "build_auto_resolved": build_decision.auto_resolved,
                    "build_registry_fallback_used": build_decision.registry_fallback_used,
                    "oss_fuzz_project_contract": oss_fuzz_contract.to_dict(),
                    "build_matrix_manifest_path": build_matrix_path,
                },
            )
            queue.ack(QueueNames.BUILD, task_id)
            return
        try:
            registry = build_ossfuzz_project(
                task_id=task_id,
                source_dir=source_dir,
                oss_fuzz_project_dir=Path(oss_fuzz_contract.project_root_path),
                build_dir=build_dir,
                capability=capability,
            )
        except Exception as exc:
            build_matrix_path = _write_build_matrix_manifest(
                task_id=task_id,
                now=task_store.now(),
                build_decision=build_decision,
                oss_fuzz_contract=oss_fuzz_contract,
                registry=None,
                failure_reason=str(exc),
                source_resolution=source_resolution,
            )
            task_store.update_status(
                task_id,
                TaskStatus.FAILED,
                runtime_patch={
                    "build_completed_at": task_store.now(),
                    "build_status": "FAILED",
                    "build_error": str(exc),
                    "build_decision": build_decision.to_dict(),
                    "build_capability": capability.to_dict() if capability else None,
                    "build_auto_resolved": build_decision.auto_resolved,
                    "build_registry_fallback_used": build_decision.registry_fallback_used,
                    "oss_fuzz_project_contract": oss_fuzz_contract.to_dict(),
                    "build_matrix_manifest_path": build_matrix_path,
                },
            )
            queue.ack(QueueNames.BUILD, task_id)
            return
    build_matrix_path = _write_build_matrix_manifest(
        task_id=task_id,
        now=task_store.now(),
        build_decision=build_decision,
        oss_fuzz_contract=oss_fuzz_contract,
        registry=registry,
        source_resolution=source_resolution,
    )
    registry_bridge_paths = _write_registry_bridge_manifests(
        task_id=task_id,
        now=task_store.now(),
        registry=registry,
        build_decision=build_decision,
        source_resolution=source_resolution,
    )

    task_store.update_runtime(
        task_id,
        {
            "build_completed_at": task_store.now(),
            "build_status": "BUILT",
            "build_registry_path": registry["artifacts"]["build_registry.json"],
            "build_artifacts": registry["artifacts"],
            "imported_fuzzer_count": len(registry["fuzzers"]),
            "imported_harness_count": len(registry["harnesses"]),
            "imported_seed_corpus_count": len(registry["seed_corpora"]),
            "build_mode": registry.get("mode"),
            "build_command": registry.get("build_command"),
            "build_decision": build_decision.to_dict(),
            "build_capability": capability.to_dict() if capability else None,
            "build_auto_resolved": build_decision.auto_resolved,
            "build_registry_fallback_used": build_decision.registry_fallback_used,
            "oss_fuzz_project_contract": oss_fuzz_contract.to_dict(),
            "source_resolution": source_resolution,
            "build_matrix_manifest_path": build_matrix_path,
            **registry_bridge_paths,
        },
    )
    if not maybe_enqueue_seed(task_id, task_store, queue):
        logger.warning("task %s build completed but seed was not queued", task_id)
    queue.ack(QueueNames.BUILD, task_id)
    logger.info("task %s imported build assets successfully", task_id)


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("builder worker started")
    while True:
        task_id = queue.pop(QueueNames.BUILD, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("builder failed for task %s: %s", task_id, exc)
            task_store.update_runtime(
                task_id,
                {
                    "build_status": "FAILED",
                    "build_error": str(exc),
                    "build_failed_at": task_store.now(),
                },
            )
            queue.ack(QueueNames.BUILD, task_id)


if __name__ == "__main__":
    main()

from __future__ import annotations

from dataclasses import replace
import json
import logging
import time
from pathlib import Path
from typing import Any

from benchmarks.seed_fixtures import build_source_heuristic_module as build_benchmark_source_heuristic_module
from core.buttercup_compat.seed_init import write_seed_init_chain_manifest
from core.models.task import TaskStatus
from core.program_model.runtime_query import ProgramModelRuntimeView
from core.fuzz.queue import maybe_enqueue_fuzz
from core.queues.redis_queue import QueueNames, RedisQueue
from core.seed import (
    LLMCallError,
    LLMClient,
    SeedParseError,
    build_non_llm_metadata,
    build_messages,
    execute_seed_functions,
    extract_content,
    merge_generated_seeds,
    parse_seed_module,
    parse_seed_module_with_repair,
    retrieve_context,
    select_harness,
    stage_imported_seed_material,
    write_seed_manifest,
)
from core.seed.llm_audit import write_llm_seed_audit
from core.seed.selector_manifests import (
    write_coverage_to_selector_bridge_manifest,
    write_function_selector_manifest,
    write_harness_selector_manifest,
    write_seed_mode_trigger_manifest,
    write_seed_mode_semantics_manifest,
    write_seed_task_sampling_manifest,
    write_seed_family_plan_manifest,
    write_selector_feedback_consumption,
    write_weighted_function_selector_manifest,
    write_weighted_harness_selector_manifest,
)
from core.seed.harness_selector import select_harness_by_name
from core.seed.models import ParsedSeedModule
from core.seed_strategy import select_seed_task_mode
from core.seed_strategy import write_seed_task_manifest
from core.state.task_state import TaskStateStore
from core.storage.layout import seed_manifest_path
from core.utils.settings import (
    resolve_float_setting,
    resolve_bool_setting,
    resolve_int_setting,
    resolve_optional_int_setting,
    resolve_text_setting,
    settings,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("seed-worker")

_RECENTLY_USED_TARGETS_BY_ROTATION_SESSION: dict[str, set[str]] = {}
_ELIGIBLE_TARGET_POOL_BY_ROTATION_SESSION: dict[str, dict[str, dict[str, Any]]] = {}


def _load_json(path_str: str) -> dict[str, Any]:
    path = Path(path_str)
    return json.loads(path.read_text(encoding="utf-8"))


def _active_corpus_count(corpus_dir: Path) -> int:
    return sum(1 for candidate in corpus_dir.rglob("*") if candidate.is_file())


def _write_text(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def _llm_fields(metadata_obj) -> dict[str, Any]:
    return metadata_obj.to_dict()


def _clean_policy_fields(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "verification_mode": resolve_text_setting(metadata, "verification_mode", "standard"),
        "seed_material_policy": resolve_text_setting(metadata, "seed_material_policy", "default"),
        "allow_imported_seed_material": resolve_bool_setting(metadata, "allow_imported_seed_material", True),
        "allow_cached_seed_material": resolve_bool_setting(metadata, "allow_cached_seed_material", False),
        "allow_fallback_non_llm": resolve_bool_setting(metadata, "allow_fallback_non_llm", True),
    }


def _build_source_heuristic_module(project_name: str, harness_name: str, task_mode: str) -> ParsedSeedModule:
    return build_benchmark_source_heuristic_module(project_name, harness_name, task_mode)


def _derive_seed_family_plan(task, context, seed_decision) -> dict[str, Any]:
    target_names = [item.get("name") for item in context.selected_target_functions if isinstance(item, dict) and item.get("name")]
    coverage_entries = _coverage_target_entries(context)
    coverage_group_counts: dict[str, int] = {}
    for item in coverage_entries:
        queue_kind = str(item.get("queue_kind") or "coverage_gap").strip() or "coverage_gap"
        coverage_group_counts[queue_kind] = coverage_group_counts.get(queue_kind, 0) + 1
    sample_blob = "\n".join(context.sample_inputs[:4]).lower()
    parser_hints: list[str] = []
    if "[" in sample_blob and "]" in sample_blob:
        parser_hints.append("section_delimiters")
    if "=" in sample_blob or ":" in sample_blob:
        parser_hints.append("key_value_pairs")
    if "{" in sample_blob or "[" in sample_blob:
        parser_hints.append("structured_container_tokens")
    if "\\n" in sample_blob or "\n" in sample_blob:
        parser_hints.append("multi_line_inputs")
    if not parser_hints:
        parser_hints.append("opaque_binary_or_text_parser")

    if seed_decision.mode == "VULN_DISCOVERY":
        families = ["boundary_length_pressure", "truncation_or_malformed_delimiters", "allocator_or_teardown_edges"]
    elif seed_decision.mode == "SEED_EXPLORE":
        families = ["structural_variants", "format_feature_coverage", "harness_adjacent_graph_explore"]
    else:
        families = ["starter_valid_inputs", "near_valid_inputs", "entrypoint_format_bootstrap"]

    return {
        "task_id": task.task_id,
        "adapter_type": "source_adapter",
        "seed_mode": seed_decision.mode,
        "selected_harness": context.selected_harness,
        "selected_target_functions": target_names,
        "selection_rationale": context.selection_rationale,
        "parser_hints": parser_hints,
        "coverage_group_counts": coverage_group_counts,
        "coverage_target_names": [str(item.get("name") or "") for item in coverage_entries if item.get("name")][:8],
        "family_groups": families,
        "sample_input_count": len(context.sample_inputs),
        "context_package_path": context.context_package_path,
    }


def _seed_mode_semantics(seed_mode: str) -> dict[str, Any]:
    semantics = {
        "SEED_INIT": {
            "goal": "bootstrap valid or near-valid parser inputs around entrypoints",
            "context_focus": ["entry_parser_functions", "format_hints", "starter_valid_inputs"],
            "weighting_bias": "favor parser-entry and low-coverage bootstrap functions",
            "downstream_target": "initial fuzz/corpus activation",
        },
        "SEED_EXPLORE": {
            "goal": "expand structural coverage around harness-adjacent graph branches",
            "context_focus": ["call_graph_neighbors", "format_feature_variants", "coverage_gap_functions"],
            "weighting_bias": "favor coverage gaps and graph exploration when crashes are not yet actionable",
            "downstream_target": "coverage growth and alternate parser states",
        },
        "VULN_DISCOVERY": {
            "goal": "push exploit-oriented edge cases near suspicious crash-adjacent functions",
            "context_focus": ["low-coverage sink functions", "memory-sensitive operations", "crash history"],
            "weighting_bias": "favor crash-adjacent or allocator/string-heavy functions",
            "downstream_target": "raw crash candidate generation and trace follow-up",
        },
    }
    return semantics[seed_mode]


def _coverage_target_entries(context) -> list[dict[str, Any]]:
    raw_entries = list((context.context_package or {}).get("campaign_reseed_target_entries") or [])
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_entries:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        entries.append(dict(item))
    return entries


def _coverage_target_groups(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in entries:
        queue_kind = str(item.get("queue_kind") or "coverage_gap").strip() or "coverage_gap"
        groups.setdefault(queue_kind, []).append(dict(item))
    ordering = {
        "uncovered": 0,
        "low_growth": 1,
        "partial_degraded": 2,
        "candidate_bridge": 3,
        "coverage_gap": 4,
    }
    selected: list[dict[str, Any]] = []
    for queue_kind, members in sorted(
        groups.items(),
        key=lambda item: (ordering.get(item[0], 99), item[0]),
    ):
        members = sorted(
            members,
            key=lambda entry: (
                -int(entry.get("priority") or 0),
                float(entry.get("coverage_fraction") if entry.get("coverage_fraction") is not None else 2.0),
                entry.get("name") or "",
            ),
        )
        selected.append(
            {
                "queue_kind": queue_kind,
                "target_entries": members[:4],
                "target_names": [str(item.get("name") or "") for item in members if item.get("name")][:4],
            },
        )
    return selected


def _coverage_entry_name(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("name") or "").strip()


def _coverage_entry_sort_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (
        -int(entry.get("priority") or 0),
        float(entry.get("coverage_fraction") if entry.get("coverage_fraction") is not None else 2.0),
        entry.get("name") or "",
    )


def _ordered_unique_entries(*entry_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for group in entry_groups:
        for item in group:
            if not isinstance(item, dict):
                continue
            name = _coverage_entry_name(item)
            if not name or name in seen:
                continue
            seen.add(name)
            selected.append(dict(item))
    return sorted(selected, key=_coverage_entry_sort_key)


def _exact_uncovered_target_entries(context) -> list[dict[str, Any]]:
    return _ordered_unique_entries(list((context.context_package or {}).get("exact_uncovered_target_functions") or []))


def _low_growth_target_entries(context) -> list[dict[str, Any]]:
    return _ordered_unique_entries(
        [
            dict(item)
            for item in list((context.context_package or {}).get("campaign_reseed_target_entries") or [])
            if isinstance(item, dict) and str(item.get("queue_kind") or "").strip() == "low_growth"
        ]
    )


def _family_stagnation_target_entries(context) -> list[dict[str, Any]]:
    return _ordered_unique_entries(list((context.context_package or {}).get("family_stagnation_targets") or []))


def _pm_runtime_query_payload(context) -> dict[str, Any]:
    return dict((context.context_package or {}).get("pm_runtime_query") or {})


def _pm_runtime_target_entries(context) -> list[dict[str, Any]]:
    return _ordered_unique_entries(list(_pm_runtime_query_payload(context).get("eligible_pool_entries") or []))


def _pm_query_summary(context) -> dict[str, Any]:
    return dict(_pm_runtime_query_payload(context).get("query_summary") or {})


def _pm_entry(
    item: dict[str, Any],
    *,
    source: str,
    reason: str,
    priority: int,
) -> dict[str, Any]:
    return {
        "name": str(item.get("name") or "").strip(),
        "file": item.get("file"),
        "line": item.get("line"),
        "reason": reason,
        "queue_kind": "pm_runtime",
        "source_level": "pm_runtime",
        "priority": int(priority),
        "coverage_summary": item.get("coverage_summary"),
        "eligible_pool_source": source,
        "pm_query_source": item.get("pm_query_source") or source,
        "distance": int(item.get("distance") or 0),
        "relation": item.get("relation"),
    }


def _filter_project_scoped_entries(
    runtime_view: ProgramModelRuntimeView,
    entries: list[dict[str, Any]],
    *,
    allow_unresolved_pseudotargets: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    def _entry_in_project_scope(item: dict[str, Any]) -> bool:
        source_file = runtime_view._fact_source_file(item)
        if source_file is not None:
            return runtime_view._fact_in_task_src_scope(item)
        return runtime_view.entry_in_task_scope(
            item,
            allow_unresolved_pseudotargets=allow_unresolved_pseudotargets,
        )

    kept: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for item in list(entries or []):
        if not isinstance(item, dict):
            continue
        if _entry_in_project_scope(item):
            kept.append(dict(item))
            continue
        removed.append(
            {
                "name": item.get("name"),
                "file": item.get("file"),
                "reason": item.get("reason"),
                "queue_kind": item.get("queue_kind"),
                "eligible_pool_source": item.get("eligible_pool_source"),
            }
        )
    return _ordered_unique_entries(kept), removed


def _strict_project_scoped_entries(
    runtime_view: ProgramModelRuntimeView,
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    filtered, _ = _filter_project_scoped_entries(
        runtime_view,
        entries,
        allow_unresolved_pseudotargets=False,
    )
    return filtered


_SELECTOR_FUNCTION_NAME_FIELDS = {"selected_target_function"}
_SELECTOR_FUNCTION_NAME_LIST_FIELDS = {
    "callers",
    "callees",
    "campaign_reseed_targets",
    "target_names",
}


def _selector_name_in_project_scope(
    runtime_view: ProgramModelRuntimeView,
    value: Any,
) -> bool:
    name = str(value or "").strip()
    if not name:
        return False
    if runtime_view.is_name_in_task_scope(name):
        return True
    prefix = name.split(":", 1)[0].strip()
    suffix = Path(prefix).suffix.lower()
    if suffix not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}:
        return False
    prefix_path = Path(prefix)
    for relative_path in runtime_view.index.known_source_relative_paths:
        candidate = Path(relative_path)
        if str(candidate) == prefix or candidate.name == prefix_path.name:
            return True
    return False


def _selector_entry_in_project_scope(
    runtime_view: ProgramModelRuntimeView,
    entry: dict[str, Any],
) -> bool:
    if runtime_view.entry_in_task_scope(
        entry,
        allow_unresolved_pseudotargets=False,
    ):
        return True
    return _selector_name_in_project_scope(runtime_view, entry.get("name"))


def _sanitize_selector_payload(
    runtime_view: ProgramModelRuntimeView,
    value: Any,
    *,
    field_name: str | None = None,
) -> Any:
    if isinstance(value, dict):
        if isinstance(value.get("name"), str) and not _selector_entry_in_project_scope(runtime_view, value):
            return None
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            cleaned = _sanitize_selector_payload(
                runtime_view,
                item,
                field_name=key,
            )
            if cleaned is None:
                continue
            sanitized[key] = cleaned
        return sanitized
    if isinstance(value, list):
        sanitized_items: list[Any] = []
        for item in value:
            cleaned = _sanitize_selector_payload(
                runtime_view,
                item,
                field_name=field_name,
            )
            if cleaned is None:
                continue
            sanitized_items.append(cleaned)
        return sanitized_items
    if isinstance(value, str) and field_name in _SELECTOR_FUNCTION_NAME_FIELDS:
        return value if _selector_name_in_project_scope(runtime_view, value) else None
    if isinstance(value, str) and field_name in _SELECTOR_FUNCTION_NAME_LIST_FIELDS:
        return value if _selector_name_in_project_scope(runtime_view, value) else None
    return value


def _apply_project_scope_filter(context, runtime_view: ProgramModelRuntimeView):
    removed_examples: dict[str, list[dict[str, Any]]] = {}
    removed_counts: dict[str, int] = {}

    def _filter_section(
        section_name: str,
        entries: list[dict[str, Any]],
        *,
        allow_unresolved_pseudotargets: bool = True,
    ) -> list[dict[str, Any]]:
        filtered, removed = _filter_project_scoped_entries(
            runtime_view,
            entries,
            allow_unresolved_pseudotargets=allow_unresolved_pseudotargets,
        )
        if removed:
            removed_counts[section_name] = len(removed)
            removed_examples[section_name] = removed[:8]
        return filtered

    target_function = context.target_function if isinstance(context.target_function, dict) else None
    if target_function and not runtime_view.entry_in_task_scope(
        target_function,
        allow_unresolved_pseudotargets=False,
    ):
        removed_counts["target_function"] = 1
        removed_examples["target_function"] = [
            {
                "name": target_function.get("name"),
                "file": target_function.get("file"),
                "reason": target_function.get("reason"),
            }
        ]
        context.target_function = None

    context.selected_target_functions = _filter_section(
        "selected_target_functions",
        list(context.selected_target_functions or []),
    )
    context.context_package["campaign_reseed_target_entries"] = _filter_section(
        "campaign_reseed_target_entries",
        list((context.context_package or {}).get("campaign_reseed_target_entries") or []),
    )
    context.context_package["exact_uncovered_target_functions"] = _filter_section(
        "exact_uncovered_target_functions",
        list((context.context_package or {}).get("exact_uncovered_target_functions") or []),
    )
    context.context_package["family_stagnation_targets"] = _filter_section(
        "family_stagnation_targets",
        list((context.context_package or {}).get("family_stagnation_targets") or []),
    )

    pm_runtime_query = dict((context.context_package or {}).get("pm_runtime_query") or {})
    if pm_runtime_query:
        eligible_pool_entries = _filter_section(
            "pm_runtime_query.eligible_pool_entries",
            list(pm_runtime_query.get("eligible_pool_entries") or []),
            allow_unresolved_pseudotargets=False,
        )
        pm_runtime_query["eligible_pool_entries"] = eligible_pool_entries
        pm_runtime_query["eligible_pool_size"] = len(eligible_pool_entries)
        source_counts: dict[str, int] = {}
        for item in eligible_pool_entries:
            source = str(item.get("eligible_pool_source") or "pm_runtime").strip() or "pm_runtime"
            source_counts[source] = source_counts.get(source, 0) + 1
        pm_runtime_query["eligible_pool_source_counts"] = source_counts
        context.context_package["pm_runtime_query"] = pm_runtime_query

    context.context_package["project_scope_filter"] = {
        "enabled": True,
        "removed_counts": removed_counts,
        "removed_examples": removed_examples,
    }
    return context


def _augment_context_with_dynamic_pm_queries(
    task_id: str,
    context,
    runtime_view: ProgramModelRuntimeView | None = None,
):
    target_name = str((context.target_function or {}).get("name") or "").strip()
    if not target_name:
        return context
    runtime_view = runtime_view or ProgramModelRuntimeView.from_task(task_id)
    function_context = runtime_view.get_function_context(target_name)
    caller_entries = _ordered_unique_entries(
        [
            _pm_entry(
                item,
                source="pm_callers",
                reason=f"pm_callers::{target_name}",
                priority=max(10, 42 - int(item.get("distance") or 0)),
            )
            for item in list(function_context.get("callers") or [])
            if str(item.get("name") or "").strip()
        ]
    )
    callee_entries = _ordered_unique_entries(
        [
            _pm_entry(
                item,
                source="pm_callees",
                reason=f"pm_callees::{target_name}",
                priority=max(8, 36 - int(item.get("distance") or 0)),
            )
            for item in list(function_context.get("callees") or [])
            if str(item.get("name") or "").strip()
        ]
    )
    slice_seed_names = [
        _coverage_entry_name(item)
        for item in (_exact_uncovered_target_entries(context) or _coverage_target_entries(context))[:3]
        if _coverage_entry_name(item)
    ]
    slice_raw: list[dict[str, Any]] = []
    for slice_seed_name in slice_seed_names:
        slice_raw.extend(runtime_view.get_slice_by_entry(slice_seed_name)[:10])
    slice_entries = _ordered_unique_entries(
        [
            _pm_entry(
                item,
                source="pm_slice",
                reason=f"pm_slice::{target_name}",
                priority=max(6, 30 - int(item.get("distance") or 0)),
            )
            for item in slice_raw
            if str(item.get("name") or "").strip() != target_name
        ]
    )
    expanded_selected_target_functions = _ordered_unique_entries(
        list(context.selected_target_functions or []),
        caller_entries,
        callee_entries,
        slice_entries,
    )
    query_summary = runtime_view.summary_payload()
    source_counts = {
        "pm_callers": len(caller_entries),
        "pm_callees": len(callee_entries),
        "pm_slice": len(slice_entries),
    }
    context.selected_target_functions = expanded_selected_target_functions[:24]
    context.context_package["pm_runtime_query"] = {
        "target_function": target_name,
        "function_context": function_context,
        "eligible_pool_entries": _ordered_unique_entries(caller_entries, callee_entries, slice_entries),
        "eligible_pool_size": len(_ordered_unique_entries(caller_entries, callee_entries, slice_entries)),
        "eligible_pool_source_counts": source_counts,
        "slice_seed_names": slice_seed_names,
        "query_summary": query_summary,
    }
    context.context_package.setdefault("program_model_interface", {})
    context.context_package["program_model_interface"]["runtime_query_enabled"] = True
    context.context_package["program_model_interface"]["runtime_query_methods"] = [
        "get_function_context",
        "get_callers",
        "get_callees",
        "get_slice_by_entry",
    ]
    return context


def _coverage_rotation_session_key(task) -> str:
    runtime = task.runtime or {}
    metadata = task.metadata or {}
    for value in (
        runtime.get("campaign_runtime_state_path"),
        runtime.get("campaign_parent_task_id"),
        metadata.get("campaign_parent_task_id"),
        runtime.get("campaign_active_session_task_id"),
        task.task_id,
    ):
        normalized = str(value or "").strip()
        if normalized:
            return normalized
    return task.task_id


def _prepare_recently_used_targets(
    rotation_session_key: str | None,
    entries: list[dict[str, Any]],
    runtime_view: ProgramModelRuntimeView,
) -> set[str]:
    if not rotation_session_key:
        return set()
    eligible_pool = _ELIGIBLE_TARGET_POOL_BY_ROTATION_SESSION.setdefault(rotation_session_key, {})
    retained_pool_entries = _strict_project_scoped_entries(
        runtime_view,
        list(eligible_pool.values()),
    )
    eligible_pool.clear()
    for item in retained_pool_entries:
        name = _coverage_entry_name(item)
        if not name:
            continue
        eligible_pool[name] = dict(item)
    for item in _strict_project_scoped_entries(runtime_view, entries):
        name = _coverage_entry_name(item)
        if not name:
            continue
        eligible_pool[name] = dict(item)
    eligible_names = set(eligible_pool)
    recently_used_targets = _RECENTLY_USED_TARGETS_BY_ROTATION_SESSION.setdefault(rotation_session_key, set())
    recently_used_targets.intersection_update(eligible_names)
    if eligible_names:
        rotation_reset_threshold = max(1, (len(eligible_names) * 95 + 99) // 100)
        if len(recently_used_targets) >= rotation_reset_threshold:
            logger.info(
                "coverage rotation reset session=%s used=%s eligible=%s threshold=%s",
                rotation_session_key,
                len(recently_used_targets),
                len(eligible_names),
                rotation_reset_threshold,
            )
            recently_used_targets.clear()
    return recently_used_targets


def _remember_recently_used_target(rotation_session_key: str | None, entry: dict[str, Any] | None) -> None:
    if not rotation_session_key or not isinstance(entry, dict):
        return
    name = _coverage_entry_name(entry)
    if not name:
        return
    _RECENTLY_USED_TARGETS_BY_ROTATION_SESSION.setdefault(rotation_session_key, set()).add(name)


def _eligible_rotation_pool_entries(
    context,
    *,
    rotation_session_key: str | None,
    coverage_pool: list[dict[str, Any]],
    runtime_view: ProgramModelRuntimeView,
) -> list[dict[str, Any]]:
    pm_entries = _pm_runtime_target_entries(context)
    retained_pool_entries = _strict_project_scoped_entries(
        runtime_view,
        sorted(
            (
                dict(item)
                for item in (_ELIGIBLE_TARGET_POOL_BY_ROTATION_SESSION.get(rotation_session_key) or {}).values()
            ),
            key=_coverage_entry_sort_key,
        ),
    )
    return _strict_project_scoped_entries(
        runtime_view,
        _ordered_unique_entries(
            _exact_uncovered_target_entries(context),
            _low_growth_target_entries(context),
            coverage_pool,
            pm_entries,
            retained_pool_entries,
        ),
    )


def _claim_next_distinct_entry(
    entries: list[dict[str, Any]],
    used_names: set[str],
    *,
    skip_recently_used: set[str] | None = None,
) -> dict[str, Any] | None:
    recently_used_targets = skip_recently_used or set()
    for item in entries:
        name = _coverage_entry_name(item)
        if not name or name in used_names or name in recently_used_targets:
            continue
        used_names.add(name)
        return dict(item)
    return None


def _selected_target_record_from_entry(
    context,
    entry: dict[str, Any],
    runtime_view: ProgramModelRuntimeView,
) -> dict[str, Any]:
    name = _coverage_entry_name(entry)
    if not name:
        return {}
    scoped_entry = _strict_project_scoped_entries(runtime_view, [dict(entry)])
    if not scoped_entry:
        return {}
    candidate_lists: list[list[dict[str, Any]]] = [
        [context.target_function] if isinstance(context.target_function, dict) else [],
        list(context.selected_target_functions or []),
        list(context.related_functions or []),
        list(context.callers or []),
        list(context.callees or []),
        list(context.extended_context_functions or []),
        _pm_runtime_target_entries(context),
        list((context.context_package or {}).get("exact_uncovered_target_functions") or []),
        list((context.context_package or {}).get("family_stagnation_targets") or []),
    ]
    resolved: dict[str, Any] = {}
    for candidates in candidate_lists:
        for item in _strict_project_scoped_entries(runtime_view, candidates):
            if not isinstance(item, dict) or _coverage_entry_name(item) != name:
                continue
            resolved = dict(item)
            break
        if resolved:
            break
    coverage_summary = resolved.get("coverage_summary") if isinstance(resolved.get("coverage_summary"), dict) else {}
    if not coverage_summary:
        coverage_summary = {
            "coverage_fraction": entry.get("coverage_fraction"),
            "total_lines": int(entry.get("total_lines", 0) or 0),
            "covered_lines": int(entry.get("covered_lines", 0) or 0),
        }
    reason = (
        resolved.get("reason")
        or entry.get("reason")
        or f"coverage_gap::{entry.get('queue_kind') or 'coverage_gap'}"
    )
    materialized = {
        "name": name,
        "file": resolved.get("file") or entry.get("file"),
        "line": resolved.get("line") or entry.get("line"),
        "reason": reason,
        "coverage_target_kind": entry.get("queue_kind"),
        "coverage_target_priority": int(entry.get("priority") or 0),
        "coverage_summary": coverage_summary,
    }
    return {key: value for key, value in materialized.items() if value not in (None, "", [], {})}


def _context_for_batch_focus(
    context,
    batch: dict[str, Any],
    runtime_view: ProgramModelRuntimeView,
):
    batch_strategy = str(batch.get("batch_strategy") or "").strip()
    focus_entries = _strict_project_scoped_entries(runtime_view, list(batch.get("focus_entries") or []))
    if batch_strategy == "open_ended_exploration":
        open_ended_targets = [
            _selected_target_record_from_entry(context, item, runtime_view)
            for item in _strict_project_scoped_entries(runtime_view, _exact_uncovered_target_entries(context))[:5]
        ]
        open_ended_targets = [item for item in open_ended_targets if item.get("name")]
        if not open_ended_targets:
            open_ended_targets = [
                dict(item)
                for item in _strict_project_scoped_entries(runtime_view, list(context.selected_target_functions or []))[:5]
                if isinstance(item, dict)
            ]
        return replace(
            context,
            target_function=None,
            selected_target_functions=open_ended_targets[:5],
        )
    if not focus_entries:
        return context
    primary_target = _selected_target_record_from_entry(context, focus_entries[0], runtime_view)
    primary_name = str(primary_target.get("name") or "").strip()
    if not primary_name:
        return context
    reordered_targets = [primary_target]
    seen = {primary_name}
    for item in _strict_project_scoped_entries(runtime_view, list(context.selected_target_functions or [])):
        if not isinstance(item, dict):
            continue
        name = _coverage_entry_name(item)
        if not name or name in seen:
            continue
        seen.add(name)
        reordered_targets.append(dict(item))
        if len(reordered_targets) >= 5:
            break
    return replace(
        context,
        target_function=primary_target,
        selected_target_functions=reordered_targets[:5],
    )


def _build_coverage_request_batches(
    context,
    seed_decision,
    *,
    seed_generation_attempts: int,
    rotation_session_key: str | None = None,
    runtime_view: ProgramModelRuntimeView,
) -> list[dict[str, Any]]:
    coverage_entries = _strict_project_scoped_entries(runtime_view, _coverage_target_entries(context))
    exact_uncovered_entries = _strict_project_scoped_entries(runtime_view, _exact_uncovered_target_entries(context))
    low_growth_entries = _strict_project_scoped_entries(runtime_view, _low_growth_target_entries(context))
    family_stagnation_entries = _strict_project_scoped_entries(runtime_view, _family_stagnation_target_entries(context))
    pm_runtime_entries = _strict_project_scoped_entries(runtime_view, _pm_runtime_target_entries(context))
    ranked_coverage_entries = _ordered_unique_entries(coverage_entries)
    coverage_pool = _strict_project_scoped_entries(
        runtime_view,
        _ordered_unique_entries(
            ranked_coverage_entries,
            exact_uncovered_entries,
            low_growth_entries,
            pm_runtime_entries,
        ),
    )
    refill_pool = _strict_project_scoped_entries(
        runtime_view,
        _ordered_unique_entries(
            exact_uncovered_entries,
            low_growth_entries,
            ranked_coverage_entries,
            pm_runtime_entries,
        ),
    )
    rotation_eligible_pool = _eligible_rotation_pool_entries(
        context,
        rotation_session_key=rotation_session_key,
        coverage_pool=coverage_pool,
        runtime_view=runtime_view,
    )
    recently_used_targets = _prepare_recently_used_targets(
        rotation_session_key,
        rotation_eligible_pool,
        runtime_view,
    )
    if seed_decision.mode != "SEED_EXPLORE" or not (coverage_pool or family_stagnation_entries):
        return [
            {
                "label": "default_generation",
                "focus_reason": "default selected target context",
                "focus_entries": coverage_entries[:1],
                "repair_attempts": max(1, seed_generation_attempts),
                "batch_strategy": "default_generation",
                "primary_target_function": (context.target_function or {}).get("name"),
                "focus_source": "default_selected_target",
            },
        ]
    batches: list[dict[str, Any]] = []
    used_names: set[str] = set()
    coverage_names = {_coverage_entry_name(item) for item in coverage_entries if _coverage_entry_name(item)}
    exact_names = {_coverage_entry_name(item) for item in exact_uncovered_entries if _coverage_entry_name(item)}
    low_growth_names = {_coverage_entry_name(item) for item in low_growth_entries if _coverage_entry_name(item)}
    pm_source_by_name = {
        _coverage_entry_name(item): str(item.get("eligible_pool_source") or "pm_runtime")
        for item in pm_runtime_entries
        if _coverage_entry_name(item)
    }
    family_stagnation_count = int((context.context_package or {}).get("campaign_family_stagnation_count") or 0)

    primary_entry = _claim_next_distinct_entry(
        coverage_pool,
        used_names,
        skip_recently_used=recently_used_targets,
    )
    if primary_entry:
        _remember_recently_used_target(rotation_session_key, primary_entry)
        primary_name = _coverage_entry_name(primary_entry)
        primary_focus_source = pm_source_by_name.get(primary_name)
        batches.append(
            {
                "label": "coverage_queue_top_1",
                "focus_reason": "highest-priority current coverage queue target",
                "focus_entries": [primary_entry],
                "repair_attempts": max(1, seed_generation_attempts),
                "batch_strategy": (
                    f"{primary_focus_source}_expansion"
                    if primary_focus_source
                    else (
                    "coverage_queue_top_1"
                    if primary_name in coverage_names
                    else "exact_uncovered_refill"
                    if primary_name in exact_names
                    else "low_growth_rotation"
                    if primary_name in low_growth_names
                    else "coverage_pool_rotation"
                    )
                ),
                "primary_target_function": primary_name,
                "focus_source": (
                    primary_focus_source
                    if primary_focus_source
                    else (
                    "coverage_queue"
                    if primary_name in coverage_names
                    else "exact_uncovered_snapshot"
                    if primary_name in exact_names
                    else "durable_low_growth_queue"
                    if primary_name in low_growth_names
                    else "retained_rotation_pool"
                    )
                ),
            },
        )

    secondary_entry = _claim_next_distinct_entry(
        coverage_pool,
        used_names,
        skip_recently_used=recently_used_targets,
    )
    if secondary_entry:
        _remember_recently_used_target(rotation_session_key, secondary_entry)
        secondary_name = _coverage_entry_name(secondary_entry)
        secondary_focus_source = pm_source_by_name.get(secondary_name)
        batches.append(
            {
                "label": "coverage_queue_top_2",
                "focus_reason": "next distinct coverage queue target after the primary batch",
                "focus_entries": [secondary_entry],
                "repair_attempts": max(1, min(seed_generation_attempts, 2)),
                "batch_strategy": (
                    f"{secondary_focus_source}_expansion"
                    if secondary_focus_source
                    else (
                    "coverage_queue_top_2"
                    if secondary_name in coverage_names
                    else "exact_uncovered_refill"
                    if secondary_name in exact_names
                    else "low_growth_rotation"
                    if secondary_name in low_growth_names
                    else "coverage_pool_rotation"
                    )
                ),
                "primary_target_function": secondary_name,
                "focus_source": (
                    secondary_focus_source
                    if secondary_focus_source
                    else (
                    "coverage_queue"
                    if secondary_name in coverage_names
                    else "exact_uncovered_snapshot"
                    if secondary_name in exact_names
                    else "durable_low_growth_queue"
                    if secondary_name in low_growth_names
                    else "retained_rotation_pool"
                    )
                ),
            },
        )

    family_entry = _claim_next_distinct_entry(family_stagnation_entries, used_names)
    if family_entry:
        batches.append(
            {
                "label": "family_stagnation_focus",
                "focus_reason": "oldest stalled family target from current family diversification state",
                "focus_entries": [family_entry],
                "repair_attempts": max(1, min(seed_generation_attempts, 2)),
                "batch_strategy": "family_stagnation_target",
                "primary_target_function": _coverage_entry_name(family_entry),
                "focus_source": "family_confirmation",
            },
        )
    elif family_stagnation_count >= 2:
        family_fallback_entry = _claim_next_distinct_entry(
            refill_pool,
            used_names,
            skip_recently_used=recently_used_targets,
        )
        if family_fallback_entry:
            _remember_recently_used_target(rotation_session_key, family_fallback_entry)
            family_fallback_name = _coverage_entry_name(family_fallback_entry)
            batches.append(
                {
                    "label": "family_stagnation_focus",
                    "focus_reason": "family stagnation is active; using the next distinct target to force diversification",
                    "focus_entries": [family_fallback_entry],
                    "repair_attempts": max(1, min(seed_generation_attempts, 2)),
                    "batch_strategy": "family_stagnation_target",
                    "primary_target_function": family_fallback_name,
                    "focus_source": "family_stagnation_fallback",
                },
            )
    else:
        refill_entry = _claim_next_distinct_entry(
            refill_pool,
            used_names,
            skip_recently_used=recently_used_targets,
        )
        if refill_entry:
            _remember_recently_used_target(rotation_session_key, refill_entry)
            refill_name = _coverage_entry_name(refill_entry)
            refill_focus_source = pm_source_by_name.get(refill_name)
            batches.append(
                {
                    "label": "exact_uncovered_refill",
                    "focus_reason": "queue diversity exhausted; refilled from the current exact covered=false targets",
                    "focus_entries": [refill_entry],
                    "repair_attempts": max(1, min(seed_generation_attempts, 2)),
                    "batch_strategy": (
                        f"{refill_focus_source}_expansion"
                        if refill_focus_source
                        else "exact_uncovered_refill"
                    ),
                    "primary_target_function": refill_name,
                    "focus_source": (
                        refill_focus_source
                        if refill_focus_source
                        else "exact_uncovered_snapshot"
                        if refill_name in exact_names
                        else "coverage_queue"
                    ),
                },
            )

    batches.append(
        {
            "label": "open_ended_exploration",
            "focus_reason": "open-ended exploration across parser-adjacent and untouched exact-coverage targets",
            "focus_entries": [],
            "repair_attempts": max(1, min(seed_generation_attempts, 2)),
            "batch_strategy": "open_ended_exploration",
            "primary_target_function": None,
            "focus_source": "open_ended",
        },
    )
    return batches[:4] or [
        {
            "label": "coverage_gap_fallback",
            "focus_reason": "fallback coverage gap context",
            "focus_entries": coverage_pool[:1],
            "repair_attempts": max(1, seed_generation_attempts),
            "batch_strategy": "coverage_gap_fallback",
            "primary_target_function": _coverage_entry_name(coverage_pool[0]) if coverage_pool else None,
            "focus_source": "coverage_queue" if coverage_pool else "default_selected_target",
        },
    ]


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("seed received task %s", task_id)
    task_store.update_status(
        task_id,
        TaskStatus.SEEDING,
        runtime_patch={"seed_started_at": task_store.now()},
    )

    task = task_store.load_task(task_id)
    build_registry_path = task.runtime.get("build_registry_path")
    if not build_registry_path or not Path(build_registry_path).exists():
        raise RuntimeError("build registry is missing for seed generation")
    if not task.runtime.get("index_manifest_path"):
        raise RuntimeError("index manifest is missing for seed generation")

    client = LLMClient()

    metadata = task.metadata or {}
    seed_generation_attempts = resolve_int_setting(
        metadata,
        "SEED_GENERATION_ATTEMPTS",
        settings.seed_generation_attempts,
    )
    seed_function_timeout_seconds = resolve_int_setting(
        metadata,
        "SEED_FUNCTION_TIMEOUT_SECONDS",
        settings.seed_function_timeout_seconds,
    )
    seed_max_bytes = resolve_int_setting(metadata, "SEED_MAX_BYTES", settings.seed_max_bytes)
    llm_temperature = resolve_float_setting(metadata, "LLM_TEMPERATURE", settings.llm_temperature)
    llm_max_tokens = resolve_optional_int_setting(metadata, "LLM_MAX_TOKENS", settings.llm_max_tokens)
    llm_timeout_seconds = resolve_int_setting(
        metadata,
        "LLM_TIMEOUT_SECONDS",
        settings.llm_timeout_seconds,
    )
    llm_max_retries = resolve_int_setting(metadata, "LLM_MAX_RETRIES", settings.llm_max_retries)
    seed_generation_backend = resolve_text_setting(metadata, "SEED_GENERATION_BACKEND", "auto")
    task_partition = resolve_text_setting(metadata, "task_partition", "official_main")
    policy = _clean_policy_fields(metadata)
    allow_imported_seed_material = bool(policy["allow_imported_seed_material"])
    allow_cached_seed_material = bool(policy["allow_cached_seed_material"])
    allow_fallback_non_llm = bool(policy["allow_fallback_non_llm"])

    build_registry = _load_json(build_registry_path)
    requested_target = (
        task.runtime.get("selected_target")
        or task.runtime.get("active_harness")
        or task.metadata.get("selected_target")
    )
    harness = (
        select_harness_by_name(build_registry_path, requested_target, task.metadata.get("project"))
        if requested_target
        else None
    )
    if harness is None:
        harness = select_harness(build_registry_path, task.metadata.get("project"))
    coverage_manifest_path = task.runtime.get("coverage_feedback_manifest_path")
    coverage_manifest = _load_json(coverage_manifest_path) if coverage_manifest_path and Path(coverage_manifest_path).exists() else None
    seed_decision = select_seed_task_mode(task, coverage_manifest)
    context = retrieve_context(task_id, harness, task_mode=seed_decision.mode)
    runtime_view = ProgramModelRuntimeView.from_task(task_id)
    context = _augment_context_with_dynamic_pm_queries(task_id, context, runtime_view)
    context = _apply_project_scope_filter(context, runtime_view)
    previous_mode_counts = dict(task.runtime.get("seed_mode_counts") or {})
    seed_mode_counts = {
        "SEED_INIT": int(previous_mode_counts.get("SEED_INIT") or 0),
        "VULN_DISCOVERY": int(previous_mode_counts.get("VULN_DISCOVERY") or 0),
        "SEED_EXPLORE": int(previous_mode_counts.get("SEED_EXPLORE") or 0),
    }
    seed_mode_counts[seed_decision.mode] = seed_mode_counts.get(seed_decision.mode, 0) + 1
    query_decision_path = (context.context_package.get("evidence_paths") or {}).get("query_to_target_decision_manifest")
    query_decision = _load_json(query_decision_path) if query_decision_path else {}
    harness_selector_path = write_harness_selector_manifest(
        task_id,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "requested_target": requested_target,
            "selected_harness": harness.name,
            "selected_harness_path": str(harness.executable_path),
            "selected_by_name_override": bool(requested_target),
            "candidate_harnesses": context.candidate_harnesses,
            "selector_backend": "build_registry_plus_source_resolution",
            "coverage_feedback_manifest_path": coverage_manifest_path,
            "selection_rationale": context.selection_rationale or harness.reasons,
        },
    )
    weighted_harness_selector_path = write_weighted_harness_selector_manifest(
        task_id,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "selected_harness": harness.name,
            "selected_harness_path": str(harness.executable_path),
            "weighted_candidates": [
                {
                    "name": candidate.get("name"),
                    "path": candidate.get("path"),
                    "kind": candidate.get("kind"),
                    "score": (
                        100
                        if candidate.get("name") == (context.selected_harness or harness.name)
                        else 30
                    ),
                }
                for candidate in context.candidate_harnesses
            ],
            "coverage_feedback_manifest_path": coverage_manifest_path,
            "selector_backend": "original_like_weighted_harness_selection",
            "selection_rationale": context.selection_rationale or harness.reasons,
        },
    )
    function_selector_payload = _sanitize_selector_payload(
        runtime_view,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "seed_mode": seed_decision.mode,
            "selected_harness": context.selected_harness or harness.name,
            "selected_target_function": context.target_function,
            "selected_target_functions": context.selected_target_functions,
            "selection_rationale": context.selection_rationale,
            "context_package_path": context.context_package_path,
            "coverage_summary_manifest_path": task.runtime.get("coverage_summary_manifest_path"),
            "program_model_backend": context.context_package.get("program_model_interface", {}),
            "coverage_query_evidence": context.context_package.get("coverage_query_evidence", {}),
        },
    )
    function_selector_path = write_function_selector_manifest(
        task_id,
        function_selector_payload,
    )
    weighted_function_selector_payload = _sanitize_selector_payload(
        runtime_view,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "seed_mode": seed_decision.mode,
            "selection_backend": context.context_package.get("target_selection_backend"),
            "selected_target_function": context.target_function,
            "selected_target_functions": context.selected_target_functions,
            "query_driven_candidates": query_decision.get("query_driven_candidates", []),
            "fallback_scored_candidates": query_decision.get("fallback_scored_candidates", []),
            "selection_rationale": context.selection_rationale,
            "coverage_feedback_manifest_path": coverage_manifest_path,
            "program_model_query_validation_manifest_path": task.runtime.get("program_model_query_validation_manifest_path"),
        },
    )
    weighted_function_selector_path = write_weighted_function_selector_manifest(
        task_id,
        weighted_function_selector_payload,
    )
    seed_family_plan = _derive_seed_family_plan(task, context, seed_decision)
    seed_family_plan_path = write_seed_family_plan_manifest(task_id, seed_family_plan)
    seed_sampling_path = write_seed_task_sampling_manifest(
        task_id,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "selected_seed_mode": seed_decision.mode,
            "selected_seed_mode_reason": seed_decision.reason,
            "mode_counts_before": previous_mode_counts,
            "mode_counts_after": seed_mode_counts,
            "sampling_backend": "original_seed_gen_style_minimums_plus_feedback_bias",
            "coverage_feedback_manifest_path": coverage_manifest_path,
            "raw_crash_count": int(task.runtime.get("raw_crash_count") or 0),
            "traced_crash_count": int(task.runtime.get("traced_crash_count") or 0),
        },
    )
    seed_mode_trigger_path = write_seed_mode_trigger_manifest(
        task_id,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "selected_seed_mode": seed_decision.mode,
            "trigger_inputs": {
                "seed_mode_override": task.runtime.get("seed_task_mode_override"),
                "coverage_feedback_triggered": bool(task.runtime.get("coverage_feedback_triggered")),
                "raw_crash_count": int(task.runtime.get("raw_crash_count") or 0),
                "traced_crash_count": int(task.runtime.get("traced_crash_count") or 0),
                "patch_priority_action": task.runtime.get("patch_priority_action"),
                "campaign_budget_state": task.runtime.get("campaign_budget_state") or task.metadata.get("campaign_budget_state"),
                "mode_counts_before": previous_mode_counts,
            },
            "selected_seed_mode_reason": seed_decision.reason,
            "suppression_reason": (
                "SEED_EXPLORE suppressed because crash history already exists"
                if seed_decision.mode != "SEED_EXPLORE"
                and (int(task.runtime.get("raw_crash_count") or 0) > 0 or int(task.runtime.get("traced_crash_count") or 0) > 0)
                else None
            ),
        },
    )
    coverage_bridge_payload = _sanitize_selector_payload(
        runtime_view,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "seed_mode": seed_decision.mode,
            "coverage_feedback_manifest_path": coverage_manifest_path,
            "coverage_summary_manifest_path": task.runtime.get("coverage_summary_manifest_path"),
            "selected_harness": context.selected_harness or harness.name,
            "selected_target_function": (context.target_function or {}).get("name"),
            "selected_target_functions": context.selected_target_functions,
            "coverage_feedback_inputs": {
                "stalled": bool((coverage_manifest or {}).get("stalled")),
                "feedback_summary": (coverage_manifest or {}).get("feedback_summary") or {},
                "current_snapshot": (coverage_manifest or {}).get("current") or {},
            },
            "bridge_reason": seed_decision.reason,
            "bridge_effect": {
                "seed_mode": seed_decision.mode,
                "budget_multiplier": seed_decision.budget_multiplier,
                "priority": seed_decision.priority,
            },
        },
    )
    coverage_bridge_path = write_coverage_to_selector_bridge_manifest(
        task_id,
        coverage_bridge_payload,
    )
    selector_feedback_payload = _sanitize_selector_payload(
        runtime_view,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "before": {
                "requested_target": requested_target,
                "seed_mode_override": task.runtime.get("seed_task_mode_override"),
                "selected_target": task.runtime.get("selected_target"),
                "selected_harness": task.runtime.get("selected_harness"),
                "selected_target_function": task.runtime.get("selected_target_function"),
            },
            "after": {
                "selected_harness": context.selected_harness or harness.name,
                "selected_harness_path": context.selected_harness_path or str(harness.executable_path),
                "selected_target_function": (context.target_function or {}).get("name"),
                "selected_target_functions": context.selected_target_functions,
                "seed_mode": seed_decision.mode,
                "seed_strategy_reason": seed_decision.reason,
            },
            "consumers": ["harness_selector", "function_selector", "seed_family_planner"],
            "input_refs": [
                value
                for value in [
                    coverage_manifest_path,
                    task.runtime.get("coverage_summary_manifest_path"),
                    task.runtime.get("scheduler_feedback_consumption_path"),
                    context.context_package_path,
                ]
                if value
            ],
            "consumption_reason": seed_decision.reason,
        },
    )
    selector_feedback_path = write_selector_feedback_consumption(
        task_id,
        selector_feedback_payload,
    )
    seed_mode_semantics_path = write_seed_mode_semantics_manifest(
        task_id,
        {
            "task_id": task_id,
            "generated_at": task_store.now(),
            "selected_seed_mode": seed_decision.mode,
            "selected_seed_mode_reason": seed_decision.reason,
            "selected_seed_mode_semantics": _seed_mode_semantics(seed_decision.mode),
            "all_modes": {
                mode: _seed_mode_semantics(mode)
                for mode in ("SEED_INIT", "SEED_EXPLORE", "VULN_DISCOVERY")
            },
            "mode_transition_evidence": {
                "previous_mode_override": task.runtime.get("seed_task_mode_override"),
                "coverage_feedback_triggered": bool(task.runtime.get("coverage_feedback_triggered")),
                "raw_crash_count": int(task.runtime.get("raw_crash_count") or 0),
                "traced_crash_count": int(task.runtime.get("traced_crash_count") or 0),
            },
        },
    )

    require_real_llm = seed_generation_backend == "llm"
    raw_response_text = ""
    last_error: str | None = None
    parsed_module = None
    llm_used = False
    backend_used = "heuristic_fallback"
    parser_metadata = {
        "first_response_status": "not_attempted",
        "parser_first_pass_success": False,
        "parser_repair_attempted": False,
        "parser_final_success": False,
        "parse_failure_reason": None,
    }
    llm_metadata = build_non_llm_metadata(
        generated_by="source_seed_worker.heuristic_fallback",
        failure_reason=(
            "seed_generation_backend=heuristic_fallback"
            if seed_generation_backend == "heuristic_fallback"
            else "LLM not attempted yet"
        ),
    )
    prompt_template_id = f"source_seed::{seed_decision.mode}::{harness.name}"
    coverage_rotation_session_key = _coverage_rotation_session_key(task)
    coverage_request_batches = _build_coverage_request_batches(
        context,
        seed_decision,
        seed_generation_attempts=seed_generation_attempts,
        rotation_session_key=coverage_rotation_session_key,
        runtime_view=runtime_view,
    )
    logger.info(
        "[%s] seed request plan: mode=%s batches=%s coverage_groups=%s pm_pool=%s pm_queries=%s",
        task_id,
        seed_decision.mode,
        len(coverage_request_batches),
        (context.context_package.get("coverage_exploration_contract") or {}).get("queue_kind_counts") or {},
        (_pm_runtime_query_payload(context).get("eligible_pool_size") or 0),
        (_pm_query_summary(context).get("query_call_count") or 0),
    )
    coverage_request_batch_reports: list[dict[str, Any]] = []
    successful_batches: list[dict[str, Any]] = []
    aggregated_llm_request_count = 0
    llm_batch_success_count = 0
    llm_batch_failure_count = 0
    if require_real_llm and not client.enabled():
        llm_metadata = build_non_llm_metadata(
            generated_by="source_seed_worker.llm",
            failure_reason="real LLM requested but LLM is disabled or API key is missing",
            provenance="fallback_non_llm",
        )
        llm_audit_paths = write_llm_seed_audit(
            task_id,
            target_mode="source",
            task_partition=task_partition,
            requested_seed_backend=seed_generation_backend,
            actual_seed_backend="llm_unavailable",
            llm_metadata=_llm_fields(llm_metadata),
            seed_provenance="no_seed_generated",
            prompt_template_id=f"source_seed::{seed_decision.mode}::{harness.name}",
            task_should_fail_if_llm_missing=require_real_llm,
            fallback_used=False,
            fallback_reason=llm_metadata.llm_failure_reason,
        )
        task_store.update_runtime(task_id, {**_llm_fields(llm_metadata), **llm_audit_paths, "seed_backend_degraded": True})
        raise RuntimeError(llm_metadata.llm_failure_reason or "real LLM requested but unavailable")
    if seed_generation_backend != "heuristic_fallback" and not client.enabled():
        llm_metadata = build_non_llm_metadata(
            generated_by="source_seed_worker.heuristic_fallback",
            failure_reason="LLM disabled or API key is missing; using non-LLM fallback",
            provenance="fallback_non_llm",
        )
    if seed_generation_backend != "heuristic_fallback" and client.enabled():
        batch_total = len(coverage_request_batches)
        for batch_index, batch in enumerate(coverage_request_batches, start=1):
            batch_last_error: str | None = None
            batch_prompt_template_id = prompt_template_id
            batch_parsed_module = None
            batch_parser_metadata = dict(parser_metadata)
            batch_raw_response_text = ""
            batch_llm_metadata = llm_metadata
            batch_focus_entries = list(batch.get("focus_entries") or [])
            batch_context = _context_for_batch_focus(context, batch, runtime_view)
            logger.info(
                "[%s] seed request batch %s/%s label=%s strategy=%s primary=%s focus=%s",
                task_id,
                batch_index,
                batch_total,
                batch.get("label"),
                batch.get("batch_strategy"),
                batch.get("primary_target_function"),
                [str(item.get("name") or "") for item in batch_focus_entries if isinstance(item, dict) and item.get("name")],
            )
            batch_report = {
                "batch_index": batch_index,
                "label": batch.get("label"),
                "batch_strategy": batch.get("batch_strategy"),
                "focus_source": batch.get("focus_source"),
                "eligible_pool_source": batch.get("focus_source"),
                "focus_reason": batch.get("focus_reason"),
                "primary_target_function": batch.get("primary_target_function"),
                "focus_target_names": [
                    str(item.get("name") or "")
                    for item in batch_focus_entries
                    if isinstance(item, dict) and item.get("name")
                ],
                "repair_attempts_configured": int(batch.get("repair_attempts") or seed_generation_attempts),
                "eligible_pool_size": int(_pm_runtime_query_payload(context).get("eligible_pool_size") or 0),
                "eligible_pool_source_counts": dict(_pm_runtime_query_payload(context).get("eligible_pool_source_counts") or {}),
                "success": False,
            }
            for attempt_index in range(int(batch.get("repair_attempts") or seed_generation_attempts)):
                use_compact_prompt = bool(batch_last_error) or attempt_index > 0
                batch_prompt_template_id = (
                    f"source_seed_compact::{seed_decision.mode}::{harness.name}"
                    if use_compact_prompt
                    else f"source_seed::{seed_decision.mode}::{harness.name}"
                )
                messages = build_messages(
                    task.metadata.get("project", "unknown"),
                    harness,
                    batch_context,
                    task_mode=seed_decision.mode,
                    previous_error=batch_last_error,
                    compact=use_compact_prompt,
                    coverage_focus_entries=batch_focus_entries,
                    coverage_focus_reason=str(batch.get("focus_reason") or ""),
                    batch_strategy=str(batch.get("batch_strategy") or ""),
                )
                try:
                    response_payload, response_metadata = client.chat_with_metadata(
                        messages,
                        temperature=llm_temperature,
                        max_tokens=llm_max_tokens,
                        timeout_seconds=llm_timeout_seconds,
                        max_retries=llm_max_retries,
                        generated_by="source_seed_worker.llm",
                    )
                    batch_llm_metadata = response_metadata
                    llm_metadata = response_metadata
                    aggregated_llm_request_count += int(response_metadata.llm_request_count or 0)
                except Exception as exc:
                    if isinstance(exc, LLMCallError):
                        batch_llm_metadata = exc.metadata
                        llm_metadata = exc.metadata
                        aggregated_llm_request_count += int(exc.metadata.llm_request_count or 0)
                    batch_last_error = str(exc)
                    last_error = batch_last_error
                    logger.warning(
                        "seed llm failed task=%s harness=%s batch=%s/%s error=%s",
                        task_id,
                        harness.name,
                        batch_index,
                        batch_total,
                        batch_last_error,
                    )
                    if require_real_llm and not successful_batches and batch_index == batch_total and attempt_index == int(batch.get("repair_attempts") or seed_generation_attempts) - 1:
                        llm_audit_paths = write_llm_seed_audit(
                            task_id,
                            target_mode="source",
                            task_partition=task_partition,
                            requested_seed_backend=seed_generation_backend,
                            actual_seed_backend="llm_failed",
                            llm_metadata=_llm_fields(llm_metadata),
                            seed_provenance="no_seed_generated",
                            prompt_template_id=batch_prompt_template_id,
                            task_should_fail_if_llm_missing=require_real_llm,
                            fallback_used=False,
                            fallback_reason=llm_metadata.llm_failure_reason,
                        )
                        task_store.update_runtime(task_id, {**_llm_fields(llm_metadata), **llm_audit_paths, "seed_backend_degraded": True})
                        raise
                    continue
                batch_raw_response_text = extract_content(response_payload)
                batch_parser_metadata["first_response_status"] = batch_llm_metadata.llm_http_status
                try:
                    batch_parsed_module, batch_parser_metadata = parse_seed_module_with_repair(batch_raw_response_text)
                    llm_used = True
                    backend_used = "llm"
                    llm_batch_success_count += 1
                    batch_report.update(
                        {
                            "success": True,
                            "used_compact_prompt": use_compact_prompt,
                            "prompt_template_id": batch_prompt_template_id,
                            "llm_request_count": int(batch_llm_metadata.llm_request_count or 0),
                            "selected_target_function": (batch_context.target_function or {}).get("name"),
                            "selected_target_functions": list(batch_context.selected_target_functions),
                            "generated_functions": list(batch_parsed_module.function_names),
                        },
                    )
                    successful_batches.append(
                        {
                            "batch_index": batch_index,
                            "label": batch.get("label"),
                            "focus_reason": batch.get("focus_reason"),
                            "focus_entries": batch_focus_entries,
                            "prompt_template_id": batch_prompt_template_id,
                            "raw_response_text": batch_raw_response_text,
                            "parsed_module": batch_parsed_module,
                            "parser_metadata": batch_parser_metadata,
                            "llm_metadata": batch_llm_metadata,
                        },
                    )
                    parsed_module = batch_parsed_module
                    parser_metadata = batch_parser_metadata
                    raw_response_text = batch_raw_response_text
                    prompt_template_id = batch_prompt_template_id
                    break
                except SeedParseError as exc:
                    batch_parser_metadata = exc.metadata
                    batch_last_error = str(exc)
                    last_error = batch_last_error
                    batch_llm_metadata.llm_failure_reason = f"LLM response parse failure: {batch_last_error}"
                    llm_metadata = batch_llm_metadata
                    logger.warning(
                        "seed parsing failed task=%s harness=%s batch=%s/%s error=%s",
                        task_id,
                        harness.name,
                        batch_index,
                        batch_total,
                        batch_last_error,
                    )
                    if require_real_llm and not successful_batches and batch_index == batch_total and attempt_index == int(batch.get("repair_attempts") or seed_generation_attempts) - 1:
                        llm_audit_paths = write_llm_seed_audit(
                            task_id,
                            target_mode="source",
                            task_partition=task_partition,
                            requested_seed_backend=seed_generation_backend,
                            actual_seed_backend="llm_parse_failed",
                            llm_metadata=_llm_fields(llm_metadata),
                            seed_provenance="no_seed_generated",
                            prompt_template_id=batch_prompt_template_id,
                            task_should_fail_if_llm_missing=require_real_llm,
                            fallback_used=False,
                            fallback_reason=llm_metadata.llm_failure_reason,
                        )
                        task_store.update_runtime(
                            task_id,
                            {
                                **_llm_fields(llm_metadata),
                                **llm_audit_paths,
                                **batch_parser_metadata,
                                "seed_backend_degraded": True,
                            },
                        )
                        raise RuntimeError(llm_metadata.llm_failure_reason)
            if not batch_report.get("success"):
                llm_batch_failure_count += 1
                batch_report.update(
                    {
                        "used_compact_prompt": bool(batch_last_error),
                        "prompt_template_id": batch_prompt_template_id,
                        "error": batch_last_error,
                    },
                )
            coverage_request_batch_reports.append(batch_report)
        if aggregated_llm_request_count:
            llm_metadata.llm_request_count = aggregated_llm_request_count

    if parsed_module is None:
        if not allow_fallback_non_llm:
            llm_metadata.llm_provenance = "fallback_non_llm"
            llm_metadata.llm_failure_reason = last_error or "LLM output unavailable and fallback is disabled"
            llm_audit_paths = write_llm_seed_audit(
                task_id,
                target_mode="source",
                task_partition=task_partition,
                requested_seed_backend=seed_generation_backend,
                actual_seed_backend="llm_failed",
                llm_metadata=_llm_fields(llm_metadata),
                seed_provenance="no_seed_generated",
                prompt_template_id=prompt_template_id,
                task_should_fail_if_llm_missing=require_real_llm,
                fallback_used=False,
                fallback_reason=llm_metadata.llm_failure_reason,
            )
            task_store.update_runtime(
                task_id,
                {
                    **_llm_fields(llm_metadata),
                    **llm_audit_paths,
                    **parser_metadata,
                    "fallback_non_llm_used": False,
                    "seed_backend_degraded": True,
                },
            )
            raise RuntimeError(llm_metadata.llm_failure_reason)
        parsed_module = _build_source_heuristic_module(
            task.metadata.get("project", "unknown"),
            harness.name,
            seed_decision.mode,
        )
        raw_response_text = parsed_module.code
        backend_used = "heuristic_fallback"
        llm_metadata.llm_provenance = "fallback_non_llm"
        llm_metadata.generated_by = "source_seed_worker.heuristic_fallback"
        successful_batches = [
            {
                "batch_index": 1,
                "label": "heuristic_fallback",
                "focus_reason": "non-llm fallback",
                "focus_entries": [],
                "prompt_template_id": prompt_template_id,
                "raw_response_text": raw_response_text,
                "parsed_module": parsed_module,
                "parser_metadata": parser_metadata,
                "llm_metadata": llm_metadata,
            },
        ]
        coverage_request_batch_reports.append(
            {
                "batch_index": 1,
                "label": "heuristic_fallback",
                "focus_reason": "non-llm fallback",
                "focus_target_names": [],
                "repair_attempts_configured": 0,
                "success": True,
                "generated_functions": list(parsed_module.function_names),
                "prompt_template_id": prompt_template_id,
            },
        )

    llm_response_path = Path(task.layout["seed"]) / "llm_response.txt"
    generated_module_path = Path(task.layout["seed"]) / "generated_seed_module.py"
    response_artifact_paths: list[str] = []
    module_artifact_paths: list[str] = []
    combined_responses: list[str] = []
    combined_module_codes: list[str] = []
    generated_functions: list[str] = []
    generated_files: list[str] = []
    execution_errors: list[str] = []
    for batch in successful_batches:
        batch_index = int(batch.get("batch_index") or 0)
        batch_response_path = Path(task.layout["seed"]) / f"llm_response_batch_{batch_index:02d}.txt"
        batch_module_path = Path(task.layout["seed"]) / f"generated_seed_module_batch_{batch_index:02d}.py"
        batch_raw = str(batch.get("raw_response_text") or "")
        batch_module = batch.get("parsed_module")
        if batch_raw:
            _write_text(batch_response_path, batch_raw)
            response_artifact_paths.append(str(batch_response_path))
            combined_responses.append(f"# batch {batch_index}: {batch.get('label')}\n{batch_raw}")
        if batch_module is None:
            continue
        _write_text(batch_module_path, batch_module.code)
        module_artifact_paths.append(str(batch_module_path))
        combined_module_codes.append(batch_module.code)
        generated_functions.extend(list(batch_module.function_names))
        batch_generated_files, batch_execution_errors = execute_seed_functions(
            task_id,
            batch_module,
            Path(task.layout["seed_generated"]),
            max_bytes=seed_max_bytes,
            function_timeout_seconds=seed_function_timeout_seconds,
        )
        generated_files.extend(batch_generated_files)
        execution_errors.extend(batch_execution_errors)

    _write_text(llm_response_path, "\n\n".join(combined_responses) if combined_responses else raw_response_text)
    _write_text(generated_module_path, "\n\n".join(combined_module_codes) if combined_module_codes else parsed_module.code)
    if not generated_files:
        raise RuntimeError(
            "LLM generated functions but none executed successfully: "
            + "; ".join(execution_errors or ["no outputs"])
        )

    resolved_imports = task.runtime.get("resolved_imports", {})
    imported_seed_count = (
        stage_imported_seed_material(
            imported_seed_path=resolved_imports.get("existing_seed_path"),
            imported_corpus_path=resolved_imports.get("existing_corpus_path"),
            seed_corpus_zips=[item["path"] for item in build_registry.get("seed_corpora", [])],
            output_dir=Path(task.layout["seed_imported"]),
        )
        if allow_imported_seed_material
        else 0
    )
    cached_seed_count = 0
    merged_paths = merge_generated_seeds(
        generated_files,
        Path(task.layout["corpus_active"]),
        imported_seed_dir=Path(task.layout["seed_imported"]) if imported_seed_count else None,
    )
    active_corpus_count = _active_corpus_count(Path(task.layout["corpus_active"]))
    fallback_non_llm_used = backend_used == "heuristic_fallback"
    seed_provenance = llm_metadata.llm_provenance if llm_used else "fallback_non_llm"
    llm_audit_paths = write_llm_seed_audit(
        task_id,
        target_mode="source",
        task_partition=task_partition,
        requested_seed_backend=seed_generation_backend,
        actual_seed_backend=backend_used,
        llm_metadata=_llm_fields(llm_metadata),
        seed_provenance=seed_provenance,
        prompt_template_id=prompt_template_id,
        task_should_fail_if_llm_missing=require_real_llm,
        fallback_used=fallback_non_llm_used,
        fallback_reason=llm_metadata.llm_failure_reason if fallback_non_llm_used else None,
    )
    seed_init_chain_manifest_path = write_seed_init_chain_manifest(
        task_id,
        generated_at=task_store.now(),
        context_phase={
            "phase": "get_context",
            "context_package_path": context.context_package_path,
            "selected_harness": context.selected_harness or harness.name,
            "selected_harness_path": context.selected_harness_path or str(harness.executable_path),
            "candidate_harnesses": context.candidate_harnesses,
            "selected_target_function": (context.target_function or {}).get("name"),
            "selected_target_functions": context.selected_target_functions,
            "selection_rationale": context.selection_rationale,
            "program_model_interface": context.context_package.get("program_model_interface", {}),
            "program_model_query_summary": _pm_query_summary(context),
            "eligible_pool_size": int(_pm_runtime_query_payload(context).get("eligible_pool_size") or 0),
            "eligible_pool_source_counts": dict(_pm_runtime_query_payload(context).get("eligible_pool_source_counts") or {}),
        },
        generation_phase={
            "phase": "generate_seeds",
            "seed_task_mode": seed_decision.mode,
            "seed_strategy_reason": seed_decision.reason,
            "seed_generation_backend": backend_used,
            "llm_used": llm_used,
            "llm_real_call_verified": llm_metadata.llm_real_call_verified,
            "llm_provenance": llm_metadata.llm_provenance,
            "prompt_sha256": llm_metadata.prompt_sha256,
            "response_sha256": llm_metadata.response_sha256,
            "parser": parser_metadata,
            "generated_functions": list(dict.fromkeys(generated_functions)),
            "coverage_request_batch_count": len(successful_batches),
            "coverage_request_batches": coverage_request_batch_reports,
            "harness_selector_manifest_path": harness_selector_path,
            "weighted_harness_selector_manifest_path": weighted_harness_selector_path,
            "function_selector_manifest_path": function_selector_path,
            "weighted_function_selector_manifest_path": weighted_function_selector_path,
            "seed_family_plan_manifest_path": seed_family_plan_path,
            "seed_task_sampling_manifest_path": seed_sampling_path,
            "seed_mode_trigger_manifest_path": seed_mode_trigger_path,
        },
        execution_phase={
            "phase": "execute_seeds",
            "generated_seed_count": len(generated_files),
            "output_files": generated_files,
            "execution_errors": execution_errors,
            "imported_seed_count": imported_seed_count,
            "merged_corpus_files": merged_paths,
            "active_corpus_count": active_corpus_count,
            "downstream_queue": QueueNames.FUZZ,
        },
    )

    manifest_payload = {
        "task_id": task_id,
        "execution_mode": (task.execution_mode.value if task.execution_mode else "fresh"),
        "selected_harness": context.selected_harness or harness.name,
        "selected_harness_path": context.selected_harness_path or str(harness.executable_path),
        "candidate_harnesses": context.candidate_harnesses,
        "harness_source_path": str(harness.source_path) if harness.source_path else None,
        "seed_task_mode": seed_decision.mode,
        "seed_strategy_reason": seed_decision.reason,
        "seed_budget_multiplier": seed_decision.budget_multiplier,
        "seed_generation_backend": backend_used,
        "llm_used": llm_used,
        "llm_model": client.model if llm_used else None,
        "llm_temperature": llm_temperature,
        "llm_max_tokens": llm_max_tokens,
        **parser_metadata,
        **_llm_fields(llm_metadata),
        **policy,
        "seed_provenance": seed_provenance,
        "task_partition": task_partition,
        "requested_seed_backend": seed_generation_backend,
        "actual_seed_backend": backend_used,
        "cached_seed_count": cached_seed_count,
        "fallback_non_llm_used": fallback_non_llm_used,
        "llm_seed_audit_manifest_path": llm_audit_paths["llm_seed_audit_manifest_path"],
        "llm_backend_integrity_report_path": llm_audit_paths["llm_backend_integrity_report_path"],
        "seed_backend_degradation_report_path": llm_audit_paths["seed_backend_degradation_report_path"],
        "context_sources": context.context_sources,
        "context_package_path": context.context_package_path,
        "context_backend_contribution_path": str(Path(task.task_dir) / "index" / "context_backend_contribution.json"),
        "target_selection_backend_manifest_path": str(Path(task.task_dir) / "index" / "target_selection_backend_manifest.json"),
        "query_to_target_decision_manifest_path": str(Path(task.task_dir) / "index" / "query_to_target_decision_manifest.json"),
        "query_candidate_denoising_report_path": str(Path(task.task_dir) / "index" / "query_candidate_denoising_report.json"),
        "seed_init_chain_manifest_path": seed_init_chain_manifest_path,
        "harness_selector_manifest_path": harness_selector_path,
        "weighted_harness_selector_manifest_path": weighted_harness_selector_path,
        "function_selector_manifest_path": function_selector_path,
        "weighted_function_selector_manifest_path": weighted_function_selector_path,
        "seed_family_plan_manifest_path": seed_family_plan_path,
        "seed_task_sampling_manifest_path": seed_sampling_path,
        "seed_mode_trigger_manifest_path": seed_mode_trigger_path,
        "coverage_to_selector_bridge_manifest_path": coverage_bridge_path,
        "selector_feedback_consumption_path": selector_feedback_path,
        "seed_mode_semantics_manifest_path": seed_mode_semantics_path,
        "context_package_consumed": bool(context.context_package),
        "target_function_name": (context.target_function or {}).get("name"),
        "target_function_path": (context.target_function or {}).get("file"),
        "target_function_line": (context.target_function or {}).get("line"),
        "selected_target_functions": context.selected_target_functions,
        "eligible_pool_size": int(_pm_runtime_query_payload(context).get("eligible_pool_size") or 0),
        "eligible_pool_sources": sorted(((_pm_runtime_query_payload(context).get("eligible_pool_source_counts") or {}).keys())),
        "eligible_pool_source_counts": dict(_pm_runtime_query_payload(context).get("eligible_pool_source_counts") or {}),
        "program_model_query_call_count": int(_pm_query_summary(context).get("query_call_count") or 0),
        "program_model_query_summary": _pm_query_summary(context),
        "caller_count": len(context.callers),
        "callee_count": len(context.callees),
        "key_type_count": len(context.key_types),
        "key_constant_count": len(context.key_constants),
        "context_selection_rationale": context.selection_rationale,
        "coverage_request_batch_count": len(successful_batches),
        "coverage_request_batches": coverage_request_batch_reports,
        "coverage_target_group_counts": (context.context_package.get("coverage_exploration_contract") or {}).get("queue_kind_counts") or {},
        "coverage_target_entries": list((context.context_package or {}).get("campaign_reseed_target_entries") or []),
        "generated_function_count": len(list(dict.fromkeys(generated_functions))),
        "generated_functions": list(dict.fromkeys(generated_functions)),
        "generated_seed_count": len(generated_files),
        "generated_module_path": str(generated_module_path),
        "llm_response_path": str(llm_response_path),
        "generated_module_artifact_paths": module_artifact_paths,
        "llm_response_artifact_paths": response_artifact_paths,
        "imported_seed_count": imported_seed_count,
        "active_corpus_count": active_corpus_count,
        "output_files": generated_files,
        "merged_corpus_files": merged_paths,
        "status": TaskStatus.SEEDED.value,
        "errors": execution_errors,
    }
    manifest_path = write_seed_manifest(task_id, manifest_payload)
    seed_task_manifest_path = write_seed_task_manifest(
        task_id,
        target_mode="source",
        payload={
            "task_id": task_id,
            "generated_at": task_store.now(),
            "adapter_type": "source_adapter",
            "seed_mode": seed_decision.mode,
            "selection_rationale": seed_decision.reason,
            "input_evidence_refs": [
                value
                for value in [
                    coverage_manifest_path,
                    task.runtime.get("scheduler_feedback_consumption_path"),
                    task.runtime.get("execution_plan_path"),
                    context.context_package_path,
                ]
                if value
            ],
            "selected_target": harness.name,
            "selected_harness": context.selected_harness or harness.name,
            "selected_harness_path": context.selected_harness_path or str(harness.executable_path),
            "candidate_harnesses": context.candidate_harnesses,
            "selected_target_function": (context.target_function or {}).get("name"),
            "selected_target_functions": context.selected_target_functions,
            "context_package_path": context.context_package_path,
            "eligible_pool_size": int(_pm_runtime_query_payload(context).get("eligible_pool_size") or 0),
            "eligible_pool_source_counts": dict(_pm_runtime_query_payload(context).get("eligible_pool_source_counts") or {}),
            "program_model_query_call_count": int(_pm_query_summary(context).get("query_call_count") or 0),
            "program_model_query_summary": _pm_query_summary(context),
            "context_backend_contribution_path": str(Path(task.task_dir) / "index" / "context_backend_contribution.json"),
            "target_selection_backend_manifest_path": str(Path(task.task_dir) / "index" / "target_selection_backend_manifest.json"),
            "query_to_target_decision_manifest_path": str(Path(task.task_dir) / "index" / "query_to_target_decision_manifest.json"),
            "query_candidate_denoising_report_path": str(Path(task.task_dir) / "index" / "query_candidate_denoising_report.json"),
            "seed_init_chain_manifest_path": seed_init_chain_manifest_path,
            "harness_selector_manifest_path": harness_selector_path,
            "weighted_harness_selector_manifest_path": weighted_harness_selector_path,
            "function_selector_manifest_path": function_selector_path,
            "weighted_function_selector_manifest_path": weighted_function_selector_path,
            "seed_family_plan_manifest_path": seed_family_plan_path,
            "seed_task_sampling_manifest_path": seed_sampling_path,
            "seed_mode_trigger_manifest_path": seed_mode_trigger_path,
            "coverage_to_selector_bridge_manifest_path": coverage_bridge_path,
            "selector_feedback_consumption_path": selector_feedback_path,
            "seed_mode_semantics_manifest_path": seed_mode_semantics_path,
            "budget_input": {
                "seed_generation_attempts": seed_generation_attempts,
                "seed_budget_multiplier": seed_decision.budget_multiplier,
                "priority": seed_decision.priority,
            },
            "feedback_input": {
                "coverage_feedback_manifest_path": coverage_manifest_path,
                "coverage_summary_manifest_path": task.runtime.get("coverage_summary_manifest_path"),
                "coverage_to_selector_bridge_manifest_path": coverage_bridge_path,
                "selector_feedback_consumption_path": selector_feedback_path,
                "seed_strategy_reason": seed_decision.reason,
                "context_selection_rationale": context.selection_rationale,
                "coverage_request_batches": coverage_request_batch_reports,
            },
            "seed_family_plan": seed_family_plan,
            "produced_seed_count": len(generated_files),
            "produced_seeds": generated_files,
            "downstream_execution_target": {
                "queue": QueueNames.FUZZ,
                "target": harness.name,
                "corpus_active": task.layout["corpus_active"],
            },
            "downstream_execution_linkage": {
                "enqueue_behavior": "seed worker calls maybe_enqueue_fuzz",
                "expected_next_queue": QueueNames.FUZZ,
                "expected_execution_target": harness.name,
            },
            "result_summary": {
                "seed_generation_backend": backend_used,
                "llm_used": llm_used,
                "llm_provenance": llm_metadata.llm_provenance,
                "llm_real_call_verified": llm_metadata.llm_real_call_verified,
                "requested_seed_backend": seed_generation_backend,
                "actual_seed_backend": backend_used,
                "coverage_request_batch_count": len(successful_batches),
                "llm_batch_success_count": llm_batch_success_count,
                "llm_batch_failure_count": llm_batch_failure_count,
                "generated_seed_count": len(generated_files),
                "imported_seed_count": imported_seed_count,
                "cached_seed_count": cached_seed_count,
                "fallback_non_llm_used": fallback_non_llm_used,
                "task_partition": task_partition,
            },
            **parser_metadata,
            **policy,
            "seed_provenance": seed_provenance,
            "task_partition": task_partition,
            "requested_seed_backend": seed_generation_backend,
            "actual_seed_backend": backend_used,
            "cached_seed_count": cached_seed_count,
            "fallback_non_llm_used": fallback_non_llm_used,
            **llm_audit_paths,
            **_llm_fields(llm_metadata),
        },
    )
    task_store.update_status(
        task_id,
        TaskStatus.SEEDED,
        runtime_patch={
            "seed_completed_at": task_store.now(),
            "seed_manifest_path": str(manifest_path),
            "seed_task_manifest_path": str(seed_task_manifest_path),
            "context_package_path": context.context_package_path,
            "context_backend_contribution_path": str(Path(task.task_dir) / "index" / "context_backend_contribution.json"),
            "target_selection_backend_manifest_path": str(Path(task.task_dir) / "index" / "target_selection_backend_manifest.json"),
            "query_to_target_decision_manifest_path": str(Path(task.task_dir) / "index" / "query_to_target_decision_manifest.json"),
            "query_candidate_denoising_report_path": str(Path(task.task_dir) / "index" / "query_candidate_denoising_report.json"),
            "seed_init_chain_manifest_path": seed_init_chain_manifest_path,
            "harness_selector_manifest_path": harness_selector_path,
            "weighted_harness_selector_manifest_path": weighted_harness_selector_path,
            "function_selector_manifest_path": function_selector_path,
            "weighted_function_selector_manifest_path": weighted_function_selector_path,
            "seed_family_plan_manifest_path": seed_family_plan_path,
            "seed_task_sampling_manifest_path": seed_sampling_path,
            "seed_mode_trigger_manifest_path": seed_mode_trigger_path,
            "coverage_to_selector_bridge_manifest_path": coverage_bridge_path,
            "selector_feedback_consumption_path": selector_feedback_path,
            "seed_mode_semantics_manifest_path": seed_mode_semantics_path,
            "seed_generated_count": len(generated_files),
            "seed_imported_count": imported_seed_count,
            "active_corpus_count": active_corpus_count,
            "selected_harness": harness.name,
            "selected_harness_path": str(harness.executable_path),
            "harness_source_path": str(harness.source_path) if harness.source_path else None,
            "active_harness": harness.name,
            "active_harness_path": str(harness.executable_path),
            "selected_target_function": (context.target_function or {}).get("name"),
            "selected_target_functions": context.selected_target_functions,
            "coverage_request_batch_count": len(successful_batches),
            "coverage_request_batches": coverage_request_batch_reports,
            "coverage_target_group_counts": (context.context_package.get("coverage_exploration_contract") or {}).get("queue_kind_counts") or {},
            "seed_task_mode": seed_decision.mode,
            "seed_mode_counts": seed_mode_counts,
            "seed_strategy_reason": seed_decision.reason,
            "seed_budget_multiplier": seed_decision.budget_multiplier,
            "seed_generation_backend": backend_used,
            "llm_used": llm_used,
            "llm_model": client.model if llm_used else None,
            "llm_temperature": llm_temperature,
            "llm_max_tokens": llm_max_tokens,
            **parser_metadata,
            **_llm_fields(llm_metadata),
            **policy,
            "seed_provenance": seed_provenance,
            "task_partition": task_partition,
            "requested_seed_backend": seed_generation_backend,
            "actual_seed_backend": backend_used,
            "cached_seed_count": cached_seed_count,
            "fallback_non_llm_used": fallback_non_llm_used,
            **llm_audit_paths,
            "crash_source_policy": settings.crash_source_policy,
            "trace_mode": None,
            "closure_mode": None,
        },
    )
    maybe_enqueue_fuzz(task_id, task_store, queue)
    queue.ack(QueueNames.SEED, task_id)
    logger.info(
        "task %s seeded successfully harness=%s generated=%s corpus_active=%s",
        task_id,
        harness.name,
        len(generated_files),
        active_corpus_count,
    )


def _write_failure_manifest(task_id: str, task_store: TaskStateStore, error_message: str) -> None:
    task = task_store.load_task(task_id)
    llm_fields = {
        key: value
        for key, value in task.runtime.items()
        if key.startswith("llm_") or key in {"prompt_sha256", "response_sha256", "generated_by"}
    }
    parser_fields = {
        key: value
        for key, value in task.runtime.items()
        if key in {"first_response_status", "parser_first_pass_success", "parser_repair_attempted", "parser_final_success", "parse_failure_reason"}
    }
    policy_fields = {
        key: value
        for key, value in task.runtime.items()
        if key in {
            "verification_mode",
            "seed_material_policy",
            "allow_imported_seed_material",
            "allow_cached_seed_material",
            "allow_fallback_non_llm",
            "seed_provenance",
            "cached_seed_count",
            "fallback_non_llm_used",
        }
    }
    if not llm_fields:
        llm_fields = _llm_fields(
            build_non_llm_metadata(
                generated_by="source_seed_worker.failure",
                failure_reason=error_message,
                provenance="fallback_non_llm",
            ),
        )
    payload = {
        "task_id": task_id,
        "execution_mode": (task.execution_mode.value if task.execution_mode else "fresh"),
        "llm_used": False,
        "llm_model": settings.llm_model,
        "selected_harness": task.runtime.get("selected_harness"),
        "selected_harness_path": task.runtime.get("selected_harness_path"),
        "harness_source_path": task.runtime.get("harness_source_path"),
        "generated_seed_count": 0,
        "output_files": [],
        "status": TaskStatus.SEED_FAILED.value,
        "errors": [error_message],
        **parser_fields,
        **llm_fields,
        **policy_fields,
    }
    write_seed_manifest(task_id, payload)


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("seed worker started")
    while True:
        task_id = queue.pop(QueueNames.SEED, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("seed failed for task %s: %s", task_id, exc)
            _write_failure_manifest(task_id, task_store, str(exc))
            task_store.update_status(
                task_id,
                TaskStatus.SEED_FAILED,
                runtime_patch={
                    "seed_error": str(exc),
                    "seed_failed_at": task_store.now(),
                    "seed_manifest_path": str(seed_manifest_path(task_id)),
                },
            )
            queue.ack(QueueNames.SEED, task_id)


if __name__ == "__main__":
    main()

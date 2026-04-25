from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.buttercup_compat.program_model import LiteCodeQueryView
from core.storage.layout import (
    context_backend_contribution_path,
    parser_local_denoising_manifest_path,
    context_package_path,
    query_candidate_denoising_report_path,
    query_to_target_decision_manifest_path,
    richer_typed_relations_manifest_path,
    target_selection_backend_manifest_path,
    task_json_path,
    task_root,
    tree_sitter_backend_manifest_path,
    typed_query_results_path,
)
from core.utils.settings import settings

if TYPE_CHECKING:
    from core.seed.models import HarnessSelection

CALL_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
PARSER_AND_MEMORY_TOKENS = (
    "parse",
    "read",
    "load",
    "decode",
    "scan",
    "token",
    "lex",
    "line",
    "buffer",
    "delete",
    "free",
    "print",
    "write",
    "copy",
    "str",
    "mem",
    "alloc",
    "object",
    "array",
    "string",
    "stream",
    "field",
    "key",
    "value",
    "config",
)
PARSER_LOCAL_TOKENS = ("parse", "read", "load", "decode", "scan", "stream", "token", "lex", "valuehandler")
DESTRUCTOR_OR_RENDER_TOKENS = ("delete", "free", "print", "render", "dump")
LIBC_NOISE_SYMBOLS = {
    "strlen",
    "memcpy",
    "memmove",
    "memcmp",
    "strcpy",
    "strncpy",
    "strcmp",
    "strncmp",
    "malloc",
    "calloc",
    "realloc",
    "free",
}
STACKTRACE_FUNCTION_PATTERN = re.compile(r"\bin\s+([A-Za-z_][A-Za-z0-9_]*)\b")


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _read_text(path: Path | None, limit: int = 3000) -> str:
    if path is None or not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")[:limit]


def _load_build_registry(task_id: str) -> dict[str, Any]:
    build_registry_path = task_root(task_id) / "build" / "build_registry.json"
    return _load_json(build_registry_path, {})


def _load_campaign_runtime(task_id: str) -> dict[str, Any]:
    task_payload = _load_json(task_json_path(task_id), {})
    return task_payload.get("runtime") or {}


def _coverage_queue_kind_order(value: str | None) -> int:
    normalized = str(value or "").strip().lower()
    ordering = {
        "uncovered": 0,
        "low_growth": 1,
        "stalled": 2,
        "partial_degraded": 3,
        "harness_focus": 4,
        "candidate_bridge": 5,
        "coverage_gap": 6,
        "coverage_plane_queue": 7,
    }
    return ordering.get(normalized, 99)


def _normalize_campaign_reseed_target_entries(campaign_runtime: dict[str, Any]) -> list[dict[str, Any]]:
    selected_target_function = str(campaign_runtime.get("selected_target_function") or "").strip()
    queue_kind = str(campaign_runtime.get("campaign_coverage_queue_kind") or "").strip() or None
    raw_groups = [
        campaign_runtime.get("campaign_coverage_request_plan", {}).get("target_entries"),
        campaign_runtime.get("campaign_coverage_selected_entries"),
        campaign_runtime.get("campaign_coverage_queue_selected_entries"),
        campaign_runtime.get("campaign_coverage_target_queue"),
        campaign_runtime.get("campaign_low_growth_functions"),
        campaign_runtime.get("campaign_uncovered_functions"),
        campaign_runtime.get("campaign_partial_degraded_targets"),
        campaign_runtime.get("campaign_stalled_targets"),
        campaign_runtime.get("campaign_reseed_target_entries"),
        campaign_runtime.get("coverage_feedback_reseed_target_entries"),
        campaign_runtime.get("campaign_reseed_target_functions"),
        campaign_runtime.get("coverage_feedback_reseed_target_functions"),
        campaign_runtime.get("uncovered_functions"),
        campaign_runtime.get("coverage_feedback_uncovered_functions"),
        campaign_runtime.get("selected_target_functions"),
        ([selected_target_function] if selected_target_function else []),
    ]
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_targets in raw_groups:
        if not isinstance(raw_targets, list):
            continue
        for item in raw_targets:
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                entry = {
                    "name": name,
                    "target_type": str(item.get("target_type") or "function").strip() or "function",
                    "queue_kind": str(item.get("queue_kind") or queue_kind or "coverage_gap").strip() or "coverage_gap",
                    "priority": int(item.get("priority", 0) or 0),
                    "reason": str(item.get("reason") or "").strip() or None,
                    "source_level": str(item.get("source_level") or "").strip() or None,
                    "coverage_fraction": item.get("coverage_fraction"),
                    "total_lines": int(item.get("total_lines", 0) or 0),
                    "covered_lines": int(item.get("covered_lines", 0) or 0),
                    "function_paths": list(item.get("function_paths") or []),
                    "degraded_reason": str(item.get("degraded_reason") or "").strip() or None,
                    "degraded_detail": dict(item.get("degraded_detail") or {}) or None,
                    "selection_scope": str(item.get("selection_scope") or "").strip() or None,
                    "consume_count": int(item.get("consume_count", 0) or 0),
                    "hit_count": int(item.get("hit_count", 0) or 0),
                    "activation_state": str(item.get("activation_state") or "").strip() or None,
                }
            else:
                name = str(item or "").strip()
                entry = {
                    "name": name,
                    "target_type": "function",
                    "queue_kind": queue_kind or "coverage_gap",
                    "priority": 0,
                    "reason": None,
                    "source_level": None,
                    "coverage_fraction": None,
                    "total_lines": 0,
                    "covered_lines": 0,
                    "function_paths": [],
                    "degraded_reason": None,
                    "degraded_detail": None,
                    "selection_scope": None,
                    "consume_count": 0,
                    "hit_count": 0,
                    "activation_state": None,
                }
            if not name or name in seen:
                continue
            seen.add(name)
            entries.append(entry)
    entries.sort(
        key=lambda item: (
            _coverage_queue_kind_order(item.get("queue_kind")),
            0 if str(item.get("selection_scope") or "") == "system" else 1,
            -int(item.get("priority") or 0),
            -int(item.get("hit_count") or 0),
            int(item.get("consume_count") or 0),
            float(item.get("coverage_fraction") if item.get("coverage_fraction") is not None else 2.0),
            item.get("name") or "",
        ),
    )
    return entries[:12]


def _normalize_campaign_reseed_targets(campaign_runtime: dict[str, Any]) -> list[str]:
    return [str(item.get("name") or "") for item in _normalize_campaign_reseed_target_entries(campaign_runtime) if item.get("name")]


def _build_coverage_exploration_contract(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {
            "primary_queue_kind": None,
            "queue_kind_counts": {},
            "target_groups": [],
            "target_entries": [],
        }
    queue_kind_counts: dict[str, int] = {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in entries:
        queue_kind = str(item.get("queue_kind") or "coverage_gap").strip() or "coverage_gap"
        queue_kind_counts[queue_kind] = queue_kind_counts.get(queue_kind, 0) + 1
        grouped.setdefault(queue_kind, []).append(dict(item))
    target_groups: list[dict[str, Any]] = []
    for queue_kind in sorted(grouped, key=_coverage_queue_kind_order):
        members = sorted(
            grouped[queue_kind],
            key=lambda entry: (
                0 if str(entry.get("selection_scope") or "") == "system" else 1,
                -int(entry.get("priority") or 0),
                -int(entry.get("hit_count") or 0),
                int(entry.get("consume_count") or 0),
                float(entry.get("coverage_fraction") if entry.get("coverage_fraction") is not None else 2.0),
                entry.get("name") or "",
            ),
        )
        target_groups.append(
            {
                "queue_kind": queue_kind,
                "target_names": [str(item.get("name") or "") for item in members if item.get("name")][:4],
                "target_entries": members[:4],
            },
        )
    return {
        "primary_queue_kind": target_groups[0]["queue_kind"] if target_groups else None,
        "queue_kind_counts": queue_kind_counts,
        "target_groups": target_groups[:4],
        "target_entries": entries[:8],
    }


def _by_name(function_facts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("name")): item for item in function_facts if item.get("name")}


def _trim_text(value: str | None, limit: int) -> str:
    text = str(value or "").strip()
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def _compact_context_function(
    fact: dict[str, Any],
    *,
    distance: int | None = None,
    rationale: str | None = None,
    relation: str | None = None,
    signature_limit: int = 180,
    snippet_limit: int = 240,
) -> dict[str, Any]:
    coverage_summary = fact.get("coverage_summary") or {}
    entry = {
        "name": fact.get("name"),
        "file": fact.get("file"),
        "line": fact.get("line"),
        "signature": _trim_text(fact.get("signature"), signature_limit) or None,
        "snippet": _trim_text(fact.get("snippet") or fact.get("body_excerpt"), snippet_limit) or None,
        "query_backend": fact.get("query_backend"),
        "parser_adjacent": bool(((fact.get("tree_sitter_record") or {}).get("parser_adjacent"))),
        "callers_count": len(fact.get("callers") or []),
        "callees_count": len(fact.get("callees") or []),
        "coverage_fraction": coverage_summary.get("coverage_fraction"),
        "relation": relation,
        "distance": distance,
        "rationale": rationale,
    }
    return {key: value for key, value in entry.items() if value not in (None, "", [], {})}


def _entry_char_size(entry: dict[str, Any]) -> int:
    return len(json.dumps(entry, ensure_ascii=False))


def _fit_entry_to_budget(entry: dict[str, Any], budget_chars: int) -> dict[str, Any] | None:
    if budget_chars <= 0:
        return None
    candidate = {key: value for key, value in entry.items() if value not in (None, "", [], {})}
    if _entry_char_size(candidate) <= budget_chars:
        return candidate
    for signature_limit, snippet_limit in ((140, 180), (96, 120), (72, 80), (0, 80), (0, 0)):
        shrunken = dict(candidate)
        if "signature" in shrunken:
            shrunken["signature"] = _trim_text(shrunken.get("signature"), signature_limit) or None
        if "snippet" in shrunken:
            shrunken["snippet"] = _trim_text(shrunken.get("snippet"), snippet_limit) or None
        shrunken = {key: value for key, value in shrunken.items() if value not in (None, "", [], {})}
        if _entry_char_size(shrunken) <= budget_chars:
            return shrunken
    minimal = {
        key: candidate[key]
        for key in ("name", "file", "line", "distance", "rationale", "relation")
        if candidate.get(key) not in (None, "", [], {})
    }
    if minimal and _entry_char_size(minimal) <= budget_chars:
        return minimal
    return None


def _budget_select_entries(
    entries: list[dict[str, Any]],
    *,
    budget_chars: int,
    max_items: int,
) -> tuple[list[dict[str, Any]], int]:
    selected: list[dict[str, Any]] = []
    used_chars = 0
    for entry in entries:
        if len(selected) >= max_items:
            break
        remaining = budget_chars - used_chars
        if remaining <= 0:
            break
        fitted = _fit_entry_to_budget(entry, remaining)
        if fitted is None:
            continue
        selected.append(fitted)
        used_chars += _entry_char_size(fitted)
    return selected, used_chars


def _dedupe_function_facts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        name = str(item.get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        deduped.append(item)
    return deduped


def _normalize_hop_keywords(raw_keywords: str) -> tuple[str, ...]:
    return tuple(
        keyword
        for keyword in (part.strip().lower() for part in str(raw_keywords or "").split(","))
        if keyword
    )


def _load_trace_function_names(task_id: str, *, facts_by_name: dict[str, dict[str, Any]]) -> set[str]:
    trace_dir = task_root(task_id) / "trace" / "traced_crashes"
    if not trace_dir.exists():
        return set()
    names: set[str] = set()
    for path in sorted(trace_dir.glob("*.json"))[:12]:
        payload = _load_json(path, {})
        for line in (payload.get("stacktrace") or []):
            match = STACKTRACE_FUNCTION_PATTERN.search(str(line))
            if not match:
                continue
            name = match.group(1)
            if name in facts_by_name:
                names.add(name)
        crash_state = str(payload.get("crash_state") or "")
        for match in STACKTRACE_FUNCTION_PATTERN.finditer(crash_state):
            name = match.group(1)
            if name in facts_by_name:
                names.add(name)
    return names


def _is_test_like_fact(fact: dict[str, Any]) -> bool:
    name = str(fact.get("name") or "").lower()
    file_path = str(fact.get("file") or "").lower()
    return (
        name.startswith("test_")
        or name.endswith("_test")
        or "/test/" in file_path
        or "/tests/" in file_path
        or "/example/" in file_path
        or "/examples/" in file_path
    )


def _expand_context_hops(
    query_view: LiteCodeQueryView,
    *,
    seed_nodes: list[dict[str, Any]],
    facts_by_name: dict[str, dict[str, Any]],
    typed_functions: dict[str, dict[str, Any]],
    trace_function_names: set[str],
    budget_chars: int,
    max_hops: int = 2,
    priority_keywords: tuple[str, ...] | None = None,
    visited: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if budget_chars <= 0 or not seed_nodes:
        return [], {
            "hop_budget_chars": budget_chars,
            "hop_budgets": {},
            "selected_count": 0,
            "distance_counts": {},
            "trace_function_names": sorted(trace_function_names)[:12],
        }

    keywords = tuple(priority_keywords or ())
    visited_names = set(visited or set())
    frontier_names = [str(item.get("name") or "").strip() for item in seed_nodes if str(item.get("name") or "").strip()]
    selected_entries: list[dict[str, Any]] = []
    distance_counts: dict[str, int] = {}
    per_hop_budgets: dict[int, int] = {}
    remaining_budget = budget_chars

    for hop_index in range(max_hops):
        distance = hop_index + 2
        if distance == 2:
            hop_budget = int(budget_chars * 0.6)
        else:
            hop_budget = remaining_budget
        hop_budget = max(0, min(hop_budget, remaining_budget))
        per_hop_budgets[distance] = hop_budget
        if hop_budget <= 0 or not frontier_names:
            frontier_names = []
            continue

        candidates: dict[str, dict[str, Any]] = {}
        for source_name in frontier_names:
            neighbors = _dedupe_function_facts(
                [
                    *query_view.get_callers(source_name),
                    *query_view.get_callees(source_name),
                ]
            )
            for fact in neighbors:
                name = str(fact.get("name") or "").strip()
                if not name or name in visited_names:
                    continue
                if _is_test_like_fact(fact):
                    continue
                typed_record = typed_functions.get(name, {})
                lowered = name.lower()
                keyword_hits = [keyword for keyword in keywords if keyword in lowered]
                reasons: list[str] = []
                if keyword_hits:
                    reasons.append(f"keyword:{keyword_hits[0]}")
                if name in trace_function_names:
                    reasons.append("appears_in_trace")
                if typed_record.get("parser_adjacent"):
                    reasons.append("parser_adjacent")
                if not reasons:
                    continue

                score = 0.0
                score += len(keyword_hits) * 1.1
                if name in trace_function_names:
                    score += 2.0
                if typed_record.get("parser_adjacent"):
                    score += 1.6
                score += max(0, 0.4 - (distance - 2) * 0.15)
                score += min(int(typed_record.get("call_count") or 0), 5) * 0.1

                candidate = {
                    "score": round(score, 4),
                    "fact": fact,
                    "distance": distance,
                    "rationale": ", ".join(reasons),
                }
                existing = candidates.get(name)
                if existing is None or candidate["score"] > existing["score"]:
                    candidates[name] = candidate

        ranked = sorted(candidates.values(), key=lambda item: item["score"], reverse=True)
        compact_candidates = [
            _compact_context_function(
                dict(item["fact"]),
                distance=item["distance"],
                rationale=item["rationale"],
                relation=f"{item['distance']}-hop from target",
                signature_limit=140,
                snippet_limit=160,
            )
            for item in ranked
        ]
        max_items = 6 if distance == 2 else 4
        selected_for_hop, used_chars = _budget_select_entries(
            compact_candidates,
            budget_chars=hop_budget,
            max_items=max_items,
        )
        selected_entries.extend(selected_for_hop)
        remaining_budget -= used_chars

        next_frontier: list[str] = []
        for entry in selected_for_hop:
            name = str(entry.get("name") or "").strip()
            if not name or name in visited_names:
                continue
            visited_names.add(name)
            next_frontier.append(name)
        distance_counts[str(distance)] = len(selected_for_hop)
        frontier_names = next_frontier

    return selected_entries, {
        "hop_budget_chars": budget_chars,
        "hop_budgets": {str(key): value for key, value in per_hop_budgets.items()},
        "selected_count": len(selected_entries),
        "distance_counts": distance_counts,
        "trace_function_names": sorted(trace_function_names)[:12],
    }


def _score_function(
    name: str,
    fact: dict[str, Any],
    harness_calls: set[str],
    task_mode: str,
    coverage_ratio: float | None = None,
) -> tuple[float, list[str]]:
    lowered = name.lower()
    score = 0.0
    reasons: list[str] = []
    if name in harness_calls:
        score += 2.0
        reasons.append("called_from_harness")
    if fact.get("harness_related"):
        score += 0.4
        reasons.append("harness_adjacent")
    if coverage_ratio is not None:
        score += max(0.0, 1.0 - coverage_ratio) * 1.4
        reasons.append("coverage_gap_bias")
        if coverage_ratio == 0:
            score += 0.35
            reasons.append("uncovered_function_bias")
    suspicious_hits = sum(1 for token in PARSER_AND_MEMORY_TOKENS if token in lowered)
    if suspicious_hits:
        score += suspicious_hits * 0.35
        reasons.append("keyword_match")
    if task_mode == "VULN_DISCOVERY" and any(
        token in lowered for token in ("alloc", "free", "delete", "print", "copy", "str", "mem", "parse")
    ):
        score += 1.0
        reasons.append("vuln_discovery_bias")
    elif task_mode == "SEED_EXPLORE" and len(fact.get("callees", [])) >= 2:
        score += 0.7
        reasons.append("explore_graph_bias")
    elif task_mode == "SEED_INIT" and any(token in lowered for token in ("parse", "read", "load", "decode")):
        score += 0.6
        reasons.append("seed_init_parser_bias")
    return score, reasons


def _type_matches(type_fact: dict[str, Any], snippet_blob: str) -> bool:
    name = str(type_fact.get("name") or "")
    if not name or name == "<anonymous>":
        return False
    return name in snippet_blob


def _load_coverage_function_map(task_id: str) -> dict[str, dict[str, Any]]:
    summary_path = task_root(task_id) / "coverage" / "coverage_summary_manifest.json"
    summary = _load_json(summary_path, {})
    rows = summary.get("per_function_summary") or summary.get("coverage_function_summary") or []
    mapping: dict[str, dict[str, Any]] = {}
    for item in rows:
        name = str(item.get("name") or item.get("function_name") or "")
        if not name:
            continue
        mapping[name] = item
    return mapping


def _coverage_snapshot_level(summary: dict[str, Any]) -> str | None:
    for key in ("coverage_level", "coverage_kind", "coverage_artifacts_level"):
        value = str(summary.get(key) or "").strip()
        if value:
            return value
    return None


def _build_exact_uncovered_target_functions(
    coverage_function_map: dict[str, dict[str, Any]],
    facts_by_name: dict[str, dict[str, Any]],
    *,
    limit: int = 12,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for name, item in coverage_function_map.items():
        total_lines = int(item.get("total_lines", 0) or 0)
        covered_lines = int(item.get("covered_lines", 0) or 0)
        coverage_fraction = item.get("coverage_fraction")
        if coverage_fraction is None and total_lines:
            coverage_fraction = round(float(covered_lines) / max(float(total_lines), 1.0), 4)
        try:
            normalized_fraction = float(coverage_fraction if coverage_fraction is not None else 0.0)
        except (TypeError, ValueError):
            normalized_fraction = 0.0
        if total_lines <= 0 or covered_lines > 0 or normalized_fraction > 0.0:
            continue
        fact = facts_by_name.get(name) or {}
        entries.append(
            {
                "name": name,
                "file": fact.get("file"),
                "line": fact.get("line"),
                "target_type": "function",
                "queue_kind": "uncovered",
                "priority": max(total_lines, 1),
                "reason": "exact_coverage_unreached",
                "source_level": "exact",
                "coverage_fraction": 0.0,
                "total_lines": total_lines,
                "covered_lines": covered_lines,
                "function_paths": list(item.get("function_paths") or []),
                "selection_scope": "current_coverage_snapshot",
            }
        )
    entries.sort(
        key=lambda entry: (
            -int(entry.get("priority") or 0),
            entry.get("name") or "",
        ),
    )
    return entries[:limit]


def _build_family_stagnation_targets(
    campaign_runtime: dict[str, Any],
    campaign_reseed_target_entries: list[dict[str, Any]],
    facts_by_name: dict[str, dict[str, Any]],
    *,
    limit: int = 4,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_entry(item: dict[str, Any], *, fallback_reason: str | None = None) -> None:
        name = str(item.get("name") or item.get("selected_target_function") or "").strip()
        if not name or name in seen:
            return
        seen.add(name)
        fact = facts_by_name.get(name) or {}
        entries.append(
            {
                "name": name,
                "file": fact.get("file") or item.get("file"),
                "line": fact.get("line") or item.get("line"),
                "target_type": str(item.get("target_type") or "function").strip() or "function",
                "queue_kind": str(item.get("queue_kind") or "family_stagnation").strip() or "family_stagnation",
                "priority": int(item.get("priority", 0) or 0),
                "reason": str(item.get("reason") or fallback_reason or "family_stagnation_focus").strip(),
                "source_level": str(item.get("source_level") or "family").strip() or "family",
                "coverage_fraction": item.get("coverage_fraction"),
                "total_lines": int(item.get("total_lines", 0) or 0),
                "covered_lines": int(item.get("covered_lines", 0) or 0),
                "function_paths": list(item.get("function_paths") or []),
                "selection_scope": str(item.get("selection_scope") or "campaign").strip() or "campaign",
            }
        )

    for item in campaign_reseed_target_entries:
        if not isinstance(item, dict):
            continue
        queue_kind = str(item.get("queue_kind") or "").strip()
        source_level = str(item.get("source_level") or "").strip()
        if queue_kind == "family_confirmation" or source_level == "family":
            add_entry(item)

    family_stagnation_count = int(campaign_runtime.get("campaign_family_stagnation_count") or 0)
    if family_stagnation_count >= 2:
        last_state = dict(campaign_runtime.get("campaign_last_stagnation_state") or campaign_runtime.get("last_stagnation_state") or {})
        add_entry(
            {
                "name": last_state.get("selected_target_function") or campaign_runtime.get("selected_target_function"),
                "queue_kind": "family_stagnation",
                "priority": max(40, family_stagnation_count),
                "source_level": "family",
            },
            fallback_reason="family_stagnation_oldest_target",
        )

    entries.sort(
        key=lambda entry: (
            -int(entry.get("priority") or 0),
            entry.get("name") or "",
        ),
    )
    return entries[:limit]


def _load_tree_sitter_payload(task_id: str) -> dict[str, Any]:
    payload = _load_json(typed_query_results_path(task_id), {})
    return payload.get("typed_query_results", payload) if isinstance(payload, dict) else {}


def _query_candidate(
    *,
    name: str,
    facts_by_name: dict[str, dict[str, Any]],
    query_view: LiteCodeQueryView,
    coverage_function_map: dict[str, dict[str, Any]],
    typed_functions: dict[str, dict[str, Any]],
    task_mode: str,
    reasons: list[str],
    query_weight: float,
) -> dict[str, Any] | None:
    fact = dict(facts_by_name.get(name) or {})
    if not fact:
        query_matches = query_view.get_functions(name, fuzzy=False)
        if query_matches:
            fact = dict(query_matches[0])
    if not fact:
        return None
    coverage_entry = coverage_function_map.get(name, {})
    coverage_ratio = coverage_entry.get("coverage_fraction")
    if coverage_ratio is None and coverage_entry.get("total_lines"):
        coverage_ratio = round(
            float(coverage_entry.get("covered_lines", 0)) / max(float(coverage_entry.get("total_lines", 1)), 1.0),
            4,
        )
    typed_record = typed_functions.get(name, {})
    lowered = name.lower()
    breakdown: dict[str, float] = {
        "original_query_reachability": query_weight,
        "coverage_gap": max(0.0, 1.0 - float(coverage_ratio or 0.0)) * 1.5,
        "tree_sitter_parser_adjacent": 1.0 if typed_record.get("parser_adjacent") else 0.0,
        "tree_sitter_type_evidence": min(float(typed_record.get("type_ref_count") or 0), 4.0) * 0.2,
        "parser_local_bias": 0.0,
        "task_mode_bias": 0.0,
    }
    if any(token in lowered for token in PARSER_LOCAL_TOKENS):
        breakdown["parser_local_bias"] += 1.1
        reasons.append("parser_local_query_bias")
    if any(token in lowered for token in DESTRUCTOR_OR_RENDER_TOKENS):
        breakdown["parser_local_bias"] -= 0.9
        reasons.append("destructor_or_render_penalty")
    if task_mode == "VULN_DISCOVERY" and any(
        token in lowered for token in ("alloc", "free", "delete", "print", "copy", "str", "mem", "parse")
    ):
        breakdown["task_mode_bias"] += 0.9
        reasons.append("vuln_discovery_query_bias")
    elif task_mode == "SEED_EXPLORE" and int(typed_record.get("call_count") or 0) >= 3:
        breakdown["task_mode_bias"] += 0.9
        reasons.append("seed_explore_query_bias")
    elif task_mode == "SEED_INIT" and any(token in lowered for token in ("parse", "read", "load", "decode")):
        breakdown["task_mode_bias"] += 0.6
        reasons.append("seed_init_query_bias")
    score = round(sum(breakdown.values()), 4)
    fact["coverage_summary"] = coverage_entry or fact.get("coverage_summary")
    fact["tree_sitter_record"] = typed_record or None
    fact["target_selection_backend"] = "original_query_backend"
    fact.setdefault("query_backend", "cqsearch")
    return {
        "name": name,
        "score": score,
        "score_breakdown": breakdown,
        "reasons": list(dict.fromkeys(reasons)),
        "fact": fact,
    }


def _is_noisy_candidate(item: dict[str, Any], *, harness_source_path: str | None) -> tuple[bool, str | None]:
    name = str(item.get("name") or "")
    fact = item.get("fact") or {}
    file_path = str(fact.get("file") or "")
    lowered_name = name.lower()
    lowered_file = file_path.lower()
    harness_source_lower = str(harness_source_path or "").lower()
    tree_sitter_record = item.get("fact", {}).get("tree_sitter_record") or {}
    if lowered_name in LIBC_NOISE_SYMBOLS:
        return True, "libc_runtime_symbol"
    if lowered_file.endswith(".h") or "/include/" in lowered_file:
        return True, "header_only_path"
    if any(token in lowered_file for token in ("/test", "/tests", "/example", "/examples")) and lowered_file != harness_source_lower:
        return True, "test_or_example_path"
    if lowered_name.startswith("test") or lowered_name.startswith("example"):
        return True, "test_or_example_symbol"
    if not tree_sitter_record.get("parser_adjacent") and any(token in lowered_name for token in DESTRUCTOR_OR_RENDER_TOKENS):
        return True, "non_parser_destructor_or_render_symbol"
    if name and harness_source_lower and lowered_file and lowered_file != harness_source_lower and not item.get("reasons"):
        return True, "weak_non_harness_candidate"
    return False, None


def _denoise_query_candidates(
    candidates: list[dict[str, Any]],
    *,
    harness_source_path: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for item in candidates:
        noisy, reason = _is_noisy_candidate(item, harness_source_path=harness_source_path)
        if noisy:
            removed.append(
                {
                    "name": item.get("name"),
                    "file": (item.get("fact") or {}).get("file"),
                    "reason": reason,
                }
            )
            continue
        kept.append(item)
    report = {
        "before_count": len(candidates),
        "after_count": len(kept),
        "removed_count": len(removed),
        "removed_candidates": removed[:24],
        "kept_candidates": [
            {
                "name": item.get("name"),
                "file": (item.get("fact") or {}).get("file"),
                "score": item.get("score"),
                "reasons": item.get("reasons"),
            }
            for item in kept[:24]
        ],
    }
    return kept, report


def _build_query_driven_candidates(
    *,
    harness_calls: set[str],
    facts_by_name: dict[str, dict[str, Any]],
    query_view: LiteCodeQueryView,
    coverage_function_map: dict[str, dict[str, Any]],
    typed_functions: dict[str, dict[str, Any]],
    task_mode: str,
) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for harness_call in sorted(harness_calls):
        direct_matches = query_view.get_functions(harness_call, fuzzy=False)
        direct_file = str(direct_matches[0].get("file")) if direct_matches else None
        related_sets = [
            ("harness_direct_query", direct_matches, 2.5),
            ("query_callee_of_harness", query_view.get_callees(harness_call, file_path=direct_file), 3.5),
            ("query_caller_of_harness", query_view.get_callers(harness_call), 1.5),
        ]
        for reason, items, weight in related_sets:
            for item in items:
                name = str(item.get("name") or "")
                if not name:
                    continue
                candidate = _query_candidate(
                    name=name,
                    facts_by_name=facts_by_name,
                    query_view=query_view,
                    coverage_function_map=coverage_function_map,
                    typed_functions=typed_functions,
                    task_mode=task_mode,
                    reasons=[reason],
                    query_weight=weight,
                )
                if candidate is None:
                    continue
                existing = candidates.get(name)
                if existing is None or candidate["score"] > existing["score"]:
                    candidates[name] = candidate
    parser_adjacent = sorted(
        (
            name
            for name, record in typed_functions.items()
            if record.get("parser_adjacent")
        ),
    )
    for name in parser_adjacent[:16]:
        if name in candidates:
            continue
        candidate = _query_candidate(
            name=name,
            facts_by_name=facts_by_name,
            query_view=query_view,
            coverage_function_map=coverage_function_map,
            typed_functions=typed_functions,
            task_mode=task_mode,
            reasons=["tree_sitter_parser_adjacent"],
            query_weight=1.2,
        )
        if candidate is not None:
            candidates[name] = candidate
    return sorted(candidates.values(), key=lambda item: item["score"], reverse=True)


def _apply_campaign_diversification_bias(
    *,
    task_mode: str,
    campaign_runtime: dict[str, Any],
    query_candidates: list[dict[str, Any]],
    scored_candidates: list[tuple[float, list[str], dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[tuple[float, list[str], dict[str, Any]]], dict[str, Any]]:
    cooled_target = str(campaign_runtime.get("target_cooldown_function") or "").strip()
    second_family_search_active = bool(campaign_runtime.get("second_family_search_active"))
    seen_signature_penalty_active = bool(campaign_runtime.get("seen_signature_penalty_active"))
    budget_state = str(campaign_runtime.get("campaign_budget_state") or "normal")
    already_traced_targets = {
        str(item).strip()
        for item in (campaign_runtime.get("already_traced_target_functions") or [])
        if str(item).strip()
    }
    already_patched_targets = {
        str(item).strip()
        for item in (campaign_runtime.get("already_patched_target_functions") or [])
        if str(item).strip()
    }
    if not any(
        (
            cooled_target,
            second_family_search_active,
            seen_signature_penalty_active,
            budget_state != "normal",
            already_traced_targets,
            already_patched_targets,
        )
    ):
        return query_candidates, scored_candidates, {
            "campaign_runtime_bias_active": False,
            "cooled_target": None,
            "second_family_search_active": False,
            "seen_signature_penalty_active": False,
            "campaign_budget_state": budget_state,
            "already_traced_targets": [],
            "already_patched_targets": [],
            "affected_candidates": [],
        }

    affected: list[dict[str, Any]] = []
    adjusted_query_candidates: list[dict[str, Any]] = []
    for item in query_candidates:
        adjusted = dict(item)
        name = str(adjusted.get("name") or "")
        fact = dict(adjusted.get("fact") or {})
        tree_sitter_record = fact.get("tree_sitter_record") or {}
        breakdown = dict(adjusted.get("score_breakdown") or {})
        reasons = list(adjusted.get("reasons") or [])
        delta = 0.0
        if cooled_target and name == cooled_target:
            cooldown_penalty = 4.2 if second_family_search_active else 1.8
            delta -= cooldown_penalty
            breakdown["campaign_target_cooldown_penalty"] = -round(cooldown_penalty, 4)
            reasons.append("campaign_target_cooldown_penalty")
        else:
            if name in already_patched_targets:
                patched_penalty = 2.8 if second_family_search_active else 1.1
                delta -= patched_penalty
                breakdown["already_patched_path_penalty"] = -round(patched_penalty, 4)
                reasons.append("already_patched_path_penalty")
            elif name in already_traced_targets:
                traced_penalty = 1.7 if second_family_search_active else 0.7
                delta -= traced_penalty
                breakdown["already_traced_path_penalty"] = -round(traced_penalty, 4)
                reasons.append("already_traced_path_penalty")
            if second_family_search_active:
                family_bonus = 1.35 + (0.55 if tree_sitter_record.get("parser_adjacent") else 0.0)
                delta += family_bonus
                breakdown["second_family_search_bonus"] = round(family_bonus, 4)
                reasons.append("second_family_search_bonus")
                if tree_sitter_record.get("parser_adjacent") and name not in already_traced_targets and name not in already_patched_targets:
                    unexplored_bonus = 0.8
                    delta += unexplored_bonus
                    breakdown["unexplored_parser_adjacent_bonus"] = round(unexplored_bonus, 4)
                    reasons.append("unexplored_parser_adjacent_bonus")
            if seen_signature_penalty_active and task_mode == "SEED_EXPLORE":
                explore_bonus = 0.7
                delta += explore_bonus
                breakdown["seed_explore_diversification_bonus"] = round(explore_bonus, 4)
                reasons.append("seed_explore_diversification_bonus")
        if budget_state == "explore" and name != cooled_target:
            budget_bonus = 0.45
            delta += budget_bonus
            breakdown["campaign_budget_explore_bonus"] = round(budget_bonus, 4)
            reasons.append("campaign_budget_explore_bonus")
        adjusted["score"] = round(float(adjusted.get("score") or 0.0) + delta, 4)
        adjusted["score_breakdown"] = breakdown
        adjusted["reasons"] = list(dict.fromkeys(reasons))
        adjusted_query_candidates.append(adjusted)
        if delta:
            affected.append(
                {
                    "name": name,
                    "delta": round(delta, 4),
                    "new_score": adjusted["score"],
                    "reasons": adjusted["reasons"],
                }
            )
    adjusted_query_candidates.sort(key=lambda item: item["score"], reverse=True)

    adjusted_scored_candidates: list[tuple[float, list[str], dict[str, Any]]] = []
    for score, reasons, fact in scored_candidates:
        name = str(fact.get("name") or "")
        delta = 0.0
        adjusted_reasons = list(reasons)
        if cooled_target and name == cooled_target:
            delta -= 2.4 if second_family_search_active else 1.0
            adjusted_reasons.append("campaign_target_cooldown_penalty")
        else:
            if name in already_patched_targets:
                delta -= 1.5 if second_family_search_active else 0.6
                adjusted_reasons.append("already_patched_path_penalty")
            elif name in already_traced_targets:
                delta -= 1.0 if second_family_search_active else 0.4
                adjusted_reasons.append("already_traced_path_penalty")
            if second_family_search_active:
                delta += 0.9
                adjusted_reasons.append("second_family_search_bonus")
        if budget_state == "explore" and name != cooled_target:
            delta += 0.3
            adjusted_reasons.append("campaign_budget_explore_bonus")
        adjusted_scored_candidates.append(
            (
                round(float(score) + delta, 4),
                list(dict.fromkeys(adjusted_reasons)),
                fact,
            )
        )
    adjusted_scored_candidates.sort(key=lambda item: item[0], reverse=True)
    return adjusted_query_candidates, adjusted_scored_candidates, {
        "campaign_runtime_bias_active": True,
        "cooled_target": cooled_target or None,
        "second_family_search_active": second_family_search_active,
        "seen_signature_penalty_active": seen_signature_penalty_active,
        "campaign_budget_state": budget_state,
        "already_traced_targets": sorted(already_traced_targets),
        "already_patched_targets": sorted(already_patched_targets),
        "affected_candidates": affected[:24],
    }


def _apply_explicit_reseed_target_bias(
    *,
    target_names: list[str],
    query_candidates: list[dict[str, Any]],
    scored_candidates: list[tuple[float, list[str], dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[tuple[float, list[str], dict[str, Any]]], dict[str, Any]]:
    target_set = {name for name in target_names if name}
    if not target_set:
        return query_candidates, scored_candidates, {
            "campaign_reseed_target_bias_active": False,
            "target_names": [],
            "affected_candidates": [],
        }

    affected: list[dict[str, Any]] = []
    adjusted_query_candidates: list[dict[str, Any]] = []
    for item in query_candidates:
        adjusted = dict(item)
        name = str(adjusted.get("name") or "")
        if name in target_set:
            breakdown = dict(adjusted.get("score_breakdown") or {})
            reasons = list(adjusted.get("reasons") or [])
            bonus = 2.2
            breakdown["campaign_reseed_target_bonus"] = round(bonus, 4)
            reasons.append("campaign_reseed_target_bonus")
            adjusted["score"] = round(float(adjusted.get("score") or 0.0) + bonus, 4)
            adjusted["score_breakdown"] = breakdown
            adjusted["reasons"] = list(dict.fromkeys(reasons))
            affected.append(
                {
                    "name": name,
                    "delta": round(bonus, 4),
                    "new_score": adjusted["score"],
                    "reasons": adjusted["reasons"],
                }
            )
        adjusted_query_candidates.append(adjusted)
    adjusted_query_candidates.sort(key=lambda item: item["score"], reverse=True)

    adjusted_scored_candidates: list[tuple[float, list[str], dict[str, Any]]] = []
    for score, reasons, fact in scored_candidates:
        name = str((fact or {}).get("name") or "")
        adjusted_score = float(score)
        adjusted_reasons = list(reasons)
        if name in target_set:
            adjusted_score += 1.4
            adjusted_reasons.append("campaign_reseed_target_bonus")
        adjusted_scored_candidates.append(
            (
                round(adjusted_score, 4),
                list(dict.fromkeys(adjusted_reasons)),
                fact,
            )
        )
    adjusted_scored_candidates.sort(key=lambda item: item[0], reverse=True)
    return adjusted_query_candidates, adjusted_scored_candidates, {
        "campaign_reseed_target_bias_active": True,
        "target_names": sorted(target_set),
        "affected_candidates": affected[:24],
    }


def build_context_package(task_id: str, harness: "HarnessSelection", *, task_mode: str) -> tuple[Path, dict[str, Any]]:
    index_dir = task_root(task_id) / "index"
    build_registry = _load_build_registry(task_id)
    backend_manifest = _load_json(index_dir / "program_model_backend_manifest.json", {})
    validation_manifest = _load_json(index_dir / "program_model_query_validation_manifest.json", {})
    codequery_view_manifest = _load_json(index_dir / "codequery_view_manifest.json", {})
    tree_sitter_backend_manifest = _load_json(tree_sitter_backend_manifest_path(task_id), {})
    typed_query_payload = _load_tree_sitter_payload(task_id)
    typed_functions = dict(typed_query_payload.get("functions") or {})
    typed_types = list(typed_query_payload.get("types") or [])
    query_view = LiteCodeQueryView.from_task(task_id)
    coverage_summary = _load_json(task_root(task_id) / "coverage" / "coverage_summary_manifest.json", {})
    coverage_function_map = _load_coverage_function_map(task_id)
    campaign_runtime = _load_campaign_runtime(task_id)
    campaign_reseed_target_entries = _normalize_campaign_reseed_target_entries(campaign_runtime)
    campaign_reseed_targets = [str(item.get("name") or "") for item in campaign_reseed_target_entries if item.get("name")]
    coverage_exploration_contract = _build_coverage_exploration_contract(campaign_reseed_target_entries)
    function_facts = query_view.function_facts
    type_facts = query_view.type_facts

    harness_source = _read_text(harness.source_path, limit=12000)
    harness_calls = {name for name in CALL_PATTERN.findall(harness_source) if name}
    facts_by_name = _by_name(function_facts)
    trace_function_names = _load_trace_function_names(task_id, facts_by_name=facts_by_name)
    exact_uncovered_target_functions = _build_exact_uncovered_target_functions(coverage_function_map, facts_by_name)
    family_stagnation_targets = _build_family_stagnation_targets(
        campaign_runtime,
        campaign_reseed_target_entries,
        facts_by_name,
    )

    scored: list[tuple[float, list[str], dict[str, Any]]] = []
    for name, fact in facts_by_name.items():
        coverage_entry = coverage_function_map.get(name, {})
        coverage_ratio = coverage_entry.get("coverage_fraction")
        if coverage_ratio is None and coverage_entry.get("total_lines"):
            coverage_ratio = round(
                float(coverage_entry.get("covered_lines", 0)) / max(float(coverage_entry.get("total_lines", 1)), 1.0),
                4,
            )
        score, reasons = _score_function(name, fact, harness_calls, task_mode, coverage_ratio)
        if score <= 0:
            continue
        enriched = dict(fact)
        if coverage_entry:
            enriched["coverage_summary"] = coverage_entry
        scored.append((score, reasons, enriched))
    scored.sort(key=lambda item: item[0], reverse=True)
    raw_query_driven_candidates = _build_query_driven_candidates(
        harness_calls=harness_calls,
        facts_by_name=facts_by_name,
        query_view=query_view,
        coverage_function_map=coverage_function_map,
        typed_functions=typed_functions,
        task_mode=task_mode,
    )
    query_driven_candidates, denoising_report = _denoise_query_candidates(
        raw_query_driven_candidates,
        harness_source_path=str(harness.source_path) if harness.source_path else None,
    )
    query_driven_candidates, scored, diversification_report = _apply_campaign_diversification_bias(
        task_mode=task_mode,
        campaign_runtime=campaign_runtime,
        query_candidates=query_driven_candidates,
        scored_candidates=scored,
    )
    query_driven_candidates, scored, reseed_target_report = _apply_explicit_reseed_target_bias(
        target_names=campaign_reseed_targets,
        query_candidates=query_driven_candidates,
        scored_candidates=scored,
    )
    target_fact = None
    target_selection_backend = "lite_selector_scoring"
    target_selection_reasons: list[str] = []
    if query_driven_candidates:
        target_fact = dict(query_driven_candidates[0]["fact"])
        target_selection_backend = "original_query_backend_plus_tree_sitter"
        target_selection_reasons = list(query_driven_candidates[0]["reasons"])
    elif scored:
        target_fact = scored[0][2]
        target_selection_reasons = list(scored[0][1])
    else:
        target_fact = facts_by_name.get(harness.name) or None
    related_facts = []
    if query_driven_candidates:
        related_facts.extend([dict(item["fact"]) for item in query_driven_candidates[:6]])
    for item in scored[:6]:
        fact = item[2]
        if any(existing.get("name") == fact.get("name") for existing in related_facts if isinstance(existing, dict)):
            continue
        related_facts.append(fact)
    related_facts = related_facts[:6]
    callers = []
    callees = []
    extended_context_functions: list[dict[str, Any]] = []
    selection_rationale: list[str] = []
    selection_rationale.extend(target_selection_reasons)
    if diversification_report.get("campaign_runtime_bias_active"):
        if diversification_report.get("cooled_target"):
            selection_rationale.append(
                f"campaign cooled previously plateaued target {diversification_report['cooled_target']}"
            )
        if diversification_report.get("second_family_search_active"):
            selection_rationale.append("second_family_search_bonus_active")
        if diversification_report.get("campaign_budget_state") == "explore":
            selection_rationale.append("campaign_budget_explore_bonus_active")
    if reseed_target_report.get("campaign_reseed_target_bias_active"):
        selection_rationale.append("campaign_reseed_target_bias_active")
        selection_rationale.extend(
            f"campaign_reseed_target:{name}"
            for name in reseed_target_report.get("target_names", [])[:5]
        )
    for item in campaign_reseed_target_entries[:4]:
        name = str(item.get("name") or "").strip()
        queue_kind = str(item.get("queue_kind") or "").strip() or "coverage_gap"
        if name:
            selection_rationale.append(f"coverage_target::{queue_kind}::{name}")
    if target_fact:
        hop_budget_chars = max(1200, settings.context_hop_budget_chars)
        layer1_budget_chars = int(hop_budget_chars * 0.6)
        layer23_budget_chars = max(0, hop_budget_chars - layer1_budget_chars)
        caller_candidates = [
            _compact_context_function(
                dict(item),
                distance=1,
                rationale="direct caller of target",
                relation="1-hop caller",
                signature_limit=160,
                snippet_limit=180,
            )
            for item in _dedupe_function_facts(query_view.get_callers(target_fact["name"]))
        ]
        callers, caller_used_chars = _budget_select_entries(
            caller_candidates,
            budget_chars=max(1, layer1_budget_chars // 2),
            max_items=6,
        )
        callee_candidates = [
            _compact_context_function(
                dict(item),
                distance=1,
                rationale="direct callee of target",
                relation="1-hop callee",
                signature_limit=160,
                snippet_limit=180,
            )
            for item in _dedupe_function_facts(query_view.get_callees(target_fact["name"]))
        ]
        callees, callee_used_chars = _budget_select_entries(
            callee_candidates,
            budget_chars=max(1, layer1_budget_chars - caller_used_chars),
            max_items=6,
        )
        extended_context_functions, hop_budget_report = _expand_context_hops(
            query_view,
            seed_nodes=[*callers, *callees],
            facts_by_name=facts_by_name,
            typed_functions=typed_functions,
            trace_function_names=trace_function_names,
            budget_chars=layer23_budget_chars,
            max_hops=max(1, settings.context_max_hops),
            priority_keywords=_normalize_hop_keywords(settings.context_hop_keywords),
            visited={
                str(target_fact.get("name") or "").strip(),
                *[str(item.get("name") or "").strip() for item in callers],
                *[str(item.get("name") or "").strip() for item in callees],
            },
        )
        query_examples = {
            "get_functions": query_view.get_functions(target_fact["name"], fuzzy=False)[:3],
            "get_callers": callers[:3],
            "get_callees": callees[:3],
        }
    else:
        query_examples = {}
        hop_budget_report = {
            "hop_budget_chars": settings.context_hop_budget_chars,
            "selected_count": 0,
            "distance_counts": {},
        }

    snippet_blob = "\n".join(
        [
            harness_source,
            target_fact.get("snippet", "") if target_fact else "",
            *[item.get("snippet", "") for item in related_facts],
        ]
    )
    key_types = [
        item
        for item in query_view.get_types_referenced_by([snippet_blob], limit=12)
        if item.get("kind") in {"struct", "enum"}
    ][:6]
    selected_tree_sitter = typed_functions.get(str((target_fact or {}).get("name") or ""), {})
    for type_name in selected_tree_sitter.get("type_refs", []):
        for item in query_view.original_like_backend.get_types(type_name, fuzzy=False)[:3] if query_view.original_like_backend else []:
            if item.get("kind") in {"struct", "enum", "type_definition", "struct_specifier", "enum_specifier"} and all(
                existing.get("name") != item.get("name") for existing in key_types if isinstance(existing, dict)
            ):
                key_types.append(item)
    if len(key_types) > 6:
        key_types = key_types[:6]
    key_constants = [item for item in type_facts if item.get("kind") in {"macro", "constant"} and _type_matches(item, snippet_blob)][:8]
    harness_symbols = [name for name in sorted(harness_calls) if name in facts_by_name][:12]
    candidate_harnesses = [
        {
            "name": item.get("name"),
            "path": item.get("path"),
            "kind": "fuzzer",
        }
        for item in build_registry.get("fuzzers", [])
        if item.get("name") and item.get("path")
    ]
    candidate_harnesses.extend(
        {
            "name": item.get("name"),
            "path": item.get("path"),
            "kind": "harness_source",
        }
        for item in build_registry.get("harnesses", [])
        if item.get("name") and item.get("path") and all(existing["name"] != item.get("name") for existing in candidate_harnesses)
    )
    selected_target_functions = []
    if target_fact:
        selected_target_functions.append(
            {
                "name": target_fact.get("name"),
                "file": target_fact.get("file"),
                "line": target_fact.get("line"),
                "reason": "primary_target",
                "coverage_summary": target_fact.get("coverage_summary"),
            },
        )
    for entry in campaign_reseed_target_entries[:4]:
        name = str(entry.get("name") or "").strip()
        if not name or any(item["name"] == name for item in selected_target_functions):
            continue
        fact = facts_by_name.get(name) or {}
        selected_target_functions.append(
            {
                "name": name,
                "file": fact.get("file"),
                "line": fact.get("line"),
                "reason": f"coverage_gap::{entry.get('queue_kind') or 'coverage_gap'}",
                "coverage_target_kind": entry.get("queue_kind"),
                "coverage_target_priority": int(entry.get("priority") or 0),
                "coverage_summary": fact.get("coverage_summary")
                or {
                    "coverage_fraction": entry.get("coverage_fraction"),
                    "total_lines": int(entry.get("total_lines") or 0),
                    "covered_lines": int(entry.get("covered_lines") or 0),
                },
            },
        )
    for fact in related_facts[:3]:
        if not fact or not fact.get("name") or any(item["name"] == fact.get("name") for item in selected_target_functions):
            continue
        selected_target_functions.append(
            {
                "name": fact.get("name"),
                "file": fact.get("file"),
                "line": fact.get("line"),
                "reason": "related_context",
                "coverage_summary": fact.get("coverage_summary"),
            },
        )

    source_snippets: list[dict[str, Any]] = []
    if harness.source_path:
        source_snippets.append(
            {
                "kind": "harness_source",
                "path": str(harness.source_path),
                "snippet": harness_source[:2500],
            },
        )
    for kind, items in (("target_function", [target_fact] if target_fact else []), ("related_function", related_facts[:4])):
        for fact in items:
            if not fact:
                continue
            source_snippets.append(
                {
                    "kind": kind,
                    "path": fact.get("file"),
                    "line": fact.get("line"),
                    "symbol": fact.get("name"),
                    "snippet": fact.get("snippet"),
                },
            )

    payload = {
        "task_id": task_id,
        "task_mode": task_mode,
        "candidate_harnesses": candidate_harnesses,
        "selected_harness": harness.name,
        "selected_harness_path": str(harness.executable_path),
        "harness": {
            "name": harness.name,
            "executable_path": str(harness.executable_path),
            "source_path": str(harness.source_path) if harness.source_path else None,
            "dict_path": str(harness.dict_path) if harness.dict_path else None,
            "options_path": str(harness.options_path) if harness.options_path else None,
        },
        "target_function": target_fact,
        "selected_target_function": target_fact,
        "selected_target_functions": selected_target_functions,
        "related_functions": related_facts,
        "callers": callers,
        "callees": callees,
        "extended_context_functions": extended_context_functions,
        "key_types": key_types,
        "key_constants": key_constants,
        "harness_symbols": harness_symbols,
        "source_snippets": source_snippets,
        "selection_rationale": selection_rationale or ["fallback_to_harness_context"],
        "campaign_runtime_bias": diversification_report,
        "campaign_reseed_target_entries": campaign_reseed_target_entries,
        "campaign_reseed_targets": campaign_reseed_targets,
        "campaign_reseed_target_bias": reseed_target_report,
        "campaign_family_stagnation_count": int(campaign_runtime.get("campaign_family_stagnation_count") or 0),
        "family_stagnation_targets": family_stagnation_targets,
        "exact_uncovered_target_functions": exact_uncovered_target_functions,
        "coverage_runtime_snapshot": {
            "coverage_level": _coverage_snapshot_level(coverage_summary),
            "coverage_summary_kind": coverage_summary.get("coverage_summary_kind"),
            "per_function_summary_count": len(coverage_function_map),
            "exact_uncovered_target_count": len(exact_uncovered_target_functions),
        },
        "coverage_exploration_contract": coverage_exploration_contract,
        "coverage_query_evidence": {
            "coverage_summary_manifest_path": str(task_root(task_id) / "coverage" / "coverage_summary_manifest.json"),
            "function_coverage_rows_available": len(coverage_function_map),
            "query_examples": query_examples,
            "tree_sitter_parser_adjacent_candidates": typed_query_payload.get("parser_adjacent_candidates", [])[:6],
            "campaign_reseed_targets": campaign_reseed_targets,
            "campaign_reseed_target_entries": campaign_reseed_target_entries,
            "coverage_exploration_contract": coverage_exploration_contract,
            "exact_uncovered_target_functions": exact_uncovered_target_functions[:8],
        },
        "context_hop_budget": hop_budget_report,
        "evidence_paths": {
            "index_manifest": str(index_dir / "manifest.json"),
            "program_model_backend_manifest": str(index_dir / "program_model_backend_manifest.json"),
            "function_facts": str(index_dir / "function_facts.json"),
            "type_facts": str(index_dir / "type_facts.json"),
            "call_graph": str(index_dir / "call_graph.json"),
            "program_model_query_manifest": str(index_dir / "codequery_view_manifest.json"),
            "tree_sitter_backend_manifest": str(tree_sitter_backend_manifest_path(task_id)),
            "typed_query_results": str(typed_query_results_path(task_id)),
            "target_selection_backend_manifest": str(target_selection_backend_manifest_path(task_id)),
            "query_to_target_decision_manifest": str(query_to_target_decision_manifest_path(task_id)),
            "query_candidate_denoising_report": str(query_candidate_denoising_report_path(task_id)),
        },
        "program_model_interface": {
            "compat_source": "original_buttercup.program_model.CodeQueryPersistent",
            "query_methods_consumed": ["get_callers", "get_callees", "get_types_referenced_by"],
            "implementation": codequery_view_manifest.get("implementation") or "lite_adapted_query_view",
            "backend": backend_manifest.get("backend"),
            "backend_kind": backend_manifest.get("backend_kind"),
            "backend_strength": backend_manifest.get("backend_strength"),
            "artifact_presence": backend_manifest.get("artifact_presence", {}),
            "query_backend_capabilities": backend_manifest.get("query_backend_capabilities", {}),
            "query_validation_manifest_path": str(index_dir / "program_model_query_validation_manifest.json"),
            "query_capability_matrix": validation_manifest.get("query_capability_matrix", {}),
            "tree_sitter_backend": tree_sitter_backend_manifest,
        },
        "target_selection_backend": target_selection_backend,
    }
    output_path = context_package_path(task_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    contribution_payload = {
        "task_id": task_id,
        "task_mode": task_mode,
        "backend_kind": backend_manifest.get("backend_kind"),
        "original_backend_available": backend_manifest.get("original_backend_available"),
        "context_field_sources": {
            "candidate_harnesses": "build_registry_and_source_resolution",
            "selected_harness": "build_registry_and_source_resolution",
            "target_function": target_selection_backend,
            "related_functions": "original_query_candidates_with_tree_sitter_and_coverage_bias",
            "callers": (
                "original_like_query_backend"
                if any(item.get("query_backend") == "cqsearch" for item in callers if isinstance(item, dict))
                else "lite_call_graph_fallback"
            ),
            "callees": (
                "original_like_query_backend"
                if any(item.get("query_backend") == "cqsearch" for item in callees if isinstance(item, dict))
                else "lite_call_graph_fallback"
            ),
            "extended_context_functions": "budget_aware_multi_hop_expansion",
            "key_types": (
                "original_like_query_backend"
                if any(item.get("query_backend") == "cqsearch" for item in key_types if isinstance(item, dict))
                else "tree_sitter_then_lite_type_fact_scan"
            ),
            "key_constants": "lite_type_fact_scan",
            "selection_rationale": "original_query_backend_plus_tree_sitter_target_decision",
            "coverage_query_evidence": "coverage_summary_manifest",
            "source_snippets": "harness_source_and_symbol_snippets",
        },
        "backend_contribution_summary": {
            "original_query_selected_target": target_selection_backend != "lite_selector_scoring",
            "original_query_callers_count": sum(1 for item in callers if isinstance(item, dict) and item.get("query_backend") == "cqsearch"),
            "original_query_callees_count": sum(1 for item in callees if isinstance(item, dict) and item.get("query_backend") == "cqsearch"),
            "extended_context_function_count": len(extended_context_functions),
            "original_query_type_count": sum(1 for item in key_types if isinstance(item, dict) and item.get("query_backend") == "cqsearch"),
            "lite_related_function_count": len(related_facts),
            "coverage_augmented_function_count": sum(1 for item in related_facts if isinstance(item, dict) and item.get("coverage_summary")),
            "tree_sitter_type_count": len(typed_types),
            "tree_sitter_parser_adjacent_candidates": len(typed_query_payload.get("parser_adjacent_candidates", [])),
        },
        "campaign_runtime_bias": diversification_report,
        "campaign_reseed_target_bias": reseed_target_report,
        "query_capability_matrix": validation_manifest.get("query_capability_matrix", {}),
        "sample_query_results_path": str(index_dir / "sample_query_results.json"),
        "program_model_query_validation_manifest_path": str(index_dir / "program_model_query_validation_manifest.json"),
    }
    _write_json(context_backend_contribution_path(task_id), contribution_payload)
    parser_local_payload = {
        "task_id": task_id,
        "task_mode": task_mode,
        "selected_target_function": (target_fact or {}).get("name"),
        "selected_target_parser_adjacent": bool(selected_tree_sitter.get("parser_adjacent")),
        "selected_target_type_refs": selected_tree_sitter.get("type_refs") or [],
        "selected_target_call_count": int(selected_tree_sitter.get("call_count") or 0),
        "campaign_runtime_bias": diversification_report,
        "campaign_reseed_target_bias": reseed_target_report,
        "parser_local_candidates": [
            {
                "name": item["name"],
                "score": item["score"],
                "reasons": item["reasons"],
                "file": item["fact"].get("file"),
                "parser_adjacent": bool(((item.get("fact") or {}).get("tree_sitter_record") or {}).get("parser_adjacent")),
            }
            for item in query_driven_candidates[:12]
        ],
        "noise_filter_summary": denoising_report,
    }
    _write_json(parser_local_denoising_manifest_path(task_id), parser_local_payload)
    richer_typed_relations_payload = {
        "task_id": task_id,
        "task_mode": task_mode,
        "selected_target_function": (target_fact or {}).get("name"),
        "selected_target_tree_sitter_record": selected_tree_sitter,
        "typed_parser_adjacent_candidates": typed_query_payload.get("parser_adjacent_candidates", [])[:16],
        "campaign_reseed_target_bias": reseed_target_report,
        "typed_relations_summary": {
            "typed_function_count": len(typed_functions),
            "typed_type_count": len(typed_types),
            "selected_target_type_ref_count": len(selected_tree_sitter.get("type_refs") or []),
            "selected_target_call_count": int(selected_tree_sitter.get("call_count") or 0),
            "key_type_count": len(key_types),
            "extended_context_function_count": len(extended_context_functions),
        },
        "selected_target_callers": callers[:8],
        "selected_target_callees": callees[:8],
        "extended_context_functions": extended_context_functions[:10],
        "key_types": key_types,
    }
    _write_json(richer_typed_relations_manifest_path(task_id), richer_typed_relations_payload)
    _write_json(
        query_candidate_denoising_report_path(task_id),
        {
            "task_id": task_id,
            "task_mode": task_mode,
            **denoising_report,
            "denoising_backend": "query_backend_candidate_filtering",
            "harness_source_path": str(harness.source_path) if harness.source_path else None,
        },
    )
    target_selection_payload = {
        "task_id": task_id,
        "task_mode": task_mode,
        "backend_kind": backend_manifest.get("backend_kind"),
        "selected_target_function": (target_fact or {}).get("name"),
        "selected_target_functions": [item.get("name") for item in selected_target_functions if isinstance(item, dict)],
        "selection_backend": target_selection_backend,
        "selection_rationale": selection_rationale or ["fallback_to_harness_context"],
        "campaign_runtime_bias": diversification_report,
        "campaign_reseed_target_bias": reseed_target_report,
        "query_backend_dominant": target_selection_backend != "lite_selector_scoring",
        "program_model_query_validation_manifest_path": str(index_dir / "program_model_query_validation_manifest.json"),
        "tree_sitter_backend_manifest_path": str(tree_sitter_backend_manifest_path(task_id)),
        "typed_query_results_path": str(typed_query_results_path(task_id)),
        "query_candidate_denoising_report_path": str(query_candidate_denoising_report_path(task_id)),
        "parser_local_denoising_manifest_path": str(parser_local_denoising_manifest_path(task_id)),
        "richer_typed_relations_manifest_path": str(richer_typed_relations_manifest_path(task_id)),
    }
    _write_json(target_selection_backend_manifest_path(task_id), target_selection_payload)
    decision_payload = {
        "task_id": task_id,
        "task_mode": task_mode,
        "selection_backend": target_selection_backend,
        "query_driven_candidates": [
            {
                "name": item["name"],
                "score": item["score"],
                "score_breakdown": item["score_breakdown"],
                "reasons": item["reasons"],
                "file": item["fact"].get("file"),
                "line": item["fact"].get("line"),
            }
            for item in query_driven_candidates[:12]
        ],
        "fallback_scored_candidates": [
            {
                "name": fact.get("name"),
                "score": score,
                "reasons": reasons,
                "file": fact.get("file"),
                "line": fact.get("line"),
            }
            for score, reasons, fact in scored[:12]
        ],
        "selected_target_function": (target_fact or {}).get("name"),
        "campaign_runtime_bias": diversification_report,
        "campaign_reseed_target_bias": reseed_target_report,
        "parser_local_dominant": any("parser_local_query_bias" in item.get("reasons", []) for item in query_driven_candidates[:3]),
        "parser_local_denoising_manifest_path": str(parser_local_denoising_manifest_path(task_id)),
        "richer_typed_relations_manifest_path": str(richer_typed_relations_manifest_path(task_id)),
    }
    _write_json(query_to_target_decision_manifest_path(task_id), decision_payload)
    return output_path, payload

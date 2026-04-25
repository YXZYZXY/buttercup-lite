from __future__ import annotations

import json

from core.seed.models import HarnessSelection, SeedContext
from core.utils.settings import settings


SYSTEM_PROMPT = """You generate Python seed generators for fuzzing.
Your entire response must be executable Python source only.
Do not add markdown fences, comments, explanations, bullet points, or prose before/after the code.
Rules:
- No imports.
- Define 3 to 6 functions named gen_<name>() -> bytes.
- Each function must return bytes.
- Every gen_* function must include an explicit return annotation: -> bytes.
- Generate varied, deterministic inputs that match the selected harness format.
- Prefer bytes literals, repetition, and simple concatenation over complex logic.
- Do not access files, network, environment, subprocesses, or system resources.
- Do not loop forever.
- Keep code simple enough to execute quickly.
"""


def _mode_specific_instructions(task_mode: str) -> str:
    if task_mode == "VULN_DISCOVERY":
        return (
            "Task mode: VULN_DISCOVERY.\n"
            "- Bias toward edge cases that stress parser, allocator, print, and teardown paths.\n"
            "- Prefer malformed delimiters, deep nesting, escaped strings, truncation, and boundary payload sizes.\n"
            "Requirements for this mode:\n"
            "- At least one seed must trigger deep allocation: deeply nested structures or repeated key/value pairs (>50 levels).\n"
            "- At least one seed must be truncated mid-structure (valid prefix, abrupt end).\n"
            "- At least one seed must have size values just above/below power-of-2 boundaries (e.g., 127, 128, 129, 255, 256, 257).\n"
        )
    if task_mode == "SEED_EXPLORE":
        return (
            "Task mode: SEED_EXPLORE.\n"
            "- Treat the supplied uncovered / low-growth / degraded coverage targets as first-class exploration objectives.\n"
            "- Prefer structurally different valid and near-valid inputs that are plausible routes into those target functions.\n"
            "- Use different structural hypotheses per generated function instead of many tiny mutations of one shape.\n"
            "Requirements for this mode:\n"
            "- Dedicate different gen_* functions to different target groups when coverage-gap targets are available.\n"
            "- At least one seed must preserve overall format validity while varying lengths, nesting, ordering, or flags.\n"
            "- At least one seed must be malformed-but-parseable (valid structure with invalid field values or boundary metadata).\n"
            "- At least one seed must explore a parser-state transition that a simple starter corpus is unlikely to reach.\n"
        )
    return (
        "Task mode: SEED_INIT.\n"
        "- Produce a compact starter corpus with valid and near-valid inputs.\n"
        "Requirements for this mode:\n"
        "- At least one seed must be empty or minimal (0-4 bytes).\n"
        "- At least one seed must be at boundary size (255 or 256 bytes). This seed must have meaningful structural content, NOT just repeated bytes or padding. For example, for a JSON parser: a valid JSON object with many nested keys totaling ~256 bytes.\n"
        "- At least one seed must exercise the primary parse entry point with a structurally complete input.\n"
    )


def _format_specific_instructions(project_name: str, harness_name: str) -> str:
    return (
        f"Target-specific format for project={project_name}, harness={harness_name}:\n"
        "- Infer the expected input shape from the harness source, related functions, sample fragments, dictionaries, and options.\n"
        "- Prefer structured bytes that are likely to be parsed meaningfully.\n"
        "- Include both valid and near-valid examples when reasonable.\n"
        "- Use the selected target function and call graph as the source of truth for parser entrypoints and edge cases.\n"
        "- Keep each generated payload small enough to execute quickly unless the supplied context clearly calls for larger boundary cases."
    )


def _format_parser_adjacent_section(context: SeedContext) -> str:
    seen_names: set[str] = set()
    lines: list[str] = []
    for candidate in context.parser_adjacent_candidates:
        if not isinstance(candidate, dict):
            continue
        name = str(candidate.get("name") or "").strip()
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        lines.append(f"- {name}: likely involved in parsing/input processing")
        if len(lines) >= 5:
            break
    if not lines:
        return ""
    return "Parser-Adjacent Functions:\n" + "\n".join(lines)


def _format_key_struct_fields_section(context: SeedContext) -> str:
    seen_names: set[str] = set()
    lines: list[str] = []
    for item in context.key_types:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        snippet = str(item.get("snippet") or "").strip()
        if item.get("kind") != "struct" or not name or not snippet or name in seen_names:
            continue
        seen_names.add(name)
        lines.append(f"- {name}: key type referenced near crash/parse path")
        if len(lines) >= 5:
            break
    if not lines:
        return ""
    return "Key Struct Fields:\n" + "\n".join(lines)


def _coverage_target_entries(context: SeedContext) -> list[dict]:
    raw_entries = list((context.context_package or {}).get("campaign_reseed_target_entries") or [])
    selected: list[dict] = []
    for item in raw_entries:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        selected.append(dict(item))
    return selected


def _queue_kind_label(value: str) -> str:
    labels = {
        "uncovered": "Uncovered Functions",
        "exact_uncovered": "Exact Uncovered Functions",
        "low_growth": "Low-Growth Functions",
        "partial_degraded": "Degraded / Partial Coverage Targets",
        "family_confirmation": "Family Confirmation Targets",
        "family_stagnation": "Family Stagnation Targets",
        "candidate_bridge": "Suspicious Candidate Bridge Targets",
        "coverage_gap": "Coverage-Gap Targets",
    }
    return labels.get(str(value or "").strip(), str(value or "Coverage-Gap Targets").replace("_", " ").title())


def _format_coverage_gap_targets_section(
    context: SeedContext,
    *,
    focus_entries: list[dict] | None = None,
) -> str:
    targets = focus_entries or _coverage_target_entries(context)
    if not targets:
        return ""
    groups: dict[str, list[dict]] = {}
    for item in targets:
        groups.setdefault(str(item.get("queue_kind") or "coverage_gap"), []).append(item)
    lines: list[str] = []
    for queue_kind, entries in groups.items():
        lines.append(f"{_queue_kind_label(queue_kind)}:")
        for entry in entries[:4]:
            name = str(entry.get("name") or "").strip()
            coverage_fraction = entry.get("coverage_fraction")
            priority = entry.get("priority")
            if not name:
                continue
            detail_parts = []
            if coverage_fraction is not None:
                detail_parts.append(f"coverage={coverage_fraction}")
            if priority not in (None, "", 0):
                detail_parts.append(f"priority={priority}")
            details = f" ({', '.join(detail_parts)})" if detail_parts else ""
            lines.append(f"- {name}{details}")
    if len(lines) <= 1:
        return ""
    return "Coverage-Gap Targets:\n" + "\n".join(lines)


def _format_coverage_exploration_contract_section(
    context: SeedContext,
    *,
    focus_entries: list[dict] | None = None,
    focus_reason: str | None = None,
) -> str:
    contract = dict((context.context_package or {}).get("coverage_exploration_contract") or {})
    target_entries = focus_entries or list(contract.get("target_entries") or []) or _coverage_target_entries(context)
    if not target_entries:
        return ""
    queue_kind_counts = dict(contract.get("queue_kind_counts") or {})
    primary_queue_kind = str(contract.get("primary_queue_kind") or "").strip() or None
    lines = [
        "Coverage Exploration Contract:",
        "- This request is coverage-driven: generate seeds that are plausible routes into the listed low-coverage targets.",
        "- Do not treat the target list as a hint; use it to decide seed structure, parser state transitions, nesting, flags, and boundary metadata.",
        "- Spread gen_* functions across distinct structural hypotheses instead of emitting near-duplicates.",
    ]
    if primary_queue_kind:
        lines.append(f"- Primary queue pressure: {_queue_kind_label(primary_queue_kind)}.")
    if queue_kind_counts:
        lines.append(f"- Queue kind counts: {json.dumps(queue_kind_counts, ensure_ascii=False)}")
    if focus_reason:
        lines.append(f"- Current focus batch: {focus_reason}.")
    lines.extend(
        [
            "- For uncovered targets, prefer inputs that remain structurally plausible long enough to enter deeper parser branches.",
            "- For low-growth targets, preserve the overall format while changing control flow through lengths, ordering, nesting, flags, offsets, or field combinations.",
            "- For degraded/partial targets, vary parser-adjacent structures that could recover more exact coverage around the same region.",
        ]
    )
    return "\n".join(lines)


def _format_batch_strategy_section(
    *,
    batch_strategy: str | None = None,
    focus_entries: list[dict] | None = None,
) -> str:
    strategy = str(batch_strategy or "").strip()
    if not strategy:
        return ""
    focus_names = [
        str(item.get("name") or "").strip()
        for item in (focus_entries or [])
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    ]
    lines = ["Batch Strategy:"]
    if strategy == "coverage_queue_top_1":
        lines.append("- This batch is the highest-priority current coverage-queue target.")
        lines.append("- Generate materially different routes into this function instead of many minor mutations.")
    elif strategy == "coverage_queue_top_2":
        lines.append("- This batch must explore a different coverage target than the primary batch.")
        lines.append("- Do not collapse back onto the first batch's function or input shape.")
    elif strategy == "family_stagnation_target":
        lines.append("- This batch is reserved for the function that has stalled longest under family diversification pressure.")
        lines.append("- Prefer alternate parser states or branch conditions that could split the current family plateau.")
    elif strategy == "exact_uncovered_refill":
        lines.append("- Coverage-queue diversity was exhausted, so this batch is refilled from the current exact covered=false snapshot.")
        lines.append("- Prioritize routes into functions that still have zero covered lines.")
    elif strategy == "open_ended_exploration":
        lines.append("- This is the open-ended batch: do not anchor every gen_* function to one named target.")
        lines.append("- Spread exploration across parser-adjacent logic and the never-reached exact coverage targets listed below.")
    else:
        lines.append(f"- Active strategy: {strategy}.")
    if focus_names:
        lines.append(f"- Primary batch targets: {json.dumps(focus_names[:4], ensure_ascii=False)}")
    return "\n".join(lines)


def _format_exact_uncovered_targets_section(context: SeedContext, *, compact: bool) -> str:
    targets = list((context.context_package or {}).get("exact_uncovered_target_functions") or [])
    if not targets:
        return ""
    lines = [
        "Never-Reached Exact Coverage Targets:",
        "- These functions come from the current exact coverage snapshot and still have covered_lines=0.",
        "- Use them to diversify away from repeatedly exercised paths, especially for generalized source exploration.",
    ]
    for entry in targets[: (4 if compact else 8)]:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        detail_parts = []
        total_lines = int(entry.get("total_lines", 0) or 0)
        if total_lines > 0:
            detail_parts.append(f"total_lines={total_lines}")
        function_paths = list(entry.get("function_paths") or [])
        if function_paths:
            detail_parts.append(f"path={function_paths[0]}")
        details = f" ({', '.join(detail_parts)})" if detail_parts else ""
        lines.append(f"- {name}{details}")
    return "\n".join(lines) if len(lines) > 3 else ""


def _compact_function_for_prompt(item: dict) -> dict:
    summary = {
        "name": item.get("name"),
        "file": item.get("file"),
        "line": item.get("line"),
        "distance": item.get("distance"),
        "rationale": item.get("rationale"),
        "signature": str(item.get("signature") or "").strip()[:180] or None,
        "snippet": str(item.get("snippet") or item.get("body_excerpt") or "").strip()[:220] or None,
    }
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def _format_budgeted_json_list(items: list[dict], *, budget_chars: int, max_items: int) -> str:
    selected: list[dict] = []
    used_chars = 0
    for item in items:
        if len(selected) >= max_items:
            break
        compact = _compact_function_for_prompt(item)
        if not compact:
            continue
        encoded = json.dumps(compact, ensure_ascii=False)
        remaining = budget_chars - used_chars
        if remaining <= 0:
            break
        if len(encoded) > remaining:
            if compact.get("snippet"):
                compact["snippet"] = compact["snippet"][: max(0, min(len(compact["snippet"]), remaining // 3))]
            if compact.get("signature") and len(json.dumps(compact, ensure_ascii=False)) > remaining:
                compact["signature"] = compact["signature"][: max(0, min(len(compact["signature"]), remaining // 4))]
            compact = {key: value for key, value in compact.items() if value not in (None, "", [], {})}
            encoded = json.dumps(compact, ensure_ascii=False)
        if len(encoded) > remaining:
            continue
        selected.append(compact)
        used_chars += len(encoded)
    return json.dumps(selected, indent=2, ensure_ascii=False)


def _format_extended_context_functions_section(context: SeedContext) -> str:
    if not context.extended_context_functions:
        return ""
    lines = ["## Extended Context Functions"]
    for item in context.extended_context_functions[:10]:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        distance = item.get("distance")
        rationale = str(item.get("rationale") or item.get("relation") or "expanded context").strip()
        lines.append(f"- {name} (distance: {distance}, reason: {rationale})")
    return "\n".join(lines)


def build_messages(
    project_name: str,
    harness: HarnessSelection,
    context: SeedContext,
    *,
    task_mode: str = "SEED_INIT",
    previous_error: str | None = None,
    compact: bool = False,
    coverage_focus_entries: list[dict] | None = None,
    coverage_focus_reason: str | None = None,
    batch_strategy: str | None = None,
) -> list[dict]:
    focus_budget_chars = max(1200 if compact else 2000, int(settings.context_hop_budget_chars * (0.55 if compact else 1.0)))
    related_budget_chars = max(700 if compact else 1200, int(focus_budget_chars * (0.3 if compact else 0.4)))
    caller_budget_chars = max(500 if compact else 900, int(focus_budget_chars * 0.2))
    callee_budget_chars = max(500 if compact else 900, int(focus_budget_chars * 0.2))
    candidate_harness_blob = json.dumps(context.candidate_harnesses, indent=2)[: (600 if compact else 1200)]
    target_function_blob = json.dumps(context.target_function, indent=2)[: (1400 if compact else 2500)]
    selected_target_functions_blob = json.dumps(context.selected_target_functions, indent=2)[: (1200 if compact else 2500)]
    harness_source_blob = context.harness_source[: (1800 if compact else 6000)]
    key_types_blob = json.dumps(context.key_types, indent=2)[: (900 if compact else 1800)]
    key_constants_blob = json.dumps(context.key_constants, indent=2)[: (900 if compact else 1800)]
    sample_inputs_blob = "\n---\n".join(context.sample_inputs[: (2 if compact else 4)])[: (1200 if compact else 3000)]
    user_sections = [
        f"Project: {project_name}",
        f"Selected harness: {context.selected_harness or harness.name}",
        f"Harness path: {harness.executable_path}",
        "Candidate harnesses:",
        candidate_harness_blob,
        _mode_specific_instructions(task_mode),
        _format_specific_instructions(project_name, harness.name),
        f"Context package path: {context.context_package_path or 'none'}",
        "Context selection rationale:",
        "\n".join(context.selection_rationale[:6]),
        "Primary target function:",
        target_function_blob,
        "Selected target functions:",
        selected_target_functions_blob,
        _format_coverage_exploration_contract_section(
            context,
            focus_entries=coverage_focus_entries,
            focus_reason=coverage_focus_reason,
        ),
        _format_batch_strategy_section(
            batch_strategy=batch_strategy,
            focus_entries=coverage_focus_entries,
        ),
        _format_coverage_gap_targets_section(context, focus_entries=coverage_focus_entries),
        _format_exact_uncovered_targets_section(context, compact=compact),
        "Harness source:",
        harness_source_blob,
        "Related parser functions:",
        _format_budgeted_json_list(context.related_functions, budget_chars=related_budget_chars, max_items=6),
        "Callers of the target function:",
        _format_budgeted_json_list(context.callers, budget_chars=caller_budget_chars, max_items=6),
        "Callees of the target function:",
        _format_budgeted_json_list(context.callees, budget_chars=callee_budget_chars, max_items=6),
        "" if compact else _format_extended_context_functions_section(context),
        "Key types / structs / enums:",
        key_types_blob,
        "Key constants / macros:",
        key_constants_blob,
        _format_parser_adjacent_section(context),
        _format_key_struct_fields_section(context),
        "Sample input fragments:",
        sample_inputs_blob,
        "Dictionary snippet:",
        (context.dict_snippet or "")[: (600 if compact else 1200)],
        "Options snippet:",
        (context.options_snippet or "")[: (300 if compact else 600)],
        "Compact prompt mode is active: prioritize the selected harness contract, primary target function, and parser-adjacent evidence; omit low-value repetition."
        if compact
        else "",
        "Implementation hint: use pure Python bytes expressions only. Byte repetition like b\"A\" * 1024 is allowed.",
        "Return only Python code with gen_* functions that create bytes inputs suitable for this harness.",
        "Response format contract: every generated function must look like def gen_name() -> bytes: and the response must contain nothing except Python source code.",
    ]
    if previous_error:
        user_sections.append(f"Previous generation failed because: {previous_error}")
        user_sections.append("Correct the issue and return only Python code.")

    return [
        {
            "role": "system",
            "content": [{"type": "text", "text": SYSTEM_PROMPT}],
        },
        {
            "role": "user",
            "content": [{"type": "text", "text": "\n\n".join(section for section in user_sections if section)}],
        },
    ]

from __future__ import annotations

import json
from pathlib import Path

from core.binary_seed.models import BinarySeedContext

SYSTEM_PROMPT = """You generate binary-native seed generators for fuzzing.
Your entire response must be executable Python source only.
Do not add markdown fences, comments, explanations, bullet points, or prose before/after the code.
Rules:
- No imports.
- Define 3 to 6 functions named gen_<name>() -> bytes.
- Every function must return bytes.
- Every gen_* function must include an explicit return annotation: -> bytes.
- Keep the Python simple: use bytes literals plus straightforward concatenation only.
- Use ASCII-safe escaped byte strings for non-printable bytes; never emit literal raw NUL/control characters directly in the source text.
- Avoid list comprehensions, generator expressions, unmatched brackets, helper functions, or complicated string assembly.
- Prefer deterministic, structured bytes that match the binary's likely input format.
- Do not access files, subprocesses, the network, environment variables, or OS resources.
- Do not loop forever.
- Keep outputs under 256 KiB and make them execute quickly.
"""


def _mode_specific_instructions(task_mode: str) -> str:
    if task_mode == "VULN_DISCOVERY":
        return (
            "Task mode: VULN_DISCOVERY.\n"
            "- Bias toward boundary payloads, deep nesting, teardown stress, truncation, and realloc-like pressure.\n"
            "- Prefer malformed delimiters, long strings, repeated structures, and parser edge cases.\n"
        )
    if task_mode == "SEED_EXPLORE":
        return (
            "Task mode: SEED_EXPLORE.\n"
            "- Bias toward structurally diverse valid and near-valid inputs.\n"
            "- Prefer multiple different container shapes, escaped strings, mixed scalar types, and alternate nesting patterns.\n"
        )
    return (
        "Task mode: SEED_INIT.\n"
        "- Produce a compact starter corpus with valid and near-valid inputs.\n"
    )


def _format_specific_guidance(binary_target_name: str, slice_payload: dict) -> str:
    blob = json.dumps(
        {
            "binary_target_name": binary_target_name,
            "selected_target_function": slice_payload.get("selected_target_function"),
            "parser_candidates": slice_payload.get("parser_candidates", [])[:6],
            "relevant_strings": slice_payload.get("relevant_strings", [])[:8],
        },
        ensure_ascii=False,
    ).lower()
    hints: list[str] = []
    if any(token in blob for token in ("json", "object", "array", "string", "number")):
        hints.extend(
            [
                "The target appears JSON-like: include deeply nested arrays/objects, very long strings, escaped unicode/backslash strings, duplicate keys, truncated containers, and mixed scalar/object/array payloads.",
                "For VULN_DISCOVERY, include at least one payload with depth or string length pressure and one near-valid truncated object/array.",
                "If contract hints mention control flags or termination, honor them explicitly: prefix required flag bytes before the JSON body and terminate the payload with a NUL byte when required.",
            ]
        )
    if any(token in blob for token in ("ini", "section", "key", "value", "config")):
        hints.extend(
            [
                "The target appears INI-like: include oversized section names, duplicate sections, multiline-looking values, comment/semicolon variants, and malformed brackets.",
                "For VULN_DISCOVERY, include at least one oversized section header and one nested/malformed bracket input.",
            ]
        )
    if any(token in blob for token in ("yaml", "scanner", "anchor", "alias", "document")):
        hints.extend(
            [
                "The target appears YAML-like: include nested mappings/sequences, anchors/aliases, long scalars, indentation edge cases, explicit tags, and truncated documents.",
                "For VULN_DISCOVERY, include at least one deeply indented mapping and one alias/anchor pressure case.",
            ]
        )
    if any(token in blob for token in ("plist", "bplist", "xplist", "xml plist", "property list")):
        hints.extend(
            [
                "The target appears plist-like: prefer parser-oriented payloads such as XML plist snippets, compact binary plist headers, truncated trailer variants, and malformed object/table layouts.",
                "Use escaped byte sequences for non-printable bytes; do not place literal control characters directly in the Python source.",
                "For VULN_DISCOVERY, include at least one valid-ish XML plist, one compact binary-plist header/trailer case, and one truncated near-valid payload.",
            ]
        )
    if not hints:
        hints.append(
            "Use parser-adjacent strings and function names to infer the format; include both valid starter inputs and malformed boundary inputs."
        )
    return "\n".join(f"- {hint}" for hint in hints)


def _format_source_signature(entry: dict) -> str:
    snippet = str(entry.get("snippet") or "").strip()
    if not snippet:
        return ""
    collected: list[str] = []
    for raw_line in snippet.splitlines():
        line = raw_line.strip()
        if not line or line == "{":
            break
        collected.append(line)
        if line.endswith(")"):
            break
    return " ".join(collected)[:180]


def _format_source_context_section(context: BinarySeedContext) -> str:
    if not context.summary.get("source_context_available"):
        return ""
    parser_adjacent = context.summary.get("source_parser_adjacent") or []
    typed_functions = context.summary.get("source_typed_functions") or []
    fallback_symbols = context.summary.get("source_function_symbols") or []
    function_entries = typed_functions or fallback_symbols
    if not parser_adjacent and not function_entries:
        return ""

    lines = [
        "## Source Code Context",
        "",
    ]
    if parser_adjacent:
        lines.append("### Parser-Adjacent Functions from Source")
        for item in parser_adjacent[:5]:
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            file_name = Path(str(item.get("file") or "")).name or "unknown"
            line = item.get("line")
            location = f" ({file_name}:{line})" if line else f" ({file_name})"
            lines.append(f"- {name}{location}")
        lines.append("")
    if function_entries:
        lines.append("### Key Source Functions")
        for item in function_entries[:10]:
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            signature = _format_source_signature(item)
            if signature:
                lines.append(f"- {name}: {signature}")
            else:
                file_name = Path(str(item.get("file") or "")).name or "unknown"
                line = item.get("line")
                location = f"{file_name}:{line}" if line else file_name
                lines.append(f"- {name}: {location}")
        lines.append("")
    lines.extend(
        [
            "Note: This binary was compiled from source code.",
            "The above functions are identified from source analysis and may correspond to key parsing/processing paths.",
        ]
    )
    return "\n".join(lines)


def _dataset_contract_guidance(context: BinarySeedContext) -> str:
    hints = [str(item) for item in (context.summary.get("dataset_contract_hints") or []) if item]
    if not hints:
        return ""
    joined = "\n".join(hints).lower()
    guidance: list[str] = ["Non-negotiable contract obligations from the binary package:"]
    if "4 ascii control flag bytes" in joined:
        guidance.append("- Every generated payload MUST begin with exactly 4 ASCII bytes using only '0' or '1' before the structured body.")
    if "final byte" in joined and "nul" in joined:
        guidance.append("- Every generated payload MUST end with a NUL byte (b'\\x00').")
    if "whole-document yaml bytes" in joined:
        guidance.append("- Treat the payload as a whole YAML document delivered by file path, not a fragment or stdin command stream.")
    if "argv file replay" in joined or "argv-file" in joined:
        guidance.append("- The replay binary consumes the entire file as input bytes; do not emit command-line fragments or prose.")
    if len(guidance) == 1:
        guidance.extend(f"- {hint}" for hint in hints[:4])
    return "\n".join(guidance)


def build_binary_seed_messages(
    *,
    binary_target_name: str,
    context: BinarySeedContext,
    task_mode: str,
    focus_hint: str | None = None,
    previous_error: str | None = None,
) -> list[dict]:
    slice_payload = {
        "entry_candidates": context.binary_slice.entry_candidates[:8],
        "parser_candidates": context.binary_slice.parser_candidates[:12],
        "selected_target_function": context.binary_slice.selected_target_function,
        "selection_rationale": context.binary_slice.selection_rationale,
        "contract_inference": context.binary_slice.contract_inference,
        "dataset_contract_context": context.summary.get("dataset_contract_context", {}),
        "relevant_functions": context.binary_slice.relevant_functions[:16],
        "relevant_strings": context.binary_slice.relevant_strings[:12],
        "relevant_imports": context.binary_slice.relevant_imports[:12],
    }
    user_sections = [
        f"Target mode: binary",
        f"Binary target: {binary_target_name}",
        f"Input mode: {context.binary_slice.input_mode}",
        f"Launcher semantics source: {context.binary_slice.launcher_semantics_source}",
        _mode_specific_instructions(task_mode),
        "Use the following binary-derived context to infer input format and sensitive code paths.",
        json.dumps(slice_payload, indent=2)[:6500],
        "Additional analysis summary:",
        json.dumps(context.summary, indent=2)[:1800],
        "Artifact sources:",
        json.dumps(context.artifact_sources, indent=2),
        "Input-contract evidence:",
        json.dumps(
            {
                "input_mode": context.binary_slice.input_mode,
                "launcher_semantics_source": context.binary_slice.launcher_semantics_source,
                "contract_interpretation": "Treat argv-file-driven targets as whole-file bytes delivered through a path; do not assume stdin unless input_mode says stdin.",
                "dataset_contract_hints": context.summary.get("dataset_contract_hints", []),
            },
            indent=2,
        ),
        "Dictionary snippet:",
        (context.dict_snippet or "")[:1500],
        "Options snippet:",
        (context.options_snippet or "")[:800],
        _format_source_context_section(context),
        "Format-specific guidance inferred from binary context:",
        _format_specific_guidance(binary_target_name, slice_payload),
        _dataset_contract_guidance(context),
        f"Preferred slice focus: {focus_hint}" if focus_hint else "",
        "Target-specific hint: infer the likely format from entrypoints, function names, strings, imports, runtime observations, and any provided dictionary/options snippets.",
        "Return only Python code with gen_*() -> bytes functions.",
        "Response format contract: every generated function must look like def gen_name() -> bytes: and the response must contain nothing except Python source code.",
    ]
    if previous_error:
        user_sections.append(f"Previous generation failed because: {previous_error}")
        user_sections.append("Correct the issue and return only Python code.")
    return [
        {"role": "system", "content": [{"type": "text", "text": SYSTEM_PROMPT}]},
        {"role": "user", "content": [{"type": "text", "text": "\n\n".join(user_sections)}]},
    ]


def build_binary_seed_repair_messages(
    *,
    binary_target_name: str,
    context: BinarySeedContext,
    task_mode: str,
    broken_response: str,
    parse_error: str,
) -> list[dict]:
    slice_payload = {
        "binary_target_name": binary_target_name,
        "selected_target_function": context.binary_slice.selected_target_function,
        "input_mode": context.binary_slice.input_mode,
        "launcher_semantics_source": context.binary_slice.launcher_semantics_source,
        "dataset_contract_hints": context.summary.get("dataset_contract_hints", []),
    }
    repair_sections = [
        f"Target mode: binary ({task_mode})",
        "Your previous response was almost correct semantically, but invalid as Python source.",
        f"Parse error: {parse_error}",
        "Repair the code instead of inventing a new long explanation.",
        "Keep 3 to 6 gen_*() -> bytes functions.",
        "Every function must return bytes and include the -> bytes annotation.",
        "Honor the same input contract hints as before.",
        json.dumps(slice_payload, indent=2)[:1200],
        _dataset_contract_guidance(context),
        "Broken code to repair:",
        broken_response[:3500],
        "Return only corrected Python source code.",
    ]
    return [
        {"role": "system", "content": [{"type": "text", "text": SYSTEM_PROMPT}]},
        {"role": "user", "content": [{"type": "text", "text": "\n\n".join(section for section in repair_sections if section)}]},
    ]

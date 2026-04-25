from __future__ import annotations

import re
from pathlib import Path
from typing import Any


FUNCTION_PATTERN = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s\*\(\),]*?\s+)?([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
    re.MULTILINE,
)
CALL_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
STRUCT_PATTERN = re.compile(r"^\s*(typedef\s+)?struct\s+([A-Za-z_]\w*)?", re.MULTILINE)
ENUM_PATTERN = re.compile(r"^\s*(typedef\s+)?enum\s+([A-Za-z_]\w*)?", re.MULTILINE)
DEFINE_PATTERN = re.compile(r"^\s*#define\s+([A-Za-z_]\w*)\b(.*)$", re.MULTILINE)
CONST_PATTERN = re.compile(
    r"^\s*(?:static\s+)?(?:const|constexpr)\s+[A-Za-z_][\w\s\*]*\s+([A-Za-z_]\w*)\s*=\s*(.+?);$",
    re.MULTILINE,
)
CONTROL_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch"}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _extract_balanced_block(text: str, start_offset: int) -> tuple[str, int]:
    brace_depth = 0
    started = False
    for index in range(start_offset, len(text)):
        char = text[index]
        if char == "{":
            brace_depth += 1
            started = True
        elif char == "}":
            brace_depth -= 1
            if started and brace_depth <= 0:
                return text[start_offset : index + 1], index + 1
    return text[start_offset:], len(text)


def _snippet(text: str, start: int, end: int, limit: int = 1200) -> str:
    return text[start : min(end, start + limit)]


def _is_test_noise(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.startswith("test_")
        or lowered.startswith("_test")
        or lowered.endswith("_test")
        or lowered.endswith("test_")
    )


def _calls_from_body(body: str, known_function_names: set[str], caller_name: str) -> list[str]:
    calls: list[str] = []
    seen: set[str] = set()
    for name in CALL_PATTERN.findall(body):
        if (
            name in CONTROL_KEYWORDS
            or name not in known_function_names
            or name in seen
            or name == caller_name
            or _is_test_noise(name)
        ):
            continue
        seen.add(name)
        calls.append(name)
    return calls


def extract_function_facts(source_files: list[Path]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_functions: list[dict[str, Any]] = []
    for source_file in source_files:
        text = _read_text(source_file)
        if not text:
            continue
        for match in FUNCTION_PATTERN.finditer(text):
            name = match.group(1)
            if name in CONTROL_KEYWORDS:
                continue
            block, end_offset = _extract_balanced_block(text, match.start())
            raw_functions.append(
                {
                    "name": name,
                    "file": str(source_file),
                    "line": _line_number(text, match.start()),
                    "signature": text[match.start() : text.find("{", match.start())].strip(),
                    "snippet": _snippet(text, match.start(), end_offset),
                    "body_excerpt": block[:2000],
                    "harness_related": any(part in {"fuzz", "fuzzing"} for part in source_file.parts),
                },
            )

    known_names = {item["name"] for item in raw_functions}
    functions: list[dict[str, Any]] = []
    for item in raw_functions:
        caller_name = str(item.get("name") or "")
        calls = _calls_from_body(
            str(item.get("body_excerpt") or ""),
            known_names,
            caller_name,
        )
        functions.append({**item, "callees": calls})

    callers: dict[str, list[str]] = {item["name"]: [] for item in functions}
    for item in functions:
        caller_name = item["name"]
        for callee in item.get("callees", []):
            callers.setdefault(callee, [])
            if caller_name not in callers[callee]:
                callers[callee].append(caller_name)

    for item in functions:
        item["callers"] = callers.get(item["name"], [])

    call_graph = {
        item["name"]: {
            "file": item["file"],
            "line": item["line"],
            "callers": item.get("callers", []),
            "callees": item.get("callees", []),
        }
        for item in functions
    }
    return functions, call_graph


def extract_type_facts(source_files: list[Path]) -> list[dict[str, Any]]:
    type_facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int]] = set()
    for source_file in source_files:
        text = _read_text(source_file)
        if not text:
            continue

        for pattern, kind in (
            (STRUCT_PATTERN, "struct"),
            (ENUM_PATTERN, "enum"),
            (DEFINE_PATTERN, "macro"),
            (CONST_PATTERN, "constant"),
        ):
            for match in pattern.finditer(text):
                name = (match.group(2) if kind in {"struct", "enum"} else match.group(1) if match.lastindex else None) or "<anonymous>"
                line = _line_number(text, match.start())
                key = (kind, name, str(source_file), line)
                if key in seen:
                    continue
                seen.add(key)
                snippet_end = text.find("\n", match.end())
                if snippet_end == -1:
                    snippet_end = len(text)
                value = match.group(2).strip() if kind == "constant" and match.lastindex and match.lastindex >= 2 else None
                type_facts.append(
                    {
                        "name": name,
                        "kind": kind,
                        "file": str(source_file),
                        "line": line,
                        "snippet": _snippet(text, match.start(), snippet_end + 1, limit=400),
                        "value": value,
                    },
                )
    return type_facts

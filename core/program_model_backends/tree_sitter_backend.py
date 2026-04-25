from __future__ import annotations

import json
from pathlib import Path
from typing import Any

LANGUAGE_BY_SUFFIX = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
}
PARSER_TOKENS = (
    "parse",
    "read",
    "load",
    "decode",
    "print",
    "value",
    "buffer",
    "line",
    "section",
    "key",
    "object",
    "array",
    "string",
    "stream",
)

try:  # pragma: no cover - runtime capability
    from tree_sitter_language_pack import get_parser
except Exception as exc:  # pragma: no cover - runtime capability
    get_parser = None
    TREE_SITTER_IMPORT_ERROR = str(exc)
else:  # pragma: no cover - runtime capability
    TREE_SITTER_IMPORT_ERROR = None


def _iter_nodes(root: Any) -> list[Any]:
    stack = [root]
    ordered: list[Any] = []
    while stack:
        node = stack.pop()
        ordered.append(node)
        stack.extend(reversed(list(getattr(node, "children", []) or [])))
    return ordered


def _node_text(node: Any, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _first_named(node: Any, kinds: set[str]) -> Any | None:
    for candidate in _iter_nodes(node):
        if getattr(candidate, "type", None) in kinds:
            return candidate
    return None


def _all_named(node: Any, kinds: set[str]) -> list[Any]:
    return [candidate for candidate in _iter_nodes(node) if getattr(candidate, "type", None) in kinds]


def _language_for_path(path: Path) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def _type_names_from_facts(type_facts: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for fact in type_facts:
        name = str(fact.get("name") or "")
        if name and name != "<anonymous>":
            names.add(name)
    return names


def _extract_function_record(
    *,
    node: Any,
    source_bytes: bytes,
    source_file: Path,
    known_type_names: set[str],
) -> dict[str, Any] | None:
    declarator = getattr(node, "child_by_field_name", lambda _name: None)("declarator") or node
    body = getattr(node, "child_by_field_name", lambda _name: None)("body")
    name_node = _first_named(
        declarator,
        {"identifier", "field_identifier", "qualified_identifier"},
    )
    if name_node is None:
        return None
    function_name = _node_text(name_node, source_bytes).split("::")[-1].strip()
    if not function_name:
        return None
    snippet = _node_text(node, source_bytes)
    call_nodes = _all_named(node, {"call_expression"})
    call_names: list[str] = []
    for call_node in call_nodes:
        function_child = getattr(call_node, "child_by_field_name", lambda _name: None)("function") or call_node
        target = _first_named(function_child, {"identifier", "field_identifier", "qualified_identifier"})
        if target is None:
            continue
        called_name = _node_text(target, source_bytes).split("::")[-1].strip()
        if called_name and called_name not in call_names:
            call_names.append(called_name)
    identifiers = [_node_text(item, source_bytes) for item in _all_named(node, {"identifier", "type_identifier"})]
    type_refs = [name for name in identifiers if name in known_type_names]
    lowered = function_name.lower()
    parser_tokens = [token for token in PARSER_TOKENS if token in lowered]
    if body is not None:
        body_text = _node_text(body, source_bytes).lower()
        for token in PARSER_TOKENS:
            if token in body_text and token not in parser_tokens:
                parser_tokens.append(token)
    return {
        "name": function_name,
        "file": str(source_file),
        "line": int(getattr(node, "start_point", (0, 0))[0]) + 1,
        "body_line": int(getattr(body, "start_point", (0, 0))[0]) + 1 if body is not None else None,
        "call_names": call_names,
        "call_count": len(call_names),
        "type_refs": sorted(set(type_refs)),
        "type_ref_count": len(set(type_refs)),
        "parser_tokens": parser_tokens,
        "parser_adjacent": bool(parser_tokens or type_refs),
        "query_backend": "tree_sitter",
        "snippet": snippet[:2000],
    }


def _extract_type_records(*, root: Any, source_bytes: bytes, source_file: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for node in _iter_nodes(root):
        node_type = getattr(node, "type", "")
        if node_type not in {
            "struct_specifier",
            "union_specifier",
            "enum_specifier",
            "type_definition",
            "preproc_def",
            "preproc_function_def",
            "class_specifier",
        }:
            continue
        name_node = _first_named(node, {"type_identifier", "identifier"})
        if name_node is None:
            continue
        name = _node_text(name_node, source_bytes).strip()
        if not name:
            continue
        line = int(getattr(node, "start_point", (0, 0))[0]) + 1
        key = (name, line)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "name": name,
                "kind": node_type,
                "file": str(source_file),
                "line": line,
                "query_backend": "tree_sitter",
                "snippet": _node_text(node, source_bytes)[:1200],
            },
        )
    return records


def analyze_tree_sitter_index(
    *,
    source_files: list[Path],
    function_facts: list[dict[str, Any]],
    type_facts: list[dict[str, Any]],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tree_sitter_available": False,
        "import_error": TREE_SITTER_IMPORT_ERROR,
        "files_considered": len(source_files),
        "files_parsed": 0,
        "languages_seen": [],
        "typed_query_results": {
            "functions": {},
            "parser_adjacent_candidates": [],
            "types": [],
        },
    }
    if get_parser is None:
        return payload

    known_type_names = _type_names_from_facts(type_facts)
    functions_by_name: dict[str, dict[str, Any]] = {}
    types: list[dict[str, Any]] = []
    languages_seen: set[str] = set()
    parse_failures: list[dict[str, Any]] = []

    for source_file in source_files:
        language = _language_for_path(source_file)
        if language is None:
            continue
        try:
            parser = get_parser(language)
        except Exception as exc:  # pragma: no cover - runtime capability
            parse_failures.append({"file": str(source_file), "language": language, "error": str(exc)})
            continue
        source_bytes = source_file.read_bytes()
        try:
            tree = parser.parse(source_bytes)
        except Exception as exc:  # pragma: no cover - runtime capability
            parse_failures.append({"file": str(source_file), "language": language, "error": str(exc)})
            continue
        languages_seen.add(language)
        payload["files_parsed"] += 1
        root = getattr(tree, "root_node", None)
        if root is None:
            continue
        for node in _iter_nodes(root):
            if getattr(node, "type", "") != "function_definition":
                continue
            record = _extract_function_record(
                node=node,
                source_bytes=source_bytes,
                source_file=source_file,
                known_type_names=known_type_names,
            )
            if record is None:
                continue
            existing = functions_by_name.get(record["name"])
            if existing is None or (
                record["parser_adjacent"]
                and not existing.get("parser_adjacent")
            ):
                functions_by_name[record["name"]] = record
        types.extend(_extract_type_records(root=root, source_bytes=source_bytes, source_file=source_file))

    sample_function_names = {
        str(item.get("name"))
        for item in function_facts
        if item.get("name")
    }
    typed_functions = {
        name: record
        for name, record in functions_by_name.items()
        if name in sample_function_names or record.get("parser_adjacent")
    }
    parser_adjacent_candidates = sorted(
        typed_functions.values(),
        key=lambda item: (item.get("type_ref_count", 0), item.get("call_count", 0), len(item.get("parser_tokens", []))),
        reverse=True,
    )[:24]

    payload.update(
        {
            "tree_sitter_available": True,
            "import_error": None,
            "languages_seen": sorted(languages_seen),
            "parse_failures": parse_failures,
            "function_record_count": len(typed_functions),
            "type_record_count": len(types),
            "typed_query_results": {
                "functions": typed_functions,
                "parser_adjacent_candidates": parser_adjacent_candidates,
                "types": types[:64],
            },
        },
    )
    return payload


def write_tree_sitter_manifests(
    *,
    task_id: str,
    generated_at: str,
    source_files: list[Path],
    function_facts: list[dict[str, Any]],
    type_facts: list[dict[str, Any]],
    tree_sitter_backend_manifest_path: Path,
    typed_query_results_path: Path,
) -> dict[str, Any]:
    payload = analyze_tree_sitter_index(
        source_files=source_files,
        function_facts=function_facts,
        type_facts=type_facts,
    )
    backend_payload = {
        "task_id": task_id,
        "generated_at": generated_at,
        "tree_sitter_available": payload.get("tree_sitter_available", False),
        "languages_seen": payload.get("languages_seen", []),
        "files_considered": payload.get("files_considered"),
        "files_parsed": payload.get("files_parsed"),
        "function_record_count": payload.get("function_record_count", 0),
        "type_record_count": payload.get("type_record_count", 0),
        "parse_failures": payload.get("parse_failures", []),
        "import_error": payload.get("import_error"),
    }
    tree_sitter_backend_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tree_sitter_backend_manifest_path.write_text(json.dumps(backend_payload, indent=2), encoding="utf-8")
    typed_payload = {
        "task_id": task_id,
        "generated_at": generated_at,
        "typed_query_results": payload.get("typed_query_results", {}),
    }
    typed_query_results_path.parent.mkdir(parents=True, exist_ok=True)
    typed_query_results_path.write_text(json.dumps(typed_payload, indent=2), encoding="utf-8")
    return {
        **backend_payload,
        "tree_sitter_backend_manifest_path": str(tree_sitter_backend_manifest_path),
        "typed_query_results_path": str(typed_query_results_path),
        "typed_query_results": payload.get("typed_query_results", {}),
    }

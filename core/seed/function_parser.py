from __future__ import annotations

import ast
import re

from core.seed.models import ParsedSeedModule

CODE_BLOCK_PATTERN = re.compile(r"```(?:python)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
GEN_DEF_WITHOUT_RETURN_PATTERN = re.compile(r"^(\s*def\s+gen_[A-Za-z0-9_]+\s*\([^)]*\))\s*:\s*$", re.MULTILINE)
BANNED_NAME_NODES = {"open", "exec", "eval", "compile", "__import__", "input", "breakpoint"}
BANNED_ATTR_BASES = {"os", "subprocess", "socket", "pathlib", "sys", "requests", "urllib"}


class SeedParseError(RuntimeError):
    def __init__(self, message: str, metadata: dict[str, object]) -> None:
        super().__init__(message)
        self.metadata = metadata


def _extract_code(raw_text: str) -> str:
    match = CODE_BLOCK_PATTERN.search(raw_text)
    if match:
        return match.group(1).strip()
    return raw_text.strip()


def _repair_code(code: str) -> tuple[str, str | None]:
    repaired = code
    repair_notes: list[str] = []

    first_def = re.search(r"^\s*def\s+gen_[A-Za-z0-9_]+\s*\(", repaired, re.MULTILINE)
    if first_def and first_def.start() > 0:
        repaired = repaired[first_def.start() :].lstrip()
        repair_notes.append("trimmed leading non-code prose")

    updated = GEN_DEF_WITHOUT_RETURN_PATTERN.sub(r"\1 -> bytes:", repaired)
    if updated != repaired:
        repaired = updated
        repair_notes.append("added missing -> bytes annotations")

    return repaired, "; ".join(repair_notes) if repair_notes else None


def _validate_ast(tree: ast.Module) -> list[str]:
    errors: list[str] = []
    function_names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            errors.append("imports are not allowed")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in BANNED_NAME_NODES:
            errors.append(f"banned call: {node.func.id}")
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in BANNED_ATTR_BASES:
            errors.append(f"banned attribute access: {node.value.id}")
        if isinstance(node, ast.FunctionDef):
            if not node.name.startswith("gen_"):
                continue
            function_names.append(node.name)
            if not isinstance(node.returns, ast.Name) or node.returns.id != "bytes":
                errors.append(f"function {node.name} must annotate return type as bytes")

    if not function_names:
        errors.append("no gen_* functions found")
    return errors


def parse_seed_module(raw_text: str) -> ParsedSeedModule:
    code = _extract_code(raw_text)
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise RuntimeError(f"generated code is not valid Python: {exc}") from exc

    errors = _validate_ast(tree)
    if errors:
        raise RuntimeError("; ".join(sorted(set(errors))))

    function_names = [node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("gen_")]
    return ParsedSeedModule(code=code, function_names=function_names)


def parse_seed_module_with_repair(raw_text: str) -> tuple[ParsedSeedModule, dict[str, object]]:
    code = _extract_code(raw_text)
    metadata = {
        "first_response_status": "empty" if not code.strip() else "received",
        "parser_first_pass_success": False,
        "parser_repair_attempted": False,
        "parser_final_success": False,
        "parse_failure_reason": None,
    }
    try:
        parsed = parse_seed_module(code)
        metadata["parser_first_pass_success"] = True
        metadata["parser_final_success"] = True
        return parsed, metadata
    except Exception as exc:
        metadata["parse_failure_reason"] = str(exc)
        repaired_code, repair_note = _repair_code(code)
        if repaired_code == code:
            raise SeedParseError(str(exc), metadata) from exc
        metadata["parser_repair_attempted"] = True
        try:
            parsed = parse_seed_module(repaired_code)
            metadata["parser_final_success"] = True
            if repair_note:
                metadata["parse_failure_reason"] = f"{metadata['parse_failure_reason']} | repaired: {repair_note}"
            return parsed, metadata
        except Exception as repair_exc:
            metadata["parse_failure_reason"] = str(repair_exc)
            raise SeedParseError(str(repair_exc), metadata) from repair_exc

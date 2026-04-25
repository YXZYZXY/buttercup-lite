from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.binary.importer import load_imported_analysis
from core.binary.mcp_client import invoke_ida_mcp
from core.binary.models import BinaryAnalysisBackend, BinaryAnalysisRequest, BinaryAnalysisResult, BinaryToolResult
from core.binary.manifest import write_json
from core.storage.layout import (
    binary_analysis_manifest_path,
    binary_analysis_summary_path,
    binary_entrypoints_path,
    binary_exports_path,
    binary_functions_path,
    binary_imports_path,
    binary_manifest_path,
    binary_strings_path,
)
from core.utils.settings import settings


def _tool_available(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run_command(command: list[str], *, timeout: int) -> BinaryToolResult:
    if not command:
        return BinaryToolResult(command=[], return_code=127, stderr="empty command", available=False)
    if not _tool_available(command[0]):
        return BinaryToolResult(command=command, return_code=127, stderr="tool not available", available=False)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return BinaryToolResult(
            command=command,
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            available=True,
        )
    except subprocess.TimeoutExpired as exc:
        return BinaryToolResult(
            command=command,
            return_code=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
            available=True,
        )


def _parse_entrypoint(readelf_stdout: str) -> dict[str, Any] | None:
    for line in readelf_stdout.splitlines():
        if "Entry point address:" in line:
            value = line.split(":", 1)[1].strip()
            return {"name": "_start", "address": value, "source": "readelf -hW"}
    return None


def _parse_header_fields(readelf_stdout: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for line in readelf_stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key == "Class":
            fields["elf_class"] = value
        elif key == "Machine":
            fields["architecture"] = value
        elif key == "Type":
            fields["elf_type"] = value
        elif key == "Entry point address":
            fields["entrypoint_address"] = value
    return fields


def _parse_nm_functions(stdout: str) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) != 3:
            continue
        address, symbol_type, name = parts
        if symbol_type not in {"T", "t", "W", "w"}:
            continue
        functions.append(
            {
                "name": name,
                "address": f"0x{address.lstrip('0') or '0'}",
                "symbol_type": symbol_type,
                "source": "nm -n --defined-only",
            }
        )
        if len(functions) >= settings.binary_functions_limit:
            break
    return functions


def _parse_strings(stdout: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    items: list[dict[str, Any]] = []
    for raw in stdout.splitlines():
        value = raw.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        items.append({"value": value, "source": "strings -a -n 4"})
        if len(items) >= settings.binary_strings_limit:
            break
    return items


def _parse_symbols(stdout: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    imports: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Symbol table") or line.startswith("Num:"):
            continue
        parts = line.split(maxsplit=7)
        if len(parts) < 8:
            continue
        num, value, size, symbol_type, bind, vis, ndx = parts[:7]
        if not num.endswith(":"):
            continue
        name = parts[7]
        record = {
            "name": name,
            "value": value,
            "size": size,
            "symbol_type": symbol_type,
            "bind": bind,
            "visibility": vis,
            "section": ndx,
            "source": "readelf -Ws",
        }
        if ndx == "UND":
            imports.append(record)
        else:
            exports.append(record)
    return imports, exports


def _normalize_from_payload(
    request: BinaryAnalysisRequest,
    payload: dict[str, Any],
    *,
    backend: BinaryAnalysisBackend,
    tool_runs: dict[str, Any] | None = None,
) -> BinaryAnalysisResult:
    summary = payload.get("summary") or payload.get("analysis_summary") or {}
    manifest = payload.get("manifest") or {}
    functions = payload.get("functions") or []
    strings = payload.get("strings") or []
    imports = payload.get("imports") or []
    exports = payload.get("exports") or []
    entrypoints = payload.get("entrypoints") or []

    summary.setdefault("task_id", request.task_id)
    summary.setdefault("backend", backend.value)
    summary.setdefault("binary_path", str(request.binary_path))
    summary.setdefault("binary_name", request.binary_name)
    summary.setdefault("function_count", len(functions))
    summary.setdefault("string_count", len(strings))
    summary.setdefault("import_count", len(imports))
    summary.setdefault("export_count", len(exports))
    summary.setdefault("entrypoint_count", len(entrypoints))
    if tool_runs is not None:
        summary["tool_runs"] = tool_runs

    artifact_paths = {
        "binary_manifest.json": str(binary_manifest_path(request.task_id)),
        "analysis_summary.json": str(binary_analysis_summary_path(request.task_id)),
        "functions.json": str(binary_functions_path(request.task_id)),
        "strings.json": str(binary_strings_path(request.task_id)),
        "imports.json": str(binary_imports_path(request.task_id)),
        "exports.json": str(binary_exports_path(request.task_id)),
        "entrypoints.json": str(binary_entrypoints_path(request.task_id)),
        "binary_analysis_manifest.json": str(binary_analysis_manifest_path(request.task_id)),
    }
    manifest.update(
        {
            "task_id": request.task_id,
            "backend": backend.value,
            "binary_path": str(request.binary_path),
            "binary_name": request.binary_name,
            "artifacts": artifact_paths,
            "summary": {
                "function_count": len(functions),
                "string_count": len(strings),
                "import_count": len(imports),
                "export_count": len(exports),
                "entrypoint_count": len(entrypoints),
            },
        }
    )
    return BinaryAnalysisResult(
        backend=backend,
        manifest=manifest,
        summary=summary,
        functions=functions,
        strings=strings,
        imports=imports,
        exports=exports,
        entrypoints=entrypoints,
    )


def _analyze_with_wrapper_command(request: BinaryAnalysisRequest) -> BinaryAnalysisResult | None:
    command_prefix: list[str] | None = None
    if request.launcher_path and request.launcher_path.exists():
        command_prefix = [str(request.launcher_path)]
        if request.wrapper_path and request.wrapper_path.exists():
            command_prefix.append(str(request.wrapper_path))
    elif request.wrapper_path and request.wrapper_path.exists():
        command_prefix = [str(request.wrapper_path)]
    if not command_prefix:
        return None

    tool_result = _run_command(
        command_prefix + [str(request.binary_path), str(request.output_dir)],
        timeout=settings.binary_wrapper_timeout_seconds,
    )
    if tool_result.return_code != 0:
        raise RuntimeError(f"wrapper script failed with exit code {tool_result.return_code}")

    payload: dict[str, Any]
    stdout = tool_result.stdout.strip()
    if stdout:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = {}
    else:
        payload = {}
    if request.output_dir.exists():
        payload = {**load_imported_analysis(request.output_dir), **payload}
    payload.setdefault("manifest", {})
    payload["manifest"].update(
        {
            "mode": "generated",
            "selected_backend": BinaryAnalysisBackend.WRAPPER_SCRIPT.value,
            "wrapper_command": tool_result.command,
        }
    )
    return _normalize_from_payload(
        request,
        payload,
        backend=BinaryAnalysisBackend.WRAPPER_SCRIPT,
        tool_runs={"wrapper_script": tool_result.model_dump(mode="json")},
    )


def _write_outputs(request: BinaryAnalysisRequest, result: BinaryAnalysisResult) -> BinaryAnalysisResult:
    runtime_manifest = {
        **result.manifest,
        "analysis_summary_path": str(binary_analysis_summary_path(request.task_id)),
        "generated_outputs": {
            "functions": str(binary_functions_path(request.task_id)),
            "strings": str(binary_strings_path(request.task_id)),
            "imports": str(binary_imports_path(request.task_id)),
            "exports": str(binary_exports_path(request.task_id)),
            "entrypoints": str(binary_entrypoints_path(request.task_id)),
        },
    }
    write_json(binary_manifest_path(request.task_id), result.manifest)
    write_json(binary_analysis_summary_path(request.task_id), result.summary)
    write_json(binary_functions_path(request.task_id), result.functions)
    write_json(binary_strings_path(request.task_id), result.strings)
    write_json(binary_imports_path(request.task_id), result.imports)
    write_json(binary_exports_path(request.task_id), result.exports)
    write_json(binary_entrypoints_path(request.task_id), result.entrypoints)
    write_json(binary_analysis_manifest_path(request.task_id), runtime_manifest)
    result.manifest = runtime_manifest
    return result


def _analyze_with_wrapper(request: BinaryAnalysisRequest) -> BinaryAnalysisResult:
    scripted = _analyze_with_wrapper_command(request)
    if scripted is not None:
        return scripted
    tool_runs = {
        "file": _run_command(["file", str(request.binary_path)], timeout=settings.binary_wrapper_timeout_seconds),
        "readelf_header": _run_command(["readelf", "-hW", str(request.binary_path)], timeout=settings.binary_wrapper_timeout_seconds),
        "readelf_symbols": _run_command(["readelf", "-Ws", str(request.binary_path)], timeout=settings.binary_wrapper_timeout_seconds),
        "nm_defined": _run_command(
            ["nm", "-n", "--defined-only", str(request.binary_path)],
            timeout=settings.binary_wrapper_timeout_seconds,
        ),
        "strings": _run_command(
            ["strings", "-a", "-n", "4", str(request.binary_path)],
            timeout=settings.binary_wrapper_timeout_seconds,
        ),
        "objdump_headers": _run_command(
            ["objdump", "-f", str(request.binary_path)],
            timeout=settings.binary_wrapper_timeout_seconds,
        ),
    }
    functions = _parse_nm_functions(tool_runs["nm_defined"].stdout) if tool_runs["nm_defined"].return_code == 0 else []
    strings = _parse_strings(tool_runs["strings"].stdout) if tool_runs["strings"].return_code == 0 else []
    imports, exports = (
        _parse_symbols(tool_runs["readelf_symbols"].stdout)
        if tool_runs["readelf_symbols"].return_code == 0
        else ([], [])
    )
    entrypoints = []
    entrypoint = _parse_entrypoint(tool_runs["readelf_header"].stdout)
    if entrypoint is not None:
        entrypoints.append(entrypoint)
    if not any(item["name"] == "main" for item in entrypoints):
        main_matches = [item for item in functions if item["name"] == "main"]
        entrypoints.extend({"name": "main", "address": item["address"], "source": "nm"} for item in main_matches[:1])

    payload = {
        "manifest": {
            "mode": "generated",
            "requested_backend": request.backend.value,
            "selected_backend": BinaryAnalysisBackend.WRAPPER_SCRIPT.value,
        },
        "analysis_summary": {
            "file_description": tool_runs["file"].stdout.strip(),
            "objdump_header": tool_runs["objdump_headers"].stdout.strip().splitlines()[:8],
            **_parse_header_fields(tool_runs["readelf_header"].stdout),
            "tool_runs": {
                name: item.model_dump(mode="json")
                for name, item in tool_runs.items()
            },
        },
        "functions": functions,
        "strings": strings,
        "imports": imports,
        "exports": exports,
        "entrypoints": entrypoints,
    }
    return _normalize_from_payload(
        request,
        payload,
        backend=BinaryAnalysisBackend.WRAPPER_SCRIPT,
        tool_runs={name: item.model_dump(mode="json") for name, item in tool_runs.items()},
    )


def _analyze_imported(request: BinaryAnalysisRequest) -> BinaryAnalysisResult:
    if request.imported_analysis_path is None:
        raise RuntimeError("imported_analysis backend requires existing_binary_analysis_path")
    payload = load_imported_analysis(request.imported_analysis_path)
    if not payload.get("summary"):
        payload["summary"] = {
            "task_id": request.task_id,
            "backend": BinaryAnalysisBackend.IMPORTED_ANALYSIS.value,
            "binary_path": str(request.binary_path),
            "binary_name": request.binary_name,
            "imported_from": str(request.imported_analysis_path),
        }
    payload.setdefault("manifest", {})
    payload["manifest"].update(
        {
            "mode": "imported",
            "imported_from": str(request.imported_analysis_path),
        }
    )
    return _normalize_from_payload(request, payload, backend=BinaryAnalysisBackend.IMPORTED_ANALYSIS)


def _analyze_ida_mcp(request: BinaryAnalysisRequest) -> BinaryAnalysisResult:
    payload, tool_result = invoke_ida_mcp(request.binary_path, request.output_dir)
    if request.output_dir.exists():
        payload = {**load_imported_analysis(request.output_dir), **payload}
    if not payload:
        payload = {"summary": {"ida_mcp_stdout": tool_result.stdout}}
    payload.setdefault("manifest", {})
    payload["manifest"].update(
        {
            "mode": "generated",
            "selected_backend": BinaryAnalysisBackend.IDA_MCP.value,
            "ida_mcp_command": tool_result.command,
        }
    )
    payload.setdefault("analysis_summary", payload.get("summary") or {})
    payload["analysis_summary"]["tool_runs"] = {"ida_mcp": tool_result.model_dump(mode="json")}
    return _normalize_from_payload(
        request,
        payload,
        backend=BinaryAnalysisBackend.IDA_MCP,
        tool_runs={"ida_mcp": tool_result.model_dump(mode="json")},
    )


def run_binary_analysis(request: BinaryAnalysisRequest) -> BinaryAnalysisResult:
    selected_backend = request.backend
    fallback_used = False
    fallback_reason: str | None = None

    try:
        if request.backend == BinaryAnalysisBackend.IMPORTED_ANALYSIS:
            result = _analyze_imported(request)
        elif request.backend == BinaryAnalysisBackend.IDA_MCP:
            result = _analyze_ida_mcp(request)
        else:
            result = _analyze_with_wrapper(request)
    except Exception as exc:
        if request.backend != BinaryAnalysisBackend.IDA_MCP:
            raise
        fallback_used = True
        fallback_reason = str(exc)
        selected_backend = BinaryAnalysisBackend.WRAPPER_SCRIPT
        result = _analyze_with_wrapper(request)

    result.manifest.update(
        {
            "requested_backend": request.backend.value,
            "selected_backend": selected_backend.value,
            "fallback_used": fallback_used,
            "fallback_reason": fallback_reason,
        }
    )
    result.summary.update(
        {
            "requested_backend": request.backend.value,
            "selected_backend": selected_backend.value,
            "fallback_used": fallback_used,
            "fallback_reason": fallback_reason,
        }
    )
    return _write_outputs(request, result)

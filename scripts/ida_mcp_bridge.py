#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path


def _candidate_ida_dirs() -> list[Path]:
    candidates = []
    explicit = os.environ.get("IDA_INSTALL_DIR") or os.environ.get("IDADIR")
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            Path("/app/ida_pro"),
            Path("/home/buttercup2/Project/buttercup-lite/ida_pro"),
        ]
    )
    return candidates


def _find_ida_dir() -> Path:
    for candidate in _candidate_ida_dirs():
        if (candidate / "idalib" / "python" / "idapro").exists():
            return candidate
    raise RuntimeError("could not locate IDA installation with idalib/python/idapro")


def _prepare_ida_user_dir(runtime_dir: Path) -> Path:
    idausr = runtime_dir / "idausr"
    idausr.mkdir(parents=True, exist_ok=True)
    host_reg_candidates = [
        Path(os.environ.get("IDA_HOST_REG_PATH", "")),
        Path("/home/buttercup2/.idapro/ida.reg"),
        Path.home() / ".idapro" / "ida.reg",
    ]
    for candidate in host_reg_candidates:
        if not str(candidate):
            continue
        if candidate.exists() and candidate.is_file():
            destination = idausr / "ida.reg"
            try:
                shutil.copy2(candidate, destination)
            except PermissionError:
                destination.unlink(missing_ok=True)
                shutil.copy2(candidate, destination)
            break
    return idausr


def _hex(value: int | None) -> str | None:
    if value is None:
        return None
    return hex(value)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _looks_like_parser_function(name: str) -> bool:
    lowered = name.lower()
    return any(
        token in lowered
        for token in (
            "parse",
            "read",
            "load",
            "scan",
            "decode",
            "print",
            "json",
            "xml",
            "ini",
            "yaml",
            "plist",
            "zip",
            "config",
            "stream",
        )
    )


def _infer_contract(
    *,
    imports: list[dict[str, object]],
    strings: list[dict[str, object]],
    functions: list[dict[str, object]],
) -> dict[str, object]:
    import_names = {str(item.get("name") or "").lower() for item in imports}
    string_values = [str(item.get("value") or "").lower() for item in strings[:500]]
    usage_lines = [text for text in string_values if "usage" in text or "stdin" in text or "--" in text][:24]
    function_names = {str(item.get("name") or "").lower() for item in functions[:5000]}

    has_file_io = any(name for name in import_names if any(token in name for token in ("fopen", "open", "read", "fread", "getline")))
    has_stdin_io = any(name for name in import_names if any(token in name for token in ("stdin", "getc", "fgets", "scanf", "read")))
    has_argv = any("getopt" in name for name in import_names) or any("argv" in line or "usage:" in line for line in usage_lines)
    has_dir = any(token in " ".join(string_values) for token in ("directory", "folder", "input-dir", "inputs/"))
    libfuzzer_harness = any("llvmfuzzertestoneinput" in name for name in function_names)

    candidates: list[dict[str, object]] = []
    if libfuzzer_harness:
        candidates.append({"input_mode": "argv-file-driven", "confidence": "high", "reason": "LLVMFuzzerTestOneInput symbol indicates libFuzzer replay with argv file input"})
    if has_argv and has_file_io:
        candidates.append({"input_mode": "argv-file-driven", "confidence": "high", "reason": "usage/imports indicate argv + file I/O"})
    if has_stdin_io and not has_file_io:
        candidates.append({"input_mode": "stdin-driven", "confidence": "medium", "reason": "stdio imports without strong file-only evidence"})
    if has_dir:
        candidates.append({"input_mode": "file-drop/input-dir-driven", "confidence": "medium", "reason": "strings reference input directories or folders"})
    if has_argv and not has_file_io:
        candidates.append({"input_mode": "argv-scalar-driven", "confidence": "medium", "reason": "usage/imports indicate argv but not file-only APIs"})
    if has_stdin_io and has_file_io and not any(item["input_mode"] == "argv-file-driven" for item in candidates):
        candidates.append({"input_mode": "mixed", "confidence": "medium", "reason": "stdio and file I/O both appear in imports/strings"})
    if not candidates:
        candidates.append({"input_mode": "unknown", "confidence": "low", "reason": "no strong contract evidence from imports/strings"})

    selected = candidates[0]
    return {
        "selected_input_mode": selected["input_mode"],
        "selected_confidence": selected["confidence"],
        "selected_reason": selected["reason"],
        "usage_lines": usage_lines[:12],
        "candidates": candidates,
        "import_evidence": sorted(name for name in import_names if name)[:64],
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: ida_mcp_bridge.py <binary_path> <output_dir>", file=sys.stderr)
        return 2

    binary_path = Path(sys.argv[1]).resolve()
    output_dir = Path(sys.argv[2]).resolve()
    task_dir = output_dir.parent
    runtime_dir = task_dir / "runtime"
    output_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)

    ida_dir = _find_ida_dir()
    idausr = _prepare_ida_user_dir(runtime_dir)
    os.environ["IDADIR"] = str(ida_dir)
    os.environ["IDAUSR"] = str(idausr)
    os.environ["HOME"] = str(idausr.parent)
    sys.path.insert(0, str(ida_dir / "idalib" / "python"))

    import idapro  # type: ignore
    import ida_auto  # type: ignore
    import ida_entry  # type: ignore
    import ida_funcs  # type: ignore
    import ida_ida  # type: ignore
    import ida_idaapi  # type: ignore
    import ida_nalt  # type: ignore
    import idautils  # type: ignore

    functions: list[dict[str, object]] = []
    strings: list[dict[str, object]] = []
    imports: list[dict[str, object]] = []
    exports: list[dict[str, object]] = []
    entrypoints: list[dict[str, object]] = []
    callgraph_edges: list[dict[str, object]] = []
    string_refs: dict[str, list[str]] = {}

    try:
        idapro.enable_console_messages(False)
        result = idapro.open_database(str(binary_path), True)
        if result != 0:
            raise RuntimeError(f"idapro.open_database returned {result}")
        ida_auto.auto_wait()

        function_limit = int(os.environ.get("BINARY_FUNCTIONS_LIMIT", "20000"))
        string_limit = int(os.environ.get("BINARY_STRINGS_LIMIT", "20000"))

        seen_functions: set[int] = set()
        for ea in idautils.Functions():
            if ea in seen_functions:
                continue
            seen_functions.add(ea)
            func = ida_funcs.get_func(ea)
            name = ida_funcs.get_func_name(ea) or f"sub_{ea:x}"
            functions.append(
                {
                    "name": name,
                    "address": _hex(ea),
                    "end_address": _hex(func.end_ea if func else None),
                    "size": (func.end_ea - func.start_ea) if func else None,
                    "source": "ida_funcs",
                }
            )
            if len(functions) >= function_limit:
                break

        string_list = idautils.Strings(default_setup=True)
        for item in string_list:
            value = str(item)
            if not value:
                continue
            ref_functions: list[str] = []
            for xref in idautils.XrefsTo(item.ea):
                func = ida_funcs.get_func(xref.frm)
                if func is None:
                    continue
                ref_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
                if ref_name not in ref_functions:
                    ref_functions.append(ref_name)
                if len(ref_functions) >= 5:
                    break
            strings.append(
                {
                    "value": value,
                    "address": _hex(item.ea),
                    "length": item.length,
                    "referenced_functions": ref_functions,
                    "source": "idautils.Strings",
                }
            )
            if ref_functions:
                string_refs[value] = ref_functions
            if len(strings) >= string_limit:
                break

        max_imports = 10000
        import_module_qty = ida_nalt.get_import_module_qty()
        for index in range(import_module_qty):
            module_name = ida_nalt.get_import_module_name(index) or f"module_{index}"

            def _callback(ea: int, name: str | None, ordinal: int) -> bool:
                imports.append(
                    {
                        "name": name or f"ord_{ordinal}",
                        "address": None if ea == ida_idaapi.BADADDR else _hex(ea),
                        "ordinal": ordinal,
                        "module": module_name,
                        "source": "ida_nalt.enum_import_names",
                    }
                )
                return len(imports) < max_imports

            ida_nalt.enum_import_names(index, _callback)

        for index, ordinal, ea, name in idautils.Entries():
            record = {
                "name": name or f"entry_{ordinal}",
                "ordinal": ordinal,
                "address": _hex(ea),
                "source": "idautils.Entries",
            }
            entrypoints.append(record)
            exports.append(record)

        if not any(item["name"] == "main" for item in entrypoints):
            for function in functions:
                if function["name"] == "main":
                    entrypoints.append(
                        {
                            "name": "main",
                            "ordinal": None,
                            "address": function["address"],
                            "source": "ida_funcs",
                        }
                    )
                    break

        by_start = {
            int(str(item["address"]), 16): str(item["name"])
            for item in functions
            if item.get("address")
        }
        edge_limit = int(os.environ.get("BINARY_CALLGRAPH_EDGE_LIMIT", "20000"))
        seen_edges: set[tuple[str, str]] = set()
        for start_ea, caller_name in by_start.items():
            func = ida_funcs.get_func(start_ea)
            if func is None:
                continue
            for item_ea in idautils.FuncItems(func.start_ea):
                for ref in idautils.CodeRefsFrom(item_ea, False):
                    callee = ida_funcs.get_func(ref)
                    if callee is None:
                        continue
                    callee_name = ida_funcs.get_func_name(callee.start_ea) or f"sub_{callee.start_ea:x}"
                    if callee_name == caller_name:
                        continue
                    key = (caller_name, callee_name)
                    if key in seen_edges:
                        continue
                    seen_edges.add(key)
                    callgraph_edges.append(
                        {
                            "caller": caller_name,
                            "callee": callee_name,
                            "caller_address": _hex(func.start_ea),
                            "callee_address": _hex(callee.start_ea),
                            "source": "idautils.CodeRefsFrom",
                        }
                    )
                    if len(callgraph_edges) >= edge_limit:
                        break
                if len(callgraph_edges) >= edge_limit:
                    break
            if len(callgraph_edges) >= edge_limit:
                break

        callees_by_function: dict[str, list[str]] = {}
        callers_by_function: dict[str, list[str]] = {}
        for edge in callgraph_edges:
            caller = str(edge["caller"])
            callee = str(edge["callee"])
            callees_by_function.setdefault(caller, [])
            callers_by_function.setdefault(callee, [])
            if callee not in callees_by_function[caller]:
                callees_by_function[caller].append(callee)
            if caller not in callers_by_function[callee]:
                callers_by_function[callee].append(caller)

        parser_candidates = [
            {
                "name": item["name"],
                "address": item["address"],
                "reasons": [
                    reason
                    for reason, enabled in (
                        ("parser_like_name", _looks_like_parser_function(str(item["name"]))),
                        ("entrypoint", any(str(entry.get("name")) == str(item["name"]) for entry in entrypoints)),
                        ("string_reference", any(str(item["name"]) in refs for refs in string_refs.values())),
                        ("callgraph_degree", len(callees_by_function.get(str(item["name"]), [])) + len(callers_by_function.get(str(item["name"]), [])) >= 2),
                    )
                    if enabled
                ],
            }
            for item in functions
            if _looks_like_parser_function(str(item["name"]))
            or any(str(entry.get("name")) == str(item["name"]) for entry in entrypoints)
        ][:64]

        contract_inference = _infer_contract(imports=imports, strings=strings, functions=functions)
        capabilities = {
            "provider": "ida_headless_idalib",
            "functions": True,
            "strings": True,
            "imports": True,
            "exports": True,
            "entrypoints": True,
            "callgraph": bool(callgraph_edges),
            "string_xrefs": True,
            "contract_inference": True,
            "pseudo_code": False,
            "decompiler": False,
        }
        task_id = task_dir.name
        artifact_paths = {
            "analysis_summary_path": str(output_dir / "analysis_summary.json"),
            "functions_path": str(output_dir / "functions.json"),
            "strings_path": str(output_dir / "strings.json"),
            "imports_path": str(output_dir / "imports.json"),
            "exports_path": str(output_dir / "exports.json"),
            "entrypoints_path": str(output_dir / "entrypoints.json"),
            "binary_function_inventory_path": str(output_dir / "binary_function_inventory.json"),
            "binary_callgraph_manifest_path": str(output_dir / "binary_callgraph_manifest.json"),
            "binary_contract_inference_manifest_path": str(output_dir / "binary_contract_inference_manifest.json"),
            "ida_backend_capabilities_path": str(output_dir / "ida_backend_capabilities.json"),
            "ida_headless_export_manifest_path": str(output_dir / "ida_headless_export_manifest.json"),
            "ida_integration_manifest_path": str(output_dir / "ida_integration_manifest.json"),
            "ida_to_binary_context_bridge_path": str(output_dir / "ida_to_binary_context_bridge.json"),
        }

        payload = {
            "summary": {
                "backend": "ida_mcp",
                "binary_path": str(binary_path),
                "binary_name": binary_path.name,
                "architecture": ida_ida.inf_get_procname(),
                "bitness": 64 if ida_ida.inf_is_64bit() else 32,
                "entrypoint_address": entrypoints[0]["address"] if entrypoints else None,
                "function_count": len(functions),
                "string_count": len(strings),
                "import_count": len(imports),
                "export_count": len(exports),
                "entrypoint_count": len(entrypoints),
                "ida_user_dir": str(idausr),
                "callgraph_edge_count": len(callgraph_edges),
                "contract_inference": contract_inference["selected_input_mode"],
            },
            "functions": functions,
            "strings": strings,
            "imports": imports,
            "exports": exports,
            "entrypoints": entrypoints,
            "manifest": {
                "mode": "generated",
                "selected_backend": "ida_mcp",
                "task_id": task_id,
                "artifact_paths": artifact_paths,
                "capabilities": capabilities,
            },
        }
        _write_json(output_dir / "analysis_summary.json", payload["summary"])
        _write_json(output_dir / "functions.json", functions)
        _write_json(output_dir / "strings.json", strings)
        _write_json(output_dir / "imports.json", imports)
        _write_json(output_dir / "exports.json", exports)
        _write_json(output_dir / "entrypoints.json", entrypoints)
        _write_json(
            output_dir / "binary_function_inventory.json",
            {
                "task_id": task_id,
                "binary_path": str(binary_path),
                "function_count": len(functions),
                "functions": functions,
                "parser_candidates": parser_candidates,
            },
        )
        _write_json(
            output_dir / "binary_callgraph_manifest.json",
            {
                "task_id": task_id,
                "binary_path": str(binary_path),
                "edge_count": len(callgraph_edges),
                "edges": callgraph_edges,
                "callers_by_function": callers_by_function,
                "callees_by_function": callees_by_function,
            },
        )
        _write_json(
            output_dir / "binary_contract_inference_manifest.json",
            {
                "task_id": task_id,
                "binary_path": str(binary_path),
                **contract_inference,
            },
        )
        _write_json(output_dir / "ida_backend_capabilities.json", capabilities)
        _write_json(
            output_dir / "ida_headless_export_manifest.json",
            {
                "task_id": task_id,
                "binary_path": str(binary_path),
                "ida_dir": str(ida_dir),
                "ida_user_dir": str(idausr),
                "export_mode": "idapro.open_database + idalib python",
                "artifact_paths": artifact_paths,
            },
        )
        _write_json(
            output_dir / "ida_integration_manifest.json",
            {
                "task_id": task_id,
                "provider": "ida_headless_idalib",
                "binary_path": str(binary_path),
                "ida_dir": str(ida_dir),
                "ida_user_dir": str(idausr),
                "capabilities": capabilities,
            },
        )
        _write_json(
            output_dir / "ida_to_binary_context_bridge.json",
            {
                "task_id": task_id,
                "selected_input_mode": contract_inference["selected_input_mode"],
                "entry_candidates": entrypoints[:16],
                "parser_candidates": parser_candidates[:32],
                "string_reference_examples": [
                    {"value": value, "referenced_functions": refs}
                    for value, refs in list(string_refs.items())[:24]
                ],
            },
        )
        print(json.dumps(payload))
        return 0
    finally:
        try:
            idapro.close_database(False)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.utils.settings import load_benchmark_config, resolve_text_setting


def _existing_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if path.exists():
        return path
    return None


def _load_contract_inference(task) -> dict[str, Any]:
    candidate = Path(task.task_dir) / "binary" / "binary_contract_inference_manifest.json"
    if not candidate.exists():
        return {}
    return json.loads(candidate.read_text(encoding="utf-8"))


def _resolve_input_delivery_reference(task) -> Path | None:
    benchmark = load_benchmark_config(task.metadata)
    execution_block = benchmark.get("binary_execution", {})
    binary_mode = str(task.runtime.get("binary_mode") or task.metadata.get("binary_mode") or "")
    configured = execution_block.get("input_delivery_reference") or task.metadata.get("input_delivery_reference")
    if task.metadata.get("binary_input_contract_source") and not configured:
        return None
    resolved_imports = task.runtime.get("resolved_imports", {})
    harness_dir = _existing_path(resolved_imports.get("existing_harness_dir"))
    src_dir = _existing_path(resolved_imports.get("existing_src_path"))

    if configured:
        candidate = Path(str(configured))
        if candidate.is_absolute() and candidate.exists():
            return candidate
        if binary_mode != "pure_binary":
            for root in (harness_dir, src_dir):
                if root is None:
                    continue
                joined = root / candidate
                if joined.exists():
                    return joined

    if binary_mode == "pure_binary":
        return None

    for root in (harness_dir, src_dir):
        if root is None:
            continue
        for relative in ("fuzz_main.c", "afl.c", "fuzzing/fuzz_main.c", "fuzzing/afl.c"):
            candidate = root / relative
            if candidate.exists():
                return candidate
    return None


def _input_contract_kind(input_mode: str, argv_template: list[str], execution_strategy: str) -> tuple[str, list[str]]:
    rendered = " ".join(str(item) for item in argv_template)
    hints: list[str] = []
    if input_mode == "stdin":
        hints.append("input bytes are delivered on stdin")
        return "stdin-driven", hints
    if "{input_path}" in rendered and "input-dir" in execution_strategy:
        hints.append("argv contains an input path and execution strategy references input-dir")
        return "mixed contract", hints
    if "{input_path}" in rendered:
        hints.append("argv template contains {input_path}")
        return "argv-file-driven", hints
    if input_mode in {"argv", "argv-scalar"}:
        hints.append("input value is expected as argv scalar")
        return "argv-scalar-driven", hints
    if input_mode in {"file", "file-drop"}:
        hints.append("input mode is file but argv template does not expose {input_path}")
        return "file-drop/input-dir-driven", hints
    hints.append("no reliable delivery semantics discovered")
    return "unknown contract", hints


def resolve_launcher_binding(task) -> dict[str, Any]:
    benchmark = load_benchmark_config(task.metadata)
    execution_block = benchmark.get("binary_execution", {})
    resolved_imports = task.runtime.get("resolved_imports", {})
    binary_mode = str(task.runtime.get("binary_mode") or task.metadata.get("binary_mode") or "binary_native_proof")
    binary_path = Path(resolved_imports.get("existing_binary_path") or task.source.uri).resolve()
    configured_wrapper = _existing_path(task.metadata.get("existing_wrapper_path")) or _existing_path(
        execution_block.get("wrapper_path"),
    )
    wrapper_path = _existing_path(resolved_imports.get("existing_wrapper_path")) or configured_wrapper
    configured_launcher = _existing_path(task.metadata.get("existing_launcher_path")) or _existing_path(
        execution_block.get("launcher_path"),
    )
    imported_launcher = _existing_path(resolved_imports.get("existing_launcher_path"))
    explicit_launcher = configured_launcher
    contract_inference = _load_contract_inference(task)
    if explicit_launcher is None and binary_mode != "pure_binary":
        explicit_launcher = imported_launcher
    selected_launcher = explicit_launcher or binary_path
    input_delivery_reference = _resolve_input_delivery_reference(task)
    input_mode = str(
        task.metadata.get("binary_input_contract")
        or task.metadata.get("binary_input_mode")
        or execution_block.get("input_mode")
        or contract_inference.get("selected_input_mode")
        or "file",
    )
    if task.metadata.get("binary_input_contract"):
        input_contract_confidence = "high"
        input_contract_confidence_reason = "explicit_task_contract"
    elif execution_block.get("input_mode"):
        input_contract_confidence = "medium"
        input_contract_confidence_reason = "benchmark_execution_block"
    elif contract_inference.get("selected_input_mode"):
        input_contract_confidence = str(contract_inference.get("selected_confidence") or "medium")
        input_contract_confidence_reason = "ida_contract_inference"
    elif input_delivery_reference is not None:
        input_contract_confidence = "medium"
        input_contract_confidence_reason = "input_delivery_reference_detected"
    else:
        input_contract_confidence = "low"
        input_contract_confidence_reason = "default_binary_file_mode"
    execution_strategy = str(
        task.metadata.get("binary_execution_strategy")
        or execution_block.get("execution_strategy")
        or "corpus-loop"
    )
    argv_template = task.metadata.get("argv_template") or execution_block.get("argv_template")
    if not argv_template:
        if wrapper_path is not None:
            argv_template = [str(wrapper_path), "{binary_path}", "{input_path}"]
        elif explicit_launcher is not None and explicit_launcher != binary_path:
            argv_template = [str(explicit_launcher), "{input_path}"]
        elif input_mode == "stdin":
            argv_template = ["{binary_path}"]
        else:
            argv_template = ["{binary_path}", "{input_path}"]
    elif binary_mode == "pure_binary" and explicit_launcher is None and wrapper_path is None:
        argv_template = ["{binary_path}"] if input_mode == "stdin" else ["{binary_path}", "{input_path}"]
    argv_template = list(argv_template)
    contract_kind, contract_hints = _input_contract_kind(input_mode, argv_template, execution_strategy)

    env_overrides = dict(task.metadata.get("binary_env_overrides") or execution_block.get("env_overrides") or {})
    launcher_name_hint = set()
    for candidate in (
        wrapper_path,
        configured_wrapper,
        explicit_launcher,
        imported_launcher,
        selected_launcher,
    ):
        if candidate is None:
            continue
        launcher_name_hint.add(candidate.name)
        if candidate.exists():
            launcher_name_hint.add(candidate.resolve().name)
    if "glibc239_binary_launcher.sh" in launcher_name_hint:
        runtime_root = Path(__file__).resolve().parents[2] / "runtime" / "glibc239" / "rootfs" / "usr" / "lib" / "x86_64-linux-gnu"
        env_overrides.setdefault("GLIBC_RUNTIME_ROOT", str(runtime_root))
    return {
        "selected_binary_path": str(binary_path),
        "selected_launcher_path": str(selected_launcher),
        "selected_wrapper_path": str(wrapper_path) if wrapper_path else None,
        "input_mode": input_mode,
        "binary_input_contract_kind": contract_kind,
        "binary_input_contract_hints": contract_hints,
        "input_delivery_path": str(input_delivery_reference) if input_delivery_reference is not None else None,
        "input_contract_confidence": input_contract_confidence,
        "input_contract_confidence_reason": input_contract_confidence_reason,
        "working_directory": task.layout.get("binary") or task.task_dir,
        "argv_template": argv_template,
        "env_overrides": env_overrides,
        "execution_strategy": execution_strategy,
    }

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from core.binary.trace_bridge import is_binary_task, load_binary_execution_plan
from core.fuzz.harness_binding import resolve_active_harness
from core.tracer.models import ReplayResult
from core.utils.settings import settings


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def find_symbolizer(binary_path: str | Path) -> str | None:
    binary = Path(binary_path)
    candidates = [
        binary.parent / "llvm-symbolizer",
    ]
    found = shutil.which("llvm-symbolizer")
    if found:
        candidates.append(Path(found))
    candidates.extend(
        [
            Path("/home/buttercup2/Project/buttercup-lite/.toolchains/build-env/bin/llvm-symbolizer"),
            Path("/app/.toolchains/build-env/bin/llvm-symbolizer"),
            Path(settings.build_toolchain_prefix).expanduser() / "bin" / "llvm-symbolizer",
        ]
    )

    seen: set[str] = set()
    for candidate in candidates:
        candidate_path = Path(candidate).expanduser()
        key = str(candidate_path)
        if key in seen:
            continue
        seen.add(key)
        if candidate_path.exists():
            return str(candidate_path)
    return None


def candidate_targets(task_dir: Path) -> list[tuple[str, str]]:
    if is_binary_task(task_dir):
        plan = load_binary_execution_plan(task_dir)
        target_name = plan.get("binary_target_name") or Path(plan["selected_binary_path"]).name
        return [(target_name, str(plan["selected_binary_path"]))]

    active = resolve_active_harness(task_dir)
    candidates: list[tuple[str, str]] = []
    build_registry_path = task_dir / "build" / "build_registry.json"
    build_registry = _load_json(build_registry_path) if build_registry_path.exists() else {}
    for item in build_registry.get("tracer_replay_binaries", []):
        if item.get("name") == active.name and item.get("path") and Path(item["path"]).exists():
            candidates.append((active.name, str(item["path"])))
            break
    if not candidates:
        candidates.append((active.name, str(active.executable_path)))
    if not settings.allow_harness_switch:
        return candidates

    for item in build_registry.get("fuzzers", []):
        pair = (item["name"], item["path"])
        if pair not in candidates:
            candidates.append(pair)
    return candidates


def replay_testcase(binary_path: str, harness_name: str, testcase_path: str, cwd: Path) -> ReplayResult:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=1:detect_leaks=0:allocator_may_return_null=1"
    symbolizer = find_symbolizer(binary_path)
    if symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer
    command = [binary_path, testcase_path]
    run_cwd = str(cwd)
    launcher_path = binary_path
    if is_binary_task(cwd):
        plan = load_binary_execution_plan(cwd)
        replacements = {
            "{binary_path}": binary_path,
            "{launcher_path}": plan.get("selected_launcher_path") or binary_path,
            "{wrapper_path}": plan.get("selected_wrapper_path") or "",
            "{input_path}": testcase_path,
        }
        rendered_command: list[str] = []
        for token in plan.get("argv_template", ["{binary_path}", "{input_path}"]):
            rendered = str(token)
            for placeholder, value in replacements.items():
                rendered = rendered.replace(placeholder, value)
            if rendered:
                rendered_command.append(rendered)
        if rendered_command:
            command = rendered_command
        launcher_path = str(plan.get("selected_launcher_path") or binary_path)
        env.update({key: str(value) for key, value in (plan.get("env_overrides") or {}).items()})
        run_cwd = str(plan.get("working_directory") or cwd)
    else:
        task_path = cwd / "task.json"
        if task_path.exists():
            task_payload = _load_json(task_path)
            metadata = task_payload.get("metadata", {})
            runtime = task_payload.get("runtime", {})
            launcher_path = (
                metadata.get("FUZZ_LAUNCHER_PATH")
                or metadata.get("existing_launcher_path")
                or runtime.get("active_harness_launcher_path")
            )
            if launcher_path:
                command = [str(launcher_path), binary_path, testcase_path]
                launcher_path = str(launcher_path)
    completed = subprocess.run(
        command,
        cwd=run_cwd,
        capture_output=True,
        text=True,
        env=env,
        timeout=settings.replay_timeout_seconds,
    )
    return ReplayResult(
        harness_name=harness_name,
        binary_path=binary_path,
        testcase_path=testcase_path,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        command=command,
        launcher_path=launcher_path,
        working_directory=run_cwd,
    )

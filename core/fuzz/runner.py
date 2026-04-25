from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from core.fuzz.corpus import diff_corpus_files, snapshot_corpus_files
from core.fuzz.crash_collector import scan_raw_crashes
from core.fuzz.harness_binding import resolve_active_harness
from core.fuzz.models import FuzzRunResult, FuzzTarget
from core.seed.harness_selector import select_harness
from core.utils.settings import resolve_bool_setting, resolve_int_setting, resolve_text_setting, settings


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", "replace")


def _load_libfuzzer_options(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    values: dict[str, str] = {}
    in_libfuzzer = False
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_libfuzzer = line.lower() == "[libfuzzer]"
            continue
        if not in_libfuzzer or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        values[key] = value
    return values


def _probe_fuzz_driver_kind(binary_path: Path) -> dict[str, object]:
    nm_path = shutil.which("nm")
    payload = {
        "driver_kind": "libfuzzer_cli",
        "has_llvmfuzzer_testoneinput": False,
        "has_llvmfuzzer_rundriver": False,
        "has_main": False,
        "nm_available": bool(nm_path),
    }
    if not nm_path:
        return payload
    completed = subprocess.run(
        [nm_path, "-an", str(binary_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        payload["driver_probe_error"] = completed.stderr[:400]
        return payload
    lines = completed.stdout.splitlines()
    has_testone = any("LLVMFuzzerTestOneInput" in line for line in lines)
    has_rundriver = any("LLVMFuzzerRunDriver" in line for line in lines)
    has_main = any(line.strip().endswith(" main") for line in lines)
    payload.update(
        {
            "has_llvmfuzzer_testoneinput": has_testone,
            "has_llvmfuzzer_rundriver": has_rundriver,
            "has_main": has_main,
        }
    )
    if has_rundriver:
        payload["driver_kind"] = "libfuzzer_cli"
    elif has_testone and has_main:
        payload["driver_kind"] = "file_driven_main"
    return payload


def _collect_corpus_inputs(corpus_dir: Path) -> list[Path]:
    if not corpus_dir.exists():
        return []
    return sorted(path for path in corpus_dir.rglob("*") if path.is_file())


def _run_file_driven_corpus_loop(
    *,
    target: FuzzTarget,
    task_dir: Path,
    corpus_dir: Path,
    logs_dir: Path,
    launcher_path: str,
    max_total_time_seconds: int,
    timeout_seconds: int,
    abort_on_error: bool,
) -> tuple[list[str], int, str, str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = (
        f"abort_on_error={1 if abort_on_error else 0}:"
        "symbolize=0:detect_leaks=0:allocator_may_return_null=1"
    )
    env["LLVM_PROFILE_FILE"] = str((task_dir / "coverage" / "raw") / "%p.profraw")
    inputs = _collect_corpus_inputs(corpus_dir)
    commands_run: list[str] = []
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    aggregate_exit_code = 0
    deadline = time.monotonic() + max(max_total_time_seconds, 1)
    if not inputs:
        stderr_chunks.append("file-driven fuzz loop found no corpus inputs to execute")
        return [str(target.binary_path), "<empty-corpus>"], 0, "", "\n".join(stderr_chunks)

    index = 0
    while time.monotonic() < deadline and inputs:
        input_path = inputs[index % len(inputs)]
        target_command = [str(target.binary_path), str(input_path)]
        command = [launcher_path, *target_command] if launcher_path else target_command
        commands_run.append(" ".join(command))
        try:
            completed = subprocess.run(
                command,
                cwd=str(task_dir),
                capture_output=True,
                text=True,
                env=env,
                timeout=max(timeout_seconds, 1),
            )
            stdout_chunks.append(
                f"=== input:{input_path.name} exit_code:{completed.returncode} ===\n{completed.stdout}"
            )
            stderr_chunks.append(
                f"=== input:{input_path.name} exit_code:{completed.returncode} ===\n{completed.stderr}"
            )
            if aggregate_exit_code == 0 and completed.returncode != 0:
                aggregate_exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout_chunks.append(
                f"=== input:{input_path.name} exit_code:124 ===\n"
                f"{exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b'').decode('utf-8', 'replace')}"
            )
            stderr_chunks.append(
                f"=== input:{input_path.name} exit_code:124 ===\n"
                f"{exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b'').decode('utf-8', 'replace')}\n"
                "file-driven fuzz loop timeout expired"
            )
            if aggregate_exit_code == 0:
                aggregate_exit_code = 124
        index += 1
        if index >= len(inputs) and time.monotonic() >= deadline:
            break

    (logs_dir / "fuzzer.stdout.log").write_text("\n".join(stdout_chunks), encoding="utf-8")
    (logs_dir / "fuzzer.stderr.log").write_text("\n".join(stderr_chunks), encoding="utf-8")
    return (
        [str(target.binary_path), "<file-driven-corpus-loop>", f"inputs={len(inputs)}"],
        aggregate_exit_code,
        "\n".join(stdout_chunks),
        "\n".join(stderr_chunks),
    )


def resolve_fuzz_target(task_dir: Path) -> FuzzTarget:
    try:
        active = resolve_active_harness(task_dir)
        return FuzzTarget(
            harness_name=active.name,
            binary_path=active.executable_path,
            dict_path=active.dict_path,
            options_path=active.options_path,
        )
    except RuntimeError:
        pass

    seed_manifest_path = task_dir / "seed" / "seed_manifest.json"
    build_registry_path = task_dir / "build" / "build_registry.json"
    build_registry = _load_json(build_registry_path)
    if seed_manifest_path.exists():
        seed_manifest = _load_json(seed_manifest_path)
        selected_name = seed_manifest.get("selected_harness")
        selected_path = seed_manifest.get("selected_harness_path")
        dict_path = None
        options_path = None
        for item in build_registry.get("dicts", []):
            if Path(item["name"]).stem == selected_name:
                dict_path = item["path"]
                break
        for item in build_registry.get("options", []):
            if Path(item["name"]).stem == selected_name:
                options_path = item["path"]
                break
        if selected_name and selected_path:
            return FuzzTarget(
                harness_name=selected_name,
                binary_path=Path(selected_path),
                dict_path=Path(dict_path) if dict_path else None,
                options_path=Path(options_path) if options_path else None,
            )

    selected = select_harness(build_registry_path)
    return FuzzTarget(
        harness_name=selected.name,
        binary_path=selected.executable_path,
        dict_path=selected.dict_path,
        options_path=selected.options_path,
    )


def run_libfuzzer(task_dir: Path, metadata: dict | None = None) -> FuzzRunResult:
    target = resolve_fuzz_target(task_dir)
    corpus_dir = task_dir / "corpus" / "active"
    crashes_raw_dir = task_dir / "crashes" / "raw"
    coverage_raw_dir = task_dir / "coverage" / "raw"
    logs_dir = task_dir / "logs"
    crashes_raw_dir.mkdir(parents=True, exist_ok=True)
    coverage_raw_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    artifact_prefix = f"{crashes_raw_dir}/"

    before_corpus = snapshot_corpus_files(corpus_dir)
    before_crashes = set(scan_raw_crashes(crashes_raw_dir))
    metadata = metadata or {}
    max_total_time_seconds = resolve_int_setting(
        metadata,
        "FUZZ_MAX_TOTAL_TIME_SECONDS",
        settings.fuzz_max_total_time_seconds,
    )
    timeout_seconds = resolve_int_setting(metadata, "FUZZ_TIMEOUT_SECONDS", settings.fuzz_timeout_seconds)
    rss_limit_mb = resolve_int_setting(metadata, "FUZZ_RSS_LIMIT_MB", settings.fuzz_rss_limit_mb)
    max_len = resolve_int_setting(metadata, "FUZZ_MAX_LEN", settings.fuzz_max_len)
    abort_on_error = resolve_bool_setting(metadata, "FUZZ_ABORT_ON_ERROR", settings.fuzz_abort_on_error)
    fork_mode = resolve_bool_setting(metadata, "FUZZ_FORK_MODE", settings.fuzz_fork_mode)
    fork_jobs = resolve_int_setting(metadata, "FUZZ_FORK_JOBS", settings.fuzz_fork_jobs)
    ignore_crashes = resolve_bool_setting(
        metadata,
        "FUZZ_IGNORE_CRASHES",
        settings.fuzz_ignore_crashes,
    )

    launcher_path = resolve_text_setting(
        metadata,
        "FUZZ_LAUNCHER_PATH",
        metadata.get("existing_launcher_path", "") if metadata else "",
    )
    driver_probe = _probe_fuzz_driver_kind(target.binary_path)
    if driver_probe.get("driver_kind") == "file_driven_main":
        command, exit_code, stdout_text, stderr_text = _run_file_driven_corpus_loop(
            target=target,
            task_dir=task_dir,
            corpus_dir=corpus_dir,
            logs_dir=logs_dir,
            launcher_path=launcher_path,
            max_total_time_seconds=max_total_time_seconds,
            timeout_seconds=timeout_seconds,
            abort_on_error=abort_on_error,
        )
    else:
        target_command = [
            str(target.binary_path),
            f"-artifact_prefix={artifact_prefix}",
            f"-max_total_time={max_total_time_seconds}",
            f"-timeout={timeout_seconds}",
            f"-rss_limit_mb={rss_limit_mb}",
            "-print_final_stats=1",
            str(corpus_dir),
        ]
        if fork_mode:
            target_command.insert(-1, f"-fork={max(fork_jobs, 1)}")
            if ignore_crashes:
                target_command.insert(-1, "-ignore_crashes=1")
        if target.dict_path and target.dict_path.exists():
            target_command.insert(1, f"-dict={target.dict_path}")
        options = _load_libfuzzer_options(target.options_path)
        if max_len:
            target_command.insert(1, f"-max_len={max_len}")
        elif options.get("max_len"):
            target_command.insert(1, f"-max_len={options['max_len']}")

        command = [launcher_path, *target_command] if launcher_path else target_command
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = (
            f"abort_on_error={1 if abort_on_error else 0}:"
            "symbolize=0:detect_leaks=0:allocator_may_return_null=1"
        )
        # Source-mode libFuzzer runs emit raw profiling data for downstream llvm-profdata/llvm-cov processing.
        env["LLVM_PROFILE_FILE"] = str(coverage_raw_dir / "%p.profraw")
        timeout_budget_seconds = max_total_time_seconds + settings.replay_timeout_seconds
        try:
            completed = subprocess.run(
                command,
                cwd=str(task_dir),
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout_budget_seconds,
            )
            stdout_text = completed.stdout
            stderr_text = completed.stderr
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout_text = _decode_timeout_output(exc.stdout)
            stderr_text = _decode_timeout_output(exc.stderr)
            stderr_text = (
                f"{stderr_text}\nlibfuzzer wrapper timeout reached after {timeout_budget_seconds}s; "
                "treating this round as budget-exhausted completion rather than campaign-fatal failure.\n"
            ).strip()
            exit_code = 124
        (logs_dir / "fuzzer.stdout.log").write_text(stdout_text, encoding="utf-8")
        (logs_dir / "fuzzer.stderr.log").write_text(stderr_text, encoding="utf-8")

    new_corpus = diff_corpus_files(before_corpus, corpus_dir)
    raw_crashes = [path for path in scan_raw_crashes(crashes_raw_dir) if path not in before_crashes]
    return FuzzRunResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout_text,
        stderr=stderr_text,
        harness_name=target.harness_name,
        binary_path=str(target.binary_path),
        dict_path=str(target.dict_path) if target.dict_path else None,
        options_path=str(target.options_path) if target.options_path else None,
        new_corpus_files=new_corpus,
        raw_crashes=raw_crashes,
    )

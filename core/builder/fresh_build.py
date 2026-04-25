from __future__ import annotations

import json
import os
import shutil
import subprocess
import platform
from pathlib import Path
from typing import Any

from config.build_contracts import (
    fallback_build_recipe,
    prepare_source as prepare_source_contract,
    stage_project_harness_assets,
    tracer_replay_recipe,
    write_build_options as write_build_options_contract,
)
from core.builder.contracts import BuildCapability
from core.builder.import_scan import scan_imported_build
from core.utils.settings import settings


def _link_tree(source_path: Path, destination_path: Path) -> None:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists() or destination_path.is_symlink():
        if destination_path.is_dir() and not destination_path.is_symlink():
            shutil.rmtree(destination_path)
        else:
            destination_path.unlink()
    destination_path.symlink_to(source_path, target_is_directory=source_path.is_dir())


def _mark_shell_scripts_executable(root: Path) -> None:
    if not root.exists():
        return
    for candidate in root.rglob("*.sh"):
        if not candidate.is_file():
            continue
        try:
            candidate.chmod(candidate.stat().st_mode | 0o111)
        except OSError:
            continue


PROMOTED_FUZZER_SEARCH_PATHS = ("bin", "build/bin", "build/fuzz", "fuzz", "tests", "test")
PROMOTED_FUZZER_NAME_TOKENS = ("fuzzer", "fuzz")


def _system_cxx_include_flags() -> list[str]:
    candidates = [
        Path("/usr/include/c++/11"),
        Path("/usr/include/x86_64-linux-gnu/c++/11"),
    ]
    flags: list[str] = []
    for candidate in candidates:
        if candidate.exists():
            flags.extend(["-isystem", str(candidate)])
    return flags


def _toolchain_prefix() -> Path | None:
    prefix = Path(settings.build_toolchain_prefix).expanduser()
    return prefix if prefix.exists() else None


def _toolchain_has_static_libstdcxx(prefix: Path | None) -> bool:
    if prefix is None:
        return Path("/usr/lib/x86_64-linux-gnu/libstdc++.a").exists()
    return any((prefix / subpath).exists() for subpath in ("lib/libstdc++.a", "lib64/libstdc++.a"))


def _toolchain_env() -> tuple[dict[str, str], dict]:
    env = os.environ.copy()
    prefix = _toolchain_prefix()
    if prefix is None:
        return env, {
            "environment_kind": "host",
            "toolchain_prefix": None,
            "tools": {},
        }
    bin_dir = prefix / "bin"
    lib_dirs = [prefix / "lib", prefix / "lib64"]
    env["PATH"] = os.pathsep.join(
        [str(bin_dir), env.get("PATH", "")],
    ).strip(os.pathsep)
    lib_path_entries = [str(path) for path in lib_dirs if path.exists()]
    include_dir = prefix / "include"
    existing_ld = env.get("LD_LIBRARY_PATH", "")
    if lib_path_entries or existing_ld:
        env["LD_LIBRARY_PATH"] = os.pathsep.join(
            [*lib_path_entries, existing_ld],
        ).strip(os.pathsep)
    pkg_config_entries = [
        prefix / "lib" / "pkgconfig",
        prefix / "share" / "pkgconfig",
    ]
    env["PKG_CONFIG_PATH"] = os.pathsep.join(
        [str(path) for path in pkg_config_entries if path.exists()],
    )
    aclocal = prefix / "share" / "aclocal"
    if aclocal.exists():
        env["ACLOCAL_PATH"] = str(aclocal)
    env["CMAKE_PREFIX_PATH"] = str(prefix)
    cppflags = [env.get("CPPFLAGS", "").strip()]
    if include_dir.exists():
        cppflags.append(f"-I{include_dir}")
    env["CPPFLAGS"] = " ".join(item for item in cppflags if item).strip()
    ldflags = [env.get("LDFLAGS", "").strip()]
    ldflags.extend(
        [
            f"-L{prefix / 'lib'}",
            f"-Wl,-rpath,{prefix / 'lib'}",
        ],
    )
    env["LDFLAGS"] = " ".join(item for item in ldflags if item).strip()
    env["LIBS"] = " ".join(
        item for item in [env.get("LIBS", "").strip(), f"-L{prefix / 'lib'} -liconv -lz"] if item
    ).strip()
    env["LIBXML2_EXTRA_LIBS"] = f"-L{prefix / 'lib'} -liconv"
    extra_cxx_flags = " ".join(_system_cxx_include_flags()).strip()
    if extra_cxx_flags:
        env["BUTTERCUP_EXTRA_CXXFLAGS"] = extra_cxx_flags
        env["CPLUS_INCLUDE_PATH"] = os.pathsep.join(
            [
                path
                for path in [
                    "/usr/include/c++/11",
                    "/usr/include/x86_64-linux-gnu/c++/11",
                    env.get("CPLUS_INCLUDE_PATH", ""),
                ]
                if path
            ],
        )
    tools = {
        tool: shutil.which(tool, path=env.get("PATH"))
        for tool in (
            "clang",
            "clang++",
            "cmake",
            "autoconf",
            "automake",
            "libtoolize",
            "llvm-profdata",
            "llvm-cov",
            "ninja",
            "patchelf",
        )
    }
    env["BUTTERCUP_HAS_STATIC_LIBSTDCXX"] = "1" if _toolchain_has_static_libstdcxx(prefix) else "0"
    return env, {
        "environment_kind": "host_local_toolchain",
        "toolchain_prefix": str(prefix),
        "has_static_libstdcxx": env["BUTTERCUP_HAS_STATIC_LIBSTDCXX"] == "1",
        "tools": tools,
    }


def _prepare_build_script_for_local_execution(
    *,
    original_script: Path,
    build_dir: Path,
    env: dict[str, str],
) -> tuple[Path, list[str]]:
    script_text = original_script.read_text(encoding="utf-8")
    adapted = script_text
    adaptations: list[str] = []
    if env.get("BUTTERCUP_HAS_STATIC_LIBSTDCXX") != "1" and "-static-libstdc++" in adapted:
        adapted = adapted.replace("-static-libstdc++", "")
        adaptations.append("removed_static_libstdcxx_flag")
    if os.geteuid() != 0:
        rewritten_lines: list[str] = []
        skipped_install = False
        local_prelude = (
            "\n"
            "if [[ ${BUTTERCUP_SKIP_PRIVILEGED_INSTALLS:-1} == 1 ]]; then\n"
            "  apt-get() { echo '[buttercup-lite] skipped apt-get in local non-root build: apt-get' \"$@\"; return 0; }\n"
            "  apt() { echo '[buttercup-lite] skipped apt in local non-root build: apt' \"$@\"; return 0; }\n"
            "  dpkg() { echo '[buttercup-lite] skipped dpkg in local non-root build: dpkg' \"$@\"; return 0; }\n"
            "  sudo() {\n"
            "    case \"${1:-}\" in\n"
            "      apt|apt-get|dpkg) echo '[buttercup-lite] skipped sudo privileged install in local non-root build:' \"$@\"; return 0 ;;\n"
            "      *) command sudo \"$@\" ;;\n"
            "    esac\n"
            "  }\n"
            "  export -f apt-get apt dpkg sudo\n"
            "fi\n"
        )
        for line in adapted.splitlines():
            stripped = line.strip()
            if (
                stripped.startswith("apt-get ")
                or stripped.startswith("apt ")
                or stripped.startswith("sudo apt-get ")
                or stripped.startswith("sudo apt ")
                or stripped.startswith("dpkg ")
                or " apt-get " in f" {stripped} "
                or " apt " in f" {stripped} "
                or " dpkg " in f" {stripped} "
            ):
                rewritten_lines.append("echo '[buttercup-lite] skipped privileged package install; assuming deps already exist'")
                skipped_install = True
                continue
            rewritten_lines.append(line)
        if skipped_install:
            adapted = "\n".join(rewritten_lines) + "\n"
            adaptations.append("skipped_privileged_package_install")
        adapted = adapted.replace("\n", local_prelude, 1) if adapted.startswith("#!") else local_prelude + adapted
        adaptations.append("installed_nonroot_privileged_install_shims")
    if "-DEXPAT_BUILD_FUZZERS=ON" in adapted and ("cmake ../expat" in adapted or "cmake .." in adapted):
        expat_optional_lpm_patch = r'''
if ! command -v protoc >/dev/null 2>&1; then
  echo "[buttercup-lite] protoc not found; disabling Expat protobuf-mutator LPM fuzzer while preserving C fuzzers"
  python3 - <<'PY'
from pathlib import Path
import re
cmake = Path("../expat/CMakeLists.txt")
if cmake.exists():
    text = cmake.read_text()
    pattern = re.compile(r"\n    find_package\(Protobuf REQUIRED\).*?    set_property\(TARGET xml_lpm_fuzzer PROPERTY RUNTIME_OUTPUT_DIRECTORY fuzz\)\n", re.S)
    new_text, count = pattern.subn("\n    message(STATUS \"buttercup-lite: skipped xml_lpm_fuzzer because protoc/protobuf is unavailable in local build\")\n", text, count=1)
    if count:
        cmake.write_text(new_text)
        print("[buttercup-lite] patched expat CMakeLists.txt to skip xml_lpm_fuzzer")
PY
fi
'''
        if "cmake ../expat" in adapted:
            adapted = adapted.replace("cmake ../expat", expat_optional_lpm_patch + "\ncmake ../expat", 1)
        else:
            adapted = adapted.replace("cmake ..", expat_optional_lpm_patch + "\ncmake ..", 1)
        adaptations.append("expat_skip_lpm_fuzzer_when_protobuf_missing")
    if "../LPM/external.protobuf/bin/protoc" in adapted:
        adapted = adapted.replace(
            "if [[ $CFLAGS != *sanitize=memory* ]]; then",
            "if [[ $CFLAGS != *sanitize=memory* && -x ../LPM/external.protobuf/bin/protoc ]]; then",
            1,
        )
        adaptations.append("skip_lpm_proto_fuzzer_when_local_protobuf_assets_missing")
    for shell_path in (
        "$SRC/cjson/fuzzing/ossfuzz.sh",
        "$SRC/miniz/tests/ossfuzz.sh",
    ):
        if shell_path in adapted:
            adapted = adapted.replace(shell_path, f"bash {shell_path}")
            adaptations.append(f"invoke_shell_via_bash:{Path(shell_path).name}")
    rewritten_script = build_dir / "adapted_build.sh"
    rewritten_script.write_text(adapted, encoding="utf-8")
    rewritten_script.chmod(0o755)
    return rewritten_script, adaptations


def _find_tool(name: str, env: dict[str, str]) -> str | None:
    candidates = (
        name,
        f"{name}-22",
        f"x86_64-conda-linux-gnu-{name}",
    )
    prefix = _toolchain_prefix()
    if prefix is not None:
        bin_dir = prefix / "bin"
        for candidate in candidates:
            tool_path = bin_dir / candidate
            if tool_path.exists() and os.access(tool_path, os.X_OK):
                return str(tool_path)
    for candidate in candidates:
        path = shutil.which(candidate, path=env.get("PATH"))
        if path:
            return path
    return None


def _prepare_source_for_capability(capability: BuildCapability, source_dir: Path) -> None:
    prepare_source_contract(capability.project, source_dir)


def _post_process_build_output(capability: BuildCapability, build_out_dir: Path) -> None:
    write_build_options_contract(capability.project, build_out_dir)


def _stage_oss_fuzz_harness_sources(
    *,
    capability: BuildCapability,
    source_dir: Path,
    src_root: Path | None,
    oss_fuzz_project_dir: Path,
) -> dict[str, Any]:
    staged: list[str] = []
    staged_to_src_root: list[str] = []
    missing_optional_assets: list[str] = []
    generic_asset_suffixes = {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".dict",
        ".options",
        ".zip",
    }
    ignored_names = {"Dockerfile", "build.sh", "project.yaml", "run_tests.sh"}
    for candidate in sorted(oss_fuzz_project_dir.iterdir()):
        if not candidate.is_file() or candidate.name in ignored_names:
            continue
        if candidate.suffix.lower() not in generic_asset_suffixes:
            continue
        destination = source_dir / candidate.name
        if destination.exists():
            pass
        else:
            shutil.copy2(candidate, destination)
            staged.append(str(destination))
        if src_root is not None:
            root_destination = src_root / candidate.name
            if not root_destination.exists():
                shutil.copy2(candidate, root_destination)
                staged_to_src_root.append(str(root_destination))

    project_specific = stage_project_harness_assets(
        project=capability.project,
        source_dir=source_dir,
        src_root=src_root,
        oss_fuzz_project_dir=oss_fuzz_project_dir,
    )
    staged.extend(project_specific.get("staged_in_source_dir", []))
    staged_to_src_root.extend(project_specific.get("staged_in_src_root", []))
    missing_optional_assets.extend(project_specific.get("missing_optional_assets", []))
    return {
        "staged_in_source_dir": staged,
        "staged_in_src_root": staged_to_src_root,
        "missing_optional_assets": sorted(set(missing_optional_assets)),
    }


def _discover_promotable_fuzzers(source_dir: Path) -> list[Path]:
    candidates: list[Path] = []
    seen: set[Path] = set()
    for relative_dir in PROMOTED_FUZZER_SEARCH_PATHS:
        base = source_dir / relative_dir
        if not base.exists():
            continue
        for candidate in sorted(base.rglob("*")):
            if not candidate.is_file():
                continue
            if not os.access(candidate, os.X_OK):
                continue
            lowered = candidate.name.lower()
            if not any(token in lowered for token in PROMOTED_FUZZER_NAME_TOKENS):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def _promote_discovered_fuzzers(*, source_dir: Path, out_dir: Path) -> list[str]:
    promoted: list[str] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    for candidate in _discover_promotable_fuzzers(source_dir):
        destination = out_dir / candidate.name
        if destination.exists():
            continue
        shutil.copy2(candidate, destination)
        destination.chmod(destination.stat().st_mode | 0o111)
        promoted.append(str(destination))
    return promoted


def _write_replay_main(
    *,
    output_path: Path,
    prototype: str,
) -> Path:
    output_path.write_text(
        "#include <stdint.h>\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "\n"
        f"{prototype}\n"
        "\n"
        "int main(int argc, char **argv) {\n"
        "    FILE *f;\n"
        "    unsigned char *buf = NULL;\n"
        "    long size;\n"
        "    if (argc < 2) {\n"
        "        fprintf(stderr, \"no input file\\n\");\n"
        "        return 2;\n"
        "    }\n"
        "    f = fopen(argv[1], \"rb\");\n"
        "    if (!f) {\n"
        "        fprintf(stderr, \"error opening input file %s\\n\", argv[1]);\n"
        "        return 2;\n"
        "    }\n"
        "    fseek(f, 0, SEEK_END);\n"
        "    size = ftell(f);\n"
        "    rewind(f);\n"
        "    if (size <= 0) {\n"
        "        fclose(f);\n"
        "        return 0;\n"
        "    }\n"
        "    buf = (unsigned char *)malloc((size_t)size);\n"
        "    if (!buf) {\n"
        "        fclose(f);\n"
        "        return 2;\n"
        "    }\n"
        "    if (fread(buf, (size_t)size, 1, f) != 1) {\n"
        "        free(buf);\n"
        "        fclose(f);\n"
        "        return 2;\n"
        "    }\n"
        "    LLVMFuzzerTestOneInput((const char *)buf, (size_t)size);\n"
        "    free(buf);\n"
        "    fclose(f);\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    return output_path


def _build_dedicated_replay_binary(
    *,
    source_dir: Path,
    build_dir: Path,
    logs_dir: Path,
    capability: BuildCapability,
    env: dict[str, str],
) -> dict | None:
    compiler = _find_tool("clang", env) or shutil.which("cc", path=env.get("PATH")) or shutil.which("gcc", path=env.get("PATH"))
    if compiler is None:
        return None

    recipe = tracer_replay_recipe(capability.project)
    if recipe is None:
        return None
    replay_dir = build_dir / "tracer"
    replay_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{capability.project}-tracer-build.log"
    harness_name = str(recipe["harness_name"])
    output_path = replay_dir / str(recipe["output_name"])
    sources: list[Path] = []
    replay_main_prototype = recipe.get("replay_main_prototype")
    if replay_main_prototype:
        replay_main = _write_replay_main(
            output_path=replay_dir / recipe["sources"][0],
            prototype=str(replay_main_prototype),
        )
        sources.append(replay_main)
        relative_sources = recipe["sources"][1:]
    else:
        relative_sources = recipe["sources"]
    for relative_source in relative_sources:
        sources.append(source_dir / str(relative_source))
    command = [
        compiler,
        "-O1",
        "-g",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-Wno-error",
        "-Wno-comment",
        *[str(path) for path in sources],
    ]
    for include_dir in recipe.get("include_dirs", []):
        command.extend(["-I", str(source_dir / str(include_dir))])
    command.extend(["-o", str(output_path)])

    missing = [str(path) for path in command if path.endswith((".c", ".cc", ".cpp")) and not Path(path).exists()]
    if missing:
        log_path.write_text(
            "DEDICATED TRACER BUILD SKIPPED: missing sources\n" + "\n".join(missing),
            encoding="utf-8",
        )
        return None

    completed = subprocess.run(
        command,
        cwd=str(source_dir),
        capture_output=True,
        text=True,
        env=env,
        timeout=settings.build_timeout_seconds,
    )
    log_path.write_text(
        "COMMAND:\n"
        + " ".join(command)
        + "\n\nSTDOUT:\n"
        + completed.stdout
        + "\n\nSTDERR:\n"
        + completed.stderr,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        return {
            "name": harness_name,
            "path": None,
            "status": "failed",
            "log_path": str(log_path),
            "failure_reason": f"dedicated tracer build failed with exit code {completed.returncode}",
        }
    output_path.chmod(output_path.stat().st_mode | 0o111)
    return {
        "name": harness_name,
        "path": str(output_path),
        "status": "built",
        "log_path": str(log_path),
        "build_variant": "dedicated_asan_replay_binary",
    }


def _build_dedicated_coverage_variant(
    *,
    task_id: str,
    source_dir: Path,
    build_dir: Path,
    oss_fuzz_project_dir: Path,
    capability: BuildCapability,
    env: dict[str, str],
) -> dict | None:
    coverage_out_dir = build_dir / "coverage_out"
    coverage_scan_dir = build_dir / "coverage_scan"
    coverage_logs_dir = build_dir / "logs"
    coverage_log_path = coverage_logs_dir / "coverage-build.log"
    if coverage_out_dir.exists():
        shutil.rmtree(coverage_out_dir)
    coverage_out_dir.mkdir(parents=True, exist_ok=True)

    coverage_env = env.copy()
    coverage_env["OUT"] = str(coverage_out_dir)
    coverage_compile_flags = (
        "-O0 -g -fprofile-instr-generate -fcoverage-mapping "
        "-fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -Wno-error -Wno-comment"
    )
    coverage_link_flags = "-fprofile-instr-generate -fcoverage-mapping -fsanitize=address"
    coverage_env["CFLAGS"] = coverage_compile_flags
    coverage_env["CXXFLAGS"] = " ".join(
        item for item in [coverage_compile_flags, coverage_env.get("BUTTERCUP_EXTRA_CXXFLAGS", "")] if item
    ).strip()
    coverage_env["LDFLAGS"] = " ".join(
        item for item in [coverage_env.get("LDFLAGS", ""), coverage_link_flags] if item
    ).strip()
    # Expat's CMakeLists.txt feeds LIB_FUZZING_ENGINE straight into
    # target_link_options($ENV{LIB_FUZZING_ENGINE}); if we pass a whole
    # whitespace-delimited flag bundle here CMake preserves it as one quoted
    # argument and clang++ rejects it. Keep this to the single libFuzzer link
    # token and carry coverage instrumentation via CFLAGS/CXXFLAGS/LDFLAGS.
    coverage_env["LIB_FUZZING_ENGINE"] = "-fsanitize=fuzzer,address"
    source_build_dir = source_dir / "build"
    if source_build_dir.exists():
        shutil.rmtree(source_build_dir)

    build_script_path, _ = _prepare_build_script_for_local_execution(
        original_script=oss_fuzz_project_dir / "build.sh",
        build_dir=build_dir,
        env=coverage_env,
    )

    completed = subprocess.run(
        ["bash", str(build_script_path)],
        cwd=str(source_dir),
        capture_output=True,
        text=True,
        env=coverage_env,
        timeout=settings.build_timeout_seconds,
        check=False,
    )
    coverage_log_path.write_text(
        "COMMAND:\n"
        + "bash "
        + str(build_script_path)
        + "\n\nSTDOUT:\n"
        + completed.stdout
        + "\n\nSTDERR:\n"
        + completed.stderr,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        return {
            "status": "failed",
            "log_path": str(coverage_log_path),
            "failure_reason": f"dedicated coverage build failed with exit code {completed.returncode}",
            "build_out_dir": str(coverage_out_dir),
        }

    # Some OSS-Fuzz projects leave coverage-capable fuzzers under build/fuzz or
    # similar tree locations even when $OUT is sparse; promote them so coverage
    # scanning and later llvm-cov replay can still pick the dedicated variant.
    promoted_fuzzers = _promote_discovered_fuzzers(source_dir=source_dir, out_dir=coverage_out_dir)
    coverage_registry = scan_imported_build(
        task_id=task_id,
        build_out_dir=coverage_out_dir,
        harness_dir=source_dir / capability.harness_dir_name,
        build_dir=coverage_scan_dir,
        mode="coverage_build",
    )
    return {
        "status": "built",
        "log_path": str(coverage_log_path),
        "build_variant": "dedicated_llvm_cov_build",
        "build_out_dir": str(coverage_out_dir),
        "promoted_fuzzers": promoted_fuzzers,
        "fuzzers": coverage_registry.get("fuzzers", []),
        "artifacts": coverage_registry.get("artifacts", {}),
    }


def _build_recipe_without_cmake(
    *,
    task_id: str,
    source_dir: Path,
    build_dir: Path,
    out_dir: Path,
    logs_dir: Path,
    capability: BuildCapability,
) -> dict:
    log_path = logs_dir / "build.log"
    toolchain_env, toolchain_info = _toolchain_env()
    compiler = _find_tool("clang", toolchain_env) or shutil.which("cc", path=toolchain_env.get("PATH")) or shutil.which("gcc", path=toolchain_env.get("PATH"))
    if not compiler:
        raise RuntimeError("no system C compiler (cc/gcc) is available for fallback build")
    recipe = fallback_build_recipe(capability.project)
    if recipe is None:
        raise RuntimeError(f"no fallback build recipe configured for project {capability.project}")
    command = [
        compiler,
        "-O1",
        "-g",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-Wno-error",
        "-Wno-comment",
    ]
    command.extend(str(source_dir / relative_source) for relative_source in recipe["sources"])
    for include_dir in recipe.get("include_dirs", []):
        command.extend(["-I", str(source_dir / str(include_dir))])
    command.extend(["-o", str(out_dir / str(recipe["output_name"]))])
    completed = subprocess.run(
        command,
        cwd=str(source_dir),
        capture_output=True,
        text=True,
        env=toolchain_env,
        timeout=settings.build_timeout_seconds,
    )
    log_path.write_text(
        "COMMAND:\n"
        + " ".join(command)
        + "\n\nSTDOUT:\n"
        + completed.stdout
        + "\n\nSTDERR:\n"
        + completed.stderr,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"fresh {capability.project} fallback build failed with exit code {completed.returncode}; see {log_path}",
        )
    dict_copy = recipe.get("dict_copy") or {}
    dict_source = dict_copy.get("source")
    dict_target = dict_copy.get("target")
    if dict_source and dict_target:
        dict_src = source_dir / str(dict_source)
        if dict_src.exists():
            shutil.copy2(dict_src, out_dir / str(dict_target))
    coverage_recipe = recipe.get("coverage_recipe") or {}
    coverage_output = out_dir.parent / "coverage_out"
    coverage_command = [
        compiler,
        "-O0",
        "-g",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-Wno-error",
        "-Wno-comment",
    ]
    coverage_command.extend(
        str(source_dir / relative_source)
        for relative_source in coverage_recipe.get("sources", [])
    )
    for include_dir in coverage_recipe.get("include_dirs", []):
        coverage_command.extend(["-I", str(source_dir / str(include_dir))])
    coverage_output_name = str(coverage_recipe.get("output_name") or recipe["output_name"])
    coverage_command.extend(
        [
            "-fsanitize=fuzzer,address",
            "-o",
            str(coverage_output / coverage_output_name),
        ]
    )
    coverage_output.mkdir(parents=True, exist_ok=True)
    coverage_completed = subprocess.run(
        coverage_command,
        cwd=str(source_dir),
        capture_output=True,
        text=True,
        env=toolchain_env,
        timeout=settings.build_timeout_seconds,
        check=False,
    )
    coverage_log_path = logs_dir / "coverage-build.log"
    coverage_log_path.write_text(
        "COMMAND:\n"
        + " ".join(coverage_command)
        + "\n\nSTDOUT:\n"
        + coverage_completed.stdout
        + "\n\nSTDERR:\n"
        + coverage_completed.stderr,
        encoding="utf-8",
    )
    _post_process_build_output(capability, out_dir)
    registry = scan_imported_build(
        task_id=task_id,
        build_out_dir=out_dir,
        harness_dir=source_dir / capability.harness_dir_name,
        build_dir=build_dir,
        mode="fresh_fallback",
    )
    coverage_fuzzers = []
    if coverage_recipe and coverage_completed.returncode == 0:
        coverage_registry = scan_imported_build(
            task_id=task_id,
            build_out_dir=coverage_output,
            harness_dir=source_dir / capability.harness_dir_name,
            build_dir=build_dir / "coverage_scan",
            mode="coverage_build",
        )
        coverage_fuzzers = coverage_registry.get("fuzzers", [])
    registry["artifacts"]["build_log"] = str(log_path)
    registry["artifacts"]["build_out_dir"] = str(out_dir)
    registry["artifacts"]["coverage_build_log"] = str(coverage_log_path)
    registry["artifacts"]["coverage_build_out_dir"] = str(coverage_output)
    registry["build_command"] = command
    registry["build_capability"] = capability.to_dict()
    registry["build_fallback"] = "direct_clang_without_cmake"
    registry["coverage_fuzzers"] = coverage_fuzzers
    registry["build_variants"] = {
        "coverage_build": {
            "requested_mode": "dedicated_coverage_build",
            "actual_mode": (
                "dedicated_llvm_cov_build"
                if coverage_fuzzers
                else "reuse_fallback_fuzzer_binary"
            ),
            "fallback_reason": (
                None
                if coverage_fuzzers
                else "coverage_variant_build_failed_under_direct_clang_fallback"
            ),
            "fallback_effect": (
                None
                if coverage_fuzzers
                else "coverage semantics rely on the same direct-clang binary used for fuzzing"
            ),
            "semantic_limitations": (
                []
                if coverage_fuzzers
                else [
                    "no separate coverage-only compile flags",
                    "coverage feedback quality depends on libFuzzer stderr rather than dedicated llvm-cov artifacts",
                ]
            ),
        },
        "fuzzer_build": {
            "requested_mode": "dedicated_fuzzer_build",
            "actual_mode": "direct_clang_without_cmake",
            "fallback_reason": "cmake_unavailable_in_build_environment",
            "fallback_effect": "build uses the lightweight fallback compiler path",
            "semantic_limitations": [
                "project-specific oss-fuzz build script was not used",
            ],
        },
        "tracer_build": {
            "requested_mode": "dedicated_tracer_build",
            "actual_mode": "reuse_fallback_fuzzer_binary",
            "fallback_reason": "dedicated_replay_binary_not_produced",
            "fallback_effect": "replay reuses the fallback fuzz binary",
            "semantic_limitations": [
                "asan replay semantics are coupled to the fuzz binary",
            ],
        },
        "patch_qe_build": {
            "requested_mode": "patch_qe_usable_build",
            "actual_mode": "reuse_fallback_fuzzer_binary",
            "fallback_reason": "no_patch_qe_specific_build_variant",
            "fallback_effect": "QE would reuse the fallback build output",
            "semantic_limitations": [
                "no dedicated patch validation binary",
            ],
        },
    }
    registry["build_environment"] = toolchain_info
    (build_dir / "build_registry.json").write_text(json.dumps(registry, indent=2), encoding="utf-8")
    return registry


def build_ossfuzz_project(
    *,
    task_id: str,
    source_dir: Path,
    oss_fuzz_project_dir: Path,
    build_dir: Path,
    capability: BuildCapability,
) -> dict:
    work_dir = build_dir / "work"
    src_root = work_dir / "src"
    out_dir = build_dir / "out"
    logs_dir = build_dir / "logs"
    log_path = logs_dir / "build.log"

    build_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    if work_dir.exists():
        shutil.rmtree(work_dir)
    src_root.mkdir(parents=True, exist_ok=True)

    source_build_dir = source_dir / "build"
    if source_build_dir.exists():
        shutil.rmtree(source_build_dir)
    _prepare_source_for_capability(capability, source_dir)
    staged_asset_manifest = _stage_oss_fuzz_harness_sources(
        capability=capability,
        source_dir=source_dir,
        src_root=src_root,
        oss_fuzz_project_dir=oss_fuzz_project_dir,
    )
    env, toolchain_info = _toolchain_env()

    if fallback_build_recipe(capability.project) is not None and _find_tool("cmake", env) is None:
        return _build_recipe_without_cmake(
            task_id=task_id,
            source_dir=source_dir,
            build_dir=build_dir,
            out_dir=out_dir,
            logs_dir=logs_dir,
            capability=capability,
        )

    _link_tree(source_dir, src_root / capability.source_checkout_name)
    _mark_shell_scripts_executable(src_root)
    clang_path = _find_tool("clang", env)
    clangxx_path = _find_tool("clang++", env)
    if not clang_path or not clangxx_path:
        raise RuntimeError(
            "clang/clang++ are unavailable in the configured build environment; "
            f"expected toolchain at {settings.build_toolchain_prefix}",
        )
    env.update(
        {
            "CC": clang_path,
            "CXX": clangxx_path,
            "CFLAGS": "-O1 -g -fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -Wno-error -Wno-comment",
            "CXXFLAGS": (
                "-O1 -g -fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -Wno-error -Wno-comment "
                + env.get("BUTTERCUP_EXTRA_CXXFLAGS", "")
            ).strip(),
            "LIB_FUZZING_ENGINE": "-fsanitize=fuzzer,address",
            "SANITIZER": env.get("SANITIZER", "address"),
            "ARCHITECTURE": env.get("ARCHITECTURE", platform.machine() or "x86_64"),
            "SRC": str(src_root),
            "OUT": str(out_dir),
        },
    )

    build_script_path, build_script_adaptations = _prepare_build_script_for_local_execution(
        original_script=oss_fuzz_project_dir / "build.sh",
        build_dir=build_dir,
        env=env,
    )
    command = ["bash", str(build_script_path)]
    completed = subprocess.run(
        command,
        cwd=str(source_dir),
        capture_output=True,
        text=True,
        env=env,
        timeout=settings.build_timeout_seconds,
    )
    log_path.write_text(
        "COMMAND:\n"
        + " ".join(command)
        + "\n\nSTDOUT:\n"
        + completed.stdout
        + "\n\nSTDERR:\n"
        + completed.stderr,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"fresh {capability.project} build failed with exit code {completed.returncode}; see {log_path}",
        )

    tracer_replay = _build_dedicated_replay_binary(
        source_dir=source_dir,
        build_dir=build_dir,
        logs_dir=logs_dir,
        capability=capability,
        env=env,
    )
    coverage_variant = _build_dedicated_coverage_variant(
        task_id=task_id,
        source_dir=source_dir,
        build_dir=build_dir,
        oss_fuzz_project_dir=oss_fuzz_project_dir,
        capability=capability,
        env=env,
    )
    _post_process_build_output(capability, out_dir)
    promoted_fuzzers = _promote_discovered_fuzzers(source_dir=source_dir, out_dir=out_dir)
    registry = scan_imported_build(
        task_id=task_id,
        build_out_dir=out_dir,
        harness_dir=source_dir / capability.harness_dir_name,
        build_dir=build_dir,
        mode="hybrid",
    )
    registry["artifacts"]["build_log"] = str(log_path)
    registry["artifacts"]["build_out_dir"] = str(out_dir)
    registry["build_command"] = command
    registry["build_capability"] = capability.to_dict()
    registry["staged_harness_sources"] = staged_asset_manifest.get("staged_in_source_dir", [])
    registry["staged_oss_fuzz_assets_src_root"] = staged_asset_manifest.get("staged_in_src_root", [])
    registry["promoted_fuzzers"] = promoted_fuzzers
    registry["build_script_adaptations"] = build_script_adaptations
    registry["optional_assets_handling"] = {
        "missing_optional_assets": staged_asset_manifest.get("missing_optional_assets", []),
        "graceful_degradation": True,
        "build_script_adaptations": build_script_adaptations,
    }
    registry["tracer_replay_binaries"] = [tracer_replay] if tracer_replay and tracer_replay.get("path") else []
    registry["coverage_fuzzers"] = coverage_variant.get("fuzzers", []) if coverage_variant else []
    if tracer_replay:
        registry["artifacts"]["tracer_build_log"] = tracer_replay.get("log_path")
    if coverage_variant:
        registry["artifacts"]["coverage_build_log"] = coverage_variant.get("log_path")
        registry["artifacts"]["coverage_build_out_dir"] = coverage_variant.get("build_out_dir")
    registry["build_variants"] = {
        "coverage_build": {
            "requested_mode": "dedicated_coverage_build",
            "actual_mode": (
                "dedicated_llvm_cov_build"
                if coverage_variant and coverage_variant.get("status") == "built" and coverage_variant.get("fuzzers")
                else "coverage_capable_fuzzer_build"
            ),
            "fallback_reason": (
                None
                if coverage_variant and coverage_variant.get("status") == "built" and coverage_variant.get("fuzzers")
                else (
                    coverage_variant.get("failure_reason")
                    if coverage_variant
                    else "coverage_variant_not_requested"
                )
            ),
            "fallback_effect": (
                None
                if coverage_variant and coverage_variant.get("status") == "built" and coverage_variant.get("fuzzers")
                else "coverage feedback falls back to sanitizer-enabled fuzz build without dedicated llvm profile mapping binary"
            ),
            "semantic_limitations": (
                []
                if coverage_variant and coverage_variant.get("status") == "built" and coverage_variant.get("fuzzers")
                else ["coverage may need to rely on libFuzzer stderr or partial profiling artifacts"]
            ),
        },
        "fuzzer_build": {
            "requested_mode": "dedicated_fuzzer_build",
            "actual_mode": "fresh_oss_fuzz_build",
            "fallback_reason": None,
            "fallback_effect": None,
            "semantic_limitations": [],
        },
        "tracer_build": {
            "requested_mode": "dedicated_tracer_build",
            "actual_mode": (
                "dedicated_asan_replay_binary"
                if tracer_replay and tracer_replay.get("path")
                else "reuse_fuzzer_build_for_replay"
            ),
            "fallback_reason": (
                None
                if tracer_replay and tracer_replay.get("path")
                else (
                    tracer_replay.get("failure_reason")
                    if tracer_replay
                    else "project_build_script_produced_single_fuzzer_artifact"
                )
            ),
            "fallback_effect": (
                None
                if tracer_replay and tracer_replay.get("path")
                else "replay uses the same sanitizer-enabled binary as fuzzing"
            ),
            "semantic_limitations": (
                []
                if tracer_replay and tracer_replay.get("path")
                else ["no replay-specific binary variant was emitted by the oss-fuzz build"]
            ),
        },
        "patch_qe_build": {
            "requested_mode": "patch_qe_usable_build",
            "actual_mode": "reuse_build_output_for_qe",
            "fallback_reason": "project_build_script_produced_single_fuzzer_artifact",
            "fallback_effect": "QE would reuse the same build output as fuzzing",
            "semantic_limitations": [
                "no dedicated patch/QE build variant was emitted",
            ],
        },
    }
    registry["build_environment"] = toolchain_info
    (build_dir / "build_registry.json").write_text(json.dumps(registry, indent=2), encoding="utf-8")
    return registry

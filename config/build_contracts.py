from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.utils.settings import PROJECT_ROOT


def write_build_options(project: str, build_out_dir: Path) -> Path | None:
    project = project.strip().lower()
    if project == "cjson":
        options_path = build_out_dir / "cjson_read_fuzzer.options"
        options_path.write_text("[libfuzzer]\nmax_len = 16777216\n", encoding="utf-8")
        return options_path
    if project == "inih":
        options_path = build_out_dir / "inihfuzz.options"
        options_path.write_text("[libfuzzer]\nmax_len = 512\n", encoding="utf-8")
        return options_path
    return None


def prepare_source(project: str, source_dir: Path) -> None:
    project = project.strip().lower()
    if project == "cjson":
        cjson_source = source_dir / "cJSON.c"
        if cjson_source.exists():
            content = cjson_source.read_text(encoding="utf-8")
            original = "    /*output_pointer[i] = '\\0';*/ // CWE-170\n"
            replacement = "    /* output_pointer[i] = '\\0'; */ /* CWE-170 */\n"
            if original in content:
                cjson_source.write_text(content.replace(original, replacement), encoding="utf-8")
        cmake_lists = source_dir / "CMakeLists.txt"
        if cmake_lists.exists():
            cmake_content = cmake_lists.read_text(encoding="utf-8")
            legacy = "cmake_minimum_required(VERSION 2.8.5)"
            modern = "cmake_minimum_required(VERSION 3.5)"
            if legacy in cmake_content:
                cmake_lists.write_text(cmake_content.replace(legacy, modern), encoding="utf-8")
        return
    if project == "libxml2":
        build_script = source_dir / "fuzz" / "oss-fuzz-build.sh"
        if not build_script.exists():
            return
        content = build_script.read_text(encoding="utf-8")
        original = "        $LIB_FUZZING_ENGINE \\\n        ../.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic\n"
        replacement = (
            "        $LIB_FUZZING_ENGINE \\\n"
            "        ../.libs/libxml2.a ${LIBXML2_EXTRA_LIBS:-} -Wl,-Bstatic -lz -Wl,-Bdynamic\n"
        )
        if original in content and "${LIBXML2_EXTRA_LIBS:-}" not in content:
            build_script.write_text(content.replace(original, replacement), encoding="utf-8")
        return
    if project == "inih":
        for generated in ("inihfuzz_replay_main.c",):
            candidate = source_dir / generated
            if candidate.exists():
                candidate.unlink()
        return
    if project == "miniz":
        cmake_lists = source_dir / "CMakeLists.txt"
        if not cmake_lists.exists():
            return
        content = cmake_lists.read_text(encoding="utf-8")
        legacy = "cmake_minimum_required(VERSION 3.0)"
        modern = "cmake_minimum_required(VERSION 3.5)"
        if legacy in content:
            cmake_lists.write_text(content.replace(legacy, modern), encoding="utf-8")


def stage_project_harness_assets(
    *,
    project: str,
    source_dir: Path,
    src_root: Path | None,
    oss_fuzz_project_dir: Path,
) -> dict[str, Any]:
    project = project.strip().lower()
    staged: list[str] = []
    staged_to_src_root: list[str] = []
    missing_optional_assets: list[str] = []

    if project == "inih":
        for name in ("inihfuzz.c",):
            src = oss_fuzz_project_dir / name
            dst = source_dir / name
            if src.exists():
                if not dst.exists():
                    shutil.copy2(src, dst)
                if str(dst) not in staged:
                    staged.append(str(dst))
                if src_root is not None:
                    root_dst = src_root / name
                    if not root_dst.exists():
                        shutil.copy2(src, root_dst)
                        staged_to_src_root.append(str(root_dst))
        return {
            "staged_in_source_dir": staged,
            "staged_in_src_root": staged_to_src_root,
            "missing_optional_assets": missing_optional_assets,
        }

    if project == "cjson":
        fuzzing_dir = source_dir / "fuzzing"
        if not (fuzzing_dir / "ossfuzz.sh").exists():
            fixture_dir = PROJECT_ROOT.parent / "benchmarks" / "cjson-injected" / "fuzzing"
            if fixture_dir.exists():
                shutil.copytree(fixture_dir, fuzzing_dir, dirs_exist_ok=True)
                for path in sorted(fuzzing_dir.rglob("*")):
                    if path.is_file() and str(path) not in staged:
                        staged.append(str(path))
    if project == "libspng":
        dependency_sources = {
            "zlib": "https://github.com/madler/zlib",
            "fuzzer-test-suite": "https://github.com/google/fuzzer-test-suite",
        }
        for dependency_name, repo_url in dependency_sources.items():
            destination = (src_root or source_dir) / dependency_name
            if destination.exists():
                continue
            completed = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(destination)],
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode == 0:
                staged_to_src_root.append(str(destination))
            else:
                missing_optional_assets.append(f"{dependency_name}:clone_failed")
    for optional_name in (
        f"{project}_seed_corpus.zip",
        f"{project}_fuzzer.options",
        f"{project}.dict",
        f"{project}.options",
        f"{project}.dict",
    ):
        if not (oss_fuzz_project_dir / optional_name).exists():
            missing_optional_assets.append(optional_name)
    return {
        "staged_in_source_dir": staged,
        "staged_in_src_root": staged_to_src_root,
        "missing_optional_assets": sorted(set(missing_optional_assets)),
    }


def tracer_replay_recipe(project: str) -> dict[str, Any] | None:
    project = project.strip().lower()
    if project == "cjson":
        return {
            "harness_name": "cjson_read_fuzzer",
            "output_name": "cjson_read_fuzzer_replay",
            "sources": ["fuzzing/fuzz_main.c", "fuzzing/cjson_read_fuzzer.c", "cJSON.c"],
            "include_dirs": ["."],
            "replay_main_prototype": None,
        }
    if project == "inih":
        return {
            "harness_name": "inihfuzz",
            "output_name": "inihfuzz_replay",
            "sources": ["inihfuzz_replay_main.c", "inihfuzz.c", "ini.c"],
            "include_dirs": ["."],
            "replay_main_prototype": "int LLVMFuzzerTestOneInput(const char *data, size_t size);",
        }
    return None


def fallback_build_recipe(project: str) -> dict[str, Any] | None:
    project = project.strip().lower()
    if project == "cjson":
        return {
            "output_name": "cjson_read_fuzzer",
            "sources": ["fuzzing/fuzz_main.c", "fuzzing/cjson_read_fuzzer.c", "cJSON.c"],
            "include_dirs": ["."],
            "dict_copy": {
                "source": "fuzzing/json.dict",
                "target": "cjson_read_fuzzer.dict",
            },
            "coverage_recipe": {
                "output_name": "cjson_read_fuzzer",
                "sources": ["fuzzing/fuzz_main.c", "fuzzing/cjson_read_fuzzer.c", "cJSON.c"],
                "include_dirs": ["."],
            },
        }
    return None

from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

TRUE_VALUES = {"1", "true", "yes", "on", "y", "t"}
FALSE_VALUES = {"0", "false", "no", "off", "n", "f"}
PROJECT_ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS_ROOT = PROJECT_ROOT / "benchmarks"


def parse_bool_env(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if not normalized:
        return default
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    return default


def parse_int_value(value: Any, default: int) -> int:
    if value is None or str(value).strip() == "":
        return default
    return int(str(value).strip())


def parse_float_value(value: Any, default: float) -> float:
    if value is None or str(value).strip() == "":
        return default
    return float(str(value).strip())


def parse_optional_int_value(value: Any) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    parsed = int(str(value).strip())
    if parsed == 0:
        return None
    return parsed


def is_remote_uri(value: str | None) -> bool:
    if not value:
        return False
    parsed = urlparse(str(value))
    return parsed.scheme in {"http", "https", "ssh", "git", "file"}


def expand_local_path(value: str | os.PathLike[str], *, base_dir: str | Path | None = None) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(str(value)))
    path = Path(expanded)
    if not path.is_absolute():
        root = Path(base_dir) if base_dir is not None else PROJECT_ROOT
        path = root / path
    return path.resolve()


@lru_cache(maxsize=32)
def _load_benchmark_config_from_path(path_str: str) -> dict[str, Any]:
    path = Path(path_str)
    if not path.exists() or not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=32)
def _find_benchmark_config_by_name(name: str) -> dict[str, Any]:
    for candidate in BENCHMARKS_ROOT.glob("**/benchmark.json"):
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if payload.get("name") == name:
            return payload
    return {}


def load_benchmark_config(metadata: dict[str, Any] | None) -> dict[str, Any]:
    metadata = metadata or {}
    explicit_path = metadata.get("benchmark_config_path")
    if explicit_path:
        return _load_benchmark_config_from_path(str(Path(explicit_path).expanduser().resolve()))
    benchmark_name = metadata.get("benchmark")
    if benchmark_name:
        return _find_benchmark_config_by_name(str(benchmark_name))
    return {}


def resolve_task_override(metadata: dict[str, Any] | None, key: str) -> Any:
    metadata = metadata or {}
    benchmark_config = load_benchmark_config(metadata)
    candidate_maps = [
        metadata,
        metadata.get("profile", {}),
        metadata.get("runtime_overrides", {}),
        metadata.get("config_overrides", {}),
        benchmark_config,
        benchmark_config.get("profile", {}),
        benchmark_config.get("runtime_overrides", {}),
        benchmark_config.get("config_overrides", {}),
    ]
    for source in candidate_maps:
        if isinstance(source, dict) and key in source:
            return source[key]
    return None


def resolve_text_setting(metadata: dict[str, Any] | None, key: str, default: str) -> str:
    override = resolve_task_override(metadata, key)
    if override is None or str(override).strip() == "":
        return default
    return str(override)


def resolve_int_setting(metadata: dict[str, Any] | None, key: str, default: int) -> int:
    override = resolve_task_override(metadata, key)
    return parse_int_value(override, default)


def resolve_float_setting(metadata: dict[str, Any] | None, key: str, default: float) -> float:
    override = resolve_task_override(metadata, key)
    return parse_float_value(override, default)


def resolve_bool_setting(metadata: dict[str, Any] | None, key: str, default: bool) -> bool:
    override = resolve_task_override(metadata, key)
    return parse_bool_env(override, default=default)


def resolve_optional_int_setting(
    metadata: dict[str, Any] | None,
    key: str,
    default: int | None,
) -> int | None:
    override = resolve_task_override(metadata, key)
    parsed = parse_optional_int_value(override)
    if parsed is not None:
        return parsed
    return default


@dataclass
class Settings:
    redis_url: str
    data_root: str
    queue_block_timeout: int
    scheduler_ready_hold_seconds: int
    llm_enabled: bool
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    llm_timeout_seconds: int
    llm_max_retries: int
    llm_temperature: float
    llm_max_tokens: int | None
    patch_ground_truth_mode: str
    seed_function_timeout_seconds: int
    seed_max_bytes: int
    seed_import_sample_limit: int
    seed_generation_attempts: int
    build_timeout_seconds: int
    fuzz_max_total_time_seconds: int
    fuzz_timeout_seconds: int
    fuzz_rss_limit_mb: int
    fuzz_max_len: int
    fuzz_abort_on_error: bool
    fuzz_fork_mode: bool
    fuzz_fork_jobs: int
    fuzz_ignore_crashes: bool
    fuzz_max_crashes_to_trace: int
    campaign_reseed_cooldown_rounds: int
    context_hop_budget_chars: int
    context_max_hops: int
    context_hop_keywords: str
    fuzz_seed_from_imported_valid_crashes: bool
    fuzz_imported_valid_seed_limit: int
    allow_imported_crash_fallback: bool
    allow_harness_switch: bool
    crash_source_policy: str
    replay_timeout_seconds: int
    repro_attempts: int
    binary_default_backend: str
    binary_wrapper_timeout_seconds: int
    ida_mcp_command: str
    ida_mcp_timeout_seconds: int
    binary_strings_limit: int
    binary_functions_limit: int
    build_toolchain_prefix: str
    program_model_toolchain_prefix: str
    coverage_sample_size: int
    oss_fuzz_root: str
    protocol_backend_root: str
    protocol_backend_task_json_name: str

    def _auto_ida_bridge_script(self) -> Path | None:
        script = PROJECT_ROOT / "scripts" / "ida_mcp_bridge.py"
        ida_root = PROJECT_ROOT / "ida_pro"
        if script.exists() and (ida_root / "idalib" / "python" / "idapro").exists():
            return script
        return None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/0"),
            data_root=os.getenv("DATA_ROOT", "/data/tasks"),
            queue_block_timeout=parse_int_value(os.getenv("QUEUE_BLOCK_TIMEOUT"), 2),
            scheduler_ready_hold_seconds=parse_int_value(os.getenv("SCHEDULER_READY_HOLD_SECONDS"), 0),
            llm_enabled=parse_bool_env(os.getenv("LLM_ENABLED"), default=True),
            llm_base_url=os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1"),
            llm_api_key=os.getenv("LLM_API_KEY", ""),
            llm_model=os.getenv("LLM_MODEL", "deepseek-chat"),
            llm_timeout_seconds=parse_int_value(os.getenv("LLM_TIMEOUT_SECONDS"), 300),
            llm_max_retries=parse_int_value(os.getenv("LLM_MAX_RETRIES"), 4),
            llm_temperature=parse_float_value(os.getenv("LLM_TEMPERATURE"), 0.35),
            llm_max_tokens=parse_optional_int_value(os.getenv("LLM_MAX_TOKENS")),
            patch_ground_truth_mode=os.getenv("PATCH_GROUND_TRUTH_MODE", "blind").strip() or "blind",
            seed_function_timeout_seconds=parse_int_value(os.getenv("SEED_FUNCTION_TIMEOUT_SECONDS"), 20),
            seed_max_bytes=parse_int_value(os.getenv("SEED_MAX_BYTES"), 262144),
            seed_import_sample_limit=parse_int_value(os.getenv("SEED_IMPORT_SAMPLE_LIMIT"), 64),
            seed_generation_attempts=parse_int_value(os.getenv("SEED_GENERATION_ATTEMPTS"), 6),
            build_timeout_seconds=parse_int_value(os.getenv("BUILD_TIMEOUT_SECONDS"), 1200),
            fuzz_max_total_time_seconds=parse_int_value(os.getenv("FUZZ_MAX_TOTAL_TIME_SECONDS"), 180),
            fuzz_timeout_seconds=parse_int_value(os.getenv("FUZZ_TIMEOUT_SECONDS"), 10),
            fuzz_rss_limit_mb=parse_int_value(os.getenv("FUZZ_RSS_LIMIT_MB"), 2048),
            fuzz_max_len=parse_int_value(os.getenv("FUZZ_MAX_LEN"), 262144),
            fuzz_abort_on_error=parse_bool_env(os.getenv("FUZZ_ABORT_ON_ERROR"), default=False),
            fuzz_fork_mode=parse_bool_env(os.getenv("FUZZ_FORK_MODE"), default=True),
            fuzz_fork_jobs=parse_int_value(os.getenv("FUZZ_FORK_JOBS"), 1),
            fuzz_ignore_crashes=parse_bool_env(os.getenv("FUZZ_IGNORE_CRASHES"), default=True),
            fuzz_max_crashes_to_trace=parse_int_value(os.getenv("FUZZ_MAX_CRASHES_TO_TRACE"), 50),
            campaign_reseed_cooldown_rounds=parse_int_value(
                os.getenv("CAMPAIGN_RESEED_COOLDOWN_ROUNDS"),
                3,
            ),
            context_hop_budget_chars=parse_int_value(os.getenv("CONTEXT_HOP_BUDGET_CHARS"), 6000),
            context_max_hops=parse_int_value(os.getenv("CONTEXT_MAX_HOPS"), 2),
            context_hop_keywords=os.getenv(
                "CONTEXT_HOP_KEYWORDS",
                "parse,read,alloc,free,len,size,bound,check",
            ),
            fuzz_seed_from_imported_valid_crashes=parse_bool_env(
                os.getenv("FUZZ_SEED_FROM_IMPORTED_VALID_CRASHES"),
                default=True,
            ),
            fuzz_imported_valid_seed_limit=parse_int_value(os.getenv("FUZZ_IMPORTED_VALID_SEED_LIMIT"), 4),
            allow_imported_crash_fallback=parse_bool_env(
                os.getenv("ALLOW_IMPORTED_CRASH_FALLBACK"),
                default=False,
            ),
            allow_harness_switch=parse_bool_env(os.getenv("ALLOW_HARNESS_SWITCH"), default=False),
            crash_source_policy=os.getenv("CRASH_SOURCE_POLICY", "live_raw_only"),
            replay_timeout_seconds=parse_int_value(os.getenv("REPLAY_TIMEOUT_SECONDS"), 60),
            repro_attempts=parse_int_value(os.getenv("REPRO_ATTEMPTS"), 5),
            binary_default_backend=os.getenv("BINARY_DEFAULT_BACKEND", "auto"),
            binary_wrapper_timeout_seconds=parse_int_value(os.getenv("BINARY_WRAPPER_TIMEOUT_SECONDS"), 300),
            ida_mcp_command=os.getenv("IDA_MCP_COMMAND", "").strip(),
            ida_mcp_timeout_seconds=parse_int_value(os.getenv("IDA_MCP_TIMEOUT_SECONDS"), 1200),
            binary_strings_limit=parse_int_value(os.getenv("BINARY_STRINGS_LIMIT"), 20000),
            binary_functions_limit=parse_int_value(os.getenv("BINARY_FUNCTIONS_LIMIT"), 20000),
            build_toolchain_prefix=os.getenv(
                "BUILD_TOOLCHAIN_PREFIX",
                str(PROJECT_ROOT / ".toolchains" / "build-env"),
            ),
            program_model_toolchain_prefix=os.getenv(
                "PROGRAM_MODEL_TOOLCHAIN_PREFIX",
                str(PROJECT_ROOT / ".toolchains" / "program-model-env"),
            ),
            coverage_sample_size=parse_int_value(os.getenv("COVERAGE_SAMPLE_SIZE"), 8),
            oss_fuzz_root=os.getenv(
                "OSS_FUZZ_ROOT",
                "/home/buttercup2/Project/oss-fuzz/oss-fuzz",
            ),
            protocol_backend_root=os.getenv(
                "PROTO_BACKEND_ROOT",
                "/home/buttercup2/protocol_seed/proto-fuzz-3dockers",
            ),
            protocol_backend_task_json_name=os.getenv(
                "PROTO_BACKEND_TASK_JSON_NAME",
                "protocol/task.json",
            ),
        )

    def ida_mcp_configured(self) -> bool:
        return bool(self.ida_mcp_command.strip()) or self._auto_ida_bridge_script() is not None

    def ida_mcp_command_argv(self) -> list[str]:
        if self.ida_mcp_command.strip():
            return shlex.split(self.ida_mcp_command)
        script = self._auto_ida_bridge_script()
        if script is None:
            return []
        return ["python3", str(script)]


settings = Settings.from_env()

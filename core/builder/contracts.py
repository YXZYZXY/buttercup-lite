from __future__ import annotations

from dataclasses import asdict, dataclass
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BuildCapability:
    project: str
    source_checkout_name: str
    harness_dir_name: str
    supports_fresh_build: bool = True
    origin: str = "registry"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OssFuzzProjectContract:
    project_root_path: str | None
    project_yaml_path: str | None
    project_root_exists: bool
    project_yaml_exists: bool
    valid: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BuildDecision:
    decision: str
    execution_mode: str
    execute_builder: bool
    supported: bool
    reason: str
    imported_build_path: str | None
    capability: BuildCapability | None
    oss_fuzz_project_contract: OssFuzzProjectContract
    auto_resolved: bool
    registry_fallback_used: bool

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["capability"] = self.capability.to_dict() if self.capability else None
        payload["oss_fuzz_project_contract"] = self.oss_fuzz_project_contract.to_dict()
        return payload


BUILD_CAPABILITIES: dict[str, BuildCapability] = {
    "cjson": BuildCapability(
        project="cjson",
        source_checkout_name="cjson",
        harness_dir_name="fuzzing",
    ),
    "libxml2": BuildCapability(
        project="libxml2",
        source_checkout_name="libxml2",
        harness_dir_name="fuzz",
    ),
    "inih": BuildCapability(
        project="inih",
        source_checkout_name="inih",
        harness_dir_name=".",
    ),
}


def resolve_build_capability(project_name: str | None) -> BuildCapability | None:
    key = (project_name or "").strip().lower()
    if not key:
        return None
    return BUILD_CAPABILITIES.get(key)


def infer_build_capability(
    *,
    project_name: str | None,
    source_dir: str | Path | None = None,
    source_resolution: dict[str, Any] | None = None,
) -> BuildCapability | None:
    project = (
        (source_resolution or {}).get("selected_oss_fuzz_project")
        or project_name
        or ""
    ).strip().lower()
    if not project:
        return None

    source_root = Path(source_dir).expanduser().resolve() if source_dir else None
    source_checkout_name = source_root.name if source_root else project
    if source_checkout_name.lower() in {"src", "source", "current", "checkout"}:
        source_checkout_name = project
    harness_dir_name = "."
    harness_paths: list[Path] = []
    for item in (source_resolution or {}).get("discovered_harnesses", []):
        raw_path = item.get("path")
        if not raw_path:
            continue
        candidate = Path(raw_path)
        if source_root and candidate.exists():
            try:
                harness_paths.append(candidate.resolve().relative_to(source_root).parent)
            except ValueError:
                continue
    if harness_paths:
        common = harness_paths[0]
        for candidate in harness_paths[1:]:
            common = Path(os.path.commonpath([str(common), str(candidate)]))
        harness_dir_name = common.as_posix() or "."
    elif project in BUILD_CAPABILITIES:
        harness_dir_name = BUILD_CAPABILITIES[project].harness_dir_name

    return BuildCapability(
        project=project,
        source_checkout_name=source_checkout_name,
        harness_dir_name=harness_dir_name,
        supports_fresh_build=True,
        origin="auto_resolution",
    )


def resolve_oss_fuzz_project_contract(
    project_root_path: str | None,
    project_yaml_path: str | None,
) -> OssFuzzProjectContract:
    root_exists = bool(project_root_path and Path(project_root_path).exists())
    yaml_exists = bool(project_yaml_path and Path(project_yaml_path).exists())
    valid = root_exists
    if root_exists:
        reason = "project_root_present"
    elif yaml_exists:
        reason = "project_yaml_without_project_root"
    else:
        reason = "oss_fuzz_project_missing"
    return OssFuzzProjectContract(
        project_root_path=project_root_path,
        project_yaml_path=project_yaml_path,
        project_root_exists=root_exists,
        project_yaml_exists=yaml_exists,
        valid=valid,
        reason=reason,
    )


def resolve_oss_fuzz_project_contract_from_import_manifest(import_manifest: dict[str, Any]) -> OssFuzzProjectContract:
    resolved_paths = import_manifest.get("resolved_paths", {})
    return resolve_oss_fuzz_project_contract(
        resolved_paths.get("existing_oss_fuzz_project_path"),
        resolved_paths.get("existing_project_yaml_path"),
    )


def resolve_oss_fuzz_project_contract_from_resolved_imports(resolved_imports: dict[str, Any]) -> OssFuzzProjectContract:
    return resolve_oss_fuzz_project_contract(
        resolved_imports.get("existing_oss_fuzz_project_path"),
        resolved_imports.get("existing_project_yaml_path"),
    )


def resolve_build_decision(
    *,
    project_name: str | None,
    imported_build_path: str | None,
    oss_fuzz_project_contract: OssFuzzProjectContract,
    source_dir: str | Path | None = None,
    source_resolution: dict[str, Any] | None = None,
    task_id: str | None = None,
) -> BuildDecision:
    capability = infer_build_capability(
        project_name=project_name,
        source_dir=source_dir,
        source_resolution=source_resolution,
    )
    registry_fallback_used = False
    auto_resolved = capability is not None and capability.origin == "auto_resolution"
    if capability is None:
        capability = resolve_build_capability(project_name)
        registry_fallback_used = capability is not None
        auto_resolved = False
    if imported_build_path and Path(imported_build_path).exists():
        return BuildDecision(
            decision="import_assisted",
            execution_mode="import_assisted",
            execute_builder=True,
            supported=True,
            reason="imported_build_out_present",
            imported_build_path=imported_build_path,
            capability=capability,
            oss_fuzz_project_contract=oss_fuzz_project_contract,
            auto_resolved=auto_resolved,
            registry_fallback_used=registry_fallback_used,
        )
    if capability is not None and oss_fuzz_project_contract.valid:
        return BuildDecision(
            decision="fresh_build",
            execution_mode="hybrid",
            execute_builder=True,
            supported=True,
            reason="fresh_build_capable",
            imported_build_path=None,
            capability=capability,
            oss_fuzz_project_contract=oss_fuzz_project_contract,
            auto_resolved=auto_resolved,
            registry_fallback_used=registry_fallback_used,
        )
    decision = BuildDecision(
        decision="unsupported",
        execution_mode="fresh",
        execute_builder=True,
        supported=False,
        reason=(
            "missing_oss_fuzz_project_root"
            if capability is not None and not oss_fuzz_project_contract.valid
            else "no_fresh_build_capability"
        ),
        imported_build_path=None,
        capability=capability,
        oss_fuzz_project_contract=oss_fuzz_project_contract,
        auto_resolved=auto_resolved,
        registry_fallback_used=registry_fallback_used,
    )
    logger.warning(
        "[%s] fresh build 不支持：project_yaml_exists=%s 但 project_root_exists=%s，需要提供完整的 existing_oss_fuzz_project_path 而不仅是 project_yaml_path",
        task_id or "unknown-task",
        oss_fuzz_project_contract.project_yaml_exists,
        oss_fuzz_project_contract.project_root_exists,
    )
    return decision

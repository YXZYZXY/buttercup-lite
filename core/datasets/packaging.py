from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def package_binary(
    *,
    project_name: str,
    layer: str,
    binary_path: Path,
    launcher_path: Path,
    output_root: Path,
    binary_kind: str = "fuzzer_binary",
    contract_kind: str,
    contract_hints: list[str],
    optional_sidecars: dict[str, Path | None] | None = None,
    provenance: dict[str, Any] | None = None,
    source_task_id: str | None = None,
    source_src_path: Path | None = None,
    source_index_path: Path | None = None,
    strip_symbols: bool = False,
) -> dict[str, Any]:
    package_dir = output_root / layer / project_name
    package_dir.mkdir(parents=True, exist_ok=True)

    packaged_binary = package_dir / binary_path.name
    shutil.copy2(binary_path, packaged_binary)
    packaged_launcher = package_dir / launcher_path.name
    shutil.copy2(launcher_path, packaged_launcher)

    visibility_constraints = {
        "layer": layer,
        "source_access_allowed": layer == "source-full",
        "binary_only_runtime": layer != "source-full",
        "sidecar_level": "opaque-reduced" if strip_symbols else "source-derived",
    }
    strip_result: dict[str, Any] | None = None
    if strip_symbols:
        stripped_path = package_dir / f"{packaged_binary.name}.stripped"
        shutil.copy2(packaged_binary, stripped_path)
        completed = subprocess.run(
            ["strip", "--strip-all", str(stripped_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        packaged_binary = stripped_path
        strip_result = {
            "command": ["strip", "--strip-all", str(stripped_path)],
            "return_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }

    copied_sidecars: dict[str, str] = {}
    for key, source in (optional_sidecars or {}).items():
        if source is None or not source.exists():
            continue
        target = package_dir / source.name
        if source.resolve() != target.resolve():
            shutil.copy2(source, target)
        copied_sidecars[key] = str(target)

    normalized_provenance = provenance or {}
    normalized_source_task_id = source_task_id or normalized_provenance.get("source_task_id")
    manifest = {
        "project_name": project_name,
        "layer": layer,
        "binary_path": str(packaged_binary),
        "binary_kind": binary_kind,
        "launcher_path": str(packaged_launcher),
        "contract_kind": contract_kind,
        "contract_hints": contract_hints,
        "optional_sidecar": copied_sidecars,
        "provenance": normalized_provenance,
        "source_task_id": normalized_source_task_id,
        "source_src_path": str(source_src_path.resolve()) if source_src_path else None,
        "source_index_path": str(source_index_path.resolve()) if source_index_path else None,
        "strip_result": strip_result,
    }
    manifest_path = _write_json(package_dir / "binary_package_manifest.json", manifest)
    provenance_path = _write_json(
        package_dir / "binary_dataset_provenance_manifest.json",
        {
            "project_name": project_name,
            "layer": layer,
            "binary_path": str(packaged_binary),
            "source_binary_relationship": normalized_provenance,
        },
    )
    visibility_path = _write_json(
        package_dir / "binary_visibility_constraints.json",
        visibility_constraints,
    )
    manifest.update(
        {
            "binary_package_manifest_path": manifest_path,
            "binary_dataset_provenance_manifest_path": provenance_path,
            "binary_visibility_constraints_path": visibility_path,
        }
    )
    return manifest

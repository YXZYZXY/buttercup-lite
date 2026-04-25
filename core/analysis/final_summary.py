from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_final_campaign_summary(
    *,
    source_campaign_root: Path,
    binary_campaign_root: Path,
    output_path: Path,
) -> Path:
    source_inventory = _load_json(source_campaign_root / "reports" / "pov_inventory.json")
    source_coverage = _load_json(source_campaign_root / "reports" / "vuln_coverage.json")
    source_manifest = _load_json(source_campaign_root / "runtime" / "campaign_manifest.json")
    binary_inventory = _load_json(binary_campaign_root / "reports" / "pov_inventory.json")
    binary_coverage = _load_json(binary_campaign_root / "reports" / "vuln_coverage.json")
    binary_manifest = _load_json(binary_campaign_root / "runtime" / "campaign_manifest.json")

    source_found = set(source_coverage.get("found_vuln_ids", []))
    binary_found = set(binary_coverage.get("found_vuln_ids", []))
    summary = {
        "source_side": {
            "campaign_task_id": source_inventory["campaign_task_id"],
            "campaign_duration_seconds": source_manifest.get("campaign_duration_seconds"),
            "iterations_total": source_manifest.get("iterations_total", len(source_manifest.get("rounds", []))),
            "fuzz_time_total_seconds": source_manifest.get("fuzz_time_total_seconds"),
            "pov_file_count": source_inventory.get("total_pov_count", 0),
            "distinct_crash_signatures": source_inventory.get("distinct_signature_count", 0),
            "distinct_pov_clusters": source_inventory.get("distinct_signature_count", 0),
            "distinct_vuln_count": source_coverage.get("found_vuln_count", 0),
            "found_vuln_ids": source_coverage.get("found_vuln_ids", []),
            "missing_vuln_ids": source_coverage.get("missing_vuln_ids", []),
        },
        "binary_side": {
            "campaign_task_id": binary_inventory["campaign_task_id"],
            "campaign_duration_seconds": binary_manifest.get("campaign_duration_seconds"),
            "iterations_total": binary_manifest.get("iterations_total", len(binary_manifest.get("rounds", []))),
            "fuzz_time_total_seconds": binary_manifest.get("fuzz_time_total_seconds"),
            "pov_file_count": binary_inventory.get("total_pov_count", 0),
            "distinct_crash_signatures": binary_inventory.get("distinct_signature_count", 0),
            "distinct_pov_clusters": binary_inventory.get("distinct_signature_count", 0),
            "distinct_vuln_count": binary_coverage.get("found_vuln_count", 0),
            "found_vuln_ids": binary_coverage.get("found_vuln_ids", []),
            "missing_vuln_ids": binary_coverage.get("missing_vuln_ids", []),
        },
        "comparison": {
            "found_by_both": sorted(source_found & binary_found),
            "found_only_by_source": sorted(source_found - binary_found),
            "found_only_by_binary": sorted(binary_found - source_found),
            "missing_in_both": sorted(
                set(source_coverage.get("missing_vuln_ids", [])) & set(binary_coverage.get("missing_vuln_ids", [])),
            ),
            "likely_reasons": [
                "current campaign still concentrates on a narrow set of active harnesses and execution targets",
                "seed diversity is improving corpus breadth, but not yet enough to drive the remaining injected sites",
                "runtime is sustained now, but still shorter than a long fuzz farm campaign",
                "binary path remains source_derived_binary and inherits source-side launcher semantics",
            ],
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return output_path

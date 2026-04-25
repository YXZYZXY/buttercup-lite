from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.analysis.signature_index import build_signature_index
from core.analysis.vuln_attribution import attribute_traced_crash, load_ground_truth
from core.storage.layout import pov_inventory_path, pov_lineage_path, signature_index_report_path, vuln_coverage_path


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _task_root(data_root: Path, task_id: str) -> Path:
    return data_root / task_id


def build_campaign_reports(
    *,
    campaign_task_id: str,
    origin_task_ids: list[str],
    ground_truth_path: str | Path,
    data_root: Path,
) -> dict[str, Any]:
    reports_root = pov_inventory_path(campaign_task_id).parent
    reports_root.mkdir(parents=True, exist_ok=True)
    ground_truth = load_ground_truth(ground_truth_path)
    inventory_records: list[dict[str, Any]] = []
    round_records: list[dict[str, Any]] = []

    for round_number, origin_task_id in enumerate(origin_task_ids, start=1):
        origin_root = _task_root(data_root, origin_task_id)
        task_payload = _load_json(origin_root / "task.json")
        task_runtime = task_payload.get("runtime", {})
        target_mode = task_payload.get("metadata", {}).get("target_mode") or task_payload.get("runtime", {}).get("target_mode") or "source"
        pov_dir = origin_root / "pov" / "confirmed"
        trace_dir = origin_root / "trace" / "traced_crashes"
        pov_files = sorted(pov_dir.glob("*.json"))
        traced_files = sorted(trace_dir.glob("*.json"))
        traced_by_stem = {path.stem: path for path in traced_files}
        traced_by_signature = {}
        for traced_path in traced_files:
            traced_payload = _load_json(traced_path)
            traced_by_signature.setdefault(traced_payload.get("signature"), traced_path)

        round_records.append(
            {
                "round": round_number,
                "origin_task_id": origin_task_id,
                "target_mode": target_mode,
                "status": task_payload.get("status"),
                "pov_count": len(pov_files),
                "traced_crash_count": len(traced_files),
            }
        )

        for pov_path in pov_files:
            pov_payload = _load_json(pov_path)
            traced_path = traced_by_stem.get(pov_path.stem)
            if traced_path is None:
                traced_path = traced_by_signature.get(pov_payload.get("source_crash_signature"))
            traced_payload = _load_json(traced_path) if traced_path else {}
            attribution = attribute_traced_crash(traced_payload, ground_truth, task_root=origin_root)
            inventory_records.append(
                {
                    "task_id": origin_task_id,
                    "target_mode": traced_payload.get("target_mode") or target_mode,
                    "harness": traced_payload.get("harness_name", pov_payload.get("fuzzer_name")),
                    "signature": pov_payload.get("source_crash_signature"),
                    "crash_type": traced_payload.get("crash_type"),
                    "crash_source": traced_payload.get("crash_source", pov_payload.get("crash_source")),
                    "pov_path": str(pov_path),
                    "raw_crash_path": traced_payload.get("testcase_path"),
                    "traced_crash_path": str(traced_path) if traced_path else None,
                    "first_seen_at": task_runtime.get("repro_completed_at") or task_runtime.get("trace_completed_at"),
                    "first_seen_iteration_hint": round_number,
                    "attributed_vuln_id": attribution["attributed_vuln_id"],
                    "confidence": attribution["attribution_confidence"],
                    "attribution_reason": attribution["attribution_reason"],
                    "matched_file": attribution["matched_file"],
                    "matched_function": attribution["matched_function"],
                    "matched_line_range": attribution["matched_line_range"],
                    "symbolized_frames": attribution["symbolized_frames"][:5],
                }
            )

    signature_index = build_signature_index(inventory_records)
    first_seen_by_signature: dict[str, dict[str, Any]] = {}
    for item in sorted(
        inventory_records,
        key=lambda entry: (
            entry.get("first_seen_iteration_hint", 0),
            entry.get("first_seen_at") or "",
            entry.get("pov_path") or "",
        ),
    ):
        signature = item.get("signature")
        if signature and signature not in first_seen_by_signature:
            first_seen_by_signature[signature] = item
    distinct_records = [
        {
            "signature": signature,
            "harness": record["pov_paths"][0] and next(
                item["harness"] for item in inventory_records if item["signature"] == signature
            ),
            "target_mode": next(item["target_mode"] or "source" for item in inventory_records if item["signature"] == signature),
            "crash_type": next(item["crash_type"] for item in inventory_records if item["signature"] == signature),
            "attributed_vuln_id": next(item["attributed_vuln_id"] for item in inventory_records if item["signature"] == signature),
            "confidence": next(item["confidence"] for item in inventory_records if item["signature"] == signature),
            "pov_path": record["pov_paths"][0] if record["pov_paths"] else None,
        }
        for signature, record in sorted(signature_index.items())
    ]
    lineage_records = []
    for item in sorted(
        inventory_records,
        key=lambda entry: (
            entry.get("first_seen_iteration_hint", 0),
            entry.get("first_seen_at") or "",
            entry.get("pov_path") or "",
        ),
    ):
        signature = item.get("signature")
        first_seen = first_seen_by_signature.get(signature, {})
        first_pov_path = first_seen.get("pov_path")
        is_distinct = bool(signature and item.get("pov_path") == first_pov_path)
        lineage_records.append(
            {
                "pov_path": item.get("pov_path"),
                "raw_crash_path": item.get("raw_crash_path"),
                "traced_crash_path": item.get("traced_crash_path"),
                "signature": signature,
                "attributed_vuln_id": item.get("attributed_vuln_id"),
                "attribution_confidence": item.get("confidence"),
                "target_mode": item.get("target_mode"),
                "harness_or_binary_target": item.get("harness"),
                "first_seen_iteration": first_seen.get("first_seen_iteration_hint"),
                "first_seen_at": first_seen.get("first_seen_at"),
                "is_distinct": is_distinct,
                "is_duplicate_of": None if is_distinct else first_pov_path,
            }
        )

    found_vuln_ids = sorted(
        {
            item["attributed_vuln_id"]
            for item in inventory_records
            if item.get("attributed_vuln_id")
        }
    )
    expected_vuln_ids = [item["vuln_id"] for item in ground_truth.get("vulnerabilities", [])]
    missing_vuln_ids = sorted(set(expected_vuln_ids) - set(found_vuln_ids))
    ambiguous_matches = [
        {
            "signature": item["signature"],
            "pov_path": item["pov_path"],
            "reason": item["attribution_reason"],
        }
        for item in inventory_records
        if item["attributed_vuln_id"] is None or item["confidence"] == "low"
    ]

    source_side_found = {
        item["attributed_vuln_id"]
        for item in inventory_records
        if item.get("attributed_vuln_id") and item.get("target_mode") != "binary"
    }
    binary_side_found = {
        item["attributed_vuln_id"]
        for item in inventory_records
        if item.get("attributed_vuln_id") and item.get("target_mode") == "binary"
    }

    pov_inventory = {
        "campaign_task_id": campaign_task_id,
        "total_pov_count": len(inventory_records),
        "distinct_signature_count": len(signature_index),
        "distinct_vuln_count": len(found_vuln_ids),
        "distinct_pov_paths": sorted({item["pov_path"] for item in inventory_records}),
        "rounds": round_records,
        "distinct_povs": distinct_records,
    }
    coverage = {
        "campaign_task_id": campaign_task_id,
        "expected_vuln_count": len(expected_vuln_ids),
        "found_vuln_count": len(found_vuln_ids),
        "found_vuln_ids": found_vuln_ids,
        "missing_vuln_ids": missing_vuln_ids,
        "ambiguous_matches": ambiguous_matches,
        "source_side_found_count": len(source_side_found),
        "binary_side_found_count": len(binary_side_found),
    }

    pov_inventory_path(campaign_task_id).write_text(json.dumps(pov_inventory, indent=2), encoding="utf-8")
    vuln_coverage_path(campaign_task_id).write_text(json.dumps(coverage, indent=2), encoding="utf-8")
    signature_index_report_path(campaign_task_id).write_text(
        json.dumps(signature_index, indent=2),
        encoding="utf-8",
    )
    pov_lineage_path(campaign_task_id).write_text(json.dumps(lineage_records, indent=2), encoding="utf-8")

    return {
        "pov_inventory": pov_inventory,
        "vuln_coverage": coverage,
        "signature_index": signature_index,
        "pov_lineage": lineage_records,
        "round_records": round_records,
        "pov_inventory_path": str(pov_inventory_path(campaign_task_id)),
        "vuln_coverage_path": str(vuln_coverage_path(campaign_task_id)),
        "signature_index_path": str(signature_index_report_path(campaign_task_id)),
        "pov_lineage_path": str(pov_lineage_path(campaign_task_id)),
    }

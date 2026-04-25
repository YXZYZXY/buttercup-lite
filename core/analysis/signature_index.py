from __future__ import annotations

from typing import Any


def build_signature_index(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in items:
        signature = item.get("signature")
        if not signature:
            continue
        record = index.setdefault(
            signature,
            {
                "signature": signature,
                "count": 0,
                "pov_paths": [],
                "traced_crash_paths": [],
                "target_modes": [],
                "task_ids": [],
                "attributed_vuln_ids": [],
            },
        )
        record["count"] += 1
        if item.get("pov_path") and item["pov_path"] not in record["pov_paths"]:
            record["pov_paths"].append(item["pov_path"])
        if item.get("traced_crash_path") and item["traced_crash_path"] not in record["traced_crash_paths"]:
            record["traced_crash_paths"].append(item["traced_crash_path"])
        if item.get("target_mode") and item["target_mode"] not in record["target_modes"]:
            record["target_modes"].append(item["target_mode"])
        if item.get("task_id") and item["task_id"] not in record["task_ids"]:
            record["task_ids"].append(item["task_id"])
        vuln_id = item.get("attributed_vuln_id")
        if vuln_id and vuln_id not in record["attributed_vuln_ids"]:
            record["attributed_vuln_ids"].append(vuln_id)
    return index

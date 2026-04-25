from __future__ import annotations

from pathlib import Path
from typing import Any

from core.analysis.pov_inventory import build_campaign_reports


def build_offline_campaign_reports(
    *,
    campaign_task_id: str,
    origin_task_ids: list[str],
    ground_truth_path: str | Path,
    data_root: Path,
) -> dict[str, Any]:
    return build_campaign_reports(
        campaign_task_id=campaign_task_id,
        origin_task_ids=origin_task_ids,
        ground_truth_path=ground_truth_path,
        data_root=data_root,
    )

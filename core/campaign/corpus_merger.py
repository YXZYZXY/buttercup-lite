from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.campaign.corpus_quality import build_corpus_entry, quality_gate_for_entry, safe_corpus_component

_POLICIES: dict[str, dict[str, int]] = {
    "seed_import": {"max_files": 64, "max_bytes": 16 * 1024 * 1024, "per_semantic_limit": 2},
    "seed_active": {"max_files": 256, "max_bytes": 64 * 1024 * 1024, "per_semantic_limit": 2},
    "round_local": {"max_files": 256, "max_bytes": 64 * 1024 * 1024, "per_semantic_limit": 2},
    "campaign_shared": {"max_files": 512, "max_bytes": 128 * 1024 * 1024, "per_semantic_limit": 2},
    "campaign_harness": {"max_files": 512, "max_bytes": 128 * 1024 * 1024, "per_semantic_limit": 2},
    "system_shared": {"max_files": 1024, "max_bytes": 256 * 1024 * 1024, "per_semantic_limit": 2},
    "system_harness": {"max_files": 1024, "max_bytes": 256 * 1024 * 1024, "per_semantic_limit": 2},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def corpus_policy(kind: str) -> dict[str, int]:
    return dict(_POLICIES.get(kind, _POLICIES["round_local"]))


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _iter_files(root: Path) -> list[Path]:
    if not root or not root.exists():
        return []
    return [candidate for candidate in sorted(root.rglob("*")) if candidate.is_file()]


def _load_index_rows(index_path: str | Path | None) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if not index_path:
        return {}, {}
    payload = _read_json(Path(index_path), {})
    rows = list(payload.get("files") or payload.get("selected_files") or [])
    by_digest: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        digest = str(row.get("exact_digest") or "").strip()
        if digest and digest not in by_digest:
            by_digest[digest] = row
        name = str(row.get("destination_name") or row.get("name") or "").strip()
        if name and name not in by_name:
            by_name[name] = row
    return by_digest, by_name


def _source_sort_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    return (
        float(candidate.get("quality_score") or 0.0),
        float(candidate.get("transfer_priority_boost") or 0.0),
        float(candidate.get("priority_weight") or 0.0),
        1 if candidate.get("is_existing_destination") else 0,
        -int(candidate.get("file_size") or 0),
        str(candidate.get("path") or ""),
    )


def _scan_layer(layer: dict[str, Any]) -> list[dict[str, Any]]:
    root = Path(layer["root"])
    prior_by_digest, prior_by_name = _load_index_rows(layer.get("index_path"))
    allowed_paths = {
        str(Path(path).resolve())
        for path in (layer.get("allowed_paths") or [])
        if str(path).strip()
    }
    rows: list[dict[str, Any]] = []
    for file_path in _iter_files(root):
        if allowed_paths and str(file_path.resolve()) not in allowed_paths:
            continue
        try:
            entry = build_corpus_entry(
                file_path,
                source_label=str(layer.get("label") or "unknown"),
                priority_weight=float(layer.get("priority_weight")) if layer.get("priority_weight") is not None else None,
                scope=layer.get("scope"),
                project=layer.get("project"),
                lane=layer.get("lane"),
                target_mode=layer.get("target_mode"),
                harness=layer.get("harness"),
                task_id=layer.get("task_id"),
                campaign_task_id=layer.get("campaign_task_id"),
                is_existing_destination=bool(layer.get("is_existing_destination")),
            )
        except FileNotFoundError:
            # Shared corpus pools are updated concurrently; a file can disappear
            # after enumeration but before we sample it. Skipping the vanished
            # file preserves campaign continuity without changing merge policy.
            continue
        prior = prior_by_digest.get(str(entry.get("exact_digest") or "")) or prior_by_name.get(file_path.name)
        if prior:
            for key in ("project", "lane", "target_mode", "task_id", "campaign_task_id"):
                if prior.get(key) and not entry.get(key):
                    entry[key] = prior.get(key)
            if prior.get("harness") and not entry.get("harness"):
                entry["harness"] = prior.get("harness")
            entry["origin_source_label"] = (
                prior.get("origin_source_label") or prior.get("source_label") or entry.get("source_label")
            )
            entry["origin_scope"] = prior.get("origin_scope") or prior.get("scope") or entry.get("scope")
            entry["origin_harness"] = prior.get("origin_harness") or prior.get("harness") or entry.get("harness")
            entry["origin_project"] = prior.get("origin_project") or prior.get("project") or entry.get("project")
            entry["origin_lane"] = prior.get("origin_lane") or prior.get("lane") or entry.get("lane")
            entry["origin_target_mode"] = (
                prior.get("origin_target_mode") or prior.get("target_mode") or entry.get("target_mode")
            )
            entry["origin_task_id"] = prior.get("origin_task_id") or prior.get("task_id") or entry.get("task_id")
            entry["origin_campaign_task_id"] = (
                prior.get("origin_campaign_task_id") or prior.get("campaign_task_id") or entry.get("campaign_task_id")
            )
            entry["origin_selected_target_function"] = (
                prior.get("origin_selected_target_function") or prior.get("selected_target_function")
            )
            entry["origin_signal"] = prior.get("origin_signal")
            entry["origin_input_role"] = prior.get("origin_input_role")
            entry["origin_import_reason"] = prior.get("origin_import_reason")
            entry["export_reason"] = prior.get("export_reason")
        else:
            entry["origin_source_label"] = entry.get("source_label")
            entry["origin_scope"] = entry.get("scope")
            entry["origin_harness"] = entry.get("harness")
            entry["origin_project"] = entry.get("project")
            entry["origin_lane"] = entry.get("lane")
            entry["origin_target_mode"] = entry.get("target_mode")
            entry["origin_task_id"] = entry.get("task_id")
            entry["origin_campaign_task_id"] = entry.get("campaign_task_id")
            entry["origin_selected_target_function"] = layer.get("selected_target_function")
            entry["origin_signal"] = layer.get("origin_signal")
            entry["origin_input_role"] = layer.get("origin_input_role")
            entry["origin_import_reason"] = layer.get("import_reason")
            entry["export_reason"] = layer.get("export_reason")
        entry["selected_target_function"] = layer.get("selected_target_function")
        entry["import_reason"] = layer.get("import_reason")
        entry["selection_reason"] = layer.get("selection_reason")
        entry["consumer_project"] = layer.get("consumer_project")
        entry["consumer_lane"] = layer.get("consumer_lane")
        entry["consumer_target_mode"] = layer.get("consumer_target_mode")
        entry["consumer_harness"] = layer.get("consumer_harness")
        entry["consumer_task_id"] = layer.get("consumer_task_id")
        entry["consumer_campaign_task_id"] = layer.get("consumer_campaign_task_id")
        origin_project = str(entry.get("origin_project") or "").strip() or None
        origin_lane = str(entry.get("origin_lane") or "").strip() or None
        consumer_project = str(layer.get("consumer_project") or "").strip() or None
        consumer_lane = str(layer.get("consumer_lane") or "").strip() or None
        cross_lane = bool(origin_lane and consumer_lane and origin_lane != consumer_lane)
        cross_project = bool(origin_project and consumer_project and origin_project != consumer_project)
        transfer_priority_boost = 0.0
        if cross_lane:
            transfer_priority_boost += float(layer.get("cross_lane_priority_bonus") or 0.0)
        if cross_project:
            transfer_priority_boost += float(layer.get("cross_project_priority_bonus") or 0.0)
        if transfer_priority_boost:
            entry["quality_score"] = round(float(entry.get("quality_score") or 0.0) + transfer_priority_boost, 6)
        entry["cross_lane_transfer"] = cross_lane
        entry["cross_project_transfer"] = cross_project
        entry["transfer_priority_boost"] = round(transfer_priority_boost, 6)
        rows.append(entry)
    return rows


def _selected_target_name(candidate: dict[str, Any]) -> str:
    if candidate.get("is_existing_destination"):
        return str(candidate.get("name") or Path(str(candidate["path"])).name)
    suffix = str(candidate.get("suffix") or ".bin")
    if suffix and not suffix.startswith("."):
        suffix = f".{suffix}"
    return f"{candidate['exact_digest']}{suffix or '.bin'}"


def _decision_stub(candidate: dict[str, Any], *, reason: str) -> dict[str, Any]:
    return {
        "reason": reason,
        "name": candidate.get("name"),
        "path": candidate.get("path"),
        "source_label": candidate.get("source_label"),
        "scope": candidate.get("scope"),
        "project": candidate.get("project"),
        "lane": candidate.get("lane"),
        "target_mode": candidate.get("target_mode"),
        "harness": candidate.get("harness"),
        "exact_digest": candidate.get("exact_digest"),
        "semantic_key": candidate.get("semantic_key"),
        "file_size": candidate.get("file_size"),
        "quality_score": candidate.get("quality_score"),
        "transfer_priority_boost": candidate.get("transfer_priority_boost"),
        "origin_source_label": candidate.get("origin_source_label"),
        "origin_scope": candidate.get("origin_scope"),
        "origin_project": candidate.get("origin_project"),
        "origin_lane": candidate.get("origin_lane"),
        "origin_target_mode": candidate.get("origin_target_mode"),
        "origin_harness": candidate.get("origin_harness"),
        "origin_task_id": candidate.get("origin_task_id"),
        "origin_campaign_task_id": candidate.get("origin_campaign_task_id"),
        "origin_selected_target_function": candidate.get("origin_selected_target_function"),
        "origin_signal": candidate.get("origin_signal"),
        "origin_input_role": candidate.get("origin_input_role"),
        "origin_import_reason": candidate.get("origin_import_reason"),
        "export_reason": candidate.get("export_reason"),
        "import_reason": candidate.get("import_reason"),
        "selection_reason": candidate.get("selection_reason"),
        "consumer_project": candidate.get("consumer_project"),
        "consumer_lane": candidate.get("consumer_lane"),
        "consumer_target_mode": candidate.get("consumer_target_mode"),
        "consumer_harness": candidate.get("consumer_harness"),
        "consumer_task_id": candidate.get("consumer_task_id"),
        "consumer_campaign_task_id": candidate.get("consumer_campaign_task_id"),
        "cross_lane_transfer": bool(candidate.get("cross_lane_transfer")),
        "cross_project_transfer": bool(candidate.get("cross_project_transfer")),
    }


def merge_corpus_layers(
    destination_root: Path,
    layers: list[dict[str, Any]],
    *,
    destination_kind: str,
    destination_scope: str,
    destination_project: str | None,
    destination_lane: str | None,
    destination_target_mode: str | None,
    destination_harness: str | None,
    index_path: Path | None = None,
    decision_log_path: Path | None = None,
    max_files: int | None = None,
    max_bytes: int | None = None,
    per_semantic_limit: int | None = None,
    consumer_task_id: str | None = None,
    consumer_campaign_task_id: str | None = None,
) -> dict[str, Any]:
    destination_root.mkdir(parents=True, exist_ok=True)
    policy = corpus_policy(destination_kind)
    max_files = int(max_files or policy["max_files"])
    max_bytes = int(max_bytes or policy["max_bytes"])
    per_semantic_limit = int(per_semantic_limit or policy["per_semantic_limit"])

    existing_priority = 3.8 if destination_kind == "round_local" else 6.0
    normalized_layers = [
        {
            **dict(layer),
            "consumer_project": layer.get("consumer_project", destination_project),
            "consumer_lane": layer.get("consumer_lane", destination_lane),
            "consumer_target_mode": layer.get("consumer_target_mode", destination_target_mode),
            "consumer_harness": layer.get("consumer_harness", destination_harness),
            "consumer_task_id": layer.get("consumer_task_id", consumer_task_id),
            "consumer_campaign_task_id": layer.get("consumer_campaign_task_id", consumer_campaign_task_id),
        }
        for layer in layers
    ]

    existing_layer = {
        "root": str(destination_root),
        "label": "existing_destination",
        "scope": destination_scope,
        "project": destination_project,
        "lane": destination_lane,
        "target_mode": destination_target_mode,
        "harness": destination_harness,
        "priority_weight": existing_priority,
        "is_existing_destination": True,
        "index_path": str(index_path) if index_path else None,
        "consumer_project": destination_project,
        "consumer_lane": destination_lane,
        "consumer_target_mode": destination_target_mode,
        "consumer_harness": destination_harness,
        "consumer_task_id": consumer_task_id,
        "consumer_campaign_task_id": consumer_campaign_task_id,
    }
    scanned_layers = [existing_layer, *normalized_layers]
    all_candidates: list[dict[str, Any]] = []
    for layer in scanned_layers:
        all_candidates.extend(_scan_layer(layer))

    quality_gate_passed = 0
    quality_gate_rejected = 0
    quality_gate_rejection_counts: dict[str, int] = {}
    quality_gate_selected: list[dict[str, Any]] = []
    kept_by_digest: dict[str, dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    exact_duplicate_skipped = 0
    for candidate in sorted(all_candidates, key=_source_sort_key, reverse=True):
        accepted, quality_reason, quality_detail = quality_gate_for_entry(candidate)
        if not accepted:
            quality_gate_rejected += 1
            quality_gate_rejection_counts[quality_reason or "quality_gate_rejected"] = (
                quality_gate_rejection_counts.get(quality_reason or "quality_gate_rejected", 0) + 1
            )
            stub = _decision_stub(candidate, reason=str(quality_reason or "quality_gate_rejected"))
            stub["quality_gate_detail"] = quality_detail
            rejected.append(stub)
            continue
        quality_gate_passed += 1
        quality_gate_selected.append(candidate)
        digest = str(candidate.get("exact_digest") or "")
        previous = kept_by_digest.get(digest)
        if previous is None:
            kept_by_digest[digest] = candidate
            continue
        exact_duplicate_skipped += 1
        rejected.append(_decision_stub(candidate, reason="exact_duplicate_lower_quality"))

    semantic_selected: list[dict[str, Any]] = []
    semantic_buckets: dict[str, list[dict[str, Any]]] = {}
    semantic_pruned = 0
    for candidate in sorted(kept_by_digest.values(), key=_source_sort_key, reverse=True):
        semantic_key = str(candidate.get("semantic_key") or "")
        bucket = semantic_buckets.setdefault(semantic_key, [])
        if len(bucket) >= per_semantic_limit:
            semantic_pruned += 1
            rejected.append(_decision_stub(candidate, reason="quality_gate_semantic_duplicate_pruned"))
            continue
        bucket.append(candidate)
        semantic_selected.append(candidate)

    selected: list[dict[str, Any]] = []
    selected_bytes = 0
    budget_pruned = 0
    for candidate in sorted(semantic_selected, key=_source_sort_key, reverse=True):
        candidate_size = int(candidate.get("file_size") or 0)
        would_exceed_bytes = selected_bytes + candidate_size > max_bytes
        would_exceed_files = len(selected) >= max_files
        if selected and (would_exceed_bytes or would_exceed_files):
            budget_pruned += 1
            rejected.append(
                _decision_stub(
                    candidate,
                    reason="budget_pruned_bytes" if would_exceed_bytes else "budget_pruned_files",
                )
            )
            continue
        selected.append(candidate)
        selected_bytes += candidate_size

    selected_by_digest = {str(candidate["exact_digest"]): candidate for candidate in selected}
    existing_files = _scan_layer(existing_layer)
    existing_by_digest = {str(candidate["exact_digest"]): candidate for candidate in existing_files}

    copied_count = 0
    deleted_count = 0
    retained_count = 0
    copied_bytes = 0
    selected_layer_counts: dict[str, int] = {}
    import_reason_counts: dict[str, int] = {}
    selected_origin_lane_counts: dict[str, int] = {}
    selected_origin_project_counts: dict[str, int] = {}
    cross_harness_selected_count = 0
    cross_lane_selected_count = 0
    cross_project_selected_count = 0
    selected_imported_count = 0
    selected_entries: list[dict[str, Any]] = []
    for candidate in selected:
        digest = str(candidate["exact_digest"])
        target_name = _selected_target_name(candidate)
        target_path = destination_root / target_name
        source_path = Path(str(candidate["path"]))
        if target_path.exists():
            retained_count += 1
        elif source_path.exists():
            shutil.copy2(source_path, target_path)
            copied_count += 1
            copied_bytes += int(candidate.get("file_size") or 0)
        selected_layer_counts[str(candidate.get("source_label") or "unknown")] = selected_layer_counts.get(
            str(candidate.get("source_label") or "unknown"),
            0,
        ) + 1
        import_reason = str(candidate.get("import_reason") or candidate.get("selection_reason") or "unspecified")
        import_reason_counts[import_reason] = import_reason_counts.get(import_reason, 0) + 1
        origin_lane = str(candidate.get("origin_lane") or candidate.get("lane") or "unknown")
        origin_project = str(candidate.get("origin_project") or candidate.get("project") or "unknown")
        selected_origin_lane_counts[origin_lane] = selected_origin_lane_counts.get(origin_lane, 0) + 1
        selected_origin_project_counts[origin_project] = selected_origin_project_counts.get(origin_project, 0) + 1
        source_harness = str(candidate.get("origin_harness") or candidate.get("harness") or "").strip() or None
        if destination_harness and source_harness and source_harness != destination_harness:
            cross_harness_selected_count += 1
        if bool(candidate.get("cross_lane_transfer")):
            cross_lane_selected_count += 1
        if bool(candidate.get("cross_project_transfer")):
            cross_project_selected_count += 1
        if not candidate.get("is_existing_destination"):
            selected_imported_count += 1
        selected_entries.append(
            {
                **candidate,
                "destination_name": target_name,
                "destination_path": str(target_path),
            }
        )

    for existing in existing_files:
        digest = str(existing["exact_digest"])
        selected_candidate = selected_by_digest.get(digest)
        if selected_candidate is None:
            try:
                Path(str(existing["path"])).unlink()
                deleted_count += 1
            except OSError:
                continue
            continue
        selected_name = _selected_target_name(selected_candidate)
        existing_path = Path(str(existing["path"]))
        if existing_path.name != selected_name and existing_path.exists():
            try:
                existing_path.unlink()
                deleted_count += 1
            except OSError:
                continue

    summary = {
        "generated_at": _now(),
        "destination_root": str(destination_root),
        "destination_kind": destination_kind,
        "destination_scope": destination_scope,
        "destination_project": destination_project,
        "destination_lane": destination_lane,
        "destination_target_mode": destination_target_mode,
        "destination_harness": destination_harness,
        "max_files": max_files,
        "max_bytes": max_bytes,
        "per_semantic_limit": per_semantic_limit,
        "scanned_candidate_count": len(all_candidates),
        "selected_count": len(selected),
        "selected_total_bytes": selected_bytes,
        "copied_count": copied_count,
        "retained_count": retained_count,
        "deleted_count": deleted_count,
        "exact_duplicate_skipped": exact_duplicate_skipped,
        "semantic_pruned_count": semantic_pruned,
        "budget_pruned_count": budget_pruned,
        "selected_layer_counts": selected_layer_counts,
        "selected_import_reason_counts": import_reason_counts,
        "selected_origin_lane_counts": selected_origin_lane_counts,
        "selected_origin_project_counts": selected_origin_project_counts,
        "cross_harness_selected_count": cross_harness_selected_count,
        "cross_harness_selected": cross_harness_selected_count > 0,
        "cross_lane_selected_count": cross_lane_selected_count,
        "cross_lane_selected": cross_lane_selected_count > 0,
        "cross_project_selected_count": cross_project_selected_count,
        "cross_project_selected": cross_project_selected_count > 0,
        "selected_imported_count": selected_imported_count,
        "selected_existing_destination_count": len(selected) - selected_imported_count,
        "quality_gate_passed_count": quality_gate_passed,
        "quality_gate_rejected_count": quality_gate_rejected,
        "quality_gate_pass_rate": round(
            quality_gate_passed / max(quality_gate_passed + quality_gate_rejected, 1),
            6,
        ),
        "quality_gate_rejection_counts": quality_gate_rejection_counts,
        "new_files": copied_count,
        "new_bytes": copied_bytes,
        "file_count_after": len([path for path in destination_root.rglob("*") if path.is_file()]),
    }

    if index_path:
        _write_json(
            index_path,
            {
                "generated_at": summary["generated_at"],
                "destination_root": str(destination_root),
                "destination_kind": destination_kind,
                "file_count": summary["file_count_after"],
                "total_bytes": selected_bytes,
                "files": [
                    {
                        "destination_name": entry["destination_name"],
                        "exact_digest": entry["exact_digest"],
                        "semantic_key": entry["semantic_key"],
                        "file_size": entry["file_size"],
                        "quality_score": entry["quality_score"],
                        "source_label": entry["source_label"],
                        "scope": entry["scope"],
                        "project": entry["project"],
                        "lane": entry["lane"],
                        "target_mode": entry["target_mode"],
                        "harness": entry["harness"],
                        "task_id": entry["task_id"],
                        "campaign_task_id": entry["campaign_task_id"],
                        "origin_source_label": entry.get("origin_source_label"),
                        "origin_scope": entry.get("origin_scope"),
                        "origin_project": entry.get("origin_project"),
                        "origin_lane": entry.get("origin_lane"),
                        "origin_target_mode": entry.get("origin_target_mode"),
                        "origin_harness": entry.get("origin_harness"),
                        "origin_task_id": entry.get("origin_task_id"),
                        "origin_campaign_task_id": entry.get("origin_campaign_task_id"),
                        "origin_selected_target_function": entry.get("origin_selected_target_function"),
                        "origin_signal": entry.get("origin_signal"),
                        "origin_input_role": entry.get("origin_input_role"),
                        "origin_import_reason": entry.get("origin_import_reason"),
                        "export_reason": entry.get("export_reason"),
                        "import_reason": entry.get("import_reason"),
                        "selection_reason": entry.get("selection_reason"),
                        "consumer_project": entry.get("consumer_project"),
                        "consumer_lane": entry.get("consumer_lane"),
                        "consumer_target_mode": entry.get("consumer_target_mode"),
                        "consumer_harness": entry.get("consumer_harness"),
                        "consumer_task_id": entry.get("consumer_task_id"),
                        "consumer_campaign_task_id": entry.get("consumer_campaign_task_id"),
                        "cross_lane_transfer": bool(entry.get("cross_lane_transfer")),
                        "cross_project_transfer": bool(entry.get("cross_project_transfer")),
                        "transfer_priority_boost": entry.get("transfer_priority_boost"),
                    }
                    for entry in selected_entries
                ],
            },
        )

    if decision_log_path:
        _write_json(
            decision_log_path,
            {
                "generated_at": summary["generated_at"],
                "summary": summary,
                "source_layers": [
                    {
                        "label": str(layer.get("label") or "unknown"),
                        "root": str(layer.get("root")),
                        "scope": layer.get("scope"),
                        "project": layer.get("project"),
                        "lane": layer.get("lane"),
                        "target_mode": layer.get("target_mode"),
                        "harness": layer.get("harness"),
                        "priority_weight": layer.get("priority_weight"),
                        "index_path": str(layer.get("index_path")) if layer.get("index_path") else None,
                        "import_reason": layer.get("import_reason"),
                        "selection_reason": layer.get("selection_reason"),
                        "export_reason": layer.get("export_reason"),
                    }
                    for layer in normalized_layers
                ],
                "selected_files": [
                    {
                        "destination_name": entry["destination_name"],
                        "path": entry["path"],
                        "source_label": entry["source_label"],
                        "scope": entry["scope"],
                        "project": entry["project"],
                        "lane": entry["lane"],
                        "target_mode": entry["target_mode"],
                        "harness": entry["harness"],
                        "exact_digest": entry["exact_digest"],
                        "semantic_key": entry["semantic_key"],
                        "file_size": entry["file_size"],
                        "quality_score": entry["quality_score"],
                        "task_id": entry["task_id"],
                        "campaign_task_id": entry["campaign_task_id"],
                        "origin_source_label": entry.get("origin_source_label"),
                        "origin_scope": entry.get("origin_scope"),
                        "origin_project": entry.get("origin_project"),
                        "origin_lane": entry.get("origin_lane"),
                        "origin_target_mode": entry.get("origin_target_mode"),
                        "origin_harness": entry.get("origin_harness"),
                        "origin_task_id": entry.get("origin_task_id"),
                        "origin_campaign_task_id": entry.get("origin_campaign_task_id"),
                        "origin_selected_target_function": entry.get("origin_selected_target_function"),
                        "origin_signal": entry.get("origin_signal"),
                        "origin_input_role": entry.get("origin_input_role"),
                        "origin_import_reason": entry.get("origin_import_reason"),
                        "export_reason": entry.get("export_reason"),
                        "import_reason": entry.get("import_reason"),
                        "selection_reason": entry.get("selection_reason"),
                        "consumer_project": entry.get("consumer_project"),
                        "consumer_lane": entry.get("consumer_lane"),
                        "consumer_target_mode": entry.get("consumer_target_mode"),
                        "consumer_harness": entry.get("consumer_harness"),
                        "consumer_task_id": entry.get("consumer_task_id"),
                        "consumer_campaign_task_id": entry.get("consumer_campaign_task_id"),
                        "cross_lane_transfer": bool(entry.get("cross_lane_transfer")),
                        "cross_project_transfer": bool(entry.get("cross_project_transfer")),
                        "transfer_priority_boost": entry.get("transfer_priority_boost"),
                    }
                    for entry in selected_entries[:512]
                ],
                "rejected_files": rejected[:512],
            },
        )

    summary["decision_log_path"] = str(decision_log_path) if decision_log_path else None
    summary["index_path"] = str(index_path) if index_path else None
    summary["selected_files"] = [
        {
            "destination_name": entry["destination_name"],
            "destination_path": entry["destination_path"],
            "source_label": entry["source_label"],
            "scope": entry["scope"],
            "project": entry["project"],
            "lane": entry["lane"],
            "target_mode": entry["target_mode"],
            "harness": entry["harness"],
            "exact_digest": entry["exact_digest"],
            "semantic_key": entry["semantic_key"],
            "file_size": entry["file_size"],
            "quality_score": entry["quality_score"],
            "task_id": entry["task_id"],
            "campaign_task_id": entry["campaign_task_id"],
            "origin_source_label": entry.get("origin_source_label"),
            "origin_scope": entry.get("origin_scope"),
            "origin_project": entry.get("origin_project"),
            "origin_lane": entry.get("origin_lane"),
            "origin_target_mode": entry.get("origin_target_mode"),
            "origin_harness": entry.get("origin_harness"),
            "origin_task_id": entry.get("origin_task_id"),
            "origin_campaign_task_id": entry.get("origin_campaign_task_id"),
            "origin_selected_target_function": entry.get("origin_selected_target_function"),
            "origin_signal": entry.get("origin_signal"),
            "origin_input_role": entry.get("origin_input_role"),
            "origin_import_reason": entry.get("origin_import_reason"),
            "export_reason": entry.get("export_reason"),
            "import_reason": entry.get("import_reason"),
            "selection_reason": entry.get("selection_reason"),
            "consumer_project": entry.get("consumer_project"),
            "consumer_lane": entry.get("consumer_lane"),
            "consumer_target_mode": entry.get("consumer_target_mode"),
            "consumer_harness": entry.get("consumer_harness"),
            "consumer_task_id": entry.get("consumer_task_id"),
            "consumer_campaign_task_id": entry.get("consumer_campaign_task_id"),
            "cross_lane_transfer": bool(entry.get("cross_lane_transfer")),
            "cross_project_transfer": bool(entry.get("cross_project_transfer")),
            "transfer_priority_boost": entry.get("transfer_priority_boost"),
        }
        for entry in selected_entries
    ]
    return summary


def system_corpus_namespace_root(
    *,
    base_root: Path,
    project: str,
    lane: str,
    target_mode: str,
) -> Path:
    return base_root / safe_corpus_component(project) / safe_corpus_component(lane) / safe_corpus_component(target_mode)

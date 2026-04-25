from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

_SAMPLE_PREFIX_BYTES = 2048
_SAMPLE_SUFFIX_BYTES = 2048
_PRINTABLE_BYTES = set(range(32, 127)) | {9, 10, 13}

_SOURCE_PRIORITY = {
    "generated_seed": 7.0,
    "round_crash": 6.6,
    "round_high_value": 6.2,
    "existing_destination": 6.0,
    "round_local": 5.8,
    "campaign_harness": 5.2,
    "campaign_shared": 4.8,
    "system_compatible_shared": 4.6,
    "system_harness": 4.3,
    "system_shared": 3.9,
    "imported_seed": 3.5,
    "seed_corpus_zip": 3.2,
    "unknown": 3.0,
}


def safe_corpus_component(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "default"
    return "".join(ch if ch.isalnum() or ch in {"_", ".", "-"} else "_" for ch in raw)[:160] or "default"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _sample_bytes(path: Path) -> bytes:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size <= _SAMPLE_PREFIX_BYTES + _SAMPLE_SUFFIX_BYTES:
            return handle.read()
        prefix = handle.read(_SAMPLE_PREFIX_BYTES)
        handle.seek(max(0, size - _SAMPLE_SUFFIX_BYTES))
        suffix = handle.read(_SAMPLE_SUFFIX_BYTES)
    return prefix + suffix


def _sample_stats(sample: bytes) -> dict[str, float | int]:
    if not sample:
        return {
            "sample_size": 0,
            "unique_bytes": 0,
            "byte_diversity": 0.0,
            "ascii_ratio": 0.0,
            "zero_ratio": 0.0,
            "dominant_byte_ratio": 0.0,
        }
    unique_bytes = len(set(sample))
    printable = sum(1 for byte in sample if byte in _PRINTABLE_BYTES)
    zero_bytes = sample.count(0)
    sample_size = len(sample)
    max_frequency = max(sample.count(byte) for byte in set(sample))
    return {
        "sample_size": sample_size,
        "unique_bytes": unique_bytes,
        "byte_diversity": round(unique_bytes / min(sample_size, 256), 6),
        "ascii_ratio": round(printable / sample_size, 6),
        "zero_ratio": round(zero_bytes / sample_size, 6),
        "dominant_byte_ratio": round(max_frequency / sample_size, 6),
    }


def _size_bucket(size: int) -> int:
    bucket = 16
    while bucket < max(16, size):
        bucket *= 2
    return bucket


def semantic_key_for_path(path: Path) -> str:
    sample = _sample_bytes(path)
    stats = _sample_stats(sample)
    prefix = hashlib.sha1(sample[:128]).hexdigest()[:12]
    suffix = hashlib.sha1(sample[-128:]).hexdigest()[:12]
    return (
        f"b{_size_bucket(path.stat().st_size)}:"
        f"u{int(stats['unique_bytes']) // 8}:"
        f"a{int(float(stats['ascii_ratio']) * 10)}:"
        f"z{int(float(stats['zero_ratio']) * 10)}:"
        f"{prefix}:{suffix}"
    )


def quality_score_for_path(
    path: Path,
    *,
    source_label: str,
    priority_weight: float | None = None,
) -> float:
    sample = _sample_bytes(path)
    stats = _sample_stats(sample)
    size = path.stat().st_size
    effective_priority = priority_weight if priority_weight is not None else _SOURCE_PRIORITY.get(source_label, _SOURCE_PRIORITY["unknown"])
    size_bonus = min(size, 128 * 1024) / 4096.0
    medium_bonus = 6.0 if 32 <= size <= 64 * 1024 else 2.0 if size > 0 else 0.0
    diversity_bonus = float(stats["byte_diversity"]) * 40.0
    ascii_bonus = float(stats["ascii_ratio"]) * 4.0
    zero_penalty = float(stats["zero_ratio"]) * 12.0
    oversize_penalty = max(size - (256 * 1024), 0) / (256 * 1024)
    return round((effective_priority * 100.0) + size_bonus + medium_bonus + diversity_bonus + ascii_bonus - zero_penalty - oversize_penalty, 6)


def build_corpus_entry(
    path: Path,
    *,
    source_label: str,
    priority_weight: float | None = None,
    scope: str | None = None,
    project: str | None = None,
    lane: str | None = None,
    target_mode: str | None = None,
    harness: str | None = None,
    task_id: str | None = None,
    campaign_task_id: str | None = None,
    is_existing_destination: bool = False,
) -> dict[str, Any]:
    sample = _sample_bytes(path)
    stats = _sample_stats(sample)
    suffix = path.suffix or ".bin"
    return {
        "path": str(path),
        "name": path.name,
        "suffix": suffix,
        "file_size": int(path.stat().st_size),
        "exact_digest": file_sha256(path),
        "semantic_key": semantic_key_for_path(path),
        "quality_score": quality_score_for_path(path, source_label=source_label, priority_weight=priority_weight),
        "priority_weight": float(priority_weight if priority_weight is not None else _SOURCE_PRIORITY.get(source_label, _SOURCE_PRIORITY["unknown"])),
        "source_label": source_label,
        "scope": scope,
        "project": project,
        "lane": lane,
        "target_mode": target_mode,
        "harness": harness,
        "task_id": task_id,
        "campaign_task_id": campaign_task_id,
        "is_existing_destination": bool(is_existing_destination),
        **stats,
    }


def quality_gate_for_entry(entry: dict[str, Any]) -> tuple[bool, str | None, dict[str, Any] | None]:
    file_size = int(entry.get("file_size") or 0)
    sample_size = int(entry.get("sample_size") or 0)
    unique_bytes = int(entry.get("unique_bytes") or 0)
    zero_ratio = float(entry.get("zero_ratio") or 0.0)
    byte_diversity = float(entry.get("byte_diversity") or 0.0)
    dominant_byte_ratio = float(entry.get("dominant_byte_ratio") or 0.0)
    if file_size <= 0:
        return False, "quality_gate_empty_input", {"file_size": file_size}
    if sample_size > 0 and unique_bytes <= 1:
        return False, "quality_gate_uniform_bytes", {
            "sample_size": sample_size,
            "unique_bytes": unique_bytes,
            "zero_ratio": zero_ratio,
        }
    if sample_size >= 32 and zero_ratio >= 0.98:
        return False, "quality_gate_zero_dominated", {
            "sample_size": sample_size,
            "zero_ratio": zero_ratio,
            "unique_bytes": unique_bytes,
        }
    if sample_size >= 64 and byte_diversity <= 0.02 and dominant_byte_ratio >= 0.98:
        return False, "quality_gate_low_entropy_repetitive", {
            "sample_size": sample_size,
            "byte_diversity": byte_diversity,
            "dominant_byte_ratio": dominant_byte_ratio,
        }
    return True, None, None

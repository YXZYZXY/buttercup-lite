from __future__ import annotations

import shutil
from pathlib import Path


def scan_raw_crashes(crashes_raw_dir: Path) -> list[str]:
    crashes_raw_dir.mkdir(parents=True, exist_ok=True)
    return sorted(str(path) for path in crashes_raw_dir.iterdir() if path.is_file())


def live_raw_crashes(crashes_raw_dir: Path) -> list[str]:
    return [path for path in scan_raw_crashes(crashes_raw_dir) if not Path(path).name.startswith("imported_")]


def stage_imported_valid_crashes(
    imported_root: str | None,
    crashes_raw_dir: Path,
    *,
    limit: int = 1,
) -> list[dict[str, str]]:
    if not imported_root:
        return []

    source_root = Path(imported_root)
    if not source_root.exists():
        return []

    crashes_raw_dir.mkdir(parents=True, exist_ok=True)
    staged: list[dict[str, str]] = []
    for candidate in sorted(source_root.rglob("*")):
        if not candidate.is_file():
            continue
        category = candidate.parent.name
        target = crashes_raw_dir / f"imported_{category}_{candidate.name}.bin"
        suffix = 1
        while target.exists():
            target = crashes_raw_dir / f"imported_{category}_{candidate.stem}_{suffix}{candidate.suffix or '.bin'}"
            suffix += 1
        shutil.copy2(candidate, target)
        staged.append(
            {
                "source_path": str(candidate),
                "staged_path": str(target),
                "category": category,
                "origin": "existing_valid_crashes_path",
            },
        )
        if len(staged) >= limit:
            break
    return staged

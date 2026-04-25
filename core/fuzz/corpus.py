from __future__ import annotations

import shutil
from pathlib import Path


def snapshot_corpus_files(corpus_dir: Path) -> set[str]:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    return {str(path) for path in corpus_dir.rglob("*") if path.is_file()}


def diff_corpus_files(before: set[str], corpus_dir: Path) -> list[str]:
    after = {str(path) for path in corpus_dir.rglob("*") if path.is_file()}
    return sorted(after - before)


def stage_corpus_helpers(
    corpus_dir: Path,
    source_root: str | None,
    *,
    limit: int = 1,
) -> list[dict[str, str]]:
    if not source_root:
        return []

    source_path = Path(source_root)
    if not source_path.exists():
        return []

    corpus_dir.mkdir(parents=True, exist_ok=True)
    staged: list[dict[str, str]] = []
    for candidate in sorted(source_path.rglob("*")):
        if not candidate.is_file():
            continue
        target = corpus_dir / f"helper_{candidate.parent.name}_{candidate.name}"
        suffix = 1
        while target.exists():
            target = corpus_dir / f"helper_{candidate.parent.name}_{candidate.stem}_{suffix}{candidate.suffix or '.bin'}"
            suffix += 1
        shutil.copy2(candidate, target)
        staged.append(
            {
                "source_path": str(candidate),
                "staged_path": str(target),
                "category": candidate.parent.name,
            },
        )
        if len(staged) >= limit:
            break
    return staged

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

from maccleaner.context import Context
from maccleaner.findings import Finding
from maccleaner.safety import RISK_REVIEW
from maccleaner.sizes import iter_files, parse_size

CATEGORY = "duplicate"

SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "Pods",
        ".Trash",
        "DerivedData",
        "Caches",
        ".venv",
        ".npm",
        "venv",
    }
)

MIN_GROUP_SIZE = parse_size("4K")
CHUNK = 1024 * 1024


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            hasher.update(chunk)
    return hasher.hexdigest()


def scan(ctx: Context, min_size: int | None = None) -> list[Finding]:
    threshold = min_size if min_size is not None else ctx.min_size
    if threshold <= 0:
        threshold = MIN_GROUP_SIZE

    buckets: dict[int, list[Path]] = defaultdict(list)

    for root in ctx.scan_roots():
        for path in iter_files(root, skip_dirs=SKIP_DIRS, max_depth=ctx.max_depth):
            if any(part.startswith(".") for part in path.relative_to(root).parts):
                if not ctx.include_hidden:
                    continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size < threshold:
                continue
            buckets[size].append(path)

    findings: list[Finding] = []

    for size, paths in sorted(buckets.items(), key=lambda kv: kv[0], reverse=True):
        if len(paths) < 2:
            continue
        by_hash: dict[str, list[Path]] = defaultdict(list)
        total_group = len(paths)
        for i, path in enumerate(paths, 1):
            if total_group > 100 and i % 50 == 0:
                from maccleaner import report

                report.info(f"  [DUP] hashing {i}/{total_group} file (size {size})...")
            try:
                by_hash[_digest(path)].append(path)
            except OSError:
                continue
        for group in by_hash.values():
            if len(group) < 2:
                continue
            group.sort()
            keeper = group[0]
            for path in group[1:]:
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    mtime = 0.0
                findings.append(
                    Finding(
                        path=path,
                        size=size,
                        category=CATEGORY,
                        label="duplikat",
                        mtime=mtime,
                        risk=RISK_REVIEW,
                        detail=f"salinan dari {keeper}",
                    )
                )

    if ctx.min_age_days:
        findings = [f for f in findings if f.age_days >= ctx.min_age_days]

    findings.sort(key=lambda f: f.size, reverse=True)
    return findings
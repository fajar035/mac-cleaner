from __future__ import annotations

import os
from pathlib import Path

from maccleaner.context import Context
from maccleaner.sizes import dir_size


def scan(ctx: Context, limit: int = 25, min_size: int = 1024 * 1024) -> list[tuple[Path, int]]:
    rows: list[tuple[Path, int]] = []

    for root in ctx.scan_roots():
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            try:
                entries = sorted(os.scandir(current), key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                try:
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                path = Path(entry.path)
                size = dir_size(path)
                if size >= min_size:
                    rows.append((path, size))
                if depth + 1 < ctx.max_depth:
                    stack.append((path, depth + 1))

    rows.sort(key=lambda row: row[1], reverse=True)
    return rows[:limit]
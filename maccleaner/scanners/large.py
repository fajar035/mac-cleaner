from __future__ import annotations

import time
from pathlib import Path

from maccleaner.context import Context
from maccleaner.findings import Finding
from maccleaner.safety import RISK_REVIEW
from maccleaner.sizes import iter_files, parse_size

CATEGORY = "large"

SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "Pods",
        ".Trash",
        "DerivedData",
        "Caches",
        ".venv",
        "target",
        ".gradle",
        ".npm",
        "venv",
    }
)

EXTENSIONS = (
    ".dmg",
    ".pkg",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".iso",
    ".mp4",
    ".mov",
    ".mkv",
    ".avi",
    ".heic",
    ".raw",
    ".wav",
    ".aiff",
    ".vmdk",
    ".pvm",
    ".sparsebundle",
)


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def scan(ctx: Context, min_size: int | None = None, extensions_only: bool = False) -> list[Finding]:
    threshold = min_size if min_size is not None else ctx.min_size
    if threshold <= 0:
        threshold = parse_size("200M")

    findings: list[Finding] = []
    now = time.time()

    scanned = 0
    for root in ctx.scan_roots():
        for path in iter_files(root, skip_dirs=SKIP_DIRS, max_depth=ctx.max_depth):
            scanned += 1
            if scanned % 500 == 0:
                from maccleaner import report

                report.info(f"  [LARGE] scanning files... {scanned}")
            hidden = any(part.startswith(".") for part in path.relative_to(root).parts)
            if hidden and not ctx.include_hidden:
                continue
            if extensions_only and path.suffix.lower() not in EXTENSIONS:
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            if st.st_size < threshold:
                continue
            if ctx.min_age_days and (now - st.st_mtime) / 86400 < ctx.min_age_days:
                continue
            findings.append(
                Finding(
                    path=path,
                    size=st.st_size,
                    category=CATEGORY,
                    label=path.suffix.lower() or "file",
                    mtime=st.st_mtime,
                    risk=RISK_REVIEW,
                )
            )
    if scanned:
        from maccleaner import report

        report.ok(f"  [LARGE] selesai scan {scanned} file")

    findings.sort(key=lambda f: f.size, reverse=True)
    return findings
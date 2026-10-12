from __future__ import annotations

import os
from pathlib import Path

from maccleaner.context import Context
from maccleaner.findings import Finding
from maccleaner.safety import RISK_REVIEW, RISK_SAFE
from maccleaner.sizes import size_of

CATEGORY = "devjunk"

DEVELOPER_DIR_NAMES = {
    "node_modules": ("Node modules", RISK_SAFE),
    "__pycache__": ("Python bytecode", RISK_SAFE),
    ".pytest_cache": ("pytest cache", RISK_SAFE),
    ".mypy_cache": ("mypy cache", RISK_SAFE),
    ".ruff_cache": ("ruff cache", RISK_SAFE),
    ".turbo": ("turborepo cache", RISK_SAFE),
    ".next": ("Next.js build", RISK_REVIEW),
    ".gradle": ("Gradle cache", RISK_SAFE),
    ".terraform": ("Terraform providers", RISK_REVIEW),
    ".venv": ("Python venv", RISK_REVIEW),
    "venv": ("Python venv", RISK_REVIEW),
    "target": ("Rust/Java build", RISK_REVIEW),
    "DerivedData": ("Xcode DerivedData", RISK_SAFE),
}

SKIP_DIRS = frozenset(
    {
        "Library",
        "Applications",
        ".Trash",
        ".git",
        "node_modules",
        "Pods",
        "vendor",
        "Caches",
    }
)

ABSOLUTE_TARGETS = (
    ("Library/Developer/Xcode/DerivedData", "Xcode DerivedData", RISK_SAFE),
    ("Library/Developer/Xcode/Archives", "Xcode Archives", RISK_REVIEW),
    ("Library/Developer/Xcode/watchOS DeviceSupport", "watchOS DeviceSupport", RISK_SAFE),
    ("Library/Developer/Xcode/iOS DeviceSupport", "iOS DeviceSupport", RISK_SAFE),
    ("Library/Caches/Homebrew", "Homebrew cache", RISK_SAFE),
    (".npm/_cacache", "npm cache", RISK_SAFE),
    (".npm/_logs", "npm logs", RISK_SAFE),
    (".yarn/cache", "yarn cache", RISK_SAFE),
    (".pnpm-store", "pnpm store", RISK_SAFE),
    ("Library/Caches/pip", "pip cache", RISK_SAFE),
    (".cache/pip", "pip cache", RISK_SAFE),
    (".cargo/registry/cache", "cargo cache", RISK_SAFE),
    (".gradle/caches", "Gradle cache", RISK_SAFE),
    (".gradle/daemon", "Gradle daemon logs", RISK_SAFE),
    (".docker", "Docker data (review)", RISK_REVIEW),
    (".m2/repository", "Maven repository", RISK_REVIEW),
    (".composer/cache", "Composer cache", RISK_SAFE),
    (".bundle/cache", "Bundler cache", RISK_SAFE),
    (".cocoapods/cache", "CocoaPods cache", RISK_SAFE),
    ("Library/Caches/CocoaPods", "CocoaPods cache", RISK_SAFE),
    (".rvm/cache", "Ruby gems cache", RISK_SAFE),
    (".gem/ruby/*/cache", "Ruby gem cache", RISK_SAFE),
)


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _walk(root: Path, max_depth: int) -> list[tuple[Path, str, str]]:
    matches: list[tuple[Path, str, str]] = []
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
            name = entry.name
            if name in DEVELOPER_DIR_NAMES:
                label, risk = DEVELOPER_DIR_NAMES[name]
                matches.append((path, label, risk))
                continue
            if name in SKIP_DIRS:
                continue
            if depth + 1 < max_depth:
                stack.append((path, depth + 1))
    return matches


def _absolute(root: Path, pattern: str, label: str, risk: str) -> list[tuple[Path, str, str]]:
    targets = sorted(p for p in root.glob(pattern) if p.is_dir() and not p.is_symlink())
    return [(p, label, risk) for p in targets]


def scan(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for root in ctx.scan_roots():
        candidates: list[tuple[Path, str, str]] = []
        absolute_candidates: list[tuple[Path, str, str]] = []
        for pattern, label, risk in ABSOLUTE_TARGETS:
            absolute_candidates.extend(_absolute(root, pattern, label, risk))
        candidates.extend(absolute_candidates)
        candidates.extend(_walk(root, ctx.max_depth))

        explicit: set[str] = {str(p) for p, _, _ in absolute_candidates}
        total_c = len(candidates)
        for i, (path, label, risk) in enumerate(candidates, 1):
            if total_c > 50 and i % 25 == 0:
                from maccleaner import report

                report.info(f"  [DEVJUNK] {i}/{total_c} kandidat...")
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            try:
                rel_parts = path.relative_to(root).parts[:-1]
                hidden = any(part.startswith(".") for part in rel_parts)
            except Exception:
                hidden = False
            if hidden and key not in explicit and not ctx.include_hidden:
                continue
            findings.append(
                Finding(
                    path=path,
                    size=size_of(path),
                    category=CATEGORY,
                    label=label,
                    mtime=_mtime(path),
                    risk=risk,
                    detail=str(path.parent),
                )
            )

    findings = [f for f in findings if f.size >= ctx.min_size]
    if ctx.min_age_days:
        findings = [f for f in findings if f.age_days >= ctx.min_age_days]
    findings.sort(key=lambda f: f.size, reverse=True)
    return findings
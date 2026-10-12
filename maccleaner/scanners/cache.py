from __future__ import annotations

from pathlib import Path

from maccleaner.context import Context
from maccleaner.findings import Finding
from maccleaner.safety import RISK_SAFE
from maccleaner.sizes import size_of

CATEGORY = "cache"

TARGETS = (
    ("Library/Caches", "Library/Caches"),
    ("Library/Logs", "Library/Logs"),
    ("Library/Saved Application State", "Saved Application State"),
    ("Library/WebKit", "Library/WebKit"),
    ("Library/Application Support/CrashReporter", "CrashReporter"),
    ("Library/Developer/Xcode/Archives/*", "Xcode Archives"),
    ("Library/Developer/Xcode/iOS DeviceSupport/*", "iOS DeviceSupport"),
    ("Library/Developer/CoreSimulator/Devices/*/data/Library/Caches", "Simulator Caches"),
    ("Library/Containers/*/Data/Library/Caches", "Sandboxed app caches"),
    ("Library/Group Containers/*/Library/Caches", "Group container caches"),
    (".cache", "User .cache"),
    (".npm/_cacache", "npm cache"),
)

SKIP_NAMES = {"Snapshots", "com.apple.apsd", "CloudKit", "MobileDocuments"}


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _targets_for(root: Path, pattern: str) -> list[Path]:
    if "*" in pattern:
        return sorted(p for p in root.glob(pattern) if p.is_dir() and not p.is_symlink())
    single = root / pattern
    return [single] if single.is_dir() and not single.is_symlink() else []


def scan(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for root in ctx.scan_roots():
        for pattern, label in TARGETS:
            for target in _targets_for(root, pattern):
                try:
                    children = sorted(target.iterdir())
                except OSError:
                    continue
                if not children:
                    continue
                total_c = len(children)
                for i, child in enumerate(children, 1):
                    if total_c > 200 and i % 100 == 0:
                        from maccleaner import report

                        report.info(f"  [CACHE] cek {i}/{total_c} di {label}...")
                    if child.name in SKIP_NAMES or child.is_symlink():
                        continue
                    if child.name.startswith(".") and not ctx.include_hidden:
                        continue
                    key = str(child)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            path=child,
                            size=size_of(child),
                            category=CATEGORY,
                            label=label,
                            mtime=_mtime(child),
                            risk=RISK_SAFE,
                        )
                    )

    findings = [f for f in findings if f.size >= ctx.min_size]
    if ctx.min_age_days:
        findings = [f for f in findings if f.age_days >= ctx.min_age_days]
    findings.sort(key=lambda f: f.size, reverse=True)
    return findings
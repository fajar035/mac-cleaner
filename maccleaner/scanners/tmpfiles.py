from __future__ import annotations

import tempfile
from pathlib import Path

from maccleaner.context import Context
from maccleaner.findings import Finding
from maccleaner.safety import RISK_SAFE, empty_trash
from maccleaner.sizes import size_of

CATEGORY = "tmp"

TARGETS = (
    ("Library/Caches/com.apple.dt.Xcode/Downloads", "Xcode downloads"),
    ("Library/Developer/Xcode/UserData/Previews", "Xcode previews"),
    ("Library/Developer/Xcode/UserData/IB Support", "IB Support"),
    ("Library/Caches/Safari", "Safari cache"),
    ("Library/Application Support/CallHistoryDB", "Call history DB"),
    ("Library/Safari/History.db-wal", "Safari WAL"),
    ("Library/Autosave Information", "Autosave data"),
    ("Library/Messages/Attachments", "Messages attachments"),
    ("Library/Messages/ChatDocuments", "Messages documents"),
    (".Trash", "Trash"),
)

SYSTEM_TARGETS = (
    ("/private/tmp", "/tmp"),
    ("/private/var/tmp", "/var/tmp"),
    ("/Library/Logs/DiagnosticReports", "System diagnostic reports"),
    ("/Library/Logs/CrashReporter", "System crash reports"),
    ("/Library/Application Support/CrashReporter", "System crash reports"),
)


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _children(base: Path, label: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return findings
    for entry in entries:
        if entry.is_symlink():
            continue
        findings.append(
            Finding(
                path=entry,
                size=size_of(entry),
                category=CATEGORY,
                label=label,
                mtime=_mtime(entry),
                risk=RISK_SAFE,
            )
        )
    return findings


def scan(ctx: Context, include_system: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    roots = ctx.scan_roots()
    for root in roots:
        for pattern, label in TARGETS:
            base = root / pattern
            if not base.is_dir():
                continue
            for finding in _children(base, label):
                key = str(finding.path)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

    if include_system:
        for pattern, label in SYSTEM_TARGETS:
            base = Path(pattern)
            if not base.is_dir():
                continue
            for finding in _children(base, label):
                key = str(finding.path)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

        private_tmp = Path(tempfile.gettempdir()).resolve()
        if private_tmp != Path("/tmp"):
            for finding in _children(private_tmp, "temp dir"):
                key = str(finding.path)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

    findings = [f for f in findings if f.size >= ctx.min_size]
    if ctx.min_age_days:
        findings = [f for f in findings if f.age_days >= ctx.min_age_days]
    findings.sort(key=lambda f: f.size, reverse=True)
    return findings


def trash_size() -> int:
    target = Path.home() / ".Trash"
    if not target.is_dir():
        return 0
    return sum(size_of(entry) for entry in target.iterdir() if not entry.is_symlink())


def clear_trash() -> int:
    return empty_trash()
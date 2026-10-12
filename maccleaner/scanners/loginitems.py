from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path

from maccleaner.findings import Finding
from maccleaner.safety import RISK_REVIEW, RISK_SAFE

CATEGORY = "login"

LABEL_KEYS = (
    "Label",
    "CFBundleName",
    "CFBundleDisplayName",
    "CFBundleIdentifier",
    "Program",
    "ProgramArguments",
)

AGENT_DIRS = (
    Path.home() / "Library" / "LaunchAgents",
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
    Path("/System/Library/LaunchAgents"),
)


def _describe(plist: dict) -> str:
    for key in LABEL_KEYS:
        value = plist.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, list) and value:
            return " ".join(str(part) for part in value)
    return ""


def _status(plist: dict, path: Path) -> str:
    if path.name.startswith("com.apple."):
        return "apple"
    disabled = plist.get("Disabled")
    if disabled:
        return "disabled"
    return "active"


def _from_agents() -> list[Finding]:
    findings: list[Finding] = []
    for base in AGENT_DIRS:
        if not base.is_dir():
            continue
        try:
            entries = sorted(base.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.suffix != ".plist" or entry.is_symlink():
                continue
            try:
                data = plistlib.loads(entry.read_bytes())
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            try:
                mtime = entry.stat().st_mtime
            except OSError:
                mtime = 0.0
            status = _status(data, entry)
            findings.append(
                Finding(
                    path=entry,
                    size=0,
                    category=CATEGORY,
                    label=_describe(data) or entry.stem,
                    mtime=mtime,
                    risk=RISK_SAFE if status == "disabled" else RISK_REVIEW,
                    detail=f"launchd {status} · {base}",
                )
            )
    return findings


def _from_background_items() -> list[Finding]:
    try:
        proc = subprocess.run(
            ["sfltool", "dumpbtm"],
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []

    findings: list[Finding] = []
    block: dict[str, str] = {}

    def flush() -> None:
        name = block.get("Name") or block.get("Identifier") or block.get("UUID") or ""
        if not name:
            block.clear()
            return
        disposition = block.get("Disposition", "unknown")
        kind = block.get("Type", "unknown")
        state = "disabled" if "disabled" in disposition else "enabled"
        findings.append(
            Finding(
                path=Path("sfltool://") / name,
                size=0,
                category=CATEGORY,
                label=name,
                risk=RISK_SAFE if state == "disabled" else RISK_REVIEW,
                detail=f"background item · {kind} · {state} · {disposition}",
            )
        )
        block.clear()

    BTM_KEYS = (
    "Name",
    "Identifier",
    "UUID",
    "Type",
    "Disposition",
    "Developer Name",
    "Team Identifier",
    "Flags",
)

    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") and line.endswith(":"):
            flush()
            continue
        key, sep, value = line.partition(":")
        key = key.strip()
        if not sep or key not in BTM_KEYS:
            continue
        block[key] = "" if value.strip() == "(null)" else value.strip()
    flush()

    return findings


def scan(_ctx=None, source: str = "both") -> list[Finding]:
    findings: list[Finding] = []
    if source in ("agents", "both"):
        findings.extend(_from_agents())
    if source in ("btm", "both"):
        findings.extend(_from_background_items())

    findings.sort(key=lambda f: (f.detail.startswith("launchd"), f.label.lower()))
    return findings
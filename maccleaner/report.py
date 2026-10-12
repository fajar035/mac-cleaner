from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from maccleaner.findings import Finding
from maccleaner.sizes import human

COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"


def paint(text: str, code: str) -> str:
    if not COLOR:
        return text
    return f"{code}{text}{RESET}"


def heading(text: str) -> None:
    print()
    print(paint(text, BOLD + CYAN))


def rule() -> None:
    width = min(shutil_terminal_width(), 100)
    print(paint("-" * width, DIM))


def shutil_terminal_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def shorten(path: Path | str, limit: int = 62) -> str:
    text = str(path)
    home = str(Path.home())
    if text.startswith(home):
        text = "~" + text[len(home) :]
    if len(text) <= limit:
        return text
    keep = limit - 3
    return text[: keep // 2] + "..." + text[-keep // 2 :]


def render_findings(findings: list[Finding], limit: int = 20, show_age: bool = True) -> None:
    if not findings:
        print(paint("  (tidak ada temuan)", DIM))
        return

    for finding in findings[:limit]:
        risk_color = RED if finding.risk == "review" else GREEN
        size = paint(f"{human(finding.size):>9}", BOLD)
        risk = paint(f"{finding.risk:<6}", risk_color)
        label = paint(f"{finding.label:<24}", DIM)
        suffix = ""
        if show_age:
            suffix = paint(f"{finding.age_days:>6.0f}d", DIM)
        print(f"  {size} {risk} {label} {suffix} {shorten(finding.path)}")
        if finding.detail:
            print(paint(f"                 ↳ {finding.detail}", DIM))

    if len(findings) > limit:
        hidden = len(findings) - limit
        hidden_size = sum(f.size for f in findings[limit:])
        print(paint(f"  ... {hidden} temuan lain ({human(hidden_size)})", DIM))


def render_summary(total_size: int, count: int) -> None:
    rule()
    print(f"  Total: {paint(human(total_size), BOLD + GREEN)} dari {count} item")


def dump_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def warn(text: str) -> None:
    print(paint(text, YELLOW), file=sys.stderr)


def info(text: str) -> None:
    print(paint(text, CYAN))


def ok(text: str) -> None:
    print(paint(text, GREEN))


def error(text: str) -> None:
    print(paint(text, RED), file=sys.stderr)
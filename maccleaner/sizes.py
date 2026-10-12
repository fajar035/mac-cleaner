from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

UNITS = ("B", "KB", "MB", "GB", "TB", "PB")

_SUFFIXES = {
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "t": 1024**4,
    "tb": 1024**4,
}


def human(num: float) -> str:
    n = float(num)
    for unit in UNITS:
        if abs(n) < 1024 or unit == UNITS[-1]:
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} {UNITS[-1]}"


def parse_size(text: str) -> int:
    raw = text.strip().lower().replace("_", "")
    if not raw:
        raise ValueError("ukuran kosong")
    i = 0
    while i < len(raw) and (raw[i].isdigit() or raw[i] in ".,"):
        i += 1
    number_part = raw[:i].replace(",", ".")
    suffix = raw[i:].strip()
    if not number_part:
        raise ValueError(f"ukuran tidak valid: {text}")
    value = float(number_part)
    if suffix:
        if suffix not in _SUFFIXES:
            raise ValueError(f"suffix tidak dikenal: {suffix}")
        value *= _SUFFIXES[suffix]
    return int(value)


def parse_age_days(text: str) -> float:
    raw = text.strip().lower()
    days = {
        "h": 1 / 24,
        "hour": 1 / 24,
        "hours": 1 / 24,
        "d": 1.0,
        "day": 1.0,
        "days": 1.0,
        "w": 7.0,
        "week": 7.0,
        "weeks": 7.0,
        "m": 30.0,
        "month": 30.0,
        "months": 30.0,
        "y": 365.0,
        "year": 365.0,
        "years": 365.0,
    }
    i = 0
    while i < len(raw) and (raw[i].isdigit() or raw[i] in ".,"):
        i += 1
    number_part = raw[:i].replace(",", ".")
    suffix = raw[i:].strip()
    if not number_part:
        raise ValueError(f"umur tidak valid: {text}")
    value = float(number_part)
    if suffix:
        if suffix not in days:
            raise ValueError(f"suffix umur tidak dikenal: {suffix}")
        value *= days[suffix]
    return value


def dir_size(path: Path) -> int:
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def size_of(path: Path) -> int:
    try:
        if path.is_symlink():
            return path.lstat().st_size
        if path.is_dir():
            return dir_size(path)
        return path.stat().st_size
    except OSError:
        return 0


def iter_files(
    root: Path,
    skip_dirs: frozenset[str] = frozenset(),
    max_depth: int = 12,
) -> Iterator[Path]:
    if not root.is_dir() or root.is_symlink():
        return
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth >= max_depth:
            continue
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name in skip_dirs:
                                continue
                            stack.append((Path(entry.path), depth + 1))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue
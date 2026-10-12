from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from uuid import uuid4

PROTECTED_ROOTS = (
    Path("/System"),
    Path("/bin"),
    Path("/sbin"),
    Path("/usr"),
    Path("/etc"),
    Path("/var/db"),
    Path("/private/etc"),
    Path("/private/var/db"),
    Path("/dev"),
    Path("/Volumes/Preboot"),
)

RISK_SAFE = "safe"
RISK_REVIEW = "review"


class SafetyError(RuntimeError):
    pass


def is_protected(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    for root in PROTECTED_ROOTS:
        try:
            if resolved == root or root in resolved.parents:
                return True
        except OSError:
            continue
    return False


def assert_writable_target(path: Path) -> None:
    if is_protected(path):
        raise SafetyError(f"path sistem ditolak: {path}")
    if path.is_symlink():
        raise SafetyError(f"symlink ditolak: {path}")


def trash_dir() -> Path:
    target = Path.home() / ".Trash"
    target.mkdir(parents=True, exist_ok=True)
    return target


def move_to_trash(path: Path) -> Path:
    assert_writable_target(path)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    destination = trash_dir() / f"macclean-{stamp}-{uuid4().hex[:6]}-{path.name}"
    shutil.move(str(path), str(destination))
    return destination


def purge(path: Path) -> None:
    assert_writable_target(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        os.unlink(path)


def empty_trash() -> int:
    target = trash_dir()
    freed = 0
    for entry in target.iterdir():
        try:
            from maccleaner.sizes import size_of

            freed += size_of(entry)
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                os.unlink(entry)
        except OSError:
            continue
    return freed
from __future__ import annotations

from collections.abc import Callable

from maccleaner.findings import Finding

from . import cache, devjunk, duplicates, large, loginitems, tmpfiles

Scanner = Callable[..., list[Finding]]

REGISTRY: dict[str, tuple[str, Scanner]] = {
    cache.CATEGORY: ("Cache, log & state aplikasi", cache.scan),
    devjunk.CATEGORY: ("Artefak development", devjunk.scan),
    large.CATEGORY: ("File besar", large.scan),
    duplicates.CATEGORY: ("File duplikat", duplicates.scan),
    tmpfiles.CATEGORY: ("Temporary file & Trash", tmpfiles.scan),
    loginitems.CATEGORY: ("Login items & startup", loginitems.scan),
}

DEFAULT_CATEGORIES = (
    cache.CATEGORY,
    devjunk.CATEGORY,
    large.CATEGORY,
    duplicates.CATEGORY,
    tmpfiles.CATEGORY,
)

CLEANABLE = (cache.CATEGORY, devjunk.CATEGORY, large.CATEGORY, duplicates.CATEGORY, tmpfiles.CATEGORY)


def resolve(names: list[str] | None) -> list[str]:
    if not names:
        return list(DEFAULT_CATEGORIES)
    resolved: list[str] = []
    for name in names:
        key = name.strip().lower()
        if key == "all":
            resolved.extend(CLEANABLE)
            continue
        if key not in REGISTRY:
            valid = ", ".join(sorted(REGISTRY))
            raise SystemExit(f"kategori tidak dikenal: {name}\npilihan: {valid}")
        resolved.append(key)
    return list(dict.fromkeys(resolved))


__all__ = ["CLEANABLE", "DEFAULT_CATEGORIES", "REGISTRY", "Scanner", "resolve"]
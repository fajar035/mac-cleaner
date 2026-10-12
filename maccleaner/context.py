from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Context:
    home: Path = field(default_factory=Path.home)
    min_size: int = 0
    min_age_days: float = 0.0
    include_hidden: bool = False
    max_depth: int = 10
    verbose: bool = False
    roots: list[Path] = field(default_factory=list)

    def scan_roots(self) -> list[Path]:
        return list(self.roots) if self.roots else [self.home]
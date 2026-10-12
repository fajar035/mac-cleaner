from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from maccleaner.safety import RISK_SAFE


@dataclass(slots=True)
class Finding:
    path: Path
    size: int
    category: str
    label: str
    mtime: float = 0.0
    risk: str = RISK_SAFE
    detail: str = ""

    @property
    def age_days(self) -> float:
        if not self.mtime:
            return 0.0
        return max(0.0, (time.time() - self.mtime) / 86400)

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "size": self.size,
            "category": self.category,
            "label": self.label,
            "mtime": self.mtime,
            "age_days": round(self.age_days, 1),
            "risk": self.risk,
            "detail": self.detail,
        }


@dataclass(slots=True)
class ScanResult:
    category: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(f.size for f in self.findings)
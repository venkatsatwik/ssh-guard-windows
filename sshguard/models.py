from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    reason: str
    points: int


@dataclass
class FileAssessment:
    path: Path
    sha256: str | None
    score: int
    findings: list[Finding] = field(default_factory=list)
    readable: bool = True
    error: str | None = None

    @property
    def severity(self) -> str:
        if self.score >= 70:
            return "HIGH"
        if self.score >= 35:
            return "MEDIUM"
        if self.score > 0:
            return "LOW"
        return "CLEAN"

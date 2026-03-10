from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank


@dataclass
class Issue:
    rule_id: str
    severity: Severity
    file: str
    line: int | None
    message: str
    why: str
    fix: str

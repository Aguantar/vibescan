from __future__ import annotations

from dataclasses import dataclass, field

from vibescan.models.issue import Issue, Severity


@dataclass
class ScanResult:
    issues: list[Issue] = field(default_factory=list)
    project_root: str = ""
    files_scanned: int = 0
    files_skipped: int = 0

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for sev in Severity:
            counts[sev.value] = sum(1 for i in self.issues if i.severity == sev)
        return counts

    @property
    def exit_code(self) -> int:
        for issue in self.issues:
            if issue.severity in (Severity.CRITICAL, Severity.HIGH):
                return 1
        return 0

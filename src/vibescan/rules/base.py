"""Base class for all rules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue


class BaseRule(ABC):
    @abstractmethod
    def run(self, ctx: ProjectContext) -> list[Issue]:
        ...

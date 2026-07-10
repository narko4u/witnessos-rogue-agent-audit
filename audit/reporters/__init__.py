"""Reporters for outputting audit findings in various formats."""

from abc import ABC, abstractmethod
from audit.scanner import AuditReport


class BaseReporter(ABC):
    """Base class for all report output formats."""

    @abstractmethod
    def generate(self, report: AuditReport) -> str:
        """Return the formatted report as a string."""
        ...

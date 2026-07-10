"""Base classes for audit detectors and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single audit finding — something discovered by a detector."""

    title: str
    description: str
    severity: Severity
    category: str
    location: str
    details: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


class BaseDetector:
    """Abstract base class for all audit detectors.

    Subclasses must implement :meth:`detect` and set :attr:`name`.
    """

    name: str = "base"
    description: str = ""

    async def detect(self) -> list[Finding]:
        """Run the detection logic and return findings."""
        raise NotImplementedError

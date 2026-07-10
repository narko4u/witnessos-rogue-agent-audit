"""Main scanner — orchestrates detectors and collects findings."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from audit.detectors.http_endpoint import HTTPEndpointDetector
from audit.detectors.process_monitor import ProcessMonitorDetector
from audit.detectors.network_analyzer import NetworkAnalyzerDetector
from audit.detectors.environment_check import EnvironmentCheckDetector
from audit.detectors import BaseDetector

VERSION = "0.1.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class AuditFinding:
    """A single finding from a detector, normalised to a common format."""

    detector: str
    severity: str  # info | low | medium | high | critical
    title: str
    description: str
    evidence: str | None = None
    recommendation: str | None = None
    agent_type: str | None = None


@dataclass
class AuditReport:
    """Complete audit report for a target."""

    target: str
    timestamp: str
    findings: list[AuditFinding] = field(default_factory=list)
    scan_duration_ms: float = 0.0

    def summary(self) -> dict:
        by_severity: dict[str, int] = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {
            "target": self.target,
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
            "info": by_severity.get("info", 0),
        }

    @property
    def has_critical_findings(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    @property
    def ungoverned_agent_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if "ungoverned" in f.title.lower() or "unregistered" in f.title.lower()
        )


def _normalise_severity(s: str) -> str:
    """Map detector Severity enum to lower-case string."""
    return s.lower() if isinstance(s, str) else str(s).lower()


def _finding_to_audit_finding(detector_name: str, finding) -> AuditFinding | None:
    """Convert a detector's Finding into our standard AuditFinding."""
    try:
        severity_str = _normalise_severity(finding.severity)
        evidence_parts = []
        details = getattr(finding, "details", {})
        if details:
            for k, v in details.items():
                evidence_parts.append(f"{k}: {v}")
        evidence = "\n".join(evidence_parts) if evidence_parts else None

        # Try to get location as evidence location
        location = getattr(finding, "location", "")
        if location:
            evidence_parts.insert(0, f"location: {location}")
            evidence = "\n".join(evidence_parts)

        return AuditFinding(
            detector=detector_name,
            severity=severity_str,
            title=finding.title,
            description=finding.description,
            evidence=evidence,
            recommendation=getattr(finding, "recommendation", None) or None,
        )
    except Exception:
        return None


class RogueAgentScanner:
    """Main scanner: runs all detectors and aggregates findings."""

    def __init__(self, target: str = "localhost", timeout: int = 30):
        self.target = target
        self.timeout = timeout
        self.detectors: list[BaseDetector] = [
            HTTPEndpointDetector(target=target),
            ProcessMonitorDetector(),
            NetworkAnalyzerDetector(),
            EnvironmentCheckDetector(),
        ]

    async def scan(self) -> AuditReport:
        """Run all detectors and return a complete report."""
        start = time.perf_counter()
        report = AuditReport(
            target=self.target,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        for detector in self.detectors:
            try:
                findings = await detector.detect()
                for f in findings:
                    converted = _finding_to_audit_finding(detector.name, f)
                    if converted:
                        report.findings.append(converted)
            except Exception as e:
                report.findings.append(
                    AuditFinding(
                        detector=detector.name,
                        severity="info",
                        title=f"Detector error: {detector.name}",
                        description=f"Failed to run detector: {e}",
                    )
                )

        # Sort by severity (critical first)
        report.findings.sort(
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
        )

        report.scan_duration_ms = round((time.perf_counter() - start) * 1000, 1)
        return report

    def scan_sync(self) -> AuditReport:
        """Synchronous wrapper for convenience."""
        return asyncio.run(self.scan())

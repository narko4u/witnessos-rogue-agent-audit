"""JSON reporter — machine-readable output."""

import json
from audit.scanner import AuditReport
from audit.reporters import BaseReporter


class JSONReporter(BaseReporter):
    """Output findings as structured JSON."""

    def __init__(self, indent: int = 2):
        self.indent = indent

    def generate(self, report: AuditReport) -> str:
        data = {
            "version": "0.1.0",
            "tool": "Rogue Agent Audit",
            "target": report.target,
            "timestamp": report.timestamp,
            "scan_duration_ms": report.scan_duration_ms,
            "summary": report.summary(),
            "findings": [
                {
                    "detector": f.detector,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "agent_type": f.agent_type,
                }
                for f in report.findings
            ],
        }
        return json.dumps(data, indent=self.indent)

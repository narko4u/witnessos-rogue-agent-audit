"""Unit tests for the Rogue Agent Scanner."""

import asyncio
import unittest
from unittest.mock import patch, MagicMock
from audit.scanner import RogueAgentScanner, AuditFinding, AuditReport


class TestAuditReport(unittest.TestCase):
    """Test the AuditReport data class."""

    def test_empty_report(self):
        report = AuditReport(target="localhost", timestamp="2026-07-10T00:00:00Z")
        self.assertEqual(report.target, "localhost")
        self.assertEqual(len(report.findings), 0)
        self.assertEqual(report.summary()["total_findings"], 0)

    def test_summary_counts(self):
        report = AuditReport(target="test", timestamp="now")
        report.findings = [
            AuditFinding(detector="test", severity="critical", title="C1", description=""),
            AuditFinding(detector="test", severity="high", title="H1", description=""),
            AuditFinding(detector="test", severity="high", title="H2", description=""),
            AuditFinding(detector="test", severity="medium", title="M1", description=""),
        ]
        summary = report.summary()
        self.assertEqual(summary["total_findings"], 4)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 2)
        self.assertEqual(summary["medium"], 1)

    def test_has_critical(self):
        report = AuditReport(target="test", timestamp="now")
        report.findings = [
            AuditFinding(detector="test", severity="low", title="L1", description=""),
        ]
        self.assertFalse(report.has_critical_findings)
        report.findings.append(
            AuditFinding(detector="test", severity="critical", title="C1", description="")
        )
        self.assertTrue(report.has_critical_findings)

    def test_ungoverned_count(self):
        report = AuditReport(target="test", timestamp="now")
        report.findings = [
            AuditFinding(detector="t", severity="high", title="Ungoverned agent detected", description=""),
            AuditFinding(detector="t", severity="high", title="Unregistered API endpoint", description=""),
            AuditFinding(detector="t", severity="low", title="Info only", description=""),
        ]
        self.assertEqual(report.ungoverned_agent_count, 2)


class TestScanner(unittest.TestCase):
    """Test the RogueAgentScanner."""

    def test_init(self):
        scanner = RogueAgentScanner(target="test-target", timeout=15)
        self.assertEqual(scanner.target, "test-target")
        self.assertEqual(scanner.timeout, 15)
        self.assertEqual(len(scanner.detectors), 4)

    def test_scan_returns_report(self):
        # Quick integration test — runs against localhost, should never crash
        scanner = RogueAgentScanner(target="localhost", timeout=5)
        report = scanner.scan_sync()
        self.assertIsInstance(report, AuditReport)
        self.assertEqual(report.target, "localhost")
        self.assertGreater(report.scan_duration_ms, 0)


if __name__ == "__main__":
    unittest.main()

"""Console reporter — colourful terminal output."""

from audit.scanner import AuditReport
from audit.reporters import BaseReporter

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class ConsoleReporter(BaseReporter):
    """Rich, colourised console output."""

    SEVERITY_STYLES = {
        "critical": ("bold red", "\U0001f534"),
        "high": ("orange_red1", "\U0001f7e0"),
        "medium": ("yellow", "\U0001f7e1"),
        "low": ("green", "\U0001f7e2"),
        "info": ("blue", "\U0001f535"),
    }

    def generate(self, report: AuditReport) -> str:
        """Print to console and return plain text summary."""
        summary = report.summary()

        if HAS_RICH:
            self._rich_output(report, summary)
        else:
            self._plain_output(report, summary)

        # Return plain text for file logging
        return self._plain_text(report, summary)

    def _rich_output(self, report: AuditReport, summary: dict):
        console = Console()

        console.print()
        console.print(Panel.fit(
            "[bold #6e62ff]Rogue Agent Audit[/bold #6e62ff] \u2014 v0.1.0",
            subtitle=f"Target: {report.target}",
            border_style="#6e62ff",
        ))
        console.print()

        # Summary table
        t = Table(title="Scan Summary", box=box.SIMPLE, title_style="bold")
        t.add_column("Metric", style="dim")
        t.add_column("Value")
        t.add_row("Target", f"[bold]{report.target}[/bold]")
        t.add_row("Duration", f"{report.scan_duration_ms}ms")
        t.add_row("Total findings", str(summary["total_findings"]))
        for sev in ("critical", "high", "medium", "low", "info"):
            emoji_style = self.SEVERITY_STYLES.get(sev, ("", "\u26aa"))
            style_class = emoji_style[0]
            emoji = emoji_style[1]
            count = summary["by_severity"].get(sev, 0)
            t.add_row(f"{emoji} {sev.capitalize()}", f"[{style_class}]{count}[/{style_class}]")
        console.print(t)
        console.print()

        if report.has_critical_findings:
            console.print(Panel(
                "[bold red]\u26a0\ufe0f  Critical findings detected. Immediate investigation recommended.[/bold red]",
                border_style="red",
            ))
            console.print()

        # Findings
        for i, f in enumerate(report.findings, 1):
            style_info = self.SEVERITY_STYLES.get(f.severity, ("", "\u26aa"))
            style_class = style_info[0]
            emoji = style_info[1]
            title_text = Text(f"{emoji} Finding {i}: {f.title}", style=f"bold {style_class}")
            console.print(title_text)
            console.print(f"  Detector: [dim]{f.detector}[/dim]")
            console.print(f"  Severity: [{style_class}]{f.severity.upper()}[/{style_class}]")
            console.print(f"  {f.description}")
            if f.evidence:
                console.print(f"  [dim]Evidence: {f.evidence[:120]}[/dim]")
            if f.recommendation:
                console.print(f"  [green]\u2192 {f.recommendation}[/green]")
            console.print()
        
        console.print(f"Ungoverned agents: [bold]{report.ungoverned_agent_count}[/bold]")

    def _plain_output(self, report: AuditReport, summary: dict):
        print("\u2554" + "\u2550" * 40 + "\u2557")
        print("\u2551     ROGUE AGENT AUDIT \u2014 RESULTS      \u2551")
        print("\u255a" + "\u2550" * 40 + "\u255d")
        print(f"  Target:   {report.target}")
        print(f"  Duration: {report.scan_duration_ms}ms")
        print(f"  Findings: {summary['total_findings']}")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = summary["by_severity"].get(sev, 0)
            if count:
                print(f"    {sev}: {count}")
        print()

        for i, f in enumerate(report.findings, 1):
            print(f"  [{f.severity.upper()}] Finding {i}: {f.title}")
            print(f"       {f.description}")

    def _plain_text(self, report: AuditReport, summary: dict) -> str:
        lines = [
            "Rogue Agent Audit \u2014 v0.1.0",
            f"Target: {report.target}",
            f"Duration: {report.scan_duration_ms}ms",
            f"Total findings: {summary['total_findings']}",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            count = summary["by_severity"].get(sev, 0)
            if count:
                lines.append(f"  {sev}: {count}")
        for f in report.findings:
            lines.append(f"  [{f.severity.upper()}] {f.title}")
        return "\n".join(lines)

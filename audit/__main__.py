#!/usr/bin/env python3
"""CLI entry point: python -m audit [options]"""

import argparse
import os
import sys
from audit.scanner import RogueAgentScanner
from audit.reporters.json_reporter import JSONReporter
from audit.reporters.markdown_reporter import MarkdownReporter
from audit.reporters.console_reporter import ConsoleReporter


def main():
    parser = argparse.ArgumentParser(
        description="Rogue Agent Audit — Scan for ungoverned AI agents in your environment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m audit                                    # Scan localhost, console output
  python -m audit --target 192.168.1.100 -o report.md    # Scan IP, markdown file
  python -m audit --format json -o findings.json         # JSON output
  python -m audit --quick                             # Quick scan (fewer probes)
        """,
    )
    parser.add_argument("--target", "-t", default="localhost", help="Target host (default: localhost)")
    parser.add_argument("--format", "-f", choices=["console", "json", "markdown"], default="console", help="Output format (default: console)")
    parser.add_argument("--output", "-o", help="Write output to file instead of stdout")
    parser.add_argument("--timeout", type=int, default=30, help="Per-detector timeout in seconds (default: 30)")
    parser.add_argument("--quick", "-q", action="store_true", help="Quick scan — fewer probes, shorter timeout")
    parser.add_argument("--version", "-v", action="version", version="Rogue Agent Audit 0.1.0")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification (not recommended)")
    args = parser.parse_args()

    timeout = 10 if args.quick else args.timeout
    scanner = RogueAgentScanner(target=args.target, timeout=timeout, insecure=args.insecure)
    
    print(f"Scanning {args.target} for rogue agents...")
    report = scanner.scan_sync()
    print(f"   Scan complete in {report.scan_duration_ms}ms")
    print()

    if args.format == "json":
        reporter = JSONReporter()
    elif args.format == "markdown":
        reporter = MarkdownReporter()
    else:
        reporter = ConsoleReporter()

    output = reporter.generate(report)

    if args.output:
        output_path = os.path.abspath(args.output)
        with open(output_path, "w") as f:
            f.write(output)
        print(f"Report written to {output_path}")
    else:
        print(output)

    # Exit with code based on critical findings
    if report.has_critical_findings:
        print("Critical findings — action required.")
        sys.exit(2)
    elif report.ungoverned_agent_count > 0:
        print(f"{report.ungoverned_agent_count} ungoverned agent(s) detected.")
        sys.exit(1)
    else:
        print("No critical findings.")
        sys.exit(0)


if __name__ == "__main__":
    main()

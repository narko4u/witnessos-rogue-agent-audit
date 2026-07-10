"""Detector for outbound connections to known AI API endpoints and unusual port activity."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from . import BaseDetector, Finding, Severity

KNOWN_AI_API_ENDPOINTS: list[str] = [
    "api.openai.com",
    "api.anthropic.com",
    "api.groq.com",
    "api.cohere.com",
    "api.mistral.ai",
    "api.together.xyz",
    "api.replicate.com",
    "api.deepseek.com",
    "api.perplexity.ai",
    "api.x.ai",
    "api.google.com",
    "generativelanguage.googleapis.com",
    "api.ai21.com",
    "api.huggingface.co",
    "inference.groq.com",
    "openrouter.ai",
    "api.fireworks.ai",
    "api.lemonfox.ai",
    "api.nousresearch.com",
    "api.anthropic.com",
]

SUSPICIOUS_PORTS = [4444, 6666, 7777, 8888, 9999, 13337, 31337, 54321, 12345, 31337]


class NetworkAnalyzerDetector(BaseDetector):
    """Checks for outbound connections to known AI API endpoints and unusual port activity."""

    name = "network_analyzer"
    description = "Analyzes network connections for AI API traffic and unusual port activity"

    def __init__(self, rule_file: str | None = None) -> None:
        self._endpoints: list[str] = list(KNOWN_AI_API_ENDPOINTS)
        self._suspicious_ports: list[int] = list(SUSPICIOUS_PORTS)
        if rule_file:
            self._load_rules(rule_file)

    def _load_rules(self, path: str) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            return
        for agent_type, config in data.items():
            ports = config.get("detection", {}).get("ports", [])
            for p in ports:
                if p not in self._suspicious_ports and p not in (80, 443, 22, 21, 8080):
                    self._suspicious_ports.append(p)

    def _get_connections(self) -> list[dict[str, Any]]:
        """Parse /proc/net/tcp* for active connections."""
        connections: list[dict[str, Any]] = []
        for fname in ("/proc/net/tcp", "/proc/net/tcp6"):
            path = Path(fname)
            if not path.exists():
                continue
            try:
                content = path.read_text()
                for line in content.splitlines()[1:]:  # skip header
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local_addr, remote_addr = parts[1], parts[2]
                    state = int(parts[3], 16)
                    # State 01 = ESTABLISHED
                    if state != 1:
                        continue
                    connections.append({
                        "local": local_addr,
                        "remote": remote_addr,
                        "state": "ESTABLISHED",
                    })
            except (PermissionError, FileNotFoundError):
                continue
        return connections

    def _hex_to_ip(self, hex_addr: str) -> str:
        """Convert hex IP:port to human-readable."""
        try:
            parts = hex_addr.split(":")
            ip_hex, port_hex = parts[0], parts[1]
            port = int(port_hex, 16)

            if len(ip_hex) == 8:  # IPv4
                ip = ".".join(str(int(ip_hex[i : i + 2], 16)) for i in range(6, -1, -2))
                return f"{ip}:{port}"
            elif len(ip_hex) == 32:  # IPv6
                # Collapse to shortened form
                groups = []
                for i in range(0, 32, 4):
                    groups.append(ip_hex[i : i + 4].lstrip("0") or "0")
                ip = ":".join(groups)
                return f"[{ip}]:{port}"
        except (ValueError, IndexError):
            pass
        return hex_addr

    async def detect(self) -> list[Finding]:
        """Analyze network connections for AI API traffic and suspicious patterns."""
        findings: list[Finding] = []
        connections = self._get_connections()

        connected_api_endpoints: set[str] = set()

        for conn in connections:
            remote = self._hex_to_ip(conn["remote"])
            # Check if the remote address resolves to a known API endpoint
            for endpoint in self._endpoints:
                if endpoint in remote or endpoint.split(".")[0] in remote:
                    connected_api_endpoints.add(endpoint)

            # Check for suspicious port connections
            for sp in self._suspicious_ports:
                if f":{sp}" in remote and sp not in connected_api_endpoints:
                    findings.append(
                        Finding(
                            title=f"Suspicious network connection on port {sp}",
                            description=(
                                f"An established connection to {remote} was detected "
                                f"on suspicious port {sp}. This could indicate "
                                f"unauthorized agent communication."
                            ),
                            severity=Severity.MEDIUM,
                            category="network",
                            location=f"Connection to {remote}",
                            details={
                                "remote": remote,
                                "local": self._hex_to_ip(conn["local"]),
                                "port": sp,
                            },
                            recommendation=(
                                "Investigate this connection. If unauthorized, "
                                "block at the firewall level and audit the source process."
                            ),
                        )
                    )

        for endpoint in sorted(connected_api_endpoints):
            findings.append(
                Finding(
                    title=f"Outbound connection to AI API: {endpoint}",
                    description=(
                        f"An active connection to {endpoint} was detected. "
                        "This may be legitimate AI usage or an ungoverned "
                        "agent making API calls."
                    ),
                    severity=Severity.MEDIUM,
                    category="network",
                    location=f"Connection to {endpoint}",
                    details={
                        "endpoint": endpoint,
                        "connections": list(connected_api_endpoints),
                    },
                    recommendation=(
                        "Verify this API access is authorized. "
                        "Use WitnessOS to monitor and govern AI API usage."
                    ),
                )
            )

        return findings

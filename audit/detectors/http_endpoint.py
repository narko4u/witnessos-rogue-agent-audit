"""Detector for known AI agent HTTP API endpoints."""

from __future__ import annotations

from typing import Any

import httpx
import yaml

from . import BaseDetector, Finding, Severity

COMMON_ENDPOINTS = [
    "/v1/chat/completions",
    "/v1/chat",
    "/v1/completions",
    "/api/agents",
    "/api/agent",
    "/api/chat",
    "/api/v1/chat",
    "/agents",
    "/agent",
    "/health",
    "/metrics",
    "/openai/v1/chat/completions",
    "/v1/models",
    "/api/tools",
    "/api/functions",
    "/api/execute",
    "/api/invoke",
]

COMMON_PORTS = [
    8000,
    8080,
    8081,
    9090,
    3000,
    5000,
    5001,
    7860,
    11434,
    1234,
    1337,
    8001,
    8888,
]


class HTTPEndpointDetector(BaseDetector):
    """Probes common port/path combinations for known agent API endpoints."""

    name = "http_endpoint"
    description = "Scans for AI agent HTTP API endpoints on common ports"

    def __init__(self, target: str = "localhost", rule_file: str | None = None) -> None:
        self.target = target
        self._endpoints: list[dict[str, Any]] = []
        self._ports: list[int] = list(COMMON_PORTS)
        if rule_file:
            self._load_rules(rule_file)

    def _load_rules(self, path: str) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            return
        for agent_type, config in data.items():
            endpoints = config.get("detection", {}).get("http_endpoints", [])
            for ep in endpoints:
                self._endpoints.append(ep)
            ports = config.get("detection", {}).get("ports", [])
            for p in ports:
                if p not in self._ports:
                    self._ports.append(p)

    async def detect(self) -> list[Finding]:
        """Probe endpoints and return findings."""
        findings: list[Finding] = []
        client = httpx.AsyncClient(timeout=3.0, verify=False)

        try:
            for port in self._ports:
                base_url = f"http://{self.target}:{port}"
                for path in COMMON_ENDPOINTS:
                    url = f"{base_url}{path}"
                    try:
                        response = await client.get(url)
                        if response.status_code < 500:
                            details: dict[str, Any] = {
                                "port": port,
                                "path": path,
                                "status_code": response.status_code,
                                "url": url,
                            }
                            content_type = response.headers.get("content-type", "")
                            if "json" in content_type:
                                try:
                                    body = response.json()
                                    if "model" in body:
                                        details["model"] = body["model"]
                                    if "object" in body:
                                        details["response_type"] = body["object"]
                                except Exception:
                                    pass

                            findings.append(
                                Finding(
                                    title=f"Unregistered API endpoint detected on port {port}",
                                    description=(
                                        f"An HTTP endpoint responding at {url} "
                                        f"returned status {response.status_code}. "
                                        "This may be an AI agent API running without governance."
                                    ),
                                    severity=Severity.CRITICAL,
                                    category="http_endpoint",
                                    location=url,
                                    details=details,
                                    recommendation=(
                                        "Register this API endpoint in your Agent Asset Registry "
                                        "and enforce governance via WitnessOS."
                                    ),
                                )
                            )
                    except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
                        continue
                    except Exception:
                        continue
        finally:
            await client.aclose()

        return findings

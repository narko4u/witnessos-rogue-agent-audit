"""Detector for known AI agent process names running on the system."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from . import BaseDetector, Finding, Severity

KNOWN_AGENT_PROCESSES: list[str] = [
    "autogen",
    "autogen-server",
    "autogen-studio",
    "crewai",
    "crewai-server",
    "langgraph",
    "langgraph-api",
    "semantic-kernel",
    "semantic-kernel-server",
    "openai-agents",
    "openai-agents-server",
    "pydantic-ai",
    "pydantic-ai-server",
    "smolagents",
    "smolagents-server",
    "cognee",
    "cognee-server",
    "agent-zero",
    "agent-zero-server",
    "superagent",
    "superagent-server",
    "taskweaver",
    "taskweaver-server",
    "witnessos",
    "witnessos-agent",
    "witnessos-gateway",
    "witnessos-policy",
    "chainlit",
    "gradio",
    "gradio-server",
    "llamafile",
    "ollama",
    "ollama-server",
    "vllm",
    "vllm-server",
    "text-generation-server",
    "tgi-server",
    "localai",
    "localai-server",
    "koboldcpp",
    "oobabooga",
    "text-generation-webui",
    "comfyui",
    "agno",
    "agno-server",
    "letta",
    "letta-server",
    "mem0",
    "mem0-server",
]

FRAMEWORK_KEYWORDS = [
    r"agent",
    r"autogen",
    r"crewai",
    r"langchain",
    r"langgraph",
    r"semantic.?kernel",
    r"openai",
    r"pydantic.?ai",
]


class ProcessMonitorDetector(BaseDetector):
    """Checks running processes for known agent executables and framework binaries."""

    name = "process_monitor"
    description = "Scans the process table for known AI agent processes"

    def __init__(self, rule_file: str | None = None) -> None:
        self._known_processes: list[str] = list(KNOWN_AGENT_PROCESSES)
        if rule_file:
            self._load_rules(rule_file)

    def _load_rules(self, path: str) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            return
        for agent_type, config in data.items():
            names = config.get("detection", {}).get("process_names", [])
            for name in names:
                if name not in self._known_processes:
                    self._known_processes.append(name)

    def _list_processes(self) -> list[dict[str, Any]]:
        """Read /proc to enumerate processes."""
        procs: list[dict[str, Any]] = []
        proc_path = Path("/proc")
        if not proc_path.exists():
            return procs

        for entry in proc_path.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                pid = int(entry.name)
                cmdline = (entry / "cmdline").read_text(errors="replace").replace("\0", " ").strip()
                if not cmdline:
                    continue
                comm = (entry / "comm").read_text(errors="replace").strip()
                try:
                    uid = (entry / "status").read_text().split("Uid:")[1].split()[0]
                except (IndexError, OSError):
                    uid = "?"
                procs.append({"pid": pid, "comm": comm, "cmdline": cmdline, "uid": uid})
            except (PermissionError, FileNotFoundError):
                continue
        return procs

    async def detect(self) -> list[Finding]:
        """Check process list against known agent process names."""
        findings: list[Finding] = []
        processes = self._list_processes()

        for proc in processes:
            cmdline_lower = proc["cmdline"].lower()
            comm_lower = proc["comm"].lower()

            # Check exact process name matches
            for known in self._known_processes:
                if known.lower() in cmdline_lower or known.lower() == comm_lower:
                    findings.append(
                        Finding(
                            title=f"Known agent process '{known}' running",
                            description=(
                                f"Process '{known}' (PID {proc['pid']}) is running "
                                f"on this system. This process was not registered "
                                f"through the Agent Asset Registry."
                            ),
                            severity=Severity.HIGH,
                            category="process",
                            location=f"PID {proc['pid']}",
                            details={
                                "pid": proc["pid"],
                                "process_name": known,
                                "command": proc["cmdline"][:200],
                                "user_id": proc["uid"],
                            },
                            recommendation=(
                                "Verify this agent is authorized. Register it in the "
                                "Agent Asset Registry and enforce governance via WitnessOS."
                            ),
                        )
                    )

        return findings

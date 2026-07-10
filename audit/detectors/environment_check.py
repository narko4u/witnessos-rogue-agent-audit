"""Detector for environment variables that indicate AI agent configurations."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from . import BaseDetector, Finding, Severity

SENSITIVE_ENV_KEYWORDS: list[str] = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_API_KEY",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "GROQ_API_KEY",
    "TOGETHER_API_KEY",
    "REPLICATE_API_TOKEN",
    "DEEPSEEK_API_KEY",
    "PERPLEXITY_API_KEY",
    "XAI_API_KEY",
    "HUGGINGFACE_TOKEN",
    "HUGGINGFACEHUB_API_TOKEN",
    "AI21_API_KEY",
    "OPENROUTER_API_KEY",
    "FIREWORKS_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "WITNESSOS_API_KEY",
    "WITNESSOS_ENDPOINT",
    "WITNESSOS_AGENT_ID",
    "AGENT_API_KEY",
    "AGENT_CONFIG",
    "AGENT_ENDPOINT",
]

AGENT_CONFIG_KEYWORDS: list[str] = [
    "AGENT_",
    "AUTOGEN_",
    "CREWAI_",
    "LANGCHAIN_",
    "LANGGRAPH_",
    "SEMANTIC_KERNEL_",
    "OPENAI_AGENTS_",
    "PYDANTIC_AI_",
    "SMOLAGENTS_",
    "WITNESSOS_",
    "AGNO_",
    "LETTA_",
    "MEM0_",
]


class EnvironmentCheckDetector(BaseDetector):
    """Scans environment variables for API keys, agent configs, and framework variables."""

    name = "environment_check"
    description = "Scans process environments for AI agent configuration and credentials"

    def __init__(self, rule_file: str | None = None) -> None:
        self._sensitive_vars: set[str] = set(SENSITIVE_ENV_KEYWORDS)
        self._agent_config_prefixes: list[str] = list(AGENT_CONFIG_KEYWORDS)
        if rule_file:
            self._load_rules(rule_file)

    def _load_rules(self, path: str) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            return
        for agent_type, config in data.items():
            env_vars = config.get("detection", {}).get("env_vars", [])
            for var in env_vars:
                if isinstance(var, str):
                    self._sensitive_vars.add(var)

    def _get_process_envs(self) -> list[dict[str, Any]]:
        """Read /proc/PID/environ for running processes."""
        envs: list[dict[str, Any]] = []
        proc_path = Path("/proc")
        if not proc_path.exists():
            return envs

        for entry in proc_path.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                pid = int(entry.name)
                environ_raw = (entry / "environ").read_bytes()
                environ_str = environ_raw.decode("utf-8", errors="replace")
                env_dict: dict[str, str] = {}
                for var in environ_str.split("\0"):
                    if "=" in var:
                        key, _, value = var.partition("=")
                        env_dict[key] = value
                if env_dict:
                    # Get command for context
                    cmdline = (entry / "cmdline").read_text(errors="replace").replace("\0", " ").strip()
                    envs.append({
                        "pid": pid,
                        "environ": env_dict,
                        "cmdline": cmdline[:200],
                    })
            except (PermissionError, FileNotFoundError):
                continue
        return envs

    async def detect(self) -> list[Finding]:
        """Scan process environments for agent-related variables."""
        findings: list[Finding] = []
        process_envs = self._get_process_envs()

        found_sensitive: dict[str, list[int]] = {}
        found_agent_configs: dict[str, list[dict[str, Any]]] = {}

        for proc in process_envs:
            pid = proc["pid"]
            env = proc["environ"]

            # Check for sensitive API keys
            for key in env:
                key_upper = key.upper()
                if key_upper in self._sensitive_vars:
                    if key not in found_sensitive:
                        found_sensitive[key] = []
                    found_sensitive[key].append(pid)

                # Check for agent config variable patterns
                for prefix in self._agent_config_prefixes:
                    if key_upper.startswith(prefix) and key_upper not in self._sensitive_vars:
                        if key not in found_agent_configs:
                            found_agent_configs[key] = []
                        found_agent_configs[key].append({
                            "pid": pid,
                            "value_preview": env[key][:20] + "..." if len(env[key]) > 20 else env[key],
                            "cmdline": proc["cmdline"],
                        })

        # Report findings
        for var_name, pids in sorted(found_sensitive.items()):
            value_preview = ""
            for proc in process_envs:
                if proc["pid"] in pids and var_name in proc.get("environ", {}):
                    val = proc["environ"][var_name]
                    value_preview = val[:8] + "..." if len(val) > 8 else val
                    break

            findings.append(
                Finding(
                    title=f"API credential detected: {var_name}",
                    description=(
                        f"Environment variable {var_name} was found in process "
                        f"environment(s) PID(s): {', '.join(str(p) for p in pids)}. "
                        "This API key provides access to an AI service and may "
                        "be used by ungoverned agents."
                    ),
                    severity=Severity.MEDIUM,
                    category="environment",
                    location=f"PID(s): {', '.join(str(p) for p in pids)}",
                    details={
                        "variable": var_name,
                        "pids": pids,
                        "value_preview": value_preview,
                    },
                    recommendation=(
                        f"Ensure {var_name} is authorized. Rotate the key if "
                        "the agent using it is not registered. "
                        "Use WitnessOS to manage agent credentials securely."
                    ),
                )
            )

        for var_name, proc_infos in sorted(found_agent_configs.items()):
            pids = [p["pid"] for p in proc_infos]
            findings.append(
                Finding(
                    title=f"Agent configuration variable: {var_name}",
                    description=(
                        f"Environment variable {var_name} matches an agent framework "
                        f"configuration pattern. Found in PID(s): {', '.join(str(p) for p in pids)}."
                    ),
                    severity=Severity.LOW,
                    category="environment",
                    location=f"PID(s): {', '.join(str(p) for p in pids)}",
                    details={
                        "variable": var_name,
                        "pids": pids,
                        "process_info": proc_infos[0] if proc_infos else {},
                    },
                    recommendation=(
                        "Verify this agent configuration is intentional. "
                        "Register the agent in your Agent Asset Registry."
                    ),
                )
            )

        # Also check the current process environment
        current_env = os.environ
        for key in current_env:
            key_upper = key.upper()
            if key_upper in self._sensitive_vars and key not in found_sensitive:
                findings.append(
                    Finding(
                        title=f"API credential in current env: {key}",
                        description=(
                            f"Environment variable {key} is set in the current shell. "
                            "This API key may be accessible by ungoverned agents."
                        ),
                        severity=Severity.MEDIUM,
                        category="environment",
                        location="current shell environment",
                        details={
                            "variable": key,
                        },
                        recommendation=(
                            "Remove this variable from your shell environment or "
                            "use a secrets manager."
                        ),
                    )
                )

        return findings

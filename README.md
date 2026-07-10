# 🔍 Rogue Agent Audit

**Audit your environment for ungoverned, unregistered, or misbehaving AI agents.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-beta-yellow)](https://github.com/narko4u/witnessos-rogue-agent-audit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

---

## What Is Rogue Agent Audit?

**Rogue Agent Audit** is a public, open-source diagnostic tool that scans environments for AI agents running without proper governance. It detects:

- **Ungoverned agents** — AI agent processes running outside any orchestration or registry system
- **Unregistered API endpoints** — Agent HTTP services exposed without authorization or monitoring
- **Misconfigured environments** — API keys, agent configs, and framework variables lying around without oversight
- **Suspicious network activity** — Outbound connections to AI API providers from unregistered processes
- **Known agent frameworks** — Processes from AutoGen, CrewAI, LangGraph, Semantic Kernel, and others running unchecked

The tool produces actionable reports in JSON, Markdown, or rich terminal output.

---

## Why Rogue Agents Matter

As organizations adopt AI agents, the surface area for **uncontrolled agent deployment** grows exponentially. Problems include:

| Risk | Description |
|------|-------------|
| **Shadow AI** | Teams deploy agents without IT/security knowledge, creating blind spots |
| **Data exfiltration** | Ungoverned agents leak sensitive data through unmonitored API calls |
| **Cost explosions** | Rogue agents burn through API quotas with no oversight |
| **Compliance failures** | Unregistered agents violate SOC 2, HIPAA, or GDPR requirements |
| **Supply chain risks** | Agents pulling unvetted tools or models introduce third-party vulnerabilities |

Rogue Agent Audit is the **first line of defense** — a free, open-source scanner anyone can run to discover what agents are actually present in their environment.

---

## Quick Start

```bash
# Install from source
cd rogue-agent-audit
pip install -e .

# Run a full audit
python -m audit

# Scan a remote target
python -m audit --target 192.168.1.100

# Save results as a JSON report
python -m audit --format json --output report.json

# Generate a human-readable markdown report
python -m audit --format markdown --output audit-report.md
```

---

## Sample Output

```text
╔══════════════════════════════════════════════════════════════════╗
║           ROGUE AGENT AUDIT — Diagnostic Report                 ║
║           Target: localhost         2026-07-10T14:30:00Z        ║
╚══════════════════════════════════════════════════════════════════╝

🔴 CRITICAL  - Unregistered API endpoint detected on port 8080
   Path: /v1/chat/completions
   Framework: OpenAI-compatible API
   Risk: Unauthorized model access, potential data exfiltration

🟠 HIGH      - Process 'autogen-server' running without registry entry
   PID: 1423        User: developer
   Risk: Ungoverned agent operating outside governance runtime

🟡 MEDIUM    - Environment variable OPENAI_API_KEY found
   Source: /proc/1423/environ
   Risk: API credential exposed, potential for unauthorized usage

🟢 LOW       - Unknown agent agent-unverified-v0.1.0 installed
   Path: /home/user/.local/bin
   Risk: Unvetted agent software, no security review performed

  Found 4 findings (1 critical, 1 high, 1 medium, 1 low)
  Scan completed in 2.3 seconds
```

---

## How It Works

1. **HTTP Endpoint Probing** — The scanner checks common paths (`/v1/chat`, `/api/agents`, `/health`, `/metrics`) on the target to identify running agent API services
2. **Process Inspection** — It walks the process table looking for known agent executables and framework binaries
3. **Network Analysis** — Monitors active outbound connections to known AI API endpoints and unusual port usage
4. **Environment Scanning** — Inspects process environment variables for API keys, agent configs, and framework variables

All detection patterns are defined in human-readable YAML rule files under `rules/`, making it easy to extend coverage without touching Python code.

---

## Rule Files

The tool ships with two rule collections:

- **`rules/known-agent-patterns.yaml`** — API endpoints, process names, env vars, and ports for 20+ known agent frameworks
- **`rules/suspicious-behaviors.yaml`** — Behavioral patterns indicating ungoverned agents (API calls without auth, unusual data access, etc.)

Add your own rules by creating additional YAML files in the `rules/` directory.

---

## Companion Projects

### Agent Asset Registry
[Agent Asset Registry](https://github.com/narko4u/witnessos-agent-asset-registry) is a companion tool for cataloging and registering legitimate AI agents. Use it together with Rogue Agent Audit to maintain a complete inventory: audit discovers what's running, the registry tracks what's approved.

### WitnessOS
[WitnessOS](https://github.com/narko4u/witnessos) is a governance runtime for AI agents. It provides runtime policy enforcement, audit logging, and behavioral monitoring. Rogue Agent Audit serves as the initial discovery layer — run it before deploying WitnessOS to find what needs governance, then use WitnessOS to enforce policy on all agents in your environment.

---

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy audit

# Linting
ruff check audit
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding detection rules, testing requirements, and the pull request process.

## Security

See [SECURITY.md](SECURITY.md) for our vulnerability reporting process.

---

## License

Apache 2.0 — See [LICENSE](LICENSE) for full text.

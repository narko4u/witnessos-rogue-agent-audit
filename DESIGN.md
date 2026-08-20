# Design: witnessos-rogue-agent-audit

This document describes the design of the Rogue Agent Audit tool: a Python package that scans an agent fleet for rogue/unapproved agents using rule files under audit/rules and produces reports: the actors, the actions
they perform, and the data flow. It accompanies
[THREAT-ASSESSMENT.md](THREAT-ASSESSMENT.md) (threat model) and
[TESTING.md](TESTING.md) (test policy).

## Purpose

The rogue agent audit tool: a python package that scans an agent fleet for rogue/unapproved agents using rule files under audit/rules and produces reports.

## Actors

| Actor | Description |
| --- | --- |
| Auditor operator | Runs the audit CLI against a deployed agent fleet to detect rogue agents. |
| Rule author | Maintains the audit rules in audit/rules. |
| Report consumer | Reviews generated reports under reports/. |

## Actions

| Action | Performed by | Implemented in |
| --- | --- | --- |
| Run audit over fleet | Auditor operator | `audit/ + rules` |
| Evaluate agent against rules | Auditor operator | `audit/` |
| Run tests | CI | `tests/` |

## Data flow

```
repository (main branch)
        │
        ▼
CI (on push / pull_request) ──► validate / test / security jobs
        │
        ▼
tagged release ──► build artifacts + CycloneDX SBOM + Sigstore signatures + SHA256SUMS
```

## Design invariants

1. **Open by construction.** The content is freely licensed and version-controlled.
2. **Minimal dependencies.** Fewer dependencies means a smaller attack surface.
3. **Tamper-evident releases.** Where releases exist, assets carry Sigstore signatures and checksums.

# Security Assessment

Status: assessment performed for the current release. This document records
the most likely and impactful potential security problems for this project and
the mitigations in place. It is reviewed before each release.

## What this project is

The rogue agent audit tool: a python package that scans an agent fleet for rogue/unapproved agents using rule files under audit/rules and produces reports.

## Assets

1. **Content/specification integrity** - the published content must not silently change.
2. **Tool correctness** - any shipped tooling must not be tricked into wrong output.
3. **No foothold from use** - consuming the content or running the tooling must not compromise the user's host.

## Likely and impactful problems

| # | Problem | Likelihood | Impact | Mitigation |
|---|---------|------------|--------|------------|
| Fleet data tampering during scan | Medium | Medium | Read-only analysis; outputs are reports; integrity covered by release signing |
| Rule misconfiguration causing missed rogues | Medium | High | Rules are version-controlled and covered by tests |
| Dependency supply-chain risk | Low | Medium | Minimal dependencies; SCA via OSV-Scanner in CI |

## Threat model scope

- **In scope:** content integrity, tooling input handling, release integrity.
- **Explicitly out of scope:** transport security of external endpoints the user chooses to reach.

## Attack surface analysis

- Components: Rogue Agent Audit package, audit/rules/*, reports/*.
- CI workflows: least-privilege `contents: read` permissions (plus scoped `security-events: write` for SAST).

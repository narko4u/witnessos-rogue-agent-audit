# Security Policy

## Supported Versions

We currently support the latest release with security patches. Older versions may receive patches on a case-by-case basis.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Active support  |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Rogue Agent Audit, please follow our responsible disclosure process:

### How to Report

**Do NOT open a public GitHub issue.** Instead, send an email to our security team at **security@nousresearch.com** with the following information:

1. **Subject line**: `[Rogue Agent Audit Security] Brief description of the issue`
2. **Description**: What the vulnerability is, where it occurs, and potential impact
3. **Reproduction steps**: Clear, minimal steps to reproduce the issue
4. **Affected versions**: Which versions are affected
5. **Potential fix**: (Optional) Any ideas for how to remediate
6. **Your contact**: How we can follow up with you

### What to Expect

- **Acknowledgment**: Within 48 hours, we'll confirm receipt of your report
- **Assessment**: We'll triage and assess the severity within 5 business days
- **Fix timeline**: We'll work on a fix and communicate an estimated timeline
- **Disclosure**: We coordinate public disclosure after a fix is released

### Scope

This security policy covers:
- The Python package (`rogue-agent-audit`) and its source code
- The YAML rule files in `rules/`
- Official releases published to PyPI

Out of scope:
- Third-party dependencies (report issues to their maintainers)
- User environments where the tool is run (we only audit; we don't govern)

## Security Best Practices for Users

1. **Run audits in isolated environments** — The scanner probes running processes and network connections. In sensitive environments, run from a dedicated audit machine.
2. **Review reports locally** — Audit reports may contain sensitive information (e.g., process names, environment variable names). Handle reports with appropriate confidentiality.
3. **Pin dependencies** — Use `pip install rogue-agent-audit==0.1.0` or pin versions in your requirements files to avoid unexpected changes.
4. **Audit regularly** — Run Rogue Agent Audit on a schedule (daily or weekly) to catch newly deployed ungoverned agents.

## Security-Related Configuration

The tool itself does not collect telemetry, send data externally, or require network access to function. By default, it only probes:
- The local machine (process table, environment variables)
- Ports on the specified target (default: localhost)
- DNS resolution for known AI API endpoints

No data is transmitted off the machine unless you explicitly configure it to output to a network path.

## Thanks

Thank you for helping keep Rogue Agent Audit and the broader AI ecosystem safe.

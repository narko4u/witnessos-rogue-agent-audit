# Contributing to Rogue Agent Audit

Thank you for your interest in contributing to Rogue Agent Audit! This document provides guidelines for adding detection rules, writing tests, and submitting changes.

## Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and constructive environment for everyone.

## How to Contribute

### Adding Detection Rules

The easiest way to contribute is by adding new detection rules. Rules live as YAML files in the `rules/` directory.

1. **Known agent patterns** — Add to `rules/known-agent-patterns.yaml`:
   - API endpoints the agent exposes
   - Process names used by the agent
   - Environment variables the agent reads
   - Ports the agent listens on

2. **Suspicious behaviors** — Add to `rules/suspicious-behaviors.yaml`:
   - Behavioral indicators (e.g., high-frequency API calls)
   - Network patterns (e.g., connections to unusual ports)
   - Configuration anomalies

**Rule format:**
```yaml
agent_type:
  name: "My Agent Framework"
  version: "1.0"
  detection:
    http_endpoints:
      - path: "/v1/my-agent/chat"
        method: "POST"
        expected_status: 200
    process_names:
      - "my-agent"
      - "my-agent-server"
    env_vars:
      - "MY_AGENT_API_KEY"
      - "MY_AGENT_CONFIG"
    ports:
      - 8081
      - 9090
```

### Development Setup

```bash
git clone https://github.com/narko4u/witnessos-rogue-agent-audit.git
cd rogue-agent-audit
pip install -e ".[dev]"
```

### Testing Requirements

- **Unit tests** go in `tests/` and use pytest
- **New detectors** must include tests for both detection and non-detection scenarios
- **Rule additions** should include test cases that verify the rule loads correctly
- Run all tests before submitting: `pytest`
- Ensure type hints pass: `mypy audit`

### Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Write or update tests for your changes
3. Ensure all existing tests pass
4. Run `ruff check audit` and fix any linting issues
5. Run `mypy audit` and fix any type errors
6. Submit a pull request with a clear description of the change
7. Link any related issues

### Code Style

- Python 3.12+ with type hints on all function signatures
- Follow PEP 8 conventions (enforced by ruff)
- Use docstrings for all public modules, classes, and functions
- Prefer pathlib over os.path
- Use async where I/O-bound operations are involved

### Adding a New Detector

1. Create a new file in `audit/detectors/` (e.g., `audit/detectors/file_system_scanner.py`)
2. Subclass `BaseDetector` from `audit.detectors`
3. Implement `detect() -> list[Finding]`
4. Register the detector in the scanner (see `audit/scanner.py`)
5. Add tests in `tests/test_<detector_name>.py`
6. Update the rule YAML files if your detector needs new patterns

### Adding a New Reporter

1. Create a new file in `audit/reporters/` (e.g., `audit/reporters/html_reporter.py`)
2. Subclass `BaseReporter` from `audit.reporters`
3. Implement the `generate()` method
4. Register the reporter format in `audit/__main__.py`

## Release Process

- Version numbers follow [SemVer](https://semver.org/)
- Changelog entries are maintained in GitHub Releases
- Releases are tagged from the `main` branch after review

## Questions?

Open a [GitHub Issue](https://github.com/narko4u/witnessos-rogue-agent-audit/issues) for questions, feature requests, or discussion.

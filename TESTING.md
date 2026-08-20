# Testing Policy

This document defines **when** tests run and **what is required** of every
change in this repository. It is normative: the CI pipeline enforces the
automated portion, and maintainers enforce the policy portion during review.

## When tests run

1. **Every pull request** - the CI workflow runs the validation/test suite
   (see `.github/workflows/`). A PR that breaks CI cannot be merged.
2. **Every push to `main`** - the same workflow runs again.
3. **Locally, before opening a PR** - contributors are expected to run the
   checks described in [CONTRIBUTING.md](CONTRIBUTING.md).
4. **Before every release** - the Release workflow (where present) only runs
   on a tag; the tag is created from a `main` commit that already passed CI.

## What the suite covers

CI runs the pytest suite in tests/ on every pull request and push to main, plus a Bandit SAST scan and a secrets scan (trufflehog). A PR that breaks tests or fails security scans cannot merge.

Run the same checks locally:

```sh
pip install -e . && python -m pytest tests/ -v
```

## Policy for major changes

> **Any significant change MUST add or update automated tests or validation
> coverage in the same PR.**

For this project, that means:

- A change to content MUST keep the CI validation green and update any
  affected fixtures or examples.
- A change to tooling MUST add or update a test that exercises the changed
  behaviour.

Trivial changes (typos, formatting, documentation-only edits) are exempt at
the maintainer's discretion - but a PR that touches functional content
without updating validation coverage will be blocked in review.

## Enforcement

- CI failing = merge blocked (branch protection requires the checks).
- Policy not followed = review comment, PR returned to author.

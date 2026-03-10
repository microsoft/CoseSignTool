# Copilot Agent Skills (Project)

This repo uses the Agent Skills standard (https://agentskills.io/) to provide reusable, on-demand capabilities for GitHub Copilot.

Skills live under `.github/skills/<skill-name>/SKILL.md`.

## Skills in this repo

- `architecture-designer`: Design and evolve the V2 architecture + docs.
- `spec-test-writer`: Write NUnit tests from Given/When/Then scenarios (parallel-safe).
- `implementer`: Implement V2 code to satisfy failing tests.
- `code-sanitizer`: Enforce analyzers, StyleCop, formatting, and XML docs.
- `testability`: Review DI seams and determinism.
- `security-analysis`: Security review for crypto, certs, and Azure integrations.
- `diagnosability`: Actionable exceptions, error codes, correlation IDs, structured logging.
- `documentation`: Keep V2 docs and package metadata in sync.
- `coverage-verifier`: Run coverage gate and propose tests for uncovered lines.

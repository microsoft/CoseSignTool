---
name: testability
description: Review and improve V2 testability: DI seams, interface abstractions for IO/time/Azure, deterministic behavior, and parallel-safe tests. Use when refactoring for unit tests or diagnosing flaky parallel test failures.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/05a-testability.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.

## What to check
- Constructor injection for all dependencies.
- Interfaces for external services (time, filesystem, HTTP/Azure).
- No hidden static state; deterministic behavior.
- Tests are parallel-safe: no shared mutable state, unique resources.

For detailed guidance, refactoring examples, and audit commands, see [references/REFERENCE.md](references/REFERENCE.md).

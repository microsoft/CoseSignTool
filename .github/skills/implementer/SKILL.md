---
name: implementer
description: Implement V2 production code to satisfy failing NUnit tests using V2’s interface-based, DI-friendly architecture. Use when fixing test failures, adding minimal code paths, or wiring factories/services with ILogger<T> and event IDs.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/03-implementer.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.
- Implement the smallest change that makes the failing test(s) pass.

## Implementation workflow
1. Reproduce the failing test (filter to the smallest scope).
2. Implement minimal code to pass.
3. Run the relevant test project, then the solution.
4. Keep public APIs clean: XML docs, argument validation, DI-friendly constructors.
5. Use structured logging (`ILogger<T>`) and event IDs for critical operations.

For detailed patterns (interfaces, logging patterns, build/test commands, examples), see [references/REFERENCE.md](references/REFERENCE.md).

---
name: architecture-designer
description: Design and evolve the CoseSignTool V2 architecture and documentation. Use when proposing/adjusting V2 interfaces, layering, DI patterns, signing services, validators, factories, header contributors, or when converting requirements into Given/When/Then scenarios.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/01-architecture-designer.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.
- Prefer architecture/docs changes; if code changes are needed, keep them small and aligned to V2 patterns.

## What to do
1. Inspect existing V2 architecture docs and current implementation patterns.
2. Propose interface-first designs that are DI-friendly, async-first, and fail-fast.
3. Express requirements as Given/When/Then scenarios suitable for NUnit tests.
4. Ensure public-facing APIs use `ILogger<T>` and event IDs for critical operations.

## Output expectations
- Clear architecture decisions (and ADRs when warranted).
- Scenarios that are directly translatable to tests.

For detailed guidance, examples, and command snippets, see [references/REFERENCE.md](references/REFERENCE.md).

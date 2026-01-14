---
name: documentation
description: Update CoseSignTool V2 documentation to match implemented APIs (docs/, README, CHANGELOG, NuGet metadata). Use when public APIs change, new components are added, or logging/DI patterns need to be documented.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/06-documentation.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.

## What to do
1. Update `V2/docs/` and `V2/README.md` to match current APIs.
2. Ensure examples are complete/runnable and demonstrate `ILogger<T>` injection + logging configuration.
3. Update NuGet package metadata (descriptions/tags) if public packages changed.
4. Update `CHANGELOG.md` for user-visible changes.

For templates, structure, and commands, see [references/REFERENCE.md](references/REFERENCE.md).

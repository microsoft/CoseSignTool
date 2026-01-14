---
name: code-sanitizer
description: Enforce V2 coding standards: dotnet analyzers, StyleCop, formatting, XML documentation, and structured logging rules. Use when cleaning up PRs, fixing analyzer failures, or preparing V2 code for review.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/04-code-sanitizer.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.
- Focus on quality gates: formatting, analyzers, documentation, logging.

## What to do
1. Run formatting checks (`dotnet format --verify-no-changes`).
2. Build with warnings as errors.
3. Fix StyleCop/analyzer findings in a minimal, non-invasive way.
4. Ensure public APIs have XML docs, file headers, and `ILogger<T>` injection.

For the detailed checklist, common issues, and audit commands, see [references/REFERENCE.md](references/REFERENCE.md).

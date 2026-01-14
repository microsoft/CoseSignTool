---
name: coverage-verifier
description: Verify V2 meets the 95% line coverage target using V2/collect-coverage.ps1; analyze coverage reports and propose specific tests for uncovered lines/branches. Use after adding features or when coverage gates fail.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/07-coverage-verifier.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.

## What to do
1. Run the coverage gate (`collect-coverage.ps1`).
2. If it fails, identify lowest-coverage files and the exact uncovered lines.
3. Propose/add targeted NUnit tests (parallel-safe) to cover those lines.
4. Re-run coverage to confirm the gate passes.

For detailed commands, analysis snippets, and handoff template, see [references/REFERENCE.md](references/REFERENCE.md).

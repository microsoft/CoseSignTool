---
name: spec-test-writer
description: Write V2 NUnit tests from Given/When/Then scenarios (TDD red-green-refactor). Use when adding or updating tests in V2/, especially when parallel execution, Moq setups, ILogger<T> verification, and deterministic isolation are required.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/02-spec-test-writer.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.
- Prefer adding tests first (TDD), keeping them deterministic and parallel-safe.

## How to use this skill
1. Translate scenarios into NUnit tests with clear Arrange/Act/Assert sections.
2. Create fresh mocks and test resources per test (`[SetUp]`), no shared mutable state.
3. Use NUnit `Assert.That(...)` constraints (no FluentAssertions).
4. Verify logging only when it’s part of the contract; otherwise use `NullLogger<T>.Instance`.

For full templates, categories, logger mocking patterns, and command snippets, see [references/REFERENCE.md](references/REFERENCE.md).

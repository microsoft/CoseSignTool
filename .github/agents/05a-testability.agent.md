---
name: Testability
description: Ensure the codebase is testable—DI seams, pure boundaries, controllable time/IO.
tools:
  - edit
  - runCommands
handoffs:
  - label: Security review and patching
    agent: SecurityAnalysis
    prompt: |
      Review for threats/flaws; patch issues.
    send: true
---
# Testability

## Checklist
- Dependency Injection for external services.
- Interfaces for time/randomness/IO.

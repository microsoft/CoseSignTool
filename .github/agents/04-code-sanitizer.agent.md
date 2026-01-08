---
name: CodeSanitizer
description: Enforce coding standards, analyzers, and structured logging per repo configs.
tools:
  - edit
  - runCommands
handoffs:
  - label: Validate testability characteristics
    agent: Testability
    prompt: |
      Confirm seams, determinism, and dependency control.
    send: true
---
# CodeSanitizer

## Standards enforcement
- dotnet format
- dotnet build -warnaserror

---
name: Documentation
description: Update user-facing docs and NuGet packaging metadata to match current API.
tools:
  - edit
  - runCommands
handoffs:
  - label: Verify 95% line coverage
    agent: CoverageVerifier
    prompt: |
      Run coverage; enforce 95% line coverage.
    send: false
---
# Documentation

## DocFX authoring/build
- docfx build && docfx serve

## NuGet packaging
- dotnet pack -c Release

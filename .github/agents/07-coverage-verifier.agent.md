---
name: CoverageVerifier
description: Verify ≥95% line coverage with Coverlet; propose tests for uncovered lines/branches.
tools:
  - runCommands
  - edit
handoffs:
  - label: Improve tests for uncovered lines
    agent: SpecTestWriter
    prompt: |
      Add NUnit tests targeting uncovered lines/branches.
    send: true
---
# CoverageVerifier

## Command
- dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=cobertura /p:Threshold=95 /p:ThresholdType=line

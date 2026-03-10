---
name: security-analysis
description: Review and harden CoseSignTool V2 code for security issues (crypto correctness, cert handling, input validation, secrets, Azure integrations). Use when changing signing/verification flows, adding new crypto algorithms, handling certificates/keys, or integrating Azure services.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/05b-security-analysis.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.

## What to do
1. Review changes for cryptographic correctness (approved algorithms, minimum key sizes).
2. Verify certificate and chain validation is correct and doesn’t leak secrets.
3. Validate all public inputs (null/empty/size limits/path traversal).
4. Ensure secrets are never hardcoded or logged.
5. Review Azure usage for least-privilege and managed identity.

For detailed checklists and audit commands, see [references/REFERENCE.md](references/REFERENCE.md).

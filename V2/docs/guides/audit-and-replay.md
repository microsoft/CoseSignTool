# Audit and Replay (Trust Plan)

The V2 trust stage can produce a deterministic audit record (`TrustDecisionAudit`) describing **what facts were requested** and **how rules evaluated**.

This is designed for troubleshooting and forensics ("why did trust fail?") and for building higher-level audit trails.

## Where the audit comes from

During validation, the trust stage evaluates a `CompiledTrustPlan` using `EvaluateWithAudit*` and attaches the resulting audit to the trust stage metadata.

The audit is not present when `TrustEvaluationOptions.BypassTrust` is enabled.

## Extracting the audit from a validation result

```csharp
using CoseSign1.Validation.Trust.Audit;

var result = message.Validate(validator);

if (result.Trust.Metadata.TryGetValue(nameof(TrustDecisionAudit), out var obj) && obj is TrustDecisionAudit audit)
{
    Console.WriteLine($"Trust audit schema: {audit.SchemaVersion}");
    Console.WriteLine($"MessageId: {audit.MessageId}");
    Console.WriteLine($"Subject: {audit.Subject.Kind} ({audit.Subject.Id})");
    Console.WriteLine($"Trusted: {audit.Decision.IsTrusted}");
}
```

## What the audit contains (and does not contain)

`TrustDecisionAudit` includes:

- `SchemaVersion`: current schema version (`TrustDecisionAudit.AuditSchemaVersion`)
- `MessageId`: stable message identifier (SHA-256)
- `Subject`: the evaluated subject (message, signing key, counter-signature, …)
- `Decision`: the final `TrustDecision` (including denial reasons)
- `RuleEvaluations`: deterministic rule-evaluation events (`RuleKind`, `IsTrusted`, `Reasons`, optional `Detail`)
- `Facts`: fact observations that occurred during evaluation (fact type, whether missing, value count, optional missing reason)

Important: fact observations record **types and counts**, not fact values. This is intentional to avoid leaking sensitive data and to keep audits stable.

## Persisting the audit

If you want to store or emit the audit payload, serialize it in your application layer.

Example (JSON):

```csharp
using System.Text.Json;
using CoseSign1.Validation.Trust.Audit;

if (result.Trust.Metadata.TryGetValue(nameof(TrustDecisionAudit), out var obj) && obj is TrustDecisionAudit audit)
{
    var json = JsonSerializer.Serialize(audit, new JsonSerializerOptions { WriteIndented = true });
    Console.WriteLine(json);
}
```

## Replay: what it means in V2

There is no built-in “replay engine” that can re-run a trust plan using only the audit payload.

Instead, replay generally means:

1. Take the original message bytes.
2. Re-run validation using the same trust-pack configuration and (as close as possible) the same environmental conditions.
3. Compare the resulting decision/audit with the prior record.

### What you can verify reliably

- `audit.MessageId` should match the message you replayed.
- The trust decision (`audit.Decision.IsTrusted` and denial reasons) should match when evaluation is deterministic.
- The fact-usage profile (`audit.Facts`) and rule trace (`audit.RuleEvaluations`) should be stable when the underlying fact producers are deterministic.

### What can make replay differ

Replay can differ if fact producers depend on external state:

- network I/O (online revocation, transparency endpoints)
- time-dependent checks
- mutable trust roots or configuration

If you need strong replay properties in your environment, prefer using offline or pinned evidence and configure trust packs accordingly.

## See also

- [Validation Framework](../architecture/validation-framework.md)
- [Trust Plan Deep Dive](trust-policy.md)
- [Trust Contracts](../architecture/trust-contracts.md)

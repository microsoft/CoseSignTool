# Validation Framework

The `CoseSign1.Validation` package provides a composable, security-by-default validation pipeline for COSE Sign1 messages.

## Overview

The V2 validation framework enforces:

1. **Component-based composition**: You assemble a pipeline from `IValidationComponent`s
2. **Secure ordering**: Trust evaluation before signature verification
3. **Declarative trust**: `TrustPolicy` evaluated over trust assertions
4. **Applicability filtering**: Components can opt out cheaply via `IsApplicableTo(...)`

---

## Entry Point

Use `CoseSign1Message.Validate(...)` extension methods for end-to-end verification.

Build a reusable validator:

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Certificates.Validation;

var validator = new CoseSign1ValidationBuilder(loggerFactory)
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Signer")
        .ValidateChain())
    .Build();

var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate(validator);
```

Or validate inline (builds a validator per call):

```csharp
var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain()));
```

Or use auto-discovery (uses default components from referenced extension packages):

```csharp
var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate();
```

> **Note**: Default component discovery is described in [Validation Extension Packages](../guides/validation-extension-packages.md).

---

## Pipeline Ordering

The orchestrator (`ICoseSign1Validator`) executes the pipeline in this order:

1. **Key material resolution** (`ISigningKeyResolver`)
2. **Trust evaluation** (`ISigningKeyAssertionProvider` + `TrustPolicy`)
3. **Signature verification** (performed directly using the resolved key)
4. **Post-signature checks** (`IPostSignatureValidator`)

### Why This Order?

1. **Security**: Trust evaluated before expensive crypto operations
2. **Oracle prevention**: Attackers cannot probe valid signatures for untrusted keys
3. **Performance**: Fail fast on untrusted signatures
4. **Clarity**: Clear separation of concerns

---

## Components

Validation logic is supplied to the orchestrator as a single list of `IValidationComponent`s.
Stage participation is determined by which additional interfaces a component implements:

- `ISigningKeyResolver` (key material resolution)
- `ISigningKeyAssertionProvider` (trust assertions)
- `IPostSignatureValidator` (post-signature checks)

Every component also implements `IValidationComponent.IsApplicableTo(message, options)` so the orchestrator can quickly pre-filter components.

### Implementing a post-signature validator

Post-signature validators have access to a rich context (`IPostSignatureValidationContext`) populated by earlier stages.

```csharp
using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

public sealed class CustomPostSignatureValidator : ValidationComponentBase, IPostSignatureValidator
{
    public string ComponentName => nameof(CustomPostSignatureValidator);

    public override bool IsApplicableTo(System.Security.Cryptography.Cose.CoseSign1Message? message,
        CoseSign1.Validation.CoseSign1ValidationOptions? options = null)
        => true;

    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        // Your business rule checks here.
        return ValidationResult.Success(ComponentName);
    }

    public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context,
        CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(context));
}
```

---

## Validation Results

Each component returns a `ValidationResult` (`Success` / `Failure` / `NotApplicable`).
The overall operation returns a `CoseSign1ValidationResult` with per-stage results plus `Overall`.

---

## Trust Policy

### Overview

Trust is evaluated declaratively using boolean expressions over **typed assertions** (`ISigningKeyAssertion`).

Assertion providers emit neutral facts; the policy determines which facts matter.

### Policy Primitives

| Factory Method | Description |
|----------------|-------------|
| `TrustPolicy.DenyAll(reason)` | Always deny |
| `TrustPolicy.AllowAll(reason)` | Always allow (testing only!) |
| `TrustPolicy.RequirePresent<T>(reason)` | Require an assertion type to be present |
| `TrustPolicy.Require<T>(predicate, reason)` | Require an assertion to satisfy a predicate |
| `TrustPolicy.And(policies)` | All policies must pass |
| `TrustPolicy.Or(policies)` | Any policy must pass |
| `TrustPolicy.Not(policy)` | Invert policy |
| `TrustPolicy.Implies(if, then)` | if -> then (conditional) |

### Policy Examples

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation.Trust;

// Simple: require an X.509 chain to be trusted
var simple = TrustPolicy.Require<X509ChainTrustedAssertion>(
    a => a.IsTrusted,
    "X.509 certificate chain must be trusted");

// Presence-only (any value)
var requireChainAssertion = TrustPolicy.RequirePresent<X509ChainTrustedAssertion>(
    "X.509 trust assertion must be present");

// Conditional: if an issuer assertion exists, require it to match a predicate
var conditional = TrustPolicy.Implies(
    TrustPolicy.RequirePresent<X509IssuerAssertion>("Issuer assertion must be present"),
    TrustPolicy.Require<X509IssuerAssertion>(
        a => a.Matches && (a.ActualIssuer?.Contains("CN=Contoso") ?? false),
        "Issuer must be Contoso"));
```

See [Trust Policy Guide](../guides/trust-policy.md) for comprehensive documentation.

---

## Applicability (pre-filtering)

Components opt out by returning `false` from `IValidationComponent.IsApplicableTo(message, options)`.
This check is used for pre-filtering and should be fast (no network I/O, no chain building).

If you want caching for `IsApplicableTo(...)`, inherit from `ValidationComponentBase`.

---

## Validation Pipeline Result

### CoseSign1ValidationResult

The full pipeline returns a comprehensive result:

```csharp
public sealed class CoseSign1ValidationResult
{
    public ValidationResult Resolution { get; }
    public ValidationResult Trust { get; }
    public ValidationResult Signature { get; }
    public ValidationResult PostSignaturePolicy { get; }
    public ValidationResult Overall { get; }
}
```

### Checking Results

```csharp
var result = message.Validate(validator);

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature verified!");
}
else
{
    // Check which stage failed
    if (!result.Trust.IsValid)
    {
        Console.WriteLine("Trust policy not satisfied:");
        foreach (var failure in result.Trust.Failures)
        {
            Console.WriteLine($"  {failure.ErrorCode}: {failure.Message}");
        }
    }
    else if (!result.Signature.IsValid)
    {
        Console.WriteLine("Signature verification failed");
    }
}
```

---

## Builder API

### ICoseSign1ValidationBuilder

```csharp
public interface ICoseSign1ValidationBuilder
{
    ILoggerFactory? LoggerFactory { get; }

    ICoseSign1ValidationBuilder AddComponent(IValidationComponent component);
    ICoseSign1ValidationBuilder WithOptions(CoseSign1ValidationOptions options);
    ICoseSign1ValidationBuilder WithOptions(Action<CoseSign1ValidationOptions> configure);

    ICoseSign1ValidationBuilder OverrideDefaultTrustPolicy(TrustPolicy policy);
    ICoseSign1ValidationBuilder AllowAllTrust(string? reason = null);
    ICoseSign1ValidationBuilder DenyAllTrust(string? reason = null);

    ICoseSign1Validator Build();
}
```

### Extension Methods

Validation extension packages provide fluent extension methods:

```csharp
// Certificate validation
var validator = new CoseSign1ValidationBuilder()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Production Signer")
        .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")
        .ValidateChain(allowUntrusted: false))
    .Build();
```

> **Note**: If you do not call `OverrideDefaultTrustPolicy(...)`, the default policy is computed at validation time from the set of produced assertions (`TrustPolicy.FromAssertionDefaults()`).

---

## Built-in Components

The core `CoseSign1.Validation` package defines the orchestration model, but most practical pipelines come from extension packages (certificates, transparency, plugins) that provide `IValidationComponent`s.

See:

- [Components: Certificates](../components/certificates.md)
- [Components: Transparent](../components/transparent.md)
- [Plugins](../plugins/README.md)

---

## Error Handling

### Standard Error Codes

| Code | Description |
|------|-------------|
| `TRUST_POLICY_NOT_SATISFIED` | Trust policy evaluation failed |
| `CERTIFICATE_EXPIRED` | Certificate outside validity period |
| `CERTIFICATE_CHAIN_INVALID` | Chain building or validation failed |
| `SIGNATURE_INVALID` | Cryptographic signature check failed |
| `KEY_MATERIAL_NOT_FOUND` | No signing key in headers |
| `CONTENT_TYPE_MISMATCH` | Content type validation failed |

### Handling Failures

```csharp
var result = message.Validate(validator);

if (!result.Overall.IsValid)
{
    foreach (var failure in result.Overall.Failures)
    {
        switch (failure.ErrorCode)
        {
            case "TRUST_POLICY_NOT_SATISFIED":
                // Handle trust failure
                break;
            case "CERTIFICATE_EXPIRED":
                // Handle expired certificate
                break;
            case "SIGNATURE_INVALID":
                // Handle invalid signature
                break;
            default:
                // Handle other failures
                break;
        }
    }
}
```

---

## Best Practices

### 1. Prefer default trust, override deliberately

If you do not call `OverrideDefaultTrustPolicy(...)`, trust is evaluated using the default trust policies associated with the produced assertions (`TrustPolicy.FromAssertionDefaults()`).

Use `OverrideDefaultTrustPolicy(...)` when you need explicit, deployment-specific trust requirements.

### 2. Keep `IsApplicableTo(...)` fast

`IValidationComponent.IsApplicableTo(...)` is used for pre-filtering. It should not perform expensive work or network I/O.

### 3. Reuse validators when validating many messages

Use ILoggerFactory for troubleshooting:

```csharp
var validator = new CoseSign1ValidationBuilder(loggerFactory)
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();
```

### 4. Unit test trust policies with typed assertions

Unit test your trust policies independently:

```csharp
[Test]
public void ProductionPolicy_RequiresTrustedChain()
{
    var policy = TrustPolicy.RequirePresent<X509ChainTrustedAssertion>(
        "X.509 chain must be trusted");

    var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());
    Assert.That(decision.IsTrusted, Is.False);
}
```

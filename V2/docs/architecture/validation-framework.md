# Validation Framework

The `CoseSign1.Validation` package provides a composable, secure-by-default validation pipeline for COSE Sign1 messages.

## Overview

V2 validation is **staged** and composed through dependency injection:

- Stage services are registered via `IServiceCollection`.
- Trust behavior is expressed as a compiled trust plan (`CompiledTrustPlan`) produced from trust packs (`ITrustPack`) and optional policy (`TrustPlanPolicy`).
- Reflection-based component discovery and `IValidationComponent` applicability filtering are not used in V2.

## Entry Point

Use the `CoseSign1Message.Validate(...)` extension method with an `ICoseSign1Validator`.

Most callers build a validator from a DI container (this mirrors the CLI code path):

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Plan;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var builder = services.ConfigureCoseValidation();

// Enable one or more trust packs.
builder.EnableCertificateTrust();
builder.EnableMstTrust();

using var serviceProvider = services.BuildServiceProvider();

var trustPlan = CompiledTrustPlan.CompileDefaults(serviceProvider);
var validator = new CoseSign1Validator(
    serviceProvider.GetServices<ISigningKeyResolver>(),
    serviceProvider.GetServices<IPostSignatureValidator>(),
    trustPlan);

var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate(validator);
```

## Pipeline Ordering

The orchestrator (`ICoseSign1Validator`) runs stages in this order:

1. Key material resolution (`ISigningKeyResolver`)
2. Signature verification (crypto using the resolved key)
3. Trust evaluation (compiled trust plan)
4. Post-signature validation (`IPostSignatureValidator`)

## Writing custom validators

Custom business rules usually belong in an `IPostSignatureValidator`.

Post-signature validators receive an `IPostSignatureValidationContext` containing the message plus outputs from prior stages.

See [Creating Custom Validators](../guides/custom-validators.md) for a concrete example.
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

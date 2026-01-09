# Validation Framework

The CoseSign1.Validation package provides a composable, stage-aware validation framework for COSE Sign1 messages with security-by-default semantics.

## Overview

The V2 validation framework enforces:

1. **Stage-aware execution**: Validators declare which stages they participate in
2. **Secure ordering**: Trust evaluation before signature verification
3. **Declarative trust**: Boolean policy expressions over trust claims
4. **Composability**: Build complex validation from simple primitives

---

## Entry Point

Use `Cose.Sign1Message()` to build validation pipelines:

```csharp
using CoseSign1.Validation;
using CoseSign1.Certificates.Validation;

var validator = Cose.Sign1Message(loggerFactory)
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Signer")
        .ValidateChain())
    .Build();

var result = validator.Validate(message);
```

> **Note**: Certificate signature verification is automatically included when using `ValidateCertificate()`. Trust policies from validators implementing `IProvidesDefaultTrustPolicy` are automatically aggregated.

---

## Validation Stages

### ValidationStage Enum

```csharp
public enum ValidationStage
{
    KeyMaterialResolution = 0,  // Extract signing key from headers
    KeyMaterialTrust = 1,       // Evaluate trust policy
    Signature = 2,              // Cryptographic verification
    PostSignature = 3           // Additional business rules
}
```

### Stage Execution Order

```
+-- KeyMaterialResolution (Stage 0) --+
|   Extract certificates from COSE    |
|   headers. Decode public key.       |
+-------------------------------------+
              |
              v (always runs)
+-- KeyMaterialTrust (Stage 1) -------+
|   Run trust validators              |
|   Collect trust assertions          |
|   Evaluate TrustPolicy              |
|   SHORT-CIRCUIT if policy fails     |
+-------------------------------------+
              |
              v (only if trust passes)
+-- Signature (Stage 2) --------------+
|   Cryptographic signature           |
|   verification using extracted      |
|   key material                      |
+-------------------------------------+
              |
              v (only if signature passes)
+-- PostSignature (Stage 3) ----------+
|   Additional validation rules       |
|   Business logic, policy checks     |
+-------------------------------------+
```

### Why This Order?

1. **Security**: Trust evaluated before expensive crypto operations
2. **Oracle Prevention**: Attackers can not probe valid signatures
3. **Performance**: Fail fast on untrusted signatures
4. **Clarity**: Clear separation of concerns

---

## IValidator Interface

All validators implement `IValidator`:

```csharp
public interface IValidator
{
    /// <summary>
    /// Stages this validator participates in.
    /// </summary>
    IReadOnlyCollection<ValidationStage> Stages { get; }
    
    /// <summary>
    /// Synchronous validation.
    /// </summary>
    ValidationResult Validate(CoseSign1Message input, ValidationStage stage);
    
    /// <summary>
    /// Asynchronous validation with cancellation.
    /// </summary>
    Task<ValidationResult> ValidateAsync(
        CoseSign1Message input,
        ValidationStage stage,
        CancellationToken cancellationToken = default);
}
```

### Implementing a Validator

```csharp
public class CustomPostSignatureValidator : IValidator
{
    public IReadOnlyCollection<ValidationStage> Stages => 
        new[] { ValidationStage.PostSignature };

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        // Your validation logic
        if (!IsValid(input))
        {
            return ValidationResult.Failure(
                "CustomValidator",
                stage,
                new ValidationFailure 
                { 
                    ErrorCode = "CUSTOM_CHECK_FAILED",
                    Message = "Custom validation failed"
                });
        }
        
        return ValidationResult.Success("CustomValidator", stage);
    }

    public Task<ValidationResult> ValidateAsync(
        CoseSign1Message input, 
        ValidationStage stage,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(Validate(input, stage));
    }
}
```

---

## ValidationResult

### Result Kinds

```csharp
public enum ValidationResultKind
{
    Success,        // Validation passed
    Failure,        // Validation failed
    NotApplicable   // Validator skipped (conditional, stage skipped)
}
```

### Factory Methods

```csharp
// Success with optional metadata
ValidationResult.Success(validatorName, stage, metadata);

// Failure with single error
ValidationResult.Failure(validatorName, stage, message, errorCode);

// Failure with multiple errors
ValidationResult.Failure(validatorName, stage, failures);

// Not applicable (validator skipped)
ValidationResult.NotApplicable(validatorName, stage, reason);
```

### Result Properties

```csharp
public sealed class ValidationResult
{
    public ValidationResultKind Kind { get; }
    public bool IsValid => Kind == ValidationResultKind.Success;
    public bool IsFailure => Kind == ValidationResultKind.Failure;
    public bool IsNotApplicable => Kind == ValidationResultKind.NotApplicable;
    
    public ValidationStage? Stage { get; }
    public string ValidatorName { get; }
    public IReadOnlyList<ValidationFailure> Failures { get; }
    public IReadOnlyDictionary<string, object> Metadata { get; }
}
```

---

## Trust Policy System

### Overview

Trust is evaluated declaratively using boolean expressions over **trust claims**:

```csharp
// Validators emit claims
validator.Validate(message, stage);
// Returns metadata: { "TrustAssertions": [{ ClaimId: "x509.chain.trusted", Satisfied: true }] }

// Policy evaluated against claims
var policy = TrustPolicy.Claim("x509.chain.trusted");
policy.IsSatisfied(claims); // true or false
```

### Policy Primitives

| Factory Method | Description |
|----------------|-------------|
| `TrustPolicy.DenyAll(reason)` | Always deny (default) |
| `TrustPolicy.AllowAll(reason)` | Always allow (testing only!) |
| `TrustPolicy.Claim(claimId)` | Require claim to be true |
| `TrustPolicy.And(policies)` | All policies must pass |
| `TrustPolicy.Or(policies)` | Any policy must pass |
| `TrustPolicy.Not(policy)` | Invert policy |
| `TrustPolicy.Implies(if, then)` | if -> then (conditional) |

### Policy Examples

```csharp
// Simple: require trusted chain
var simple = TrustPolicy.Claim("x509.chain.trusted");

// Combined: chain valid AND not expired
var combined = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.notexpired")
);

// Alternative: internal OR partner issuer
var alternative = TrustPolicy.Or(
    TrustPolicy.Claim("issuer.internal"),
    TrustPolicy.Claim("issuer.partner")
);

// Conditional: production requires production cert
var conditional = TrustPolicy.Implies(
    TrustPolicy.Claim("env.production"),
    TrustPolicy.Claim("cert.production")
);
```

See [Trust Policy Guide](../guides/trust-policy.md) for comprehensive documentation.

---

## Conditional Validators

Validators can implement `IConditionalValidator` to opt out:

```csharp
public interface IConditionalValidator : IValidator
{
    /// <summary>
    /// Returns false to skip this validator for the given input/stage.
    /// </summary>
    bool IsApplicable(CoseSign1Message input, ValidationStage stage);
}
```

### Example

```csharp
public class IndirectSignatureValidator : IConditionalValidator
{
    public IReadOnlyCollection<ValidationStage> Stages => 
        new[] { ValidationStage.Signature };

    public bool IsApplicable(CoseSign1Message input, ValidationStage stage)
    {
        // Only applicable for indirect signatures
        return HasIndirectSignatureHeader(input);
    }

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        // Validation logic for indirect signatures
    }
}
```

---

## Composite Validators

### CompositeValidator

Combines multiple validators with configurable behavior:

```csharp
var composite = new CompositeValidator(
    validators,
    stopOnFirstFailure: false,   // Continue after failure?
    runInParallel: false         // Parallel execution?
);
```

### AnySignatureValidator

Requires at least one signature validator to succeed:

```csharp
var anySignature = new AnySignatureValidator(new IValidator[]
{
    new DirectSignatureValidator(),
    new IndirectSignatureValidator()
});

// Succeeds if ANY validator succeeds
// Fails only if ALL validators fail
```

---

## Validation Pipeline Result

### CoseSign1ValidationResult

The full pipeline returns a comprehensive result:

```csharp
public sealed class CoseSign1ValidationResult
{
    public ValidationResult Resolution { get; }    // Stage 0 result
    public ValidationResult Trust { get; }         // Stage 1 result
    public ValidationResult Signature { get; }     // Stage 2 result
    public ValidationResult PostSignature { get; } // Stage 3 result
    public ValidationResult Overall { get; }       // Combined result
}
```

### Checking Results

```csharp
var result = validator.Validate(message);

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
    /// <summary>Add a validator.</summary>
    ICoseSign1ValidationBuilder AddValidator(IValidator validator);
    
    /// <summary>Add a trust validator with explicit policy override.</summary>
    ICoseSign1ValidationBuilder AddTrustValidator(IValidator validator, TrustPolicy? policy);
    
    /// <summary>Override the default trust policy.</summary>
    ICoseSign1ValidationBuilder OverrideDefaultTrustPolicy(TrustPolicy policy);
    
    /// <summary>Explicitly allow all trust.</summary>
    ICoseSign1ValidationBuilder AllowAllTrust(string reason);
    
    /// <summary>Explicitly deny all trust.</summary>
    ICoseSign1ValidationBuilder DenyAllTrust(string reason);
    
    /// <summary>Build the validator.</summary>
    CoseSign1Validator Build();
    
    /// <summary>Access to logger factory for extension methods.</summary>
    ILoggerFactory? LoggerFactory { get; }
}
```

### Extension Methods

Certificate, Azure Key Vault, and MST validation provide fluent extension methods:

```csharp
// Certificate validation
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Production Signer")
        .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")
        .ValidateChain(allowUntrusted: false))
    .Build();

// Azure Key Vault validation with trust policy
var akvValidator = Cose.Sign1Message()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKey()
        .RequireAzureKeyVaultOrigin()
        .FromAllowedVaults("https://prod-*.vault.azure.net/keys/*")
        .AllowOnlineVerify()
        .WithCredential(credential))
    .Build();

// MST transparency validation
var mstValidator = Cose.Sign1Message()
    .ValidateMst(mst => mst
        .RequireReceiptPresence()
        .VerifyReceipt(mstClient))
    .Build();

// Combined validation (trust policies auto-aggregate)
var combinedValidator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .ValidateMst(mst => mst.RequireReceiptPresence())
    .Build();
```

> **Note**: Validators implementing `IProvidesDefaultTrustPolicy` automatically contribute their default trust policies. These are aggregated with `TrustPolicy.And()` when `Build()` is called.

---

## Built-in Validators

### Key Material Resolution

| Validator | Purpose |
|-----------|---------|
| `CertificateKeyMaterialResolutionValidator` | Extract certificates from COSE headers |

### Key Material Trust

| Validator | Purpose | Default Trust Claim |
|-----------|---------|---------------------|
| `CertificateChainValidator` | Build and validate certificate chain | `x509.chain.trusted` |
| `CertificateNotExpiredValidator` | Check certificate validity period | `cert.notexpired` |
| `CertificateCommonNameValidator` | Validate certificate CN | — |
| `CertificateIssuerValidator` | Validate certificate issuer | — |
| `CertificateEkuValidator` | Validate Enhanced Key Usage | — |
| `AzureKeyVaultTrustValidator` | Validate kid against allowed AKV patterns | `akv.key.detected`, `akv.kid.allowed` |
| `MstReceiptPresenceTrustValidator` | Check MST receipt exists | `mst.receipt.present` |
| `MstReceiptValidator` | Verify MST receipt | `mst.receipt.trusted` |

### Signature

| Validator | Purpose |
|-----------|---------|
| `CertificateSignatureValidator` | COSE signature verification with X.509 |
| `AzureKeyVaultSignatureValidator` | COSE signature verification with AKV key |
| `AnySignatureValidator` | At least one signature validator succeeds |

### Post-Signature

| Validator | Purpose |
|-----------|---------|
| Custom validators | Business logic, policy checks |

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
var result = validator.Validate(message);

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

### 1. Use Validators with Default Trust Policies

Validators that implement `IProvidesDefaultTrustPolicy` automatically contribute secure default policies:

```csharp
// Good: ValidateCertificate provides default trust policy
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();
// Default policy: TrustPolicy.Claim("x509.chain.trusted")

// Good: Multiple validators aggregate their policies
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()
        .FromAllowedVaults("https://prod.vault.azure.net/keys/*"))
    .Build();
// Default policy: TrustPolicy.And(
//     Claim("x509.chain.trusted"),
//     Claim("akv.key.detected"),
//     Claim("akv.kid.allowed"))

// Override: Explicit trust policy replaces defaults
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .OverrideDefaultTrustPolicy(TrustPolicy.AllowAll("Testing only"))
    .Build();
```

### 2. Use Appropriate Validators for Stage

Ensure validators match their declared stages:

```csharp
// Good: Trust validator for trust stage
public class MyTrustValidator : IValidator
{
    public IReadOnlyCollection<ValidationStage> Stages =>
        new[] { ValidationStage.KeyMaterialTrust };
}
```

### 3. Log for Diagnostics

Use ILoggerFactory for troubleshooting:

```csharp
var validator = Cose.Sign1Message(loggerFactory)
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();
```

### 4. Test Trust Policies

Unit test your trust policies independently:

```csharp
[Test]
public void ProductionPolicy_RequiresTrustedChain()
{
    var policy = TrustPolicy.And(
        TrustPolicy.Claim("x509.chain.trusted"),
        TrustPolicy.Claim("cert.production"));
    
    var claims = new Dictionary<string, bool>
    {
        ["x509.chain.trusted"] = true,
        ["cert.production"] = false
    };
    
    Assert.That(policy.IsSatisfied(claims), Is.False);
}
```

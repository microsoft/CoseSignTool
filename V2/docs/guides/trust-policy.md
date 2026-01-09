# Trust Policy Deep Dive

This guide provides comprehensive documentation on the TrustPolicy system in CoseSignTool V2, including advanced usage patterns and custom trust claim implementations.

## Overview

The TrustPolicy system provides a **declarative, composable** approach to trust evaluation. Rather than writing imperative validation code, you define trust requirements as boolean expressions over **trust claims**.

### Key Concepts

| Concept | Description |
|---------|-------------|
| **TrustPolicy** | A declarative expression evaluated against claims |
| **TrustClaim** | A named boolean assertion (e.g., "x509.chain.trusted") |
| **TrustAssertion** | A validator's statement about a claim's satisfaction |
| **Trust Stage** | Validation stage where trust is evaluated (before signature verification) |

### Why Declarative Trust?

1. **Composability**: Build complex policies from simple primitives
2. **Auditability**: Policies are data, not code - easier to review and log
3. **Separation of Concerns**: Validators emit claims; policies consume them
4. **Security**: Trust evaluated before expensive cryptographic operations

---

## Default Trust Policy Behavior

When building a validator with `Cose.Sign1Message()`, the trust policy is determined as follows:

### Policy Resolution Order

1. **Explicit Policy**: If `OverrideDefaultTrustPolicy(policy)` is called, that policy is used exclusively
2. **Aggregated Defaults**: If no explicit policy, default policies from validators implementing `IProvidesDefaultTrustPolicy` are combined with `TrustPolicy.And()`
3. **Secure Fallback**: If no policies are available:
   - **With trust validators**: `TrustPolicy.AllowAll()` (validators enforce trust via failures)
   - **Without trust validators**: `TrustPolicy.DenyAll()` (secure-by-default)

### Using OverrideDefaultTrustPolicy

The `OverrideDefaultTrustPolicy` method **replaces** all default policies from validators:

```csharp
// Single policy - replaces all validator defaults
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .OverrideDefaultTrustPolicy(TrustPolicy.Claim("x509.chain.trusted"))
    .Build();

// Multiple requirements - combine with TrustPolicy.And() before calling
var policy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.notexpired"),
    TrustPolicy.Claim("cert.eku.codesigning")
);

var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain().NotExpired())
    .OverrideDefaultTrustPolicy(policy)
    .Build();
```

> **Important**: `OverrideDefaultTrustPolicy` can only be called once per builder. To require multiple policies, combine them with `TrustPolicy.And()` or `TrustPolicy.Or()` before calling.

### Relying on Validator Defaults

When validators implement `IProvidesDefaultTrustPolicy`, you can omit explicit trust policy configuration:

```csharp
// Uses default policies from certificate and AKV validators
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .ValidateAzureKeyVault(akv => akv.RequireAzureKeyVaultOrigin())
    .Build();
// Effective policy: And(x509.chain.trusted, akv.key.detected)
```

---

## Policy Primitives

### TrustPolicy.DenyAll(reason)

Always denies trust. This is the **fallback** when no trust validators or policies are provided.

```csharp
var policy = TrustPolicy.DenyAll("No trust policy configured");

var claims = new Dictionary<string, bool>
{
    ["x509.chain.trusted"] = true,
    ["cert.notexpired"] = true
};

policy.IsSatisfied(claims); // Always false
```

**Use Case**: Default deny policy, explicitly rejecting trust.

### TrustPolicy.AllowAll(reason)

Always allows trust. **Use with extreme caution** - only for testing or explicit bypass scenarios.

```csharp
var policy = TrustPolicy.AllowAll("Testing only - trust all signatures");

policy.IsSatisfied(new Dictionary<string, bool>()); // Always true
```

**Use Case**: Testing, development environments, explicit trust bypass.

### TrustPolicy.Claim(claimId)

Requires a specific claim to be present and `true`.

```csharp
var policy = TrustPolicy.Claim("x509.chain.trusted");

// Satisfied when claim exists and is true
policy.IsSatisfied(new Dictionary<string, bool> { ["x509.chain.trusted"] = true }); // true

// Not satisfied when claim is false
policy.IsSatisfied(new Dictionary<string, bool> { ["x509.chain.trusted"] = false }); // false

// Not satisfied when claim is missing
policy.IsSatisfied(new Dictionary<string, bool>()); // false
```

**Use Case**: Requiring specific validation criteria.

---

## Composite Policies

### TrustPolicy.And(policies)

All policies must be satisfied. Returns `true` when empty (vacuously true).

```csharp
// Require BOTH trusted chain AND valid certificate
var policy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.notexpired")
);

var claims = new Dictionary<string, bool>
{
    ["x509.chain.trusted"] = true,
    ["cert.notexpired"] = true
};

policy.IsSatisfied(claims); // true - both satisfied

claims["cert.notexpired"] = false;
policy.IsSatisfied(claims); // false - one claim failed
```

**Use Case**: Requiring multiple conditions simultaneously.

### TrustPolicy.Or(policies)

At least one policy must be satisfied. Returns `true` when empty (vacuously true).

```csharp
// Accept certificate from EITHER internal OR partner CA
var policy = TrustPolicy.Or(
    TrustPolicy.Claim("issuer.internal"),
    TrustPolicy.Claim("issuer.partner")
);

// Satisfied with internal issuer
policy.IsSatisfied(new Dictionary<string, bool> 
{ 
    ["issuer.internal"] = true,
    ["issuer.partner"] = false
}); // true

// Satisfied with partner issuer
policy.IsSatisfied(new Dictionary<string, bool> 
{ 
    ["issuer.internal"] = false,
    ["issuer.partner"] = true
}); // true

// Not satisfied with neither
policy.IsSatisfied(new Dictionary<string, bool> 
{ 
    ["issuer.internal"] = false,
    ["issuer.partner"] = false
}); // false
```

**Use Case**: Accepting multiple valid trust paths.

### TrustPolicy.Not(policy)

Inverts a policy's result.

```csharp
// Reject self-signed certificates
var policy = TrustPolicy.Not(TrustPolicy.Claim("cert.selfsigned"));

policy.IsSatisfied(new Dictionary<string, bool> { ["cert.selfsigned"] = false }); // true
policy.IsSatisfied(new Dictionary<string, bool> { ["cert.selfsigned"] = true }); // false
```

**Use Case**: Exclusion rules, blocklisting.

### TrustPolicy.Implies(if, then)

Logical implication: `if → then` (equivalent to `¬if ∨ then`).

```csharp
// IF production environment THEN require production certificate
var policy = TrustPolicy.Implies(
    TrustPolicy.Claim("env.production"),
    TrustPolicy.Claim("cert.production")
);

// Non-production: satisfied regardless of cert type
policy.IsSatisfied(new Dictionary<string, bool> 
{ 
    ["env.production"] = false,
    ["cert.production"] = false
}); // true (antecedent false)

// Production with production cert: satisfied
policy.IsSatisfied(new Dictionary<string, bool> 
{ 
    ["env.production"] = true,
    ["cert.production"] = true
}); // true

// Production without production cert: NOT satisfied
policy.IsSatisfied(new Dictionary<string, bool> 
{ 
    ["env.production"] = true,
    ["cert.production"] = false
}); // false
```

**Use Case**: Conditional requirements, environment-specific rules.

---

## Complex Policy Examples

### Enterprise Multi-Tier Trust

```csharp
// Trust hierarchy:
// - Internal CA certificates always trusted
// - Partner certificates require additional certification
// - All certificates must not be expired or revoked

var enterprisePolicy = TrustPolicy.And(
    // Core requirements for all certificates
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.notexpired"),
    TrustPolicy.Not(TrustPolicy.Claim("cert.revoked")),
    
    // Trust source requirements
    TrustPolicy.Or(
        // Internal certificates: trusted implicitly
        TrustPolicy.Claim("issuer.internal"),
        
        // Partner certificates: require additional certification
        TrustPolicy.And(
            TrustPolicy.Claim("issuer.partner"),
            TrustPolicy.Claim("partner.certification.valid")
        ),
        
        // Public CA certificates: require EV validation
        TrustPolicy.And(
            TrustPolicy.Claim("issuer.public"),
            TrustPolicy.Claim("cert.ev.validated")
        )
    )
);
```

### Code Signing with EKU Requirements

```csharp
// Require code signing EKU and lifetime signing for production
var codeSigningPolicy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.eku.codesigning"),
    
    // Production requires additional constraints
    TrustPolicy.Implies(
        TrustPolicy.Claim("env.production"),
        TrustPolicy.And(
            TrustPolicy.Claim("cert.lifetimesigning"),
            TrustPolicy.Claim("cert.issuer.microsoft")
        )
    )
);
```

### Time-Based Trust Windows

```csharp
// Trust during specific time windows
var timeWindowPolicy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    
    // Must be within validity window
    TrustPolicy.Claim("cert.notexpired"),
    TrustPolicy.Claim("cert.notbeforevalid"),
    
    // Grace period handling
    TrustPolicy.Or(
        TrustPolicy.Claim("cert.notingraceperiod"),
        TrustPolicy.And(
            TrustPolicy.Claim("cert.ingraceperiod"),
            TrustPolicy.Claim("grace.approved")
        )
    )
);
```

---

## Creating Custom Trust Claims

### Implementing a Trust Validator

Trust claims are emitted by validators implementing `IValidator` at the `KeyMaterialTrust` stage:

```csharp
public class CustomTrustValidator : IValidator
{
    public IReadOnlyCollection<ValidationStage> Stages => 
        new[] { ValidationStage.KeyMaterialTrust };

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        // Extract certificate from message
        var cert = ExtractCertificate(input);
        
        // Evaluate trust conditions
        var assertions = new List<TrustAssertion>();
        
        // Check if certificate is from internal issuer
        bool isInternal = cert.Issuer.Contains("CN=Internal CA");
        assertions.Add(new TrustAssertion("issuer.internal", isInternal));
        
        // Check custom organization claim
        bool isApprovedOrg = CheckApprovedOrganization(cert);
        assertions.Add(new TrustAssertion("org.approved", isApprovedOrg, 
            isApprovedOrg ? null : "Organization not in approved list"));
        
        // Check certificate policy OID
        bool hasRequiredPolicy = HasPolicyOid(cert, "1.2.3.4.5.6");
        assertions.Add(new TrustAssertion("cert.policy.required", hasRequiredPolicy));
        
        return ValidationResult.Success(
            "CustomTrustValidator",
            stage,
            new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = assertions
            }
        );
    }

    public Task<ValidationResult> ValidateAsync(
        CoseSign1Message input, 
        ValidationStage stage,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }
}
```

### Providing Default Trust Policy

Validators can implement `IProvidesDefaultTrustPolicy` to automatically contribute their trust requirements to the validation pipeline:

```csharp
public class CustomTrustValidator : IValidator, IProvidesDefaultTrustPolicy
{
    // ... IValidator implementation ...

    public TrustPolicy GetDefaultTrustPolicy(ValidationBuilderContext context)
    {
        // Return the minimum policy required for this validator's claims
        return TrustPolicy.And(
            TrustPolicy.Claim("issuer.internal"),
            TrustPolicy.Claim("org.approved")
        );
    }
}
```

When added to a builder without an explicit policy, the builder aggregates default policies using `TrustPolicy.And()`:

```csharp
// Default policy comes from validator's GetDefaultTrustPolicy()
var validator = Cose.Sign1Message()
    .AddValidator(new CustomTrustValidator())
    .Build();
// Effective policy: And(issuer.internal, org.approved)

// Multiple validators combine their defaults
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())  // Provides x509.chain.trusted
    .AddValidator(new CustomTrustValidator())            // Provides issuer.internal, org.approved
    .Build();
// Effective policy: And(x509.chain.trusted, issuer.internal, org.approved)
```

> **Note**: If you call `OverrideDefaultTrustPolicy()`, all validator defaults are ignored and only the explicit policy is used.

---

## Standard Trust Claims

### X.509 Certificate Claims

| Claim ID | Description | Validator |
|----------|-------------|-----------|
| `x509.chain.trusted` | Certificate chain validated successfully | `CertificateChainValidator` |
| `x509.chain.revoked` | Certificate or chain member revoked | `CertificateChainValidator` |
| `cert.notexpired` | Certificate within validity period | `CertificateNotExpiredValidator` |
| `cert.selfsigned` | Certificate is self-signed | `CertificateChainValidator` |

### Certificate Property Claims

| Claim ID | Description | Validator |
|----------|-------------|-----------|
| `cert.cn.<name>` | Certificate has specific Common Name | `CertificateCommonNameValidator` |
| `cert.issuer.<name>` | Certificate issued by specific CA | `CertificateIssuerValidator` |
| `cert.eku.codesigning` | Has Code Signing EKU | `CertificateEkuValidator` |
| `cert.eku.timestamping` | Has Timestamping EKU | `CertificateEkuValidator` |

### DID:x509 Claims

| Claim ID | Description | Validator |
|----------|-------------|-----------|
| `didx509.valid` | DID:x509 identifier validated | `DidX509Validator` |
| `didx509.method.validated` | DID method-specific validation passed | `DidX509Validator` |

### Azure Key Vault Claims

| Claim ID | Description | Validator |
|----------|-------------|-----------|
| `akv.key.detected` | kid header looks like an Azure Key Vault key URI | `AzureKeyVaultTrustValidator` |
| `akv.kid.allowed` | kid matches one of the configured allowed vault patterns | `AzureKeyVaultTrustValidator` |

**Usage Example:**
```csharp
var validator = Cose.Sign1Message()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()
        .FromAllowedVaults(
            "https://production-vault.vault.azure.net/keys/*",
            "https://signing-*.vault.azure.net/keys/release-*"))
    .Build();
```

### MST Transparency Claims

| Claim ID | Description | Validator |
|----------|-------------|-----------|
| `mst.receipt.present` | MST transparency receipt exists in signature | `MstReceiptPresenceTrustValidator` |
| `mst.receipt.trusted` | MST receipt verified successfully | `MstReceiptValidator` |

**Usage Example:**
```csharp
var validator = Cose.Sign1Message()
    .ValidateMst(mst => mst
        .RequireReceiptPresence()
        .VerifyReceipt(client))
    .Build();
```

---

## Policy Evaluation Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Validation Pipeline                           │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 1: Key Material Resolution                                    │
│ • Extract certificates from COSE headers                            │
│ • Decode public key material                                        │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 2: Key Material Trust                                         │
│                                                                     │
│ 1. Run trust validators (KeyMaterialTrust stage)                   │
│    ├─ CertificateChainValidator                                    │
│    │   └─ Emits: x509.chain.trusted, x509.chain.revoked            │
│    ├─ CertificateNotExpiredValidator                               │
│    │   └─ Emits: cert.notexpired                                   │
│    ├─ AzureKeyVaultTrustValidator                                  │
│    │   └─ Emits: akv.key.detected, akv.kid.allowed                 │
│    ├─ MstReceiptPresenceTrustValidator                             │
│    │   └─ Emits: mst.receipt.present                               │
│    └─ CustomTrustValidator                                         │
│        └─ Emits: issuer.internal, org.approved                     │
│                                                                     │
│ 2. Collect TrustAssertions from validator metadata                 │
│    claims = { "x509.chain.trusted": true, "cert.notexpired": true, │
│               "akv.key.detected": true, "akv.kid.allowed": true,   │
│               "mst.receipt.present": true }                        │
│                                                                     │
│ 3. Evaluate TrustPolicy against claims                             │
│    policy.IsSatisfied(claims) → true/false                         │
│                                                                     │
│ 4. If policy not satisfied:                                        │
│    • Short-circuit remaining stages                                │
│    • Return trust failure with explanation                         │
└─────────────────────────────────────────────────────────────────────┘
                                │ (only if trust satisfied)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 3: Signature Verification                                     │
│ • Cryptographic signature validation                                │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 4: Post-Signature Policy                                      │
│ • Additional business rules                                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Policy Explanation

TrustPolicy provides explanation capabilities for debugging and auditing:

```csharp
var policy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.notexpired"),
    TrustPolicy.Claim("issuer.internal")
);

var claims = new Dictionary<string, bool>
{
    ["x509.chain.trusted"] = true,
    ["cert.notexpired"] = true,
    ["issuer.internal"] = false  // This fails
};

var reasons = new List<string>();
policy.Explain(claims, reasons);

// reasons contains:
// ["Required claim not satisfied: issuer.internal"]
```

This explanation is included in validation failure messages for troubleshooting.

---

## Best Practices

### 1. Leverage Validator Defaults or Be Explicit

Validators that implement `IProvidesDefaultTrustPolicy` provide secure defaults. Choose one of these approaches:

```csharp
// Option A: Rely on validator defaults (recommended for standard scenarios)
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();
// Uses x509.chain.trusted from CertificateChainValidator

// Option B: Explicit policy (recommended for custom requirements)
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .OverrideDefaultTrustPolicy(TrustPolicy.And(
        TrustPolicy.Claim("x509.chain.trusted"),
        TrustPolicy.Claim("cert.notexpired"),
        TrustPolicy.Claim("cert.eku.codesigning")
    ))
    .Build();
```

> **Warning**: If you add validators without defaults and don't call `OverrideDefaultTrustPolicy()`, validation uses `DenyAll` and all signatures will fail trust evaluation.

### 2. Use Descriptive Claim Names

Follow a namespace convention for claim IDs:

```csharp
// Good: Clear namespace and meaning
TrustPolicy.Claim("x509.chain.trusted")
TrustPolicy.Claim("cert.eku.codesigning")
TrustPolicy.Claim("org.contoso.approved")

// Bad: Ambiguous names
TrustPolicy.Claim("trusted")
TrustPolicy.Claim("valid")
```

### 3. Document Policy Intent

Include comments explaining business requirements:

```csharp
// Production code signing policy:
// - Certificate must chain to trusted root
// - Certificate must have Code Signing EKU
// - For release builds, certificate must be from Microsoft CA
var productionPolicy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.eku.codesigning"),
    TrustPolicy.Implies(
        TrustPolicy.Claim("build.release"),
        TrustPolicy.Claim("cert.issuer.microsoft")
    )
);
```

### 4. Test Policies Independently

Unit test your trust policies:

```csharp
[Test]
public void ProductionPolicy_RequiresMicrosoftCertForRelease()
{
    var claims = new Dictionary<string, bool>
    {
        ["x509.chain.trusted"] = true,
        ["cert.eku.codesigning"] = true,
        ["build.release"] = true,
        ["cert.issuer.microsoft"] = false  // Non-Microsoft cert
    };

    Assert.That(productionPolicy.IsSatisfied(claims), Is.False);
}
```

---

## Troubleshooting

### "TRUST_POLICY_NOT_SATISFIED" Error

1. **Check claim values**: Log the claims dictionary to see what validators emitted
2. **Review policy**: Ensure policy matches available claims
3. **Use Explain()**: Get detailed failure reasons

```csharp
if (!result.Trust.IsValid)
{
    foreach (var failure in result.Trust.Failures)
    {
        Console.WriteLine($"{failure.ErrorCode}: {failure.Message}");
    }
}
```

### Missing Claims

If expected claims are missing:

1. Ensure the appropriate validator is added to the pipeline
2. Check validator runs at `KeyMaterialTrust` stage
3. Verify validator stores assertions in metadata correctly

### Conflicting Claims

If multiple validators emit the same claim with different values:

- Last writer wins (validators run in order added)
- Consider using unique claim namespaces per validator

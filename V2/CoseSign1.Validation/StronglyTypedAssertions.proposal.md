# Strongly-Typed Assertions Architecture Proposal

## Problem Statement

The current `SigningKeyAssertion` class uses an opaque property bag pattern:
- `ClaimId` is a string (fragile, no compile-time safety)
- `Value` is `object?` (requires casting, no IntelliSense)
- `WellKnownAssertionClaims` contains extension-specific claims (X509, AKV) that violate package isolation

**Decision:** Delete `WellKnownAssertionClaims` entirely. Move from "claims" model to "assertions" model.

## Proposed Solution

Replace string-keyed claims with strongly-typed assertion records per domain. Each assertion carries its own **default trust policy** to ensure secure-by-default behavior.

### Core Interface (CoseSign1.Validation)

```csharp
/// <summary>
/// Marker interface for all signing key assertions.
/// Each extension package defines its own assertion record types.
/// </summary>
/// <remarks>
/// Assertions are neutral facts about the signing key. They do NOT grant trust.
/// Trust is determined by evaluating assertions against a <see cref="TrustPolicy"/>.
/// Each assertion provides a <see cref="DefaultTrustPolicy"/> that represents
/// secure-by-default evaluation semantics for that assertion type.
/// </remarks>
public interface ISigningKeyAssertion
{
    /// <summary>
    /// Gets the assertion domain (e.g., "x509", "mst", "akv").
    /// Used for logging, diagnostics, and domain-scoped filtering.
    /// </summary>
    string Domain { get; }

    /// <summary>
    /// Gets a human-readable description of this assertion.
    /// Used in trust decision explanations and diagnostics.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Gets the default trust policy for this assertion type.
    /// This policy represents the secure-by-default evaluation for the assertion.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The default policy ensures that consumers who don't craft a custom policy
    /// get secure behavior out of the box. Extension authors MUST provide a policy
    /// that requires the assertion to indicate a positive security outcome.
    /// </para>
    /// <para>
    /// <strong>Implementation Note:</strong> Implementers SHOULD back this property
    /// with a static readonly field to ensure a single policy instance is reused.
    /// Example: <c>public TrustPolicy DefaultTrustPolicy => s_defaultPolicy;</c>
    /// where <c>s_defaultPolicy</c> is a <c>private static readonly</c> field.
    /// </para>
    /// </remarks>
    TrustPolicy DefaultTrustPolicy { get; }

    /// <summary>
    /// Gets the signing key this assertion was extracted from, or null for key-agnostic assertions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The provider that creates the assertion sets this property to indicate which
    /// signing key the assertion is associated with. This enables:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Filtering assertions by key type</description></item>
    /// <item><description>Correlating assertions back to their source key</description></item>
    /// <item><description>Diagnostics and logging showing which key produced which assertions</description></item>
    /// </list>
    /// <para>
    /// Key-agnostic assertions (e.g., MST receipt validation) may set this to null
    /// since they validate message-level data rather than key material.
    /// </para>
    /// </remarks>
    ISigningKey? SigningKey { get; }
}
```

### Extension-Specific Assertions

Each extension package defines its own strongly-typed assertion records with secure defaults:

**CoseSign1.Certificates:**
```csharp
// === Assertion Record ===
public sealed record X509ChainTrustAssertion : ISigningKeyAssertion
{
    public string Domain => "x509.chain";
    
    // Instance property returns the static default (no config needed for chain trust)
    public TrustPolicy DefaultTrustPolicy => X509ChainTrustPolicy.Default;

    // The certificate-based signing key this assertion was extracted from
    public required ISigningKey? SigningKey { get; init; }

    public required bool IsTrusted { get; init; }
    public string? RootThumbprint { get; init; }
    public bool AllowedByUntrustedMode { get; init; }
    public string? FailureReason { get; init; }
    
    public string Description => /* computed from state */;
}

// === Companion Policy Class ===
/// <summary>
/// Trust policies for X.509 chain assertions.
/// </summary>
public static class X509ChainTrustPolicy
{
    /// <summary>
    /// The secure default policy: chain must be trusted and NOT via AllowUntrusted.
    /// </summary>
    public static TrustPolicy Default { get; } = 
        TrustPolicy.Require<X509ChainTrustAssertion>(
            a => a.IsTrusted && !a.AllowedByUntrustedMode,
            "X.509 certificate chain must be trusted by system or configured roots");

    /// <summary>
    /// Requires the root certificate to be in an allowlist.
    /// </summary>
    public static TrustPolicy RequireRootInAllowlist(IEnumerable<string> allowedThumbprints)
    {
        var allowed = new HashSet<string>(allowedThumbprints, StringComparer.OrdinalIgnoreCase);
        return TrustPolicy.Require<X509ChainTrustAssertion>(
            a => a.IsTrusted && allowed.Contains(a.RootThumbprint ?? string.Empty),
            "Root certificate must be in allowlist");
    }
}

// === Example: Assertion that REQUIRES configuration ===
public sealed record X509CommonNameAssertion : ISigningKeyAssertion
{
    public string Domain => "x509.cn";
    
    // This assertion's default policy is configured per-instance
    // because it needs to know which CN values are acceptable
    private readonly TrustPolicy _defaultPolicy;
    
    public X509CommonNameAssertion(IEnumerable<string> acceptableCNs)
    {
        AcceptableCNs = acceptableCNs.ToList();
        _defaultPolicy = X509CommonNameTrustPolicy.RequireMatch(AcceptableCNs);
    }
    
    public TrustPolicy DefaultTrustPolicy => _defaultPolicy;

    // The certificate-based signing key this assertion was extracted from
    public required ISigningKey? SigningKey { get; init; }
    
    public required string ActualCN { get; init; }
    public IReadOnlyList<string> AcceptableCNs { get; }
    public bool IsMatch => AcceptableCNs.Contains(ActualCN, StringComparer.OrdinalIgnoreCase);
    
    public string Description => IsMatch 
        ? $"CN '{ActualCN}' matches acceptable list"
        : $"CN '{ActualCN}' not in acceptable list";
}

public static class X509CommonNameTrustPolicy
{
    /// <summary>
    /// Requires the CN to match the assertion's acceptable list.
    /// </summary>
    public static TrustPolicy RequireMatch(IEnumerable<string> acceptableCNs)
    {
        var allowed = new HashSet<string>(acceptableCNs, StringComparer.OrdinalIgnoreCase);
        return TrustPolicy.Require<X509CommonNameAssertion>(
            a => allowed.Contains(a.ActualCN),
            $"Certificate CN must be one of: {string.Join(", ", allowed)}");
    }
}
```

**CoseSign1.Transparent.MST:**
```csharp
// === Assertion Record ===
public sealed record MstReceiptAssertion : ISigningKeyAssertion
{
    public string Domain => "mst.receipt";
    
    // Instance property returns the static default (no config needed)
    public TrustPolicy DefaultTrustPolicy => MstReceiptTrustPolicy.Default;

    // MST receipts are key-agnostic - they validate the receipt, not the key
    // Provider sets this to null since the assertion isn't tied to key material
    public ISigningKey? SigningKey => null;
    
    public required bool IsPresent { get; init; }
    public required bool IsVerified { get; init; }
    public string? ServiceId { get; init; }
    public string? FailureReason { get; init; }
    
    public string Description => /* computed from state */;
}

// === Companion Policy Class ===
public static class MstReceiptTrustPolicy
{
    /// <summary>
    /// The secure default policy: receipt must be present AND verified.
    /// </summary>
    public static TrustPolicy Default { get; } =
        TrustPolicy.Require<MstReceiptAssertion>(
            a => a.IsPresent && a.IsVerified,
            "MST receipt must be present and cryptographically verified");

    /// <summary>
    /// Requires receipt from a specific service.
    /// </summary>
    public static TrustPolicy RequireService(string serviceId) =>
        TrustPolicy.Require<MstReceiptAssertion>(
            a => a.IsPresent && a.IsVerified 
                 && string.Equals(a.ServiceId, serviceId, StringComparison.OrdinalIgnoreCase),
            $"MST receipt must be from service: {serviceId}");
}
```

**CoseSign1.AzureKeyVault:**
```csharp
// === Assertion Record ===
public sealed record AkvKeyAssertion : ISigningKeyAssertion
{
    public string Domain => "akv.key";
    
    public TrustPolicy DefaultTrustPolicy => AkvKeyTrustPolicy.Default;

    // The AKV signing key this assertion was extracted from
    public required ISigningKey? SigningKey { get; init; }
    
    public required bool IsAkvKey { get; init; }
    public required bool IsAllowed { get; init; }
    public string? KeyId { get; init; }
    public string? VaultUri { get; init; }
    
    public string Description => /* computed from state */;
}

public static class AkvKeyTrustPolicy
{
    public static TrustPolicy Default { get; } =
        TrustPolicy.Require<AkvKeyAssertion>(
            a => a.IsAkvKey && a.IsAllowed,
            "AKV key must be from Azure Key Vault and in the configured allowlist");
}
```

### TrustPolicy: Consumer-Facing API

Consumers craft trust policies using composable factory methods. The design supports three scenarios:

#### Scenario 1: Use Default Policy (Secure by Default)
```csharp
// Use the static default from the companion policy class
var policy = X509ChainTrustPolicy.Default;

// Combine defaults from multiple assertion types
var policy = TrustPolicy.And(
    X509ChainTrustPolicy.Default,
    MstReceiptTrustPolicy.Default);
```

#### Scenario 2: Custom Policy (Consumer Knows Better)
```csharp
// Use companion class factory methods for common customizations
var enterprisePolicy = X509ChainTrustPolicy.RequireRootInAllowlist(
    "ABC123...", "DEF456...");

// Or use TrustPolicy.Require<T>() for fully custom predicates
var customPolicy = TrustPolicy.Require<X509ChainTrustAssertion>(
    a => a.IsTrusted 
         && !a.AllowedByUntrustedMode 
         && a.RootThumbprint?.StartsWith("ABC") == true,
    "Certificate must chain to an ABC-prefixed root");
```

#### Scenario 3: Complex Multi-Assertion Policies
```csharp
// Require X509 AND MST
var strictPolicy = TrustPolicy.And(
    X509ChainTrustPolicy.Default,
    MstReceiptTrustPolicy.Default);

// Require X509 OR AKV (alternative trust paths)
var flexiblePolicy = TrustPolicy.Or(
    X509ChainTrustPolicy.Default,
    AkvKeyTrustPolicy.Default);

// Negation: NOT from untrusted mode
var noUntrustedPolicy = TrustPolicy.Not(
    TrustPolicy.Require<X509ChainTrustAssertion>(
        a => a.AllowedByUntrustedMode,
        "Must not be allowed via AllowUntrusted"));

// Complex composition
var realWorldPolicy = TrustPolicy.And(
    TrustPolicy.Or(
        X509ChainTrustPolicy.Default,
        AkvKeyTrustPolicy.Default),
    MstReceiptTrustPolicy.Default);
```

### TrustPolicy API Surface

```csharp
public abstract class TrustPolicy
{
    /// <summary>
    /// Evaluates this policy against the assertion set.
    /// </summary>
    public abstract TrustDecision Evaluate(SigningKeyAssertionSet assertions);

    // --- Factory Methods ---

    /// <summary>
    /// Creates a policy requiring the assertion type to satisfy a predicate.
    /// </summary>
    public static TrustPolicy Require<T>(
        Func<T, bool> predicate, 
        string failureReason) where T : class, ISigningKeyAssertion;

    /// <summary>
    /// Creates a policy requiring the assertion type to be present (any value).
    /// </summary>
    public static TrustPolicy RequirePresent<T>(
        string failureReason) where T : class, ISigningKeyAssertion;

    /// <summary>
    /// Creates a policy satisfied when ALL provided policies are satisfied.
    /// </summary>
    public static TrustPolicy And(params TrustPolicy[] policies);

    /// <summary>
    /// Creates a policy satisfied when ANY provided policy is satisfied.
    /// </summary>
    public static TrustPolicy Or(params TrustPolicy[] policies);

    /// <summary>
    /// Creates a policy satisfied when the provided policy is NOT satisfied.
    /// </summary>
    public static TrustPolicy Not(TrustPolicy policy);

    /// <summary>
    /// Creates a policy that always grants trust. USE WITH CAUTION.
    /// </summary>
    public static TrustPolicy AllowAll();

    /// <summary>
    /// Creates a policy that always denies trust.
    /// </summary>
    public static TrustPolicy DenyAll(string reason);
}
```

### SigningKeyAssertionSet: Heterogeneous Collection

```csharp
public sealed class SigningKeyAssertionSet
{
    /// <summary>Gets all assertions.</summary>
    public IReadOnlyList<ISigningKeyAssertion> Assertions { get; }

    /// <summary>Gets all assertions of a specific type.</summary>
    public IEnumerable<T> OfType<T>() where T : ISigningKeyAssertion;

    /// <summary>Gets the single assertion of a type, or null.</summary>
    public T? Get<T>() where T : class, ISigningKeyAssertion;

    /// <summary>Checks if any assertion of the type exists.</summary>
    public bool Has<T>() where T : ISigningKeyAssertion;

    /// <summary>Gets all assertions for a domain.</summary>
    public IEnumerable<ISigningKeyAssertion> ForDomain(string domain);

    /// <summary>Combines with another set.</summary>
    public SigningKeyAssertionSet Combine(SigningKeyAssertionSet other);
}
```

### ISigningKeyAssertionProvider: How Assertions Get Created

The existing `ISigningKeyAssertionProvider` interface is responsible for **evaluating** a signing key and **producing** assertion instances. Each provider is a factory that extracts facts from the key:

```csharp
/// <summary>
/// Extracts strongly-typed assertions from signing key material.
/// </summary>
/// <remarks>
/// <para>
/// <strong>IMPORTANT:</strong> Assertion providers extract FACTS, not trust judgments.
/// They do not decide whether the facts are "good enough"—that's the policy's job.
/// </para>
/// <para>
/// Each provider specializes in a specific type of assertion extraction.
/// Multiple providers can run for the same key, each contributing their assertions.
/// </para>
/// </remarks>
public interface ISigningKeyAssertionProvider
{
    /// <summary>
    /// Gets a unique name identifying this provider.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Determines whether this provider can extract assertions from the given key.
    /// </summary>
    bool CanProvideAssertions(ISigningKey signingKey);

    /// <summary>
    /// Extracts assertions from the signing key.
    /// </summary>
    IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        AssertionExtractionContext? context = null);

    /// <summary>
    /// Asynchronously extracts assertions from the signing key.
    /// Use this when assertion extraction requires network I/O (e.g., OCSP checks,
    /// fetching CRLs, calling external services).
    /// </summary>
    Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        AssertionExtractionContext? context = null,
        CancellationToken cancellationToken = default);
}
```

> **Note:** The existing `ISigningKeyAssertionProvider` and `ISigningKeyResolver` interfaces
> already include async methods (`ExtractAssertionsAsync`, `ResolveAsync`). No interface
> changes needed—just ensure implementations use the async variants when network I/O is involved.
```

#### Provider Implementations (in extension packages)

**CoseSign1.Certificates - X509 Chain Provider:**
```csharp
public class X509ChainAssertionProvider : ISigningKeyAssertionProvider
{
    public string ProviderName => "X509ChainAssertionProvider";

    // Only run for certificate-based keys
    public bool CanProvideAssertions(ISigningKey signingKey) 
        => signingKey is ICertificateSigningKey;

    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        AssertionExtractionContext? context = null)
    {
        if (signingKey is not ICertificateSigningKey certKey)
            return Array.Empty<ISigningKeyAssertion>();

        var cert = certKey.Certificate;
        var chainResult = BuildAndValidateChain(cert, context);

        // Return a strongly-typed assertion with the evaluation results
        // The SigningKey property captures which key this assertion is for
        return new ISigningKeyAssertion[]
        {
            new X509ChainTrustAssertion
            {
                SigningKey = signingKey,  // Associate assertion with its source key
                IsTrusted = chainResult.IsTrusted,
                RootThumbprint = chainResult.RootThumbprint,
                AllowedByUntrustedMode = chainResult.AllowedByUntrustedMode,
                FailureReason = chainResult.FailureReason
            }
        };
    }
}
```

**CoseSign1.Transparent.MST - Receipt Provider:**
```csharp
public class MstReceiptAssertionProvider : ISigningKeyAssertionProvider
{
    public string ProviderName => "MstReceiptAssertionProvider";

    // MST receipts are in the message, not the key - always run
    public bool CanProvideAssertions(ISigningKey signingKey) => true;

    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        AssertionExtractionContext? context = null)
    {
        // Look for MST receipt in message headers
        var receipt = ExtractReceiptFromHeaders(message);
        
        if (receipt == null)
        {
            return new ISigningKeyAssertion[]
            {
                new MstReceiptAssertion
                {
                    IsPresent = false,
                    IsVerified = false,
                    FailureReason = "No MST receipt found in message"
                }
            };
        }

        var verificationResult = VerifyReceipt(receipt);
        
        return new ISigningKeyAssertion[]
        {
            new MstReceiptAssertion
            {
                IsPresent = true,
                IsVerified = verificationResult.IsValid,
                ServiceId = verificationResult.ServiceId,
                FailureReason = verificationResult.FailureReason
            }
        };
    }
}
```

#### Orchestration Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 2: Key Material Trust                                         │
│                                                                     │
│   1. Orchestrator has list of ISigningKeyAssertionProvider[]        │
│                                                                     │
│   2. For each provider where CanProvideAssertions(key) == true:     │
│      - Call provider.ExtractAssertions(key, message)                │
│      - Collect returned ISigningKeyAssertion instances              │
│                                                                     │
│   3. Aggregate all assertions into SigningKeyAssertionSet           │
│                                                                     │
│   4. Evaluate TrustPolicy against the assertion set                 │
│      - TrustDecision = policy.Evaluate(assertionSet)                │
│                                                                     │
│   5. If TrustDecision.IsTrusted == false → STOP                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### Relationship Summary

| Type | Responsibility |
|------|----------------|
| `ISigningKeyAssertion` | **Data record** - holds facts about a key/message |
| `ISigningKeyAssertionProvider` | **Factory** - evaluates key/message and creates assertion instances |
| `SigningKeyAssertionSet` | **Container** - aggregates assertions from multiple providers |
| `TrustPolicy` | **Evaluator** - decides if assertions satisfy trust requirements |
| `TrustDecision` | **Result** - trusted/denied with reasons |

### TrustDecision: Policy Evaluation Result

`TrustDecision` already exists in the codebase ([TrustPolicy.cs#L20](TrustPolicy.cs#L20)):

```csharp
/// <summary>
/// Represents the outcome of a trust policy evaluation.
/// </summary>
public sealed class TrustDecision
{
    /// <summary>Gets whether the signing key is trusted.</summary>
    public bool IsTrusted { get; }

    /// <summary>Gets the reasons why trust was denied (empty when trusted).</summary>
    public IReadOnlyList<string> Reasons { get; }

    public static TrustDecision Trusted();
    public static TrustDecision Denied(params string[] reasons);
    public static TrustDecision Denied(IReadOnlyList<string> reasons);
}
```

### Validation Flow: Where Assertions Fit

Assertions are part of the **Trust Stage** only. The staged validation flow in `CoseSign1Validator`:

```
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 1: Key Material Resolution                                    │
│   - Resolves signing key material from the message                  │
│   - Does NOT emit assertions                                        │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 2: Key Material Trust                                         │
│   1. Trust validators run → emit ISigningKeyAssertion instances     │
│   2. TrustPolicy.Evaluate(assertions) → TrustDecision               │
│   3. If TrustDecision.IsTrusted == false → STOP (trust failure)     │
└─────────────────────────────────────────────────────────────────────┘
                              │ (only if trusted)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 3: Signature Verification                                     │
│   - Cryptographically verifies the signature using the key          │
│   - Does NOT emit assertions or trust decisions                     │
│   - Simply passes or fails                                          │
└─────────────────────────────────────────────────────────────────────┘
                              │ (only if signature valid)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 4: Post-Signature Policy                                      │
│   - Application-specific policy checks                              │
│   - Does NOT emit trust assertions                                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- **Trust validators** (stage 2) emit `ISigningKeyAssertion` instances
- **TrustPolicy** evaluates assertions before signature validation runs
- **Signature validators** (stage 3) don't participate in trust - they just verify signatures
- Trust decisions are made **before** signature validation, not after
- **Post-signature validators** (stage 4) receive context from all previous stages

### Post-Signature Validation Context

Post-signature validators need access to outputs from previous stages. We define a context interface:

```csharp
/// <summary>
/// Context passed to post-signature validators containing outputs from all prior stages.
/// </summary>
public interface IPostSignatureValidationContext
{
    /// <summary>
    /// Gets the original COSE Sign1 message being validated.
    /// </summary>
    CoseSign1Message Message { get; }

    /// <summary>
    /// Gets the resolved signing key (from stage 1).
    /// </summary>
    ISigningKey? ResolvedSigningKey { get; }

    /// <summary>
    /// Gets all trust assertions collected during the trust stage (from stage 2).
    /// </summary>
    SigningKeyAssertionSet TrustAssertions { get; }

    /// <summary>
    /// Gets the trust decision from evaluating TrustPolicy against assertions (from stage 2).
    /// </summary>
    TrustDecision TrustDecision { get; }

    /// <summary>
    /// Gets metadata from the signature validation stage (from stage 3).
    /// </summary>
    IReadOnlyDictionary<string, object> SignatureMetadata { get; }
}

/// <summary>
/// Validator that runs after signature verification with full context from prior stages.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="IPostSignatureValidationContext"/> is populated by the orchestrator
/// (<see cref="CoseSign1Validator"/>) as it progresses through the validation stages.
/// Post-signature validators do NOT create the context—they receive it.
/// </para>
/// </remarks>
public interface IPostSignatureValidator : IValidator
{
    /// <summary>
    /// Validates the message using context from all prior validation stages.
    /// </summary>
    /// <param name="context">Context containing outputs from resolution, trust, and signature stages.</param>
    /// <returns>Validation result.</returns>
    ValidationResult Validate(IPostSignatureValidationContext context);

    /// <summary>
    /// Asynchronously validates the message using context from all prior validation stages.
    /// Use this when post-signature validation requires network I/O.
    /// </summary>
    /// <param name="context">Context containing outputs from resolution, trust, and signature stages.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing the validation result.</returns>
    Task<ValidationResult> ValidateAsync(
        IPostSignatureValidationContext context,
        CancellationToken cancellationToken = default);
}
```

#### Post-Signature Use Cases

Post-signature validators can use prior stage context for:

```csharp
// === Example: Payload policy that depends on signer identity ===
public class SignerAwarePayloadValidator : IPostSignatureValidator
{
    public ValidationStage[] Stages => new[] { ValidationStage.PostSignature };

    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        // Access trust assertions from stage 2
        var chainAssertion = context.TrustAssertions.Get<X509ChainTrustAssertion>();
        
        // Different payload rules based on who signed it
        if (chainAssertion?.RootThumbprint == "INTERNAL_ROOT_THUMBPRINT")
        {
            // Internal signer - allow larger payloads
            return ValidateInternalPayload(context.Message);
        }
        else
        {
            // External signer - stricter payload rules
            return ValidateExternalPayload(context.Message);
        }
    }
}

// === Example: Audit logging with full context ===
public class AuditLoggingValidator : IPostSignatureValidator
{
    public ValidationStage[] Stages => new[] { ValidationStage.PostSignature };

    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        // Log full validation context for audit trail
        _logger.LogInformation(
            "Signature validated. Signer: {SignerInfo}, Trust: {TrustDecision}, Key: {KeyInfo}",
            context.TrustAssertions.Get<X509ChainTrustAssertion>()?.Description,
            context.TrustDecision.IsTrusted,
            context.ResolvedSigningKey?.GetType().Name);

        return ValidationResult.Success(nameof(AuditLoggingValidator), ValidationStage.PostSignature);
    }
}

// === Example: Time-based policy using certificate validity ===
public class TimestampPolicyValidator : IPostSignatureValidator
{
    public ValidationStage[] Stages => new[] { ValidationStage.PostSignature };

    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        // Access certificate assertions to check timing
        var certAssertion = context.TrustAssertions.Get<X509CertificateAssertion>();
        
        if (certAssertion != null && certAssertion.NotAfter < DateTime.UtcNow.AddDays(30))
        {
            return ValidationResult.Warning(
                nameof(TimestampPolicyValidator),
                ValidationStage.PostSignature,
                "Signing certificate expires in less than 30 days");
        }

        return ValidationResult.Success(nameof(TimestampPolicyValidator), ValidationStage.PostSignature);
    }
}
```

#### Updated Validation Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 1: Key Material Resolution                                    │
│   Output: ISigningKey                                               │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 2: Key Material Trust                                         │
│   Output: SigningKeyAssertionSet + TrustDecision                    │
└─────────────────────────────────────────────────────────────────────┘
                              │ (only if trusted)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 3: Signature Verification                                     │
│   Output: SignatureMetadata (algorithm used, etc.)                  │
└─────────────────────────────────────────────────────────────────────┘
                              │ (only if signature valid)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 4: Post-Signature Policy                                      │
│   Input: IPostSignatureValidationContext (all prior outputs)        │
│   Output: Application-specific pass/fail                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Async Orchestrator Support

The orchestrator (`CoseSign1Validator` and `ICoseSign1Validator`) needs async methods to support
network I/O in any validation stage:

```csharp
/// <summary>
/// Validates COSE Sign1 messages using a configured staged validation policy.
/// </summary>
public interface ICoseSign1Validator
{
    TrustPolicy TrustPolicy { get; }
    IReadOnlyList<IValidator> Validators { get; }

    /// <summary>
    /// Synchronously validates the message.
    /// </summary>
    CoseSign1ValidationResult Validate(CoseSign1Message message);

    /// <summary>
    /// Asynchronously validates the message.
    /// Use this when any validator may require network I/O (OCSP, CRL fetch, external services).
    /// </summary>
    Task<CoseSign1ValidationResult> ValidateAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}
```

**Context Population by Orchestrator:**

The `IPostSignatureValidationContext` is **created and populated by `CoseSign1Validator`** as it
progresses through the validation pipeline. Post-signature validators receive a pre-populated context:

```csharp
// Inside CoseSign1Validator.ValidateAsync (simplified):
internal async Task<CoseSign1ValidationResult> ValidateInternalAsync(
    CoseSign1Message message,
    CancellationToken cancellationToken)
{
    // Stage 1: Resolve key
    var resolutionResult = await _keyResolver.ResolveAsync(message, cancellationToken);
    var signingKey = resolutionResult.SigningKey;

    // Stage 2: Extract assertions and evaluate trust
    var assertions = new List<ISigningKeyAssertion>();
    foreach (var provider in _assertionProviders.Where(p => p.CanProvideAssertions(signingKey)))
    {
        var extracted = await provider.ExtractAssertionsAsync(signingKey, message, cancellationToken);
        assertions.AddRange(extracted);
    }
    var assertionSet = new SigningKeyAssertionSet(assertions);
    var trustDecision = TrustPolicy.Evaluate(assertionSet);

    if (!trustDecision.IsTrusted)
        return /* trust failure result */;

    // Stage 3: Verify signature
    var signatureResult = await _signatureValidator.ValidateAsync(message, signingKey, cancellationToken);
    
    if (!signatureResult.IsValid)
        return /* signature failure result */;

    // Stage 4: Build context and run post-signature validators
    var postContext = new PostSignatureValidationContext
    {
        Message = message,
        ResolvedSigningKey = signingKey,
        TrustAssertions = assertionSet,        // <-- populated from stage 2
        TrustDecision = trustDecision,          // <-- populated from stage 2
        SignatureMetadata = signatureResult.Metadata  // <-- populated from stage 3
    };

    foreach (var postValidator in _postSignatureValidators)
    {
        var result = await postValidator.ValidateAsync(postContext, cancellationToken);
        if (!result.IsValid)
            return /* post-signature failure result */;
    }

    return /* success */;
}
```

## Complete Consumer Example

```csharp
// === How CoseSign1Validator uses this architecture ===
// Trust validators (stage 2) emit ISigningKeyAssertion instances.
// TrustPolicy evaluates those assertions and produces a TrustDecision.
// Signature validators (stage 3) only run if trust is established - they
// don't produce assertions; they just pass/fail signature verification.

// === Enterprise scenario: Strict policy ===
public class EnterpriseTrustPolicy
{
    // Craft a custom policy: approved root + MST receipt
    public static readonly TrustPolicy Policy = TrustPolicy.And(
        X509ChainTrustPolicy.RequireRootInAllowlist("ABC123...", "DEF456..."),
        MstReceiptTrustPolicy.Default);
}

// === Simple scenario: Use secure defaults ===
public class SimpleTrustPolicy
{
    // Just use the assertion author's secure defaults
    public static readonly TrustPolicy Policy = X509ChainTrustPolicy.Default;
}

// === Flexible scenario: Multiple trust paths ===
public class FlexibleTrustPolicy
{
    // Trust X509 path OR AKV path
    public static readonly TrustPolicy Policy = TrustPolicy.Or(
        X509ChainTrustPolicy.Default,
        AkvKeyTrustPolicy.Default);
}

// === Using with CoseSign1Validator ===
public class ValidationOrchestrationExample
{
    public CoseSign1ValidationResult ValidateMessage(CoseSign1Message message)
    {
        var validators = new List<IValidator>
        {
            // Trust stage validators - these emit ISigningKeyAssertion instances
            new X509ChainTrustValidator(),    // emits X509ChainTrustAssertion
            new MstReceiptValidator(),         // emits MstReceiptAssertion
            
            // Signature stage validators - these just verify the signature (pass/fail)
            new CoseSign1SignatureValidator()  // does NOT emit assertions
        };
        
        // TrustPolicy is evaluated BEFORE signature validation runs
        var validator = new CoseSign1Validator(validators, EnterpriseTrustPolicy.Policy);
        return validator.Validate(message);
    }
}

// === Configured assertion scenario ===
public class CNMatchingTrustPolicy
{
    private readonly TrustPolicy _policy;

    public CNMatchingTrustPolicy(IEnumerable<string> acceptableCNs)
    {
        // Policy is configured at construction time
        _policy = X509CommonNameTrustPolicy.RequireMatch(acceptableCNs);
    }

    public TrustPolicy Policy => _policy;
}
```

## Benefits

1. **Compile-time type safety** - no more string claim IDs or object casting
2. **Secure by default** - each assertion carries its secure default policy
3. **IntelliSense support** - discover assertions and their properties through types
4. **Package isolation** - X509 types in Certificates, MST in MST, AKV in AKV
5. **Rich structured data** - assertions have multiple typed properties
6. **Composable policies** - And/Or/Not combine naturally
7. **Self-documenting** - types and defaults describe themselves
8. **Consumer flexibility** - use defaults or craft custom policies

## Migration Plan

1. Define `ISigningKeyAssertion` interface with `DefaultTrustPolicy` and `SigningKey` in core package
2. Update `ISigningKeyAssertionProvider.ExtractAssertions()` to return `IReadOnlyList<ISigningKeyAssertion>` 
   - ⚠️ Breaking change to existing interface signature
3. Update `SigningKeyAssertionSet` to hold `ISigningKeyAssertion` items
4. Add generic `TrustPolicy.Require<T>()` and `TrustPolicy.UseDefault<T>()` factories
5. Create typed assertion records in each extension package:
   - `X509ChainTrustAssertion` in CoseSign1.Certificates
   - `MstReceiptAssertion` in CoseSign1.Transparent.MST  
   - `AkvKeyAssertion` in CoseSign1.AzureKeyVault
6. Update provider implementations to return typed assertions:
   - `X509ChainAssertionProvider` → returns `X509ChainTrustAssertion`
   - `MstReceiptAssertionProvider` → returns `MstReceiptAssertion`
7. Add `IPostSignatureValidator` interface with `Validate()` and `ValidateAsync()` methods
8. Add `IPostSignatureValidationContext` interface for context passing
9. Add `ValidateAsync()` to `ICoseSign1Validator` interface
10. Implement `ValidateAsync()` in `CoseSign1Validator` to orchestrate async pipeline
11. **Delete** `WellKnownAssertionClaims` from core package entirely
12. **Delete** old `SigningKeyAssertion` class (replaced by typed assertions)
13. Update validators to emit typed assertions
14. Update existing policies to use `Require<T>()`

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backward compatibility | None needed | V2 hasn't shipped |
| WellKnownAssertionClaims | Delete entirely | Claims model replaced by assertions |
| Assertion mutability | Immutable `record` | Thread-safe, defensive |
| Multiple assertions of same type | Supported via `OfType<T>()` | Real scenarios have multiples |
| DefaultTrustPolicy | Instance property | Allows config-dependent defaults (e.g., CN matching) |
| Companion policy classes | `X509ChainTrustPolicy.Default` pattern | Clean API, static for simple cases |
| Negative outcomes | Model as assertion properties | e.g., `IsTrusted = false` with `FailureReason` |
| Target framework | Keep netstandard2.0 + net10.0 | Broad compatibility required |

## Implementation Patterns

### Pattern A: Static Default (No Configuration Needed)

For assertions where the secure default doesn't need user input:

```csharp
// Assertion record
public sealed record X509ChainTrustAssertion : ISigningKeyAssertion
{
    public TrustPolicy DefaultTrustPolicy => X509ChainTrustPolicy.Default;
    public required ISigningKey? SigningKey { get; init; }  // Set by provider
    // ... properties
}

// Companion policy class with static Default
public static class X509ChainTrustPolicy
{
    public static TrustPolicy Default { get; } = 
        TrustPolicy.Require<X509ChainTrustAssertion>(
            a => a.IsTrusted && !a.AllowedByUntrustedMode,
            "X.509 certificate chain must be trusted");

    // Factory methods for common customizations
    public static TrustPolicy RequireRootInAllowlist(params string[] thumbprints) => ...;
}
```

### Pattern B: Configured Default (Requires User Input)

For assertions where the secure default depends on configuration:

```csharp
// Assertion record captures configuration
public sealed record X509CommonNameAssertion : ISigningKeyAssertion
{
    private readonly TrustPolicy _defaultPolicy;
    
    public X509CommonNameAssertion(IEnumerable<string> acceptableCNs)
    {
        AcceptableCNs = acceptableCNs.ToList();
        _defaultPolicy = X509CommonNameTrustPolicy.RequireMatch(AcceptableCNs);
    }
    
    public TrustPolicy DefaultTrustPolicy => _defaultPolicy;
    public required ISigningKey? SigningKey { get; init; }  // Set by provider
    
    public IReadOnlyList<string> AcceptableCNs { get; }
    public required string ActualCN { get; init; }
    // ...
}

// Companion policy class with factory methods only (no static Default)
public static class X509CommonNameTrustPolicy
{
    // No static Default - must be configured
    public static TrustPolicy RequireMatch(IEnumerable<string> acceptableCNs) => ...;
}
```

### Pattern C: Key-Agnostic Assertions

For assertions that don't relate to a specific signing key (e.g., receipt validation):

```csharp
public sealed record MstReceiptAssertion : ISigningKeyAssertion
{
    public TrustPolicy DefaultTrustPolicy => MstReceiptTrustPolicy.Default;
    
    // Key-agnostic - MST validates the receipt, not the signing key
    public ISigningKey? SigningKey => null;
    
    public required bool IsPresent { get; init; }
    public required bool IsVerified { get; init; }
    // ...
}
```

### When to Use Each Pattern

| Pattern | Use When | SigningKey | Example |
|---------|----------|-----------|---------|
| **Static Default** | Secure default is universal, key-type specific | Set by provider | Chain trust, AKV key |
| **Configured Default** | Secure default requires user input | Set by provider | CN matching, issuer allowlist |
| **Key-Agnostic** | Assertion validates something other than the key | Returns `null` | MST receipt, timestamp |

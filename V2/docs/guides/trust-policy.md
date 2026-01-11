# Trust Policy Deep Dive

This guide describes the V2 trust policy system.

In V2, trust is evaluated by running a `TrustPolicy` against a set of strongly-typed `ISigningKeyAssertion`s produced during validation.

## Overview

V2 trust uses an **assertion-based** model:

| Concept | Description |
|---------|-------------|
| **Assertion** (`ISigningKeyAssertion`) | A neutral fact about the signing key or message (e.g., “X.509 chain is trusted”) |
| **Assertion provider** (`ISigningKeyAssertionProvider`) | Extracts assertions during the trust stage |
| **Policy** (`TrustPolicy`) | Declarative logic that evaluates assertions and returns a `TrustDecision` |
| **Decision** (`TrustDecision`) | Trusted/Denied + human-readable reasons |

Important properties of this model:

- Assertions do **not** grant trust by themselves.
- Trust originates from the **policy**.
- Trust is evaluated after signing key resolution and before signature verification.

## Default Trust Behavior

`CoseSign1ValidationBuilder` uses `TrustPolicy.FromAssertionDefaults()` unless overridden.

`TrustPolicy.FromAssertionDefaults()` evaluates each assertion using its own `ISigningKeyAssertion.DefaultTrustPolicy` and combines them with `TrustPolicy.And(...)`.

You can override the behavior using:

- `OverrideDefaultTrustPolicy(TrustPolicy policy)`
- `AllowAllTrust(string? reason = null)`
- `DenyAllTrust(string? reason = null)`

## Common Usage

### Require a trusted X.509 chain

```csharp
var message = CoseMessage.DecodeSign1(signatureBytes);

var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain())
    .OverrideDefaultTrustPolicy(X509TrustPolicies.RequireTrustedChain()));

if (!result.Overall.IsValid)
{
    foreach (var failure in result.Trust.Failures)
    {
        Console.WriteLine($"{failure.ErrorCode}: {failure.Message}");
    }
}
```

### Require MST receipt presence and trust

```csharp
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain())
    .AddMstReceiptAssertionProvider(mst => mst.UseClient(client))
    .OverrideDefaultTrustPolicy(TrustPolicy.And(
        X509TrustPolicies.RequireTrustedChain(),
        MstTrustPolicies.RequireReceiptPresentAndTrusted())));
```

## Policy Primitives

All policy evaluation happens via:

```csharp
TrustDecision decision = policy.Evaluate(assertions);
```

### `TrustPolicy.DenyAll(reason)`

Always denies trust.

```csharp
var policy = TrustPolicy.DenyAll("No signers are trusted in this environment");
```

### `TrustPolicy.AllowAll(reason)`

Always allows trust (use sparingly).

```csharp
var policy = TrustPolicy.AllowAll("Testing only");
```

### `TrustPolicy.Require<TAssertion>(predicate, failureReason)`

Requires at least one assertion of type `TAssertion` that satisfies the predicate.

```csharp
var policy = TrustPolicy.Require<X509ChainTrustedAssertion>(
    a => a.IsTrusted,
    "X.509 chain must be trusted");
```

### `TrustPolicy.RequirePresent<TAssertion>(failureReason)`

Requires that an assertion of type `TAssertion` is present (any value).

```csharp
var policy = TrustPolicy.RequirePresent<MstReceiptPresentAssertion>(
    "MST receipt must be present");
```

### `TrustPolicy.UseDefault(assertionSample)`

Uses an assertion type’s `DefaultTrustPolicy`.

```csharp
var policy = TrustPolicy.UseDefault(new X509ChainTrustedAssertion(isTrusted: true));
```

### `TrustPolicy.And(...)` / `TrustPolicy.Or(...)` / `TrustPolicy.Not(...)` / `TrustPolicy.Implies(...)`

Compose policies using boolean logic:

```csharp
var policy = TrustPolicy.And(
    X509TrustPolicies.RequireTrustedChain(),
    TrustPolicy.Require<X509ValidityAssertion>(a => a.IsValid, "Certificate must be valid"));
```

### `TrustPolicy.FromAssertionDefaults()`

Evaluates each assertion using its own default policy and combines them.

This is the builder’s default trust behavior.

## Creating Custom Assertions

If you have an environment-specific trust signal, model it as an assertion + policy.

### 1) Define an assertion type

```csharp
public sealed record OrgApprovedAssertion(bool IsApproved) : ISigningKeyAssertion
{
    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<OrgApprovedAssertion>(
        a => a.IsApproved,
        "Signer must be approved by the organization");

    public string Domain => "org";
    public string Description => IsApproved ? "Signer is org-approved" : "Signer is not org-approved";
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;
    public ISigningKey? SigningKey { get; init; }
}
```

### 2) Emit the assertion from an assertion provider

```csharp
public sealed class OrgApprovedAssertionProvider : ISigningKeyAssertionProvider
{
    public string ComponentName => nameof(OrgApprovedAssertionProvider);

    public bool IsApplicableTo(CoseSign1Message? message, CoseSign1ValidationOptions? options = null) => true;

    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null)
        => new ISigningKeyAssertion[] { new OrgApprovedAssertion(IsApproved: true) { SigningKey = signingKey } };

    public Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null,
        CancellationToken cancellationToken = default)
        => Task.FromResult(ExtractAssertions(signingKey, message, options));
}
```

### 3) Use it in validation

```csharp
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain())
    .AddComponent(new OrgApprovedAssertionProvider())
    .OverrideDefaultTrustPolicy(TrustPolicy.And(
        X509TrustPolicies.RequireTrustedChain(),
        TrustPolicy.Require<OrgApprovedAssertion>(a => a.IsApproved, "Signer must be org-approved"))));
```

## Troubleshooting

If trust fails, the trust stage reports `TRUST_POLICY_NOT_SATISFIED` failures with reasons:

```csharp
if (!result.Trust.IsValid)
{
    foreach (var failure in result.Trust.Failures)
    {
        Console.WriteLine($"{failure.ErrorCode}: {failure.Message}");
    }
}
```

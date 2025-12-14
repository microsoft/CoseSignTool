# Header Contributors

This document describes the extensible header contribution system in CoseSignTool V2.

## Overview

Header contributors allow you to add custom headers to COSE Sign1 messages during signing. This enables SCITT compliance, CWT claims, and custom application headers.

## IHeaderContributor Interface

All header contributors implement this interface:

```csharp
public interface IHeaderContributor
{
    void ContributeHeaders(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        ReadOnlySpan<byte> payload,
        string? contentType);
}
```

## Built-in Contributors

### CertificateHeaderContributor

Adds certificate chain to unprotected headers:

```csharp
var contributor = new CertificateHeaderContributor(certChain);
```

Headers added:
- `x5chain` (33): Certificate chain in unprotected headers

### CwtClaimsHeaderContributor

Adds CWT (CBOR Web Token) claims for SCITT compliance:

```csharp
var claims = new CwtClaims
{
    Issuer = "https://build.example.com",
    Subject = "pkg:npm/my-package@1.0.0",
    IssuedAt = DateTimeOffset.UtcNow
};

var contributor = new CwtClaimsHeaderContributor(claims);
```

Headers added:
- `cwt_claims` (15): CWT claims map in protected headers

### CoseHashEnvelopeHeaderContributor

Adds hash envelope headers for indirect signatures:

```csharp
var contributor = new CoseHashEnvelopeHeaderContributor(HashAlgorithmName.SHA256);
```

Headers added:
- Content type set to `application/cose_hash_envelope+cbor`
- Hash algorithm indicator

## Creating Custom Contributors

```csharp
public class CustomHeaderContributor : IHeaderContributor
{
    private readonly string _customValue;
    
    public CustomHeaderContributor(string customValue)
    {
        _customValue = customValue;
    }
    
    public void ContributeHeaders(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        ReadOnlySpan<byte> payload,
        string? contentType)
    {
        // Add to protected headers (signed)
        protectedHeaders.Add(
            new CoseHeaderLabel("custom-header"),
            CoseHeaderValue.FromString(_customValue));
        
        // Or add to unprotected headers (not signed)
        unprotectedHeaders.Add(
            new CoseHeaderLabel("metadata"),
            CoseHeaderValue.FromString("additional-info"));
    }
}
```

## Using Contributors with Factories

```csharp
var contributors = new IHeaderContributor[]
{
    new CertificateHeaderContributor(chain),
    new CwtClaimsHeaderContributor(claims),
    new CustomHeaderContributor("my-value")
};

var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: contributors);
```

## Protected vs Unprotected Headers

| Header Type | Signed | Modifiable | Use Case |
|-------------|--------|------------|----------|
| Protected | Yes | No | Critical security data, claims |
| Unprotected | No | Yes | Certificates, metadata, receipts |

### Guidelines

**Use protected headers for:**
- Content type
- Algorithm
- CWT claims (issuer, subject, etc.)
- Critical application headers

**Use unprotected headers for:**
- Certificate chains
- Transparency receipts
- Non-critical metadata
- Headers that may be updated

## See Also

- [Custom Header Contributors Guide](../guides/custom-headers.md)
- [SCITT Compliance](../guides/scitt-compliance.md)
- [CoseSign1.Headers](../components/headers.md)

# Header Contributors

This document describes the extensible header contribution system in CoseSignTool V2.

## Overview

Header contributors allow you to add custom headers to COSE Sign1 messages during signing. This enables SCITT compliance, CWT claims, and custom application headers.

## IHeaderContributor Interface

All header contributors implement this interface:

```csharp
public interface IHeaderContributor
{
    HeaderMergeStrategy MergeStrategy { get; }

    void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
    void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
}
```

## Built-in Contributors

### CertificateHeaderContributor

Adds X.509 certificate headers for certificate-based signing keys:

```csharp
var contributor = new CertificateHeaderContributor();
```

Headers added:
- `x5t` (34): Certificate thumbprint in protected headers
- `x5chain` (33): Certificate chain (leaf-first) in protected headers

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
- `cwt_claims` (15): CWT claims map (protected by default; placement is configurable)

### CoseHashEnvelopeHeaderContributor

Adds hash envelope headers for indirect signatures:

```csharp
var contributor = new CoseHashEnvelopeHeaderContributor(
    HashAlgorithmName.SHA256,
    contentType: "application/octet-stream");
```

Headers added:
- Removes `content_type` (3) per RFC 9054 hash-envelope requirements
- Adds `payload_hash_alg` (258)
- Adds `preimage_content_type` (259)
- Optionally adds `payload_location` (260)

## Creating Custom Contributors

```csharp
public class CustomHeaderContributor : IHeaderContributor
{
    private readonly string _customValue;
    
    public CustomHeaderContributor(string customValue)
    {
        _customValue = customValue;
    }

    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        headers.Add(new CoseHeaderLabel("custom-header"), CoseHeaderValue.FromString(_customValue));
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        headers.Add(new CoseHeaderLabel("metadata"), CoseHeaderValue.FromString("additional-info"));
    }
}
```

## Using Contributors with Factories

```csharp
var contributors = new IHeaderContributor[]
{
    new CertificateHeaderContributor(),
    new CwtClaimsHeaderContributor(claims),
    new CustomHeaderContributor("my-value")
};

using var factory = new CoseSign1MessageFactory(signingService);

var options = new DirectSignatureOptions
{
    EmbedPayload = true,
    AdditionalHeaderContributors = contributors,
};

var message = await factory.CreateCoseSign1MessageAsync<DirectSignatureOptions>(
    payload,
    contentType: "application/octet-stream",
    options);
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
- Transparency receipts
- Non-critical metadata
- Headers that may be updated

## See Also

- [Custom Header Contributors Guide](../guides/custom-headers.md)
- [SCITT Compliance](../guides/scitt-compliance.md)
- [CoseSign1.Headers](../components/headers.md)

# CoseSign1.Headers

SCITT-compliant CWT claims and header management for COSE Sign1 messages.

## Installation

```bash
dotnet add package CoseSign1.Headers --version 2.0.0-preview
```

## Overview

Support for CBOR Web Token (CWT) claims and header management for Supply Chain Integrity, Transparency, and Trust (SCITT) compliance. Essential for creating verifiable supply chain attestations.

## Key Features

- ✅ **CWT Claims** - Full CBOR Web Token claims support (RFC 8392)
- ✅ **SCITT Compliance** - Standards-compliant attestation creation
- ✅ **Auto DID Generation** - Automatic DID:x509 issuer from certificate
- ✅ **Configurable Timestamps** - Automatic iat/nbf/exp population
- ✅ **Custom Claims** - Extensible claim system
- ✅ **Header Placement** - Protected, unprotected, or both

## Quick Start

### Basic CWT Claims

```csharp
using CoseSign1.Headers;

// Create CWT claims
var claims = new CwtClaims
{
    Issuer = "https://example.com",
    Subject = "package:npm/my-package@1.0.0",
    IssuedAt = DateTimeOffset.UtcNow,
    ExpirationTime = DateTimeOffset.UtcNow.AddDays(365)
};

// Create header contributor
var contributor = new CwtClaimsHeaderContributor(claims);

// Use with factory
var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: new[] { contributor });

byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    payload,
    contentType: "application/json");
```

### SCITT-Compliant Attestation

```csharp
// Full SCITT attestation with custom claims
var claims = new CwtClaims
{
    Issuer = "https://build.contoso.com",
    Subject = "package:npm/express@4.18.2",
    Audience = "https://registry.npmjs.org",
    IssuedAt = DateTimeOffset.UtcNow,
    NotBefore = DateTimeOffset.UtcNow,
    ExpirationTime = DateTimeOffset.UtcNow.AddYears(1),
    CwtId = Guid.NewGuid().ToByteArray()
};

// Add custom attestation claims
claims.AdditionalClaims["build_id"] = "build-12345";
claims.AdditionalClaims["commit_sha"] = "a1b2c3d4e5f6";
claims.AdditionalClaims["repository"] = "https://github.com/contoso/myrepo";
claims.AdditionalClaims["pipeline"] = "release-pipeline-v2";

var contributor = new CwtClaimsHeaderContributor(claims);
```

### Auto-Populate Timestamps

```csharp
var contributor = new CwtClaimsHeaderContributor(
    claims,
    autoPopulateTimestamps: true);

// When signing, the contributor will automatically set:
// - iat (issued at) to current time
// - nbf (not before) to current time
// - exp (expiration) based on configuration
```

### Auto-Generate DID:x509 Issuer

```csharp
// When using with certificate signing, issuer is auto-generated
var claims = new CwtClaims
{
    // Issuer left null - will be auto-generated from certificate
    Subject = "artifact:my-software@1.0.0"
};

var contributor = new CwtClaimsHeaderContributor(
    claims,
    autoGenerateIssuer: true);

// Issuer will be set to DID:x509 of signing certificate chain
// e.g., "did:x509:0:sha256:base64cert::subject:CN:My%20Signer"
```

## CWT Claims Properties

```csharp
public class CwtClaims
{
    // Standard claims (RFC 8392)
    public string? Issuer { get; set; }              // iss (1)
    public string? Subject { get; set; }             // sub (2)
    public string? Audience { get; set; }            // aud (3)
    public DateTimeOffset? ExpirationTime { get; set; } // exp (4)
    public DateTimeOffset? NotBefore { get; set; }   // nbf (5)
    public DateTimeOffset? IssuedAt { get; set; }    // iat (6)
    public byte[]? CwtId { get; set; }               // cti (7)
    
    // Custom claims dictionary
    public IDictionary<string, object> AdditionalClaims { get; }
}
```

## CwtClaimsHeaderContributor

### Constructor Options

```csharp
public CwtClaimsHeaderContributor(
    CwtClaims claims,
    CwtClaimsHeaderPlacement headerPlacement = CwtClaimsHeaderPlacement.ProtectedOnly,
    int? customHeaderLabel = null,
    bool autoPopulateTimestamps = false,
    bool autoGenerateIssuer = false)
```

### Header Placement

```csharp
public enum CwtClaimsHeaderPlacement
{
    ProtectedOnly,     // Claims in protected headers only (default)
    UnprotectedOnly,   // Claims in unprotected headers only
    Both               // Claims in both protected and unprotected
}
```

### Custom Header Label

```csharp
// Use standard CWT claims label (default)
var contributor = new CwtClaimsHeaderContributor(claims);

// Use custom label for claims map
var contributor = new CwtClaimsHeaderContributor(
    claims,
    customHeaderLabel: 42);  // Custom CBOR label
```

## Reading CWT Claims

```csharp
using CoseSign1.Headers.Extensions;

// Extract claims from message
CwtClaims? claims = message.GetCwtClaims();

if (claims != null)
{
    Console.WriteLine($"Issuer: {claims.Issuer}");
    Console.WriteLine($"Subject: {claims.Subject}");
    Console.WriteLine($"Issued At: {claims.IssuedAt}");
    Console.WriteLine($"Expires: {claims.ExpirationTime}");
    
    // Access custom claims
    foreach (var (key, value) in claims.AdditionalClaims)
    {
        Console.WriteLine($"{key}: {value}");
    }
}
```

## Subject Identifier Formats

SCITT recommends using URIs for subjects:

```csharp
// Package URLs (purl)
claims.Subject = "pkg:npm/%40scope/package@1.0.0";
claims.Subject = "pkg:nuget/Microsoft.Extensions.Logging@8.0.0";
claims.Subject = "pkg:pypi/requests@2.31.0";

// Container images
claims.Subject = "oci://mcr.microsoft.com/dotnet/runtime:8.0";

// Git references
claims.Subject = "git+https://github.com/org/repo@v1.0.0";

// Generic URIs
claims.Subject = "https://example.com/artifacts/my-software";
```

## CBOR Labels

Standard CWT claim labels (RFC 8392):

| Claim | Label | Type |
|-------|-------|------|
| iss | 1 | text string |
| sub | 2 | text string |
| aud | 3 | text string |
| exp | 4 | integer (epoch seconds) |
| nbf | 5 | integer (epoch seconds) |
| iat | 6 | integer (epoch seconds) |
| cti | 7 | byte string |

## Advanced Usage

### Multiple Header Contributors

```csharp
var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: new IHeaderContributor[]
    {
        // CWT claims
        new CwtClaimsHeaderContributor(claims),
        
        // Certificate headers (X5T, X5Chain)
        new CertificateHeaderContributor(),
        
        // Custom contributor
        new MyCustomHeaderContributor()
    });
```

### Conditional Claims

```csharp
var claims = new CwtClaims
{
    Issuer = "https://build.example.com",
    Subject = artifactUri
};

// Add conditional claims based on context
if (isProductionBuild)
{
    claims.AdditionalClaims["environment"] = "production";
    claims.AdditionalClaims["signed_by"] = "release-pipeline";
}
else
{
    claims.AdditionalClaims["environment"] = "development";
}

// Add build metadata
claims.AdditionalClaims["build_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
claims.AdditionalClaims["build_number"] = buildNumber;
```

### Validating CWT Claims

```csharp
using CoseSign1.Validation;

var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => { })
    .AllowAllTrust("CWT validation example")
    .AddValidator((message, stage) =>
    {
        const string validatorName = "CwtClaimsValidator";

        if (stage != ValidationStage.PostSignature)
        {
            return ValidationResult.NotApplicable(validatorName, stage);
        }

        var claims = message.GetCwtClaims();
        
        if (claims == null)
            return ValidationResult.Failure(validatorName, stage, "Missing CWT claims");
        
        if (claims.ExpirationTime < DateTimeOffset.UtcNow)
            return ValidationResult.Failure(validatorName, stage, "Claims have expired");
        
        if (claims.NotBefore > DateTimeOffset.UtcNow)
            return ValidationResult.Failure(validatorName, stage, "Claims not yet valid");
        
        if (!claims.Issuer?.StartsWith("https://trusted.") ?? true)
            return ValidationResult.Failure(validatorName, stage, "Untrusted issuer");
        
        return ValidationResult.Success(validatorName, stage);
    })
    .Build();
```

## SCITT Compliance

For full SCITT compliance, ensure:

1. **Issuer** is a DID (preferably DID:x509 from certificate)
2. **Subject** identifies the artifact (use purl format)
3. **IssuedAt** is set to signing time
4. **Content-Type** header is set appropriately
5. **Payload** contains the attestation content

```csharp
// SCITT-compliant attestation
var claims = new CwtClaims
{
    // DID:x509 generated from certificate
    Issuer = null,  // Auto-generated
    Subject = "pkg:npm/my-package@1.0.0",
    IssuedAt = DateTimeOffset.UtcNow
};

var contributor = new CwtClaimsHeaderContributor(
    claims,
    autoGenerateIssuer: true,
    autoPopulateTimestamps: true);

var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: new[] { contributor });

// Sign SCITT statement
byte[] statement = JsonSerializer.SerializeToUtf8Bytes(new
{
    type = "https://in-toto.io/Statement/v1",
    predicateType = "https://slsa.dev/provenance/v1",
    predicate = attestationData
});

byte[] signedStatement = factory.CreateCoseSign1MessageBytes(
    statement,
    contentType: "application/vnd.in-toto+json");
```

## See Also

- [CoseSign1](../CoseSign1/README.md) - Signature factories
- [CoseSign1.Certificates](../CoseSign1.Certificates/README.md) - Certificate signing
- [DIDx509](../DIDx509/README.md) - DID:x509 support
- [SCITT Specification](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) - SCITT architecture

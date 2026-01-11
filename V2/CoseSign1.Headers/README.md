# CoseSign1.Headers

SCITT-compliant CWT claims and header management for COSE Sign1 messages.

## Installation

```bash
dotnet add package CoseSign1.Headers --version 2.0.0-preview
```

## Overview
using CoseSign1.Certificates.Validation;

using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using System.Security.Cryptography.Cose;
Support for CBOR Web Token (CWT) claims and header management for Supply Chain Integrity, Transparency, and Trust (SCITT) compliance. Essential for creating verifiable supply chain attestations.
public sealed class CwtClaimsPostSignatureValidator : IPostSignatureValidator
{
    public string ComponentName => nameof(CwtClaimsPostSignatureValidator);
    public bool IsApplicableTo(CoseSign1Message? message, CoseSign1ValidationOptions? options = null) => message != null;

    public ValidationResult Validate(IPostSignatureValidationContext context)
- ✅ **SCITT Compliance** - Standards-compliant attestation creation
        var claims = context.Message.GetCwtClaims();

```csharp
            return ValidationResult.Failure(ComponentName, "Missing CWT claims");
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
            return ValidationResult.Failure(ComponentName, "Claims have expired");
// Create CWT claims
var claims = new CwtClaims
            return ValidationResult.Failure(ComponentName, "Claims not yet valid");
    Issuer = "https://example.com",
    Subject = "package:npm/my-package@1.0.0",
            return ValidationResult.Failure(ComponentName, "Untrusted issuer");
    ExpirationTime = DateTimeOffset.UtcNow.AddDays(365)
        return ValidationResult.Success(ComponentName);


    public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(context));
}

var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: CoseHeaderLocation.Any))
    .ValidateCertificate(cert => { })
    .AllowAllTrust("CWT validation example")
    .AddComponent(new CwtClaimsPostSignatureValidator())
var contributor = new CwtClaimsHeaderContributor(claims);

// Use with factory
using var factory = new CoseSign1MessageFactory(signingService);

var options = new DirectSignatureOptions
{
    EmbedPayload = true,
    AdditionalHeaderContributors = [contributor],
};

byte[] signedMessage = factory.CreateDirectCoseSign1MessageBytes(
    payload,
    contentType: "application/json",
    options: options);
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
using var factory = new CoseSign1MessageFactory(signingService);

var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors = new IHeaderContributor[]
    {
        // CWT claims
        new CwtClaimsHeaderContributor(claims),

        // Certificate headers (x5t, x5chain)
        new CertificateHeaderContributor(),

        // Custom contributor
        new MyCustomHeaderContributor(),
    },
};
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
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using System.Security.Cryptography.Cose;

public sealed class CwtClaimsPostSignatureValidator : IPostSignatureValidator
{
    public string ComponentName => nameof(CwtClaimsPostSignatureValidator);
    public bool IsApplicableTo(CoseSign1Message? message, CoseSign1ValidationOptions? options = null) => message != null;

    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        var claims = context.Message.GetCwtClaims();

        if (claims == null)
            return ValidationResult.Failure(ComponentName, "Missing CWT claims");

        if (claims.ExpirationTime < DateTimeOffset.UtcNow)
            return ValidationResult.Failure(ComponentName, "Claims have expired");

        if (claims.NotBefore > DateTimeOffset.UtcNow)
            return ValidationResult.Failure(ComponentName, "Claims not yet valid");

        if (!claims.Issuer?.StartsWith("https://trusted.") ?? true)
            return ValidationResult.Failure(ComponentName, "Untrusted issuer");

        return ValidationResult.Success(ComponentName);
    }

    public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(context));
}

var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: CoseHeaderLocation.Any))
    .ValidateCertificate(cert => { })
    .AllowAllTrust("CWT validation example")
    .AddComponent(new CwtClaimsPostSignatureValidator())
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

using var factory = new CoseSign1MessageFactory(signingService);

var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors = [contributor],
};

// Sign SCITT statement
byte[] statement = JsonSerializer.SerializeToUtf8Bytes(new
{
    type = "https://in-toto.io/Statement/v1",
    predicateType = "https://slsa.dev/provenance/v1",
    predicate = attestationData
});

byte[] signedStatement = factory.CreateDirectCoseSign1MessageBytes(
    statement,
    contentType: "application/vnd.in-toto+json",
    options: options);
```

## See Also

- [CoseSign1.Factories](../CoseSign1.Factories/README.md) - Signature factories
- [CoseSign1.Certificates](../CoseSign1.Certificates/README.md) - Certificate signing
- [DIDx509](../DIDx509/README.md) - DID:x509 support
- [SCITT Specification](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) - SCITT architecture

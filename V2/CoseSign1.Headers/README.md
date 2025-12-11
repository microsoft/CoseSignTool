# CoseSign1.Headers

SCITT-compliant CWT claims and header management for COSE Sign1 messages.

## Overview

Support for CBOR Web Token (CWT) claims and header management for Supply Chain Integrity, Transparency, and Trust (SCITT) compliance. Essential for creating verifiable supply chain attestations.

## Installation

```bash
dotnet add package CoseSign1.Headers --version 2.0.0-preview
```

## Key Features

- ✅ **CWT Claims** - Full CBOR Web Token claims support
- ✅ **SCITT Compliance** - Standards-compliant attestation creation
- ✅ **Header Contributors** - Automatic CWT claims addition
- ✅ **Subject Identifiers** - Package URLs, container images, artifacts
- ✅ **Custom Claims** - Extensible claim system
- ✅ **Transparency Ready** - Integration with transparency services

## Quick Start

### Basic CWT Claims

```csharp
using CoseSign1.Headers;

var claims = new CwtClaims
{
    Issuer = "https://contoso.com",
    Subject = "package:npm/my-package@1.0.0",
    IssuedAt = DateTimeOffset.UtcNow,
    ExpirationTime = DateTimeOffset.UtcNow.AddDays(365)
};

var contributor = new CwtClaimsHeaderContributor(claims);
var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: new[] { contributor });

var message = await factory.CreateAsync(payload);
```

### SCITT-Compliant Attestation

```csharp
var claims = new CwtClaims
{
    Issuer = "https://build.contoso.com",
    Subject = "package:npm/express@4.18.2",
    IssuedAt = DateTimeOffset.UtcNow,
    CwtId = Guid.NewGuid().ToByteArray()
};

// Add custom claims
claims.AdditionalClaims["build_id"] = "build-12345";
claims.AdditionalClaims["commit_sha"] = "a1b2c3d4";
claims.AdditionalClaims["repository"] = "https://github.com/contoso/myrepo";

var contributor = new CwtClaimsHeaderContributor(claims);
```

### Reading CWT Claims

```csharp
// Extract claims from message
CwtClaims? claims = message.GetCwtClaims();

if (claims != null)
{
    Console.WriteLine($"Issuer: {claims.Issuer}");
    Console.WriteLine($"Subject: {claims.Subject}");
    Console.WriteLine($"Issued At: {claims.IssuedAt}");
    
    foreach (var (key, value) in claims.AdditionalClaims)
    {
        Console.WriteLine($"{key}: {value}");
    }
}
```

## CWT Claims Properties

```csharp
public class CwtClaims
{
    public string? Issuer { get; set; }              // iss (1)
    public string? Subject { get; set; }             // sub (2)
    public string? Audience { get; set; }            // aud (3)
    public DateTimeOffset? ExpirationTime { get; set; } // exp (4)
    public DateTimeOffset? NotBefore { get; set; }   // nbf (5)
    public DateTimeOffset? IssuedAt { get; set; }    // iat (6)
    public byte[]? CwtId { get; set; }               // cti (7)
    
    public IDictionary<string, object> AdditionalClaims { get; }
}
```

## Subject Identifier Formats

### Package URL (purl)

```csharp
// npm package
string subject = "package:npm/express@4.18.2";

// Go package
string subject = "package:golang/github.com/gin-gonic/gin@v1.9.0";

// Maven package
string subject = "package:maven/org.springframework/spring-core@5.3.0";
```

### Container Images

```csharp
string subject = "image:docker.io/library/nginx@sha256:abc123...";
string subject = "image:mcr.microsoft.com/dotnet/runtime@sha256:def456...";
```

### Artifact by Hash

```csharp
byte[] hash = SHA256.HashData(payload);
string subject = $"artifact:sha256:{Convert.ToHexString(hash).ToLower()}";
```

### Git Commit

```csharp
string subject = "git:https://github.com/contoso/repo@a1b2c3d4";
```

## Supply Chain Attestation

```csharp
public class SupplyChainAttestationService
{
    private readonly ISigningService _signingService;
    
    public async Task<CoseSign1Message> AttestBuildAsync(
        byte[] artifact,
        BuildMetadata build)
    {
        var artifactHash = SHA256.HashData(artifact);
        var subject = $"artifact:sha256:{Convert.ToHexString(artifactHash).ToLower()}";
        
        var claims = new CwtClaims
        {
            Issuer = "https://build.contoso.com",
            Subject = subject,
            IssuedAt = DateTimeOffset.UtcNow
        };
        
        // Add build metadata
        claims.AdditionalClaims["build_id"] = build.Id;
        claims.AdditionalClaims["commit_sha"] = build.CommitSha;
        claims.AdditionalClaims["repository"] = build.Repository;
        claims.AdditionalClaims["branch"] = build.Branch;
        
        var contributor = new CwtClaimsHeaderContributor(claims);
        var factory = new DirectSignatureFactory(
            _signingService,
            headerContributors: new[] { contributor });
        
        return await factory.CreateAsync(artifact);
    }
}
```

## Claim Validation

```csharp
using CoseSign1.Validation;

public class CwtClaimsValidator : IValidator<CoseSign1Message>
{
    private readonly string[] _allowedIssuers;
    
    public ValidationResult Validate(
        CoseSign1Message message,
        ValidationOptions? options = null)
    {
        var claims = message.GetCwtClaims();
        if (claims == null)
        {
            return ValidationResult.Failed(
                new ValidationFailure
                {
                    Code = ValidationFailureCode.MissingRequiredHeader,
                    Message = "CWT claims are required"
                });
        }
        
        // Validate issuer
        if (!_allowedIssuers.Contains(claims.Issuer))
        {
            return ValidationResult.Failed(
                new ValidationFailure
                {
                    Code = ValidationFailureCode.CustomValidationFailed,
                    Message = $"Issuer '{claims.Issuer}' is not allowed"
                });
        }
        
        // Validate expiration
        if (claims.ExpirationTime < DateTimeOffset.UtcNow)
        {
            return ValidationResult.Failed(
                new ValidationFailure
                {
                    Code = ValidationFailureCode.CustomValidationFailed,
                    Message = "CWT claims have expired"
                });
        }
        
        return ValidationResult.Success(message);
    }
}
```

## Dynamic Claims

```csharp
public class DynamicCwtClaimsContributor : IHeaderContributor
{
    private readonly string _issuer;
    
    public Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken ct)
    {
        // Calculate subject from payload
        var payloadHash = SHA256.HashData(payload);
        var subject = $"artifact:sha256:{Convert.ToHexString(payloadHash).ToLower()}";
        
        var claims = new CwtClaims
        {
            Issuer = _issuer,
            Subject = subject,
            IssuedAt = DateTimeOffset.UtcNow,
            CwtId = Guid.NewGuid().ToByteArray()
        };
        
        // Add metadata from context
        if (context.Metadata.TryGetValue("BuildId", out var buildId))
        {
            claims.AdditionalClaims["build_id"] = buildId;
        }
        
        var contributor = new CwtClaimsHeaderContributor(claims);
        return contributor.ContributeAsync(
            protectedHeaders,
            unprotectedHeaders,
            payload,
            context,
            ct);
    }
}
```

## Header Label Constants

```csharp
using CoseSign1.Headers;

// Standard CWT claim labels
var issuer = CWTClaimsHeaderLabels.Issuer;      // 1
var subject = CWTClaimsHeaderLabels.Subject;    // 2
var audience = CWTClaimsHeaderLabels.Audience;  // 3
var expTime = CWTClaimsHeaderLabels.ExpirationTime; // 4
var notBefore = CWTClaimsHeaderLabels.NotBefore;    // 5
var issuedAt = CWTClaimsHeaderLabels.IssuedAt;      // 6
var cwtId = CWTClaimsHeaderLabels.CwtId;            // 7
```

## Extension Methods

```csharp
// CwtClaims to header map
CoseHeaderMap headers = claims.ToHeaderMap();

// Header map to CwtClaims
CwtClaims claims = CwtClaims.FromHeaderMap(message.ProtectedHeaders);

// Validate claims
bool isValid = claims.Validate(out var errors);

// Message extensions
CwtClaims? claims = message.GetCwtClaims();
bool hasClaims = message.HasCwtClaims();
```

## ASP.NET Core Integration

```csharp
// Startup
services.AddSingleton(new CwtClaimsTemplate
{
    IssuerTemplate = "https://{environment}.contoso.com",
    SubjectTemplate = "package:{ecosystem}/{name}@{version}",
    Lifetime = TimeSpan.FromDays(365)
});

// Controller
public class AttestationController : ControllerBase
{
    private readonly ISigningService _signingService;
    private readonly CwtClaimsTemplate _template;
    
    [HttpPost("attest")]
    public async Task<IActionResult> CreateAttestation(
        [FromBody] AttestationRequest request)
    {
        var claims = _template.CreateClaims(new Dictionary<string, object>
        {
            ["environment"] = "prod",
            ["ecosystem"] = "npm",
            ["name"] = request.PackageName,
            ["version"] = request.Version
        });
        
        var contributor = new CwtClaimsHeaderContributor(claims);
        var factory = new DirectSignatureFactory(
            _signingService,
            headerContributors: new[] { contributor });
        
        var message = await factory.CreateAsync(request.Payload);
        return File(message.Encode(), "application/cose");
    }
}
```

## When to Use

- ✅ Creating SCITT-compliant attestations
- ✅ Supply chain security and transparency
- ✅ Software artifact verification
- ✅ Build provenance attestations
- ✅ Package integrity verification
- ✅ Transparency log submissions

## Related Packages

- **CoseSign1** - Message creation
- **CoseSign1.Certificates** - Certificate-based signing
- **CoseSign1.Validation** - Claim validation
- **CoseSign1.Transparent.MST** - Transparency receipts

## Documentation

- 📖 [Full Package Documentation](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/packages/headers.md)
- 📖 [SCITT Compliance Guide](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/scitt-compliance.md)
- 📖 [Supply Chain Security](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/supply-chain.md)

## Support

- 🐛 [Report Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 Email: cosesigntool@microsoft.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

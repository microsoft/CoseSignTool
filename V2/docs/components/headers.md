# CoseSign1.Headers Package

**NuGet**: `CoseSign1.Headers`  
**Purpose**: SCITT-compliant CWT claims and header management  
**Dependencies**: CoseSign1.Abstractions

## Overview

This package provides support for CWT (CBOR Web Token) claims and header management for SCITT (Supply Chain Integrity, Transparency, and Trust) compliance. It enables creation and validation of SCITT-compliant COSE Sign1 messages.

## When to Use

- Creating SCITT-compliant signatures
- Adding CWT claims to COSE messages
- Implementing supply chain transparency
- Attesting to software artifacts
- Building transparency logs
- Compliance with SCITT specifications

## Core Components

### CwtClaims

Represents CBOR Web Token claims for SCITT compliance.

```csharp
public class CwtClaims
{
    /// <summary>
    /// Issuer: Entity that created and signed the token
    /// </summary>
    public string? Issuer { get; set; }
    
    /// <summary>
    /// Subject: Principal that is the subject of the token
    /// </summary>
    public string? Subject { get; set; }
    
    /// <summary>
    /// Audience: Recipients that the token is intended for
    /// </summary>
    public string? Audience { get; set; }
    
    /// <summary>
    /// Expiration Time: When the token expires
    /// </summary>
    public DateTimeOffset? ExpirationTime { get; set; }
    
    /// <summary>
    /// Not Before: Time before which the token is not valid
    /// </summary>
    public DateTimeOffset? NotBefore { get; set; }
    
    /// <summary>
    /// Issued At: Time when the token was issued
    /// </summary>
    public DateTimeOffset? IssuedAt { get; set; }
    
    /// <summary>
    /// CWT ID: Unique identifier for the token
    /// </summary>
    public byte[]? CwtId { get; set; }
    
    /// <summary>
    /// Custom claims with integer labels not in the standard set.
    /// The key is the claim label, and the value is the claim value.
    /// </summary>
    public Dictionary<int, object> CustomClaims { get; }
        = new Dictionary<int, object>();
}
```

**Basic Usage**:
```csharp
var claims = new CwtClaims
{
    Issuer = "https://contoso.com",
    Subject = "package:npm/my-package@1.0.0",
    Audience = "https://transparency.contoso.com",
    IssuedAt = DateTimeOffset.UtcNow,
    ExpirationTime = DateTimeOffset.UtcNow.AddDays(365)
};
```

**With Custom Claims**:
```csharp
var claims = new CwtClaims
{
    Issuer = "https://build-system.contoso.com",
    Subject = "artifact:sha256:abc123...",
    IssuedAt = DateTimeOffset.UtcNow
};

// Add custom claims (custom claim labels are integer keys)
claims.CustomClaims[1000] = "build-12345";
claims.CustomClaims[1001] = "a1b2c3d4";
claims.CustomClaims[1002] = "https://github.com/contoso/myrepo";
```

### CwtClaimsHeaderContributor

Header contributor that adds CWT claims to COSE messages.

```csharp
public class CwtClaimsHeaderContributor : IHeaderContributor
{
    public CwtClaimsHeaderContributor();
    public CwtClaimsHeaderContributor(CwtClaims claims);
}
```

**Usage with Factory**:
```csharp
var claims = new CwtClaims
{
    Issuer = "https://contoso.com",
    Subject = "package:npm/example@1.0.0",
    IssuedAt = DateTimeOffset.UtcNow
};

var contributor = new CwtClaimsHeaderContributor(claims);

var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors = [contributor]
};

var factory = new DirectSignatureFactory(signingService);
var message = await factory.CreateCoseSign1MessageAsync(
    payload,
    contentType: "application/octet-stream",
    options: options);
```

**Dynamic Claims**:
```csharp
public class DynamicCwtClaimsContributor : IHeaderContributor
{
    private readonly string _issuer;
    
    public DynamicCwtClaimsContributor(string issuer)
    {
        _issuer = issuer;
    }

    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Pick up dynamic values from per-operation context.
        // (For example, subject and build id can be passed via SigningOptions.AdditionalContext.)
        var additional = context.SigningContext.AdditionalContext;
        var subject = additional != null && additional.TryGetValue("Subject", out var subjectValue)
            ? subjectValue?.ToString() ?? "unknown"
            : "unknown";

        var cwtContributor = new CwtClaimsHeaderContributor()
            .SetIssuer(_issuer)
            .SetSubject(subject)
            .SetIssuedAt(DateTimeOffset.UtcNow);

        if (additional != null && additional.TryGetValue("BuildId", out var buildId))
        {
            // 1000 is an example custom claim label for "build_id".
            cwtContributor.SetCustomClaim(label: 1000, value: buildId);
        }

        cwtContributor.ContributeProtectedHeaders(headers, context);
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // No unprotected headers.
    }
}
```

### CWTClaimsHeaderLabels

Standard CWT claim header label constants.

```csharp
public static class CWTClaimsHeaderLabels
{
    public static readonly CoseHeaderLabel CWTClaims = new(15);

    public const int Issuer = 1;
    public const int Subject = 2;
    public const int Audience = 3;
    public const int ExpirationTime = 4;
    public const int NotBefore = 5;
    public const int IssuedAt = 6;
    public const int CwtId = 7;
}
```

**Usage**:
```csharp
// Reading claims from message
if (message.ProtectedHeaders.TryGetCwtClaims(out var claims) && claims != null)
{
    var issuer = claims.Issuer;
    var issuedAt = claims.IssuedAt;
}
```

## Extension Methods

### CwtClaims Extensions

```csharp
// Convert claims to header map
CoseHeaderMap headers = claims.ToHeaderMap();

// Create claims from header map
CwtClaims claims = CwtClaims.FromHeaderMap(message.ProtectedHeaders);

// Validate claims
bool isValid = claims.Validate(out var errors);
```

### CoseSign1Message Extensions

```csharp
// Extract CWT claims from message
CwtClaims? claims = message.GetCwtClaims();

// Check if message has CWT claims
bool hasClaims = message.HasCwtClaims();

// Validate CWT claims in message
bool isValid = message.ValidateCwtClaims(out var errors);
```

## SCITT Compliance

### SCITT Statement

Create SCITT-compliant statements:

```csharp
public class ScittStatementFactory
{
    private readonly ISigningService<SigningOptions> _signingService;
    private readonly string _issuer;
    
    public async Task<CoseSign1Message> CreateStatementAsync(
        ReadOnlyMemory<byte> payload,
        string subject,
        Dictionary<int, object>? additionalClaims = null)
    {
        var claims = new CwtClaims
        {
            Issuer = _issuer,
            Subject = subject,
            IssuedAt = DateTimeOffset.UtcNow,
            CwtId = Guid.NewGuid().ToByteArray()
        };
        
        if (additionalClaims != null)
        {
            foreach (var claim in additionalClaims)
            {
                claims.CustomClaims[claim.Key] = claim.Value;
            }
        }
        
        var contributor = new CwtClaimsHeaderContributor(claims);
        var factory = new DirectSignatureFactory(_signingService);

        var options = new DirectSignatureOptions
        {
            AdditionalHeaderContributors = [contributor]
        };

        return await factory.CreateCoseSign1MessageAsync(
            payload,
            contentType: "application/octet-stream",
            options: options);
    }
}

// Usage
var factory = new ScittStatementFactory(signingService, "https://contoso.com");

var statement = await factory.CreateStatementAsync(
    payload: artifactBytes,
    subject: "package:npm/my-package@1.0.0",
    additionalClaims: new Dictionary<int, object>
    {
        [1001] = "a1b2c3d4",
        [1003] = "release-pipeline"
    });
```

### Subject Identifiers

Use standard subject identifier formats:

```csharp
// Package URL (purl)
string purlSubject = "package:npm/express@4.18.2";
string goSubject = "package:golang/github.com/gin-gonic/gin@v1.9.0";

// Container image
string containerSubject = "image:docker.io/library/nginx@sha256:abc123...";

// Artifact by hash
byte[] hash = SHA256.HashData(payload);
string hashSubject = $"artifact:sha256:{Convert.ToHexString(hash).ToLower()}";

// Git commit
string gitSubject = "git:https://github.com/contoso/repo@a1b2c3d4";

// File path
string fileSubject = "file:///path/to/artifact.bin";

// Create claims
var claims = new CwtClaims
{
    Issuer = "https://build.contoso.com",
    Subject = purlSubject,
    IssuedAt = DateTimeOffset.UtcNow
};
```

## Advanced Scenarios

### Multi-Issuer Attestations

```csharp
public class MultiIssuerAttestationService
{
    private readonly Dictionary<string, ISigningService<SigningOptions>> _issuers;
    
    public async Task<CoseSign1Message[]> CreateAttestationsAsync(
        ReadOnlyMemory<byte> payload,
        string subject)
    {
        var attestations = new List<CoseSign1Message>();
        
        foreach (var (issuer, service) in _issuers)
        {
            var claims = new CwtClaims
            {
                Issuer = issuer,
                Subject = subject,
                IssuedAt = DateTimeOffset.UtcNow
            };
            
            var contributor = new CwtClaimsHeaderContributor(claims);

            var factory = new DirectSignatureFactory(service);
            var options = new DirectSignatureOptions
            {
                AdditionalHeaderContributors = [contributor]
            };

            var attestation = await factory.CreateCoseSign1MessageAsync(
                payload,
                contentType: "application/octet-stream",
                options: options);
            attestations.Add(attestation);
        }
        
        return attestations.ToArray();
    }
}
```

### Claim Validation

```csharp
public class CwtClaimsValidator : IValidator
{
    private readonly string[]? _allowedIssuers;
    private readonly bool _requireSubject;
    private readonly bool _checkExpiration;

    public IReadOnlyCollection<ValidationStage> Stages => new[] { ValidationStage.PostSignature };

    public CwtClaimsValidator(
        string[]? allowedIssuers = null,
        bool requireSubject = false,
        bool checkExpiration = true)
    {
        _allowedIssuers = allowedIssuers;
        _requireSubject = requireSubject;
        _checkExpiration = checkExpiration;
    }

    public ValidationResult Validate(CoseSign1Message message, ValidationStage stage)
    {
        if (stage != ValidationStage.PostSignature)
        {
            return ValidationResult.NotApplicable(nameof(CwtClaimsValidator), stage);
        }

        if (!message.ProtectedHeaders.TryGetCwtClaims(out var claims) || claims == null)
        {
            return ValidationResult.Failure(
                nameof(CwtClaimsValidator),
                stage,
                message: "CWT claims are required",
                errorCode: "CWT_CLAIMS_MISSING");
        }

        var failures = new List<ValidationFailure>();
        
        // Validate issuer
        if (_allowedIssuers != null && !_allowedIssuers.Contains(claims.Issuer))
        {
            failures.Add(new ValidationFailure
            {
                ErrorCode = "CWT_ISSUER_NOT_ALLOWED",
                Message = $"Issuer '{claims.Issuer}' is not allowed"
            });
        }
        
        // Validate subject
        if (_requireSubject && string.IsNullOrEmpty(claims.Subject))
        {
            failures.Add(new ValidationFailure
            {
                ErrorCode = "CWT_SUBJECT_REQUIRED",
                Message = "Subject claim is required"
            });
        }
        
        // Validate expiration
        if (_checkExpiration && claims.ExpirationTime.HasValue)
        {
            var validationTime = DateTimeOffset.UtcNow;
            if (claims.ExpirationTime.Value < validationTime)
            {
                failures.Add(new ValidationFailure
                {
                    ErrorCode = "CWT_EXPIRED",
                    Message = "CWT claims have expired"
                });
            }
        }
        
        // Validate not-before
        if (claims.NotBefore.HasValue)
        {
            var validationTime = DateTimeOffset.UtcNow;
            if (claims.NotBefore.Value > validationTime)
            {
                failures.Add(new ValidationFailure
                {
                    ErrorCode = "CWT_NOT_YET_VALID",
                    Message = "CWT claims not yet valid"
                });
            }
        }
        
        return failures.Count == 0
            ? ValidationResult.Success(nameof(CwtClaimsValidator), stage)
            : ValidationResult.Failure(nameof(CwtClaimsValidator), stage, failures.ToArray());
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(input, stage));
}

// Usage
var validator = new CompositeValidator(new IValidator[]
{
    new CwtClaimsValidator(
        allowedIssuers: ["https://contoso.com", "https://build.contoso.com"],
        requireSubject: true,
        checkExpiration: true)
});

ValidationResult result = validator.Validate(message, ValidationStage.PostSignature);
```

### Claim Templates

```csharp
public class CwtClaimsTemplate
{
    public string IssuerTemplate { get; set; } = "";
    public string SubjectTemplate { get; set; } = "";
    public TimeSpan? Lifetime { get; set; }
    public Dictionary<int, object> DefaultCustomClaims { get; set; } = new();
    
    public CwtClaims CreateClaims(Dictionary<string, object> variables)
    {
        var claims = new CwtClaims
        {
            Issuer = ReplaceVariables(IssuerTemplate, variables),
            Subject = ReplaceVariables(SubjectTemplate, variables),
            IssuedAt = DateTimeOffset.UtcNow
        };
        
        if (Lifetime.HasValue)
        {
            claims.ExpirationTime = DateTimeOffset.UtcNow.Add(Lifetime.Value);
        }
        
        foreach (var claim in DefaultCustomClaims)
        {
            claims.CustomClaims[claim.Key] = claim.Value;
        }
        
        return claims;
    }
    
    private string ReplaceVariables(string template, Dictionary<string, object> vars)
    {
        var result = template;
        foreach (var (key, value) in vars)
        {
            result = result.Replace($"{{{key}}}", value.ToString());
        }
        return result;
    }
}

// Usage
var template = new CwtClaimsTemplate
{
    IssuerTemplate = "https://{environment}.contoso.com",
    SubjectTemplate = "package:{ecosystem}/{name}@{version}",
    Lifetime = TimeSpan.FromDays(365),
    DefaultCustomClaims = { [1004] = "Contoso" }
};

var claims = template.CreateClaims(new Dictionary<string, object>
{
    ["environment"] = "prod",
    ["ecosystem"] = "npm",
    ["name"] = "my-package",
    ["version"] = "1.0.0"
});
// Results in:
// Issuer: https://prod.contoso.com
// Subject: package:npm/my-package@1.0.0
```

### Transparency Log Integration

```csharp
public class TransparencyLogHeaderContributor : IHeaderContributor
{
    private readonly string _logId;
    private readonly ITransparencyService _transparencyService;

    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        var additional = context.SigningContext.AdditionalContext;
        var issuer = additional != null && additional.TryGetValue("Issuer", out var issuerValue)
            ? issuerValue?.ToString()
            : null;
        var subject = additional != null && additional.TryGetValue("Subject", out var subjectValue)
            ? subjectValue?.ToString()
            : null;

        // Add standard CWT claims
        var cwtContributor = new CwtClaimsHeaderContributor();
        if (!string.IsNullOrWhiteSpace(issuer))
        {
            cwtContributor.SetIssuer(issuer);
        }

        if (!string.IsNullOrWhiteSpace(subject))
        {
            cwtContributor.SetSubject(subject);
        }

        cwtContributor.SetIssuedAt(DateTimeOffset.UtcNow);
        cwtContributor.ContributeProtectedHeaders(headers, context);

        // Add transparency log identifier
        headers.Add(new CoseHeaderLabel("log_id"), _logId);

        // Add feed identifier if present
        if (additional != null && additional.TryGetValue("FeedId", out var feedId) && feedId != null)
        {
            headers.Add(new CoseHeaderLabel("feed"), feedId);
        }
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // No unprotected headers.
    }
}
```

## Integration Patterns

### ASP.NET Core

```csharp
// Startup
services.AddSingleton<CwtClaimsTemplate>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    return new CwtClaimsTemplate
    {
        IssuerTemplate = config["Scitt:IssuerTemplate"]!,
        SubjectTemplate = config["Scitt:SubjectTemplate"]!,
        Lifetime = TimeSpan.Parse(config["Scitt:Lifetime"]!)
    };
});

// Controller
public class AttestationController : ControllerBase
{
    private readonly ISigningService<SigningOptions> _signingService;
    private readonly CwtClaimsTemplate _template;
    
    [HttpPost("attest")]
    public async Task<IActionResult> CreateAttestation(
        [FromBody] AttestationRequest request)
    {
        var claims = _template.CreateClaims(new Dictionary<string, object>
        {
            ["name"] = request.PackageName,
            ["version"] = request.Version,
            ["ecosystem"] = "npm"
        });
        
        var contributor = new CwtClaimsHeaderContributor(claims);

        var factory = new DirectSignatureFactory(_signingService);
        var options = new DirectSignatureOptions
        {
            AdditionalHeaderContributors = [contributor]
        };

        var message = await factory.CreateCoseSign1MessageAsync(
            request.Payload,
            contentType: "application/octet-stream",
            options: options);
        
        return File(message.Encode(), "application/cose");
    }
}
```

### Supply Chain Attestation

```csharp
public class SupplyChainAttestationService
{
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

        // Custom claims use integer labels; choose a private range for your application.
        claims.CustomClaims[1000] = build.Id;
        claims.CustomClaims[1001] = build.CommitSha;
        claims.CustomClaims[1002] = build.Repository;
        claims.CustomClaims[1003] = build.Branch;
        claims.CustomClaims[1005] = build.Timestamp.ToUnixTimeSeconds();
        
        var contributor = new CwtClaimsHeaderContributor(claims);

        var factory = new DirectSignatureFactory(_signingService);
        var options = new DirectSignatureOptions
        {
            AdditionalHeaderContributors = [contributor]
        };

        return await factory.CreateCoseSign1MessageAsync(
            artifact,
            contentType: "application/octet-stream",
            options: options);
    }
}
```

## Best Practices

1. **Always Include Issuer**: Required for SCITT compliance
2. **Use Standard Subject Formats**: Package URLs, container images, etc.
3. **Include Timestamps**: Add IssuedAt for auditability
4. **Validate Claims**: Always validate claims on receipt
5. **Use Unique IDs**: Include CwtId for tracking
6. **Consider Expiration**: Set appropriate lifetime for claims
7. **Document Custom Claims**: Clearly document additional claims

## See Also

- [Abstractions Package](abstractions.md)
- [CoseSign1 Package](cosesign1.md)
- [SCITT Compliance Guide](../guides/scitt-compliance.md)
- [Transparency Overview](transparent.md)

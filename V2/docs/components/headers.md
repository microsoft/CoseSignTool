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
    /// Additional custom claims
    /// </summary>
    public IDictionary<string, object> AdditionalClaims { get; }
        = new Dictionary<string, object>();
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

// Add custom claims
claims.AdditionalClaims["build_id"] = "build-12345";
claims.AdditionalClaims["commit_sha"] = "a1b2c3d4";
claims.AdditionalClaims["repo"] = "https://github.com/contoso/myrepo";
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

var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: new[] { contributor });

var message = await factory.CreateAsync(payload);
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
    
    public Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken ct)
    {
        // Calculate subject from payload
        var payloadHash = SHA256.HashData(payload);
        var subject = $"artifact:sha256:{Convert.ToHexString(payloadHash)}";
        
        var claims = new CwtClaims
        {
            Issuer = _issuer,
            Subject = subject,
            IssuedAt = DateTimeOffset.UtcNow,
            CwtId = Guid.NewGuid().ToByteArray()
        };
        
        // Add to context if needed
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

### CWTClaimsHeaderLabels

Standard CWT claim header label constants.

```csharp
public static class CWTClaimsHeaderLabels
{
    public static readonly CoseHeaderLabel Issuer = new(1);
    public static readonly CoseHeaderLabel Subject = new(2);
    public static readonly CoseHeaderLabel Audience = new(3);
    public static readonly CoseHeaderLabel ExpirationTime = new(4);
    public static readonly CoseHeaderLabel NotBefore = new(5);
    public static readonly CoseHeaderLabel IssuedAt = new(6);
    public static readonly CoseHeaderLabel CwtId = new(7);
}
```

**Usage**:
```csharp
// Reading claims from message
var issuer = message.ProtectedHeaders.GetValueOrDefault<string>(
    CWTClaimsHeaderLabels.Issuer);

var issuedAt = message.ProtectedHeaders.GetValueOrDefault<long>(
    CWTClaimsHeaderLabels.IssuedAt);

var timestamp = DateTimeOffset.FromUnixTimeSeconds(issuedAt);
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
    private readonly ISigningService _signingService;
    private readonly string _issuer;
    
    public async Task<CoseSign1Message> CreateStatementAsync(
        byte[] payload,
        string subject,
        Dictionary<string, object>? additionalClaims = null)
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
                claims.AdditionalClaims[claim.Key] = claim.Value;
            }
        }
        
        var contributor = new CwtClaimsHeaderContributor(claims);
        var factory = new DirectSignatureFactory(
            _signingService,
            headerContributors: new[] { contributor });
        
        return await factory.CreateAsync(payload);
    }
}

// Usage
var factory = new ScittStatementFactory(signingService, "https://contoso.com");

var statement = await factory.CreateStatementAsync(
    payload: artifactBytes,
    subject: "package:npm/my-package@1.0.0",
    additionalClaims: new Dictionary<string, object>
    {
        ["commit"] = "a1b2c3d4",
        ["pipeline"] = "release-pipeline"
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
    private readonly Dictionary<string, ISigningService> _issuers;
    
    public async Task<CoseSign1Message[]> CreateAttestationsAsync(
        byte[] payload,
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
            var factory = new DirectSignatureFactory(
                service,
                headerContributors: new[] { contributor });
            
            var attestation = await factory.CreateAsync(payload);
            attestations.Add(attestation);
        }
        
        return attestations.ToArray();
    }
}
```

### Claim Validation

```csharp
public class CwtClaimsValidator : IValidator<CoseSign1Message>
{
    private readonly string[]? _allowedIssuers;
    private readonly bool _requireSubject;
    private readonly bool _checkExpiration;
    
    public ValidationResult Validate(
        CoseSign1Message message, 
        ValidationOptions? options = null)
    {
        var failures = new List<ValidationFailure>();
        var claims = message.GetCwtClaims();
        
        if (claims == null)
        {
            failures.Add(new ValidationFailure
            {
                Code = ValidationFailureCode.MissingRequiredHeader,
                Message = "CWT claims are required"
            });
            return ValidationResult.Failed(failures, message);
        }
        
        // Validate issuer
        if (_allowedIssuers != null && !_allowedIssuers.Contains(claims.Issuer))
        {
            failures.Add(new ValidationFailure
            {
                Code = ValidationFailureCode.CustomValidationFailed,
                Message = $"Issuer '{claims.Issuer}' is not allowed"
            });
        }
        
        // Validate subject
        if (_requireSubject && string.IsNullOrEmpty(claims.Subject))
        {
            failures.Add(new ValidationFailure
            {
                Code = ValidationFailureCode.MissingRequiredHeader,
                Message = "Subject claim is required"
            });
        }
        
        // Validate expiration
        if (_checkExpiration && claims.ExpirationTime.HasValue)
        {
            var validationTime = options?.ValidationTime ?? DateTimeOffset.UtcNow;
            if (claims.ExpirationTime.Value < validationTime)
            {
                failures.Add(new ValidationFailure
                {
                    Code = ValidationFailureCode.CustomValidationFailed,
                    Message = "CWT claims have expired"
                });
            }
        }
        
        // Validate not-before
        if (claims.NotBefore.HasValue)
        {
            var validationTime = options?.ValidationTime ?? DateTimeOffset.UtcNow;
            if (claims.NotBefore.Value > validationTime)
            {
                failures.Add(new ValidationFailure
                {
                    Code = ValidationFailureCode.CustomValidationFailed,
                    Message = "CWT claims not yet valid"
                });
            }
        }
        
        return failures.Count == 0
            ? ValidationResult.Success(message)
            : ValidationResult.Failed(failures, message);
    }
}

// Usage
var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .AddValidator(new CwtClaimsValidator
    {
        AllowedIssuers = new[] { "https://contoso.com", "https://build.contoso.com" },
        RequireSubject = true,
        CheckExpiration = true
    })
    .Build();
```

### Claim Templates

```csharp
public class CwtClaimsTemplate
{
    public string IssuerTemplate { get; set; } = "";
    public string SubjectTemplate { get; set; } = "";
    public TimeSpan? Lifetime { get; set; }
    public Dictionary<string, object> DefaultClaims { get; set; } = new();
    
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
        
        foreach (var claim in DefaultClaims)
        {
            claims.AdditionalClaims[claim.Key] = claim.Value;
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
    DefaultClaims = { ["organization"] = "Contoso" }
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
    
    public async Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken ct)
    {
        // Add standard CWT claims
        var claims = new CwtClaims
        {
            Issuer = context.Metadata["Issuer"]?.ToString(),
            Subject = context.Metadata["Subject"]?.ToString(),
            IssuedAt = DateTimeOffset.UtcNow
        };
        
        var cwtContributor = new CwtClaimsHeaderContributor(claims);
        await cwtContributor.ContributeAsync(
            protectedHeaders, 
            unprotectedHeaders, 
            payload, 
            context, 
            ct);
        
        // Add transparency log identifier
        protectedHeaders.SetValue(
            new CoseHeaderLabel("log_id"),
            new CoseHeaderValue(_logId));
        
        // Add feed identifier if present
        if (context.Metadata.TryGetValue("FeedId", out var feedId))
        {
            protectedHeaders.SetValue(
                new CoseHeaderLabel("feed"),
                new CoseHeaderValue(feedId!));
        }
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
    private readonly ISigningService _signingService;
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
        var factory = new DirectSignatureFactory(
            _signingService,
            headerContributors: new[] { contributor });
        
        var message = await factory.CreateAsync(request.Payload);
        
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
        
        claims.AdditionalClaims["build_id"] = build.Id;
        claims.AdditionalClaims["commit_sha"] = build.CommitSha;
        claims.AdditionalClaims["repository"] = build.Repository;
        claims.AdditionalClaims["branch"] = build.Branch;
        claims.AdditionalClaims["build_time"] = build.Timestamp.ToUnixTimeSeconds();
        
        var contributor = new CwtClaimsHeaderContributor(claims);
        var factory = new DirectSignatureFactory(
            _signingService,
            headerContributors: new[] { contributor });
        
        return await factory.CreateAsync(artifact);
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
- [Transparency Guide](../guides/transparency.md)

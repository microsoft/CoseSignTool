# DIDx509 Package

**NuGet**: `DIDx509`  
**Purpose**: Decentralized Identifier (DID) support for X.509 certificates  
**Dependencies**: CoseSign1.Abstractions

## Overview

This package implements the DID:x509 method, enabling X.509 certificates to be used as decentralized identifiers. It provides parsing, resolution, and validation of DID:x509 URIs and their associated X.509 certificate chains.

## When to Use

- Converting X.509 certificate chains to DIDs
- Resolving DID:x509 URIs to certificates
- Decentralized identity scenarios
- Verifiable credentials with X.509
- Self-sovereign identity (SSI) systems
- Web3 integration with PKI

## Core Concepts

### What is DID:x509?

DID:x509 is a DID method that encodes X.509 certificate chains into DID URIs, enabling:
- **Decentralization**: No central registry required
- **Portability**: DIDs can be shared and resolved independently
- **PKI Integration**: Leverages existing X.509 infrastructure
- **Verifiability**: Cryptographic verification of identity

### DID:x509 URI Format

```
did:x509:<policy>:<certificate-chain>
```

**Components**:
- `did:x509`: Method identifier
- `policy`: Trust policy (e.g., `0` for none, `1` for standard validation)
- `certificate-chain`: Base64-encoded certificate chain

**Example**:
```
did:x509:0:MIICljCCAX4CCQDNn6...AwIBAgIQXa9r...
```

## Core Components

### DidX509Parser

Parses DID:x509 URIs into structured data.

```csharp
public class DidX509Parser
{
    public static DidX509Identifier Parse(string didUri);
    public static bool TryParse(string didUri, out DidX509Identifier? identifier);
}
```

**Usage**:
```csharp
// Parse DID URI
string didUri = "did:x509:0:MIICljCCAX4CCQDNn6...";
var did = DidX509Parser.Parse(didUri);

Console.WriteLine($"Method: {did.Method}"); // "x509"
Console.WriteLine($"Policy: {did.Policy}");
var certificates = did.GetCertificateChain();

// Safe parsing
if (DidX509Parser.TryParse(didUri, out var identifier))
{
    // Use identifier
}
else
{
    Console.WriteLine("Invalid DID URI");
}
```

### DidX509Identifier

Represents a parsed DID:x509 identifier.

```csharp
public class DidX509Identifier
{
    public string Method { get; }
    public string Policy { get; }
    public string EncodedCertificateChain { get; }
    
    public X509Certificate2[] GetCertificateChain();
    public X509Certificate2 GetLeafCertificate();
    public string ToUri();
}
```

**Usage**:
```csharp
var did = DidX509Parser.Parse(didUri);

// Get certificates
X509Certificate2[] chain = did.GetCertificateChain();
X509Certificate2 leaf = did.GetLeafCertificate();

// Convert back to URI
string uri = did.ToUri();

// Access encoded chain
string encoded = did.EncodedCertificateChain;
```

### DidX509Builder

Creates DID:x509 identifiers from certificate chains.

```csharp
public class DidX509Builder
{
    public DidX509Builder WithPolicy(string policy);
    public DidX509Builder WithCertificateChain(params X509Certificate2[] chain);
    public DidX509Builder WithCertificateChain(IEnumerable<X509Certificate2> chain);
    public DidX509Identifier Build();
}
```

**Usage**:
```csharp
// From certificate chain
using var leaf = new X509Certificate2("cert.pfx", "password");
using var intermediate = new X509Certificate2("intermediate.cer");
using var root = new X509Certificate2("root.cer");

var did = new DidX509Builder()
    .WithPolicy("0")
    .WithCertificateChain(leaf, intermediate, root)
    .Build();

string didUri = did.ToUri();
Console.WriteLine(didUri);
// Output: did:x509:0:MIICljCCAX4CCQDNn6...
```

**From Single Certificate**:
```csharp
var did = new DidX509Builder()
    .WithPolicy("0")
    .WithCertificateChain(certificate)
    .Build();
```

**With Custom Policy**:
```csharp
// Policy 0: No validation
var noValidation = new DidX509Builder()
    .WithPolicy("0")
    .WithCertificateChain(chain)
    .Build();

// Policy 1: Standard X.509 validation
var standardValidation = new DidX509Builder()
    .WithPolicy("1")
    .WithCertificateChain(chain)
    .Build();
```

### DidX509Resolver

Resolves DID:x509 URIs to certificate chains and validates them.

```csharp
public class DidX509Resolver
{
    public DidX509Resolver(X509ChainPolicy? chainPolicy = null);
    
    public ResolutionResult Resolve(string didUri);
    public ResolutionResult Resolve(DidX509Identifier identifier);
}

public class ResolutionResult
{
    public bool Success { get; }
    public X509Certificate2? Certificate { get; }
    public X509Certificate2[]? CertificateChain { get; }
    public string? ErrorMessage { get; }
    public X509ChainStatus[]? ChainStatus { get; }
}
```

**Basic Usage**:
```csharp
var resolver = new DidX509Resolver();
var result = resolver.Resolve(didUri);

if (result.Success)
{
    Console.WriteLine("DID resolved successfully");
    var cert = result.Certificate;
    var chain = result.CertificateChain;
}
else
{
    Console.WriteLine($"Resolution failed: {result.ErrorMessage}");
}
```

**With Custom Chain Policy**:
```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.EntireChain,
    VerificationFlags = X509VerificationFlags.NoFlag
};

var resolver = new DidX509Resolver(policy);
var result = resolver.Resolve(didUri);

if (!result.Success && result.ChainStatus != null)
{
    foreach (var status in result.ChainStatus)
    {
        Console.WriteLine($"Chain error: {status.Status} - {status.StatusInformation}");
    }
}
```

### DidX509Validator

Validates DID:x509 identifiers and their certificate chains.

```csharp
public class DidX509Validator : IValidator<DidX509Identifier>
{
    public DidX509Validator(
        X509ChainPolicy? chainPolicy = null,
        IEnumerable<X509Certificate2>? trustedRoots = null);
    
    public ValidationResult Validate(
        DidX509Identifier identifier,
        ValidationOptions? options = null);
}
```

**Usage**:
```csharp
var validator = new DidX509Validator();
var did = DidX509Parser.Parse(didUri);

var result = validator.Validate(did);

if (!result.Success)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"{failure.Code}: {failure.Message}");
    }
}
```

**With Trust Anchors**:
```csharp
var trustedRoots = new[]
{
    new X509Certificate2("trusted-root-1.cer"),
    new X509Certificate2("trusted-root-2.cer")
};

var validator = new DidX509Validator(
    chainPolicy: null,
    trustedRoots: trustedRoots);

var result = validator.Validate(did);
```

## Extension Methods

### X509Certificate2 Extensions

```csharp
// Create DID from certificate
using var cert = new X509Certificate2("cert.pfx", "password");
string didUri = cert.ToDid(policy: "0");

// Create DID from certificate chain
var chain = new[] { leaf, intermediate, root };
string didUri = chain.ToDidX509(policy: "1");
```

### CoseSign1Message Extensions

```csharp
// Add DID to message headers
message.AddDidX509(didIdentifier);

// Extract DID from message
DidX509Identifier? did = message.GetDidX509();

// Check if message has DID
bool hasDid = message.HasDidX509();
```

## Advanced Scenarios

### COSE Sign1 Integration

Create signatures with DID:x509 identifiers:

```csharp
public class DidX509SigningService
{
    private readonly ISigningService _signingService;
    private readonly X509Certificate2 _certificate;
    
    public async Task<CoseSign1Message> SignWithDidAsync(byte[] payload)
    {
        // Create DID from certificate
        var did = new DidX509Builder()
            .WithPolicy("0")
            .WithCertificateChain(_certificate)
            .Build();
        
        // Create header contributor that adds DID
        var contributor = new DidX509HeaderContributor(did);
        
        // Create signature
        var factory = new DirectSignatureFactory(
            _signingService,
            headerContributors: new[] { contributor });
        
        return await factory.CreateAsync(payload);
    }
}

public class DidX509HeaderContributor : IHeaderContributor
{
    private readonly DidX509Identifier _did;
    
    public DidX509HeaderContributor(DidX509Identifier did)
    {
        _did = did;
    }
    
    public Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken ct)
    {
        protectedHeaders.SetValue(
            new CoseHeaderLabel("did"),
            new CoseHeaderValue(_did.ToUri()));
        
        return Task.CompletedTask;
    }
}
```

### DID Resolution Service

Build a DID resolution service:

```csharp
public class DidResolutionService
{
    private readonly DidX509Resolver _resolver;
    private readonly IMemoryCache _cache;
    
    public DidResolutionService(X509ChainPolicy? policy = null)
    {
        _resolver = new DidX509Resolver(policy);
        _cache = new MemoryCache(new MemoryCacheOptions());
    }
    
    public async Task<ResolutionResult> ResolveAsync(string didUri)
    {
        // Check cache
        if (_cache.TryGetValue(didUri, out ResolutionResult? cached))
        {
            return cached!;
        }
        
        // Resolve
        var result = await Task.Run(() => _resolver.Resolve(didUri));
        
        // Cache successful resolutions
        if (result.Success)
        {
            _cache.Set(didUri, result, TimeSpan.FromMinutes(10));
        }
        
        return result;
    }
    
    public async Task<X509Certificate2?> ResolveToCertificateAsync(string didUri)
    {
        var result = await ResolveAsync(didUri);
        return result.Success ? result.Certificate : null;
    }
}
```

### DID Document Creation

Generate DID documents from X.509 certificates:

```csharp
public class DidDocumentBuilder
{
    public static string CreateDidDocument(DidX509Identifier did)
    {
        var cert = did.GetLeafCertificate();
        var publicKey = cert.GetECDsaPublicKey();
        
        var document = new
        {
            context = new[] { "https://www.w3.org/ns/did/v1" },
            id = did.ToUri(),
            verificationMethod = new[]
            {
                new
                {
                    id = $"{did.ToUri()}#key-1",
                    type = "JsonWebKey2020",
                    controller = did.ToUri(),
                    publicKeyJwk = new
                    {
                        kty = "EC",
                        crv = "P-256",
                        x = Convert.ToBase64String(publicKey!.ExportSubjectPublicKeyInfo())
                    }
                }
            },
            authentication = new[] { $"{did.ToUri()}#key-1" },
            assertionMethod = new[] { $"{did.ToUri()}#key-1" }
        };
        
        return JsonSerializer.Serialize(document, new JsonSerializerOptions
        {
            WriteIndented = true
        });
    }
}

// Usage
var did = DidX509Parser.Parse(didUri);
string didDocument = DidDocumentBuilder.CreateDidDocument(did);
Console.WriteLine(didDocument);
```

### Multi-DID Verification

Verify messages with multiple DIDs:

```csharp
public class MultiDidVerifier
{
    private readonly DidX509Resolver _resolver;
    
    public ValidationResult VerifyWithMultipleDids(
        CoseSign1Message message,
        string[] requiredDids)
    {
        var failures = new List<ValidationFailure>();
        
        // Extract DID from message
        var messageDid = message.GetDidX509();
        if (messageDid == null)
        {
            failures.Add(new ValidationFailure
            {
                Code = ValidationFailureCode.MissingRequiredHeader,
                Message = "Message does not contain DID:x509 identifier"
            });
            return ValidationResult.Failed(failures, message);
        }
        
        // Check if message DID is in required list
        var messageDidUri = messageDid.ToUri();
        if (!requiredDids.Contains(messageDidUri))
        {
            failures.Add(new ValidationFailure
            {
                Code = ValidationFailureCode.CustomValidationFailed,
                Message = $"DID {messageDidUri} is not in allowed list"
            });
        }
        
        // Resolve and validate DID
        var resolution = _resolver.Resolve(messageDid);
        if (!resolution.Success)
        {
            failures.Add(new ValidationFailure
            {
                Code = ValidationFailureCode.ChainValidationFailed,
                Message = $"DID resolution failed: {resolution.ErrorMessage}"
            });
        }
        
        return failures.Count == 0
            ? ValidationResult.Success(message)
            : ValidationResult.Failed(failures, message);
    }
}
```

### DID Rotation

Handle DID rotation scenarios:

```csharp
public class DidRotationService
{
    private readonly Dictionary<string, string> _didMapping = new();
    
    public void RegisterRotation(string oldDid, string newDid)
    {
        _didMapping[oldDid] = newDid;
    }
    
    public string? GetCurrentDid(string did)
    {
        // Follow rotation chain
        var current = did;
        var visited = new HashSet<string>();
        
        while (_didMapping.TryGetValue(current, out var next))
        {
            if (!visited.Add(current))
            {
                // Circular reference
                return null;
            }
            current = next;
        }
        
        return current;
    }
    
    public bool ValidateWithRotation(
        CoseSign1Message message,
        string expectedDid)
    {
        var messageDid = message.GetDidX509()?.ToUri();
        if (messageDid == null) return false;
        
        var currentDid = GetCurrentDid(expectedDid);
        return messageDid == currentDid || messageDid == expectedDid;
    }
}
```

## Integration Patterns

### ASP.NET Core

```csharp
// Startup
services.AddSingleton<DidX509Resolver>();
services.AddSingleton<DidResolutionService>();

// Controller
public class DidController : ControllerBase
{
    private readonly DidResolutionService _resolutionService;
    
    [HttpGet("resolve/{*did}")]
    public async Task<IActionResult> Resolve(string did)
    {
        var result = await _resolutionService.ResolveAsync(did);
        
        if (!result.Success)
        {
            return NotFound(new { error = result.ErrorMessage });
        }
        
        return Ok(new
        {
            did,
            certificate = Convert.ToBase64String(result.Certificate!.Export(X509ContentType.Cert)),
            chain = result.CertificateChain?.Select(c =>
                Convert.ToBase64String(c.Export(X509ContentType.Cert)))
        });
    }
    
    [HttpPost("create")]
    public IActionResult CreateDid([FromBody] CreateDidRequest request)
    {
        var cert = new X509Certificate2(
            Convert.FromBase64String(request.Certificate));
        
        var did = new DidX509Builder()
            .WithPolicy(request.Policy ?? "0")
            .WithCertificateChain(cert)
            .Build();
        
        return Ok(new { did = did.ToUri() });
    }
}
```

## Best Practices

1. **Cache Resolutions**: DID resolution can be expensive
2. **Validate Chains**: Always validate certificate chains
3. **Use Appropriate Policy**: Choose policy based on trust requirements
4. **Handle Expiration**: Check certificate expiration during resolution
5. **Secure Storage**: Protect DID private keys appropriately
6. **Document Mappings**: Maintain clear DID-to-entity mappings
7. **Plan for Rotation**: Implement DID rotation strategy

## Common Patterns

### Pattern: DID from Certificate File
```csharp
using var cert = new X509Certificate2("cert.pfx", "password");
string did = cert.ToDid("0");
```

### Pattern: Resolve and Validate
```csharp
var resolver = new DidX509Resolver();
var result = resolver.Resolve(didUri);
if (result.Success)
{
    // Use result.Certificate
}
```

### Pattern: Sign with DID
```csharp
var did = new DidX509Builder()
    .WithCertificateChain(cert)
    .Build();
var contributor = new DidX509HeaderContributor(did);
var factory = new DirectSignatureFactory(service, new[] { contributor });
```

## See Also

- [Certificates Package](certificates.md)
- [Validation Package](validation.md)
- [DID Core Specification](https://www.w3.org/TR/did-core/)
- [DID:x509 Method Specification](https://github.com/microsoft/did-x509)

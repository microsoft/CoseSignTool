# DIDx509

Decentralized Identifier (DID) support for X.509 certificates using the DID:x509 method.

## Overview

Implements the DID:x509 method for representing X.509 certificate chains as decentralized identifiers. Enables PKI integration with decentralized identity systems and Web3 applications.

## Installation

```bash
dotnet add package DIDx509 --version 2.0.0-preview
```

## Key Features

- ✅ **DID:x509 Parsing** - Parse DID:x509 URIs to certificate chains
- ✅ **DID Creation** - Create DIDs from X.509 certificates
- ✅ **DID Resolution** - Resolve DIDs to certificates with validation
- ✅ **Chain Validation** - Full X.509 chain validation
- ✅ **COSE Integration** - Use DIDs in COSE Sign1 messages
- ✅ **DID Documents** - Generate DID documents from certificates

## Quick Start

### Create DID from Certificate

```csharp
using DIDx509;

using var cert = new X509Certificate2("cert.pfx", "password");

var did = new DidX509Builder()
    .WithPolicy("0")
    .WithCertificateChain(cert)
    .Build();

string didUri = did.ToUri();
Console.WriteLine(didUri);
// Output: did:x509:0:MIICljCCAX4CCQDNn6...
```

### Parse DID URI

```csharp
string didUri = "did:x509:0:MIICljCCAX4CCQDNn6...";
var did = DidX509Parser.Parse(didUri);

Console.WriteLine($"Method: {did.Method}"); // "x509"
Console.WriteLine($"Policy: {did.Policy}"); // "0"

X509Certificate2[] chain = did.GetCertificateChain();
X509Certificate2 leaf = did.GetLeafCertificate();
```

### Resolve and Validate DID

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

## DID:x509 Format

```
did:x509:<policy>:<certificate-chain>
```

**Components:**
- `did:x509` - Method identifier
- `policy` - Trust policy (`0` = no validation, `1` = standard X.509)
- `certificate-chain` - Base64-encoded certificate chain

## Creating DIDs

### From Single Certificate

```csharp
var did = new DidX509Builder()
    .WithPolicy("0")
    .WithCertificateChain(certificate)
    .Build();
```

### From Full Chain

```csharp
using var leaf = new X509Certificate2("cert.pfx", "password");
using var intermediate = new X509Certificate2("intermediate.cer");
using var root = new X509Certificate2("root.cer");

var did = new DidX509Builder()
    .WithPolicy("1")  // Standard X.509 validation
    .WithCertificateChain(leaf, intermediate, root)
    .Build();
```

### Using Extension Method

```csharp
using var cert = new X509Certificate2("cert.pfx", "password");
string didUri = cert.ToDid(policy: "0");
```

## DID Resolution

### Basic Resolution

```csharp
var resolver = new DidX509Resolver();
var result = resolver.Resolve(didUri);

if (result.Success)
{
    // Use result.Certificate and result.CertificateChain
}
```

### With Custom Chain Policy

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
        Console.WriteLine($"Chain error: {status.Status}");
    }
}
```

## DID Validation

```csharp
using CoseSign1.Validation;

var trustedRoots = new[]
{
    new X509Certificate2("trusted-root-1.cer"),
    new X509Certificate2("trusted-root-2.cer")
};

var validator = new DidX509Validator(
    chainPolicy: null,
    trustedRoots: trustedRoots);

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

## COSE Sign1 Integration

### Sign with DID

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
        
        // Add DID to headers
        var contributor = new DidX509HeaderContributor(did);
        
        var factory = new DirectSignatureFactory(
            _signingService,
            headerContributors: new[] { contributor });
        
        return await factory.CreateAsync(payload);
    }
}
```

### Verify with DID

```csharp
// Extract DID from message
DidX509Identifier? did = message.GetDidX509();

if (did != null)
{
    var resolver = new DidX509Resolver();
    var result = resolver.Resolve(did);
    
    if (result.Success)
    {
        // Verify signature with resolved certificate
        var cert = result.Certificate;
        // ... verification logic
    }
}
```

## DID Documents

Generate W3C DID documents:

```csharp
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
```

## DID Resolution Service

Build a caching resolution service:

```csharp
public class DidResolutionService
{
    private readonly DidX509Resolver _resolver;
    private readonly IMemoryCache _cache;
    
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
}
```

## ASP.NET Core Integration

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
            certificate = Convert.ToBase64String(
                result.Certificate!.Export(X509ContentType.Cert))
        });
    }
}
```

## Extension Methods

```csharp
// Certificate to DID
string didUri = cert.ToDid("0");

// Certificate chain to DID
var chain = new[] { leaf, intermediate, root };
string didUri = chain.ToDidX509("1");

// Message extensions
message.AddDidX509(didIdentifier);
DidX509Identifier? did = message.GetDidX509();
bool hasDid = message.HasDidX509();
```

## Policy Modes

| Policy | Description | Validation |
|--------|-------------|------------|
| `0` | No validation | Parse only, no chain validation |
| `1` | Standard X.509 | Full chain validation with system roots |

## When to Use

- ✅ Decentralized identity scenarios
- ✅ Self-sovereign identity (SSI) systems
- ✅ Web3 integration with PKI
- ✅ Verifiable credentials with X.509
- ✅ DID-based authentication
- ✅ Certificate portability

## Related Packages

- **CoseSign1.Certificates** - X.509 certificate support
- **CoseSign1.Validation** - Validation framework
- **CoseSign1** - Message creation

## Documentation

- 📖 [Full Package Documentation](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/packages/didx509.md)
- 📖 [DID Core Specification](https://www.w3.org/TR/did-core/)
- 📖 [DID:x509 Method Spec](https://github.com/microsoft/did-x509)

## Support

- 🐛 [Report Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 Email: cosesigntool@microsoft.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

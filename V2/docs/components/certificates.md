# CoseSign1.Certificates Package

**NuGet**: `CoseSign1.Certificates`  
**Purpose**: Certificate-based signing and validation  
**Dependencies**: CoseSign1.Abstractions, CoseSign1, CoseSign1.Validation

## Overview

This package provides comprehensive support for X.509 certificate-based COSE signing operations. It includes local and remote signing services, certificate chain management, certificate validation, and X.509-specific extensions.

## When to Use

- Signing with X.509 certificates
- Certificate chain validation
- PKI-based trust models
- Enterprise certificate management
- Certificate-based authentication
- Code signing scenarios

## Core Components

### LocalCertificateSigningService

Signs data using a local X.509 certificate with private key.

```csharp
public class LocalCertificateSigningService : ISigningService
{
    public LocalCertificateSigningService(
        X509Certificate2 certificate,
        CertificateSigningOptions? options = null);
}
```

**Basic Usage**:
```csharp
// From file
using var cert = new X509Certificate2("cert.pfx", "password");
using var service = new LocalCertificateSigningService(cert);

byte[] signature = await service.SignAsync(data);
```

**From Certificate Store**:
```csharp
using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
store.Open(OpenFlags.ReadOnly);

var cert = store.Certificates
    .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
    .FirstOrDefault();

using var service = new LocalCertificateSigningService(cert!);
```

**With Options**:
```csharp
var options = new CertificateSigningOptions
{
    IncludeCertificateChain = true,
    ChainBuildingOptions = new X509ChainPolicy
    {
        RevocationMode = X509RevocationMode.Online,
        VerificationFlags = X509VerificationFlags.NoFlag
    }
};

using var service = new LocalCertificateSigningService(cert, options);
```

### RemoteCertificateSigningService

Abstract base for remote signing services (Azure Key Vault, HSM, etc.).

```csharp
public abstract class RemoteCertificateSigningService : ISigningService
{
    protected abstract Task<byte[]> SignRemotelyAsync(
        byte[] data, 
        CancellationToken cancellationToken);
    
    protected abstract Task<X509Certificate2> GetCertificateAsync(
        CancellationToken cancellationToken);
}
```

**Custom Implementation**:
```csharp
public class MyHsmSigningService : RemoteCertificateSigningService
{
    private readonly HsmClient _client;
    private readonly string _keyId;
    
    protected override async Task<byte[]> SignRemotelyAsync(
        byte[] data, 
        CancellationToken ct)
    {
        return await _client.SignAsync(_keyId, data, ct);
    }
    
    protected override async Task<X509Certificate2> GetCertificateAsync(
        CancellationToken ct)
    {
        return await _client.GetCertificateAsync(_keyId, ct);
    }
}
```

### Certificate Sources

#### FileCertificateSource

Loads certificate from a file.

```csharp
public class FileCertificateSource : CertificateSourceBase
{
    public FileCertificateSource(string path, string? password = null);
}

// Usage
using var certSource = new FileCertificateSource("cert.pfx", "password");
var cert = certSource.GetCertificate();
using var service = new LocalCertificateSigningService(cert!);
```

#### StoreCertificateSource

Retrieves certificate from Windows certificate store.

```csharp
public class StoreCertificateSource : CertificateSourceBase
{
    public StoreCertificateSource(
        string thumbprint,
        StoreName storeName = StoreName.My,
        StoreLocation storeLocation = StoreLocation.CurrentUser);
}

// Usage
using var certSource = new StoreCertificateSource(
    "1234567890ABCDEF",
    StoreName.My,
    StoreLocation.CurrentUser);
    
var cert = certSource.GetCertificate();
```

#### Base64CertificateSource

Loads certificate from base64-encoded string.

```csharp
public class Base64CertificateSource : CertificateSourceBase
{
    public Base64CertificateSource(string base64Certificate, string? password = null);
}

// Usage
string certBase64 = Environment.GetEnvironmentVariable("CERT_BASE64");
using var certSource = new Base64CertificateSource(certBase64, password);
```

### Certificate Chain Building

#### CertificateChainBuilder

Builds and validates certificate chains.

```csharp
public class CertificateChainBuilder
{
    public CertificateChainBuilder WithPolicy(X509ChainPolicy policy);
    public CertificateChainBuilder WithRootCertificates(IEnumerable<X509Certificate2> roots);
    public CertificateChainBuilder WithIntermediateCertificates(IEnumerable<X509Certificate2> intermediates);
    public X509Chain Build();
}
```

**Usage**:
```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.EntireChain,
    VerificationFlags = X509VerificationFlags.NoFlag,
    UrlRetrievalTimeout = TimeSpan.FromSeconds(30)
};

var chainBuilder = new CertificateChainBuilder()
    .WithPolicy(policy)
    .WithRootCertificates(trustedRoots)
    .WithIntermediateCertificates(intermediates);

using var chain = chainBuilder.Build();
bool isValid = chain.Build(certificate);
```

#### CustomTrustStore

Manage custom certificate trust stores.

```csharp
public class CustomTrustStore : IDisposable
{
    public void AddRootCertificate(X509Certificate2 certificate);
    public void AddIntermediateCertificate(X509Certificate2 certificate);
    public X509Chain CreateChain();
}

// Usage
using var trustStore = new CustomTrustStore();
trustStore.AddRootCertificate(rootCa);
trustStore.AddIntermediateCertificate(intermediateCa);

using var chain = trustStore.CreateChain();
bool isValid = chain.Build(signingCert);
```

## Certificate Validation

### CertificateSignatureValidator

Validates the cryptographic signature using the certificate.

```csharp
public class CertificateSignatureValidator : IValidator<CoseSign1Message>
{
    public ValidationResult Validate(
        CoseSign1Message message, 
        ValidationOptions? options = null);
}

// Usage
var validator = new CertificateSignatureValidator();
var result = validator.Validate(message);

if (!result.Success)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"Validation failed: {failure.Message}");
    }
}
```

### CertificateExpirationValidator

Validates certificate expiration dates.

```csharp
public class CertificateExpirationValidator : IValidator<CoseSign1Message>
{
    public CertificateExpirationValidator(DateTimeOffset? validationTime = null);
}

// Usage - Current time
var validator = new CertificateExpirationValidator();

// Usage - Specific time (for historical validation)
var historicalValidator = new CertificateExpirationValidator(
    DateTimeOffset.Parse("2024-01-01"));
```

### CertificateChainValidator

Validates the entire certificate chain.

```csharp
public class CertificateChainValidator : IValidator<CoseSign1Message>
{
    public CertificateChainValidator(
        X509ChainPolicy? policy = null,
        IEnumerable<X509Certificate2>? trustedRoots = null);
}

// Usage
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online
};

var validator = new CertificateChainValidator(policy, trustedRootCerts);
var result = validator.Validate(message);
```

### EkuPolicyValidator

Validates Extended Key Usage (EKU) extensions.

```csharp
public class EkuPolicyValidator : IValidator<CoseSign1Message>
{
    public EkuPolicyValidator(params string[] requiredEkus);
}

// Usage - Code signing
var codeSigning = new EkuPolicyValidator("1.3.6.1.5.5.7.3.3");

// Usage - Multiple EKUs
var validator = new EkuPolicyValidator(
    "1.3.6.1.5.5.7.3.3",  // Code signing
    "1.3.6.1.4.1.311.10.3.13" // Lifetime signing
);

var result = validator.Validate(message);
```

**Common EKU OIDs**:
- `1.3.6.1.5.5.7.3.1` - Server Authentication
- `1.3.6.1.5.5.7.3.2` - Client Authentication
- `1.3.6.1.5.5.7.3.3` - Code Signing
- `1.3.6.1.5.5.7.3.4` - Email Protection
- `1.3.6.1.4.1.311.10.3.13` - Lifetime Signing

### SanPolicyValidator

Validates Subject Alternative Name (SAN) extensions.

```csharp
public class SanPolicyValidator : IValidator<CoseSign1Message>
{
    public SanPolicyValidator(
        IEnumerable<string> allowedDnsNames = null,
        IEnumerable<string> allowedEmailAddresses = null,
        IEnumerable<string> allowedUris = null);
}

// Usage
var validator = new SanPolicyValidator(
    allowedDnsNames: new[] { "*.contoso.com", "app.contoso.com" },
    allowedEmailAddresses: new[] { "*@contoso.com" },
    allowedUris: new[] { "https://contoso.com/*" }
);

var result = validator.Validate(message);
```

### CertificatePredicateValidator

Custom validation with predicate functions.

```csharp
public class CertificatePredicateValidator : IValidator<CoseSign1Message>
{
    public CertificatePredicateValidator(
        Func<X509Certificate2, bool> predicate,
        string failureMessage);
}

// Usage - Custom issuer validation
var validator = new CertificatePredicateValidator(
    cert => cert.Issuer.Contains("CN=Contoso CA"),
    "Certificate must be issued by Contoso CA"
);

// Usage - Custom key size validation
var keySizeValidator = new CertificatePredicateValidator(
    cert => {
        using var key = cert.GetECDsaPublicKey();
        return key?.KeySize >= 256;
    },
    "Certificate must use at least 256-bit key"
);
```

### CertificateSignatureValidator

Validates COSE signatures using the certificate from x5t/x5chain headers.
Automatically handles both embedded and detached signatures.

```csharp
public class CertificateSignatureValidator : IValidator<CoseSign1Message>
{
    // For embedded signatures (payload in message)
    public CertificateSignatureValidator(bool allowUnprotectedHeaders = false);
    
    // For detached signatures (external payload)
    public CertificateSignatureValidator(byte[] detachedPayload, bool allowUnprotectedHeaders = false);
}

// Usage - Embedded signature
byte[] signatureWithPayload = File.ReadAllBytes("document.cose");
var message = CoseSign1Message.Decode(signatureWithPayload);
var validator = new CertificateSignatureValidator();
var result = validator.Validate(message);

// Usage - Detached signature
byte[] payload = File.ReadAllBytes("document.bin");
byte[] signature = File.ReadAllBytes("document.sig.cose");

var detachedMessage = CoseSign1Message.Decode(signature);
var detachedValidator = new CertificateSignatureValidator(payload);
var result = detachedValidator.Validate(detachedMessage);
```

## Extension Methods

### X509Certificate2 Extensions

```csharp
// Get certificate thumbprint in various formats
string sha256Thumbprint = cert.GetSha256Thumbprint();
string sha1Thumbprint = cert.GetSha1Thumbprint();
byte[] thumbprintBytes = cert.GetThumbprintBytes();

// Check certificate capabilities
bool canSign = cert.HasDigitalSignatureKeyUsage();
bool hasPrivateKey = cert.HasPrivateKey;

// Get key information
int keySize = cert.GetKeySize();
string keyAlgorithm = cert.GetKeyAlgorithmName();

// Certificate validation helpers
bool isValid = cert.IsValidNow();
bool isValidAt = cert.IsValidAt(DateTimeOffset.Parse("2024-01-01"));
bool isSelfSigned = cert.IsSelfSigned();

// EKU helpers
bool hasEku = cert.HasExtendedKeyUsage("1.3.6.1.5.5.7.3.3");
IEnumerable<string> ekus = cert.GetExtendedKeyUsages();
```

### CoseSign1Message Certificate Extensions

```csharp
// Extract certificate from message
X509Certificate2? cert = message.GetSigningCertificate();

// Extract certificate chain
IEnumerable<X509Certificate2> chain = message.GetCertificateChain();

// Get certificate thumbprint from headers
string? thumbprint = message.GetCertificateThumbprint();

// Check if message has certificate embedded
bool hasCert = message.HasEmbeddedCertificate();
```

### CoseHeaderMap Extensions

```csharp
// Add certificate to headers
headers.AddCertificate(cert);

// Add certificate chain
headers.AddCertificateChain(new[] { cert, intermediate, root });

// Add certificate thumbprint
headers.AddCertificateThumbprint(cert);

// Get certificate-related headers
var cert = headers.GetCertificate();
var chain = headers.GetCertificateChain();
var thumbprint = headers.GetCertificateThumbprint();
```

## Advanced Scenarios

### Complete Signing with Certificate Chain

```csharp
public async Task<CoseSign1Message> SignWithFullChainAsync(
    byte[] payload,
    X509Certificate2 signingCert,
    IEnumerable<X509Certificate2> intermediateCerts,
    X509Certificate2 rootCert)
{
    // Build certificate chain
    var chainBuilder = new CertificateChainBuilder()
        .WithRootCertificates(new[] { rootCert })
        .WithIntermediateCertificates(intermediateCerts);
    
    using var chain = chainBuilder.Build();
    
    // Create signing options
    var options = new CertificateSigningOptions
    {
        IncludeCertificateChain = true,
        ChainBuildingOptions = chain.ChainPolicy
    };
    
    // Create service and factory
    using var service = new LocalCertificateSigningService(signingCert, options);
    
    var headerContributors = new IHeaderContributor[]
    {
        new CertificateHeaderContributor(),
        new CwtClaimsHeaderContributor()
    };
    
    var factory = new DirectSignatureFactory(service, headerContributors);
    
    // Create signature
    return await factory.CreateAsync(payload);
}
```

### Complete Validation Pipeline

```csharp
public ValidationResult ValidateWithFullChain(
    CoseSign1Message message,
    IEnumerable<X509Certificate2> trustedRoots)
{
    var policy = new X509ChainPolicy
    {
        RevocationMode = X509RevocationMode.Online,
        RevocationFlag = X509RevocationFlag.EntireChain,
        VerificationFlags = X509VerificationFlags.NoFlag
    };
    
    var validator = new ValidatorBuilder()
        .WithSignatureValidator()
        .WithExpirationValidator()
        .WithChainValidator(policy, trustedRoots)
        .WithEkuPolicy(new[] { "1.3.6.1.5.5.7.3.3" }) // Code signing
        .Build();
    
    return validator.Validate(message);
}
```

### Custom Certificate Provider

```csharp
public class ConfigurationCertificateSource : CertificateSourceBase
{
    private readonly IConfiguration _config;
    
    public ConfigurationCertificateSource(IConfiguration config)
    {
        _config = config;
    }
    
    public override X509Certificate2? GetCertificate()
    {
        var certConfig = _config.GetSection("Signing:Certificate");
        var source = certConfig["Source"];
        
        return source switch
        {
            "File" => new FileCertificateSource(
                certConfig["Path"]!, 
                certConfig["Password"]).GetCertificate(),
            
            "Store" => new StoreCertificateSource(
                certConfig["Thumbprint"]!).GetCertificate(),
            
            "Base64" => new Base64CertificateSource(
                certConfig["Data"]!, 
                certConfig["Password"]).GetCertificate(),
            
            _ => throw new InvalidOperationException($"Unknown source: {source}")
        };
    }
}
```

### Certificate Rotation

```csharp
public class RotatingCertificateSource : CertificateSourceBase
{
    private readonly ICertificateProvider _provider;
    private X509Certificate2? _currentCert;
    private DateTimeOffset _lastRefresh;
    private readonly TimeSpan _refreshInterval = TimeSpan.FromHours(1);
    
    public override X509Certificate2? GetCertificate()
    {
        if (_currentCert == null || 
            DateTimeOffset.UtcNow - _lastRefresh > _refreshInterval)
        {
            _currentCert?.Dispose();
            _currentCert = _provider.GetLatestCertificate();
            _lastRefresh = DateTimeOffset.UtcNow;
        }
        
        return _currentCert;
    }
    
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _currentCert?.Dispose();
        }
        base.Dispose(disposing);
    }
}
```

### Multi-Certificate Signing

```csharp
public async Task<CoseSign1Message[]> SignWithMultipleCertsAsync(
    byte[] payload,
    IEnumerable<X509Certificate2> certificates)
{
    var messages = new List<CoseSign1Message>();
    
    foreach (var cert in certificates)
    {
        using var service = new LocalCertificateSigningService(cert);
        var factory = new DirectSignatureFactory(service);
        var message = await factory.CreateAsync(payload);
        messages.Add(message);
    }
    
    return messages.ToArray();
}
```

## Integration Patterns

### ASP.NET Core

```csharp
// Startup
services.AddSingleton<ICertificateSource>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    return new ConfigurationCertificateSource(config);
});

services.AddSingleton<ISigningService>(sp =>
{
    var certSource = sp.GetRequiredService<ICertificateSource>();
    var cert = certSource.GetCertificate();
    return new LocalCertificateSigningService(cert!);
});

// Usage
public class CertificateController : ControllerBase
{
    private readonly ISigningService _signingService;
    
    [HttpPost("sign")]
    public async Task<IActionResult> Sign([FromBody] byte[] payload)
    {
        var factory = new DirectSignatureFactory(_signingService);
        var message = await factory.CreateAsync(payload);
        return File(message.Encode(), "application/cose");
    }
    
    [HttpPost("validate")]
    public IActionResult Validate([FromBody] byte[] encodedMessage)
    {
        var message = CoseSign1Message.Decode(encodedMessage);
        var validator = new CertificateSignatureValidator();
        var result = validator.Validate(message);
        
        return Ok(new { result.Success, Errors = result.Failures });
    }
}
```

### Azure Functions

```csharp
public class CertificateSigningFunction
{
    private readonly ISigningService _signingService;
    
    public CertificateSigningFunction()
    {
        var thumbprint = Environment.GetEnvironmentVariable("CERT_THUMBPRINT");
        using var certSource = new StoreCertificateSource(thumbprint!);
        var cert = certSource.GetCertificate();
        _signingService = new LocalCertificateSigningService(cert!);
    }
    
    [FunctionName("Sign")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
    {
        using var reader = new StreamReader(req.Body);
        var payload = Encoding.UTF8.GetBytes(await reader.ReadToEndAsync());
        
        var factory = new DirectSignatureFactory(_signingService);
        var message = await factory.CreateAsync(payload);
        
        return new FileContentResult(message.Encode(), "application/cose");
    }
}
```

## Testing

### Test Certificate Creation

```csharp
public static class TestCertificateProvider
{
    public static X509Certificate2 CreateTestCertificate(
        string subjectName = "CN=Test",
        int keySize = 256,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        
        var request = new CertificateRequest(
            subjectName,
            ecdsa,
            HashAlgorithmName.SHA256);
        
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));
        
        return request.CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddYears(1));
    }
}
```

### Mocking Certificate Operations

```csharp
[Test]
public async Task SignAsync_WithTestCertificate_Success()
{
    // Arrange
    using var cert = TestCertificateProvider.CreateTestCertificate();
    using var service = new LocalCertificateSigningService(cert);
    var factory = new DirectSignatureFactory(service);
    
    // Act
    var message = await factory.CreateAsync(new byte[] { 1, 2, 3 });
    
    // Assert
    Assert.IsNotNull(message);
    Assert.IsNotNull(message.GetSigningCertificate());
}
```

## Best Practices

1. **Certificate Disposal**: Always dispose certificates
   ```csharp
   using var cert = new X509Certificate2("cert.pfx", "password");
   ```

2. **Chain Validation**: Always validate the full chain
   ```csharp
   var validator = new ValidatorBuilder()
       .WithChainValidator(policy, trustedRoots)
       .Build();
   ```

3. **Revocation Checking**: Enable when appropriate
   ```csharp
   var policy = new X509ChainPolicy
   {
       RevocationMode = X509RevocationMode.Online
   };
   ```

4. **Private Key Protection**: Never log or expose private keys
5. **EKU Validation**: Always validate for intended use
6. **Certificate Rotation**: Implement automatic rotation for long-running services

## See Also

- [Abstractions Package](abstractions.md)
- [Validation Package](validation.md)
- [Azure Trusted Signing Package](azure-trusted-signing.md)
- [Certificate Management Guide](../guides/certificate-management.md)

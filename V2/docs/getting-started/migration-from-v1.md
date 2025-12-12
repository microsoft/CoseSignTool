# Migration from V1 to V2

This guide helps you migrate from CoseSignTool V1 to V2.

## Overview

V2 is a complete architectural redesign. While the core functionality (creating and validating COSE Sign1 messages) remains the same, the APIs and patterns have changed significantly.

## Key Differences

| Aspect | V1 | V2 |
|--------|----|----|
| **Architecture** | Monolithic | Modular, layered |
| **Extensibility** | Limited | Plugin-based headers, validators |
| **Validation** | Built-in only | Composable framework |
| **Certificate Handling** | Manual | Abstracted sources, builders |
| **Transparency** | Add-on | First-class support |
| **Testing** | ~60% coverage | 95.5% coverage |
| **DID Support** | None | Native DID:x509 |
| **SCITT** | Manual | Built-in compliance |

## Migration Steps

### 1. Update Package References

**V1:**
```xml
<PackageReference Include="CoseHandler" Version="1.x.x" />
<PackageReference Include="CoseSign1.Certificates" Version="1.x.x" />
```

**V2:**
```xml
<PackageReference Include="CoseSign1.Certificates" Version="2.0.0-preview" />
<PackageReference Include="CoseSign1.Validation" Version="2.0.0-preview" />
```

### 2. Update Namespace Imports

**V1:**
```csharp
using CoseHandler;
using CoseSign1.Certificates;
```

**V2:**
```csharp
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using CoseSign1.Validation;
using CoseSign1.Certificates.Extensions;
```

### 3. Update Signing Code

#### Basic Signing

**V1:**
```csharp
// V1 approach
var handler = new CoseHandler();
using var cert = new X509Certificate2("cert.pfx", "password");

var message = handler.Sign(
    payload,
    cert,
    contentType: "application/json"
);
```

**V2:**
```csharp
// V2 approach - more explicit, more testable
using var cert = new X509Certificate2("cert.pfx", "password");
using var signingService = new LocalCertificateSigningService(cert);
using var factory = new DirectSignatureFactory(signingService);

byte[] message = factory.CreateCoseSign1MessageBytes(
    payload,
    contentType: "application/json"
);
```

#### Signing with Options

**V1:**
```csharp
var options = new CoseSign1Options
{
    DetachedPayload = true,
    IncludeChain = true
};

var message = handler.Sign(payload, cert, options);
```

**V2:**
```csharp
var options = new DirectSignatureOptions
{
    EmbedPayload = false  // Detached signature
};

// Chain is included automatically by LocalCertificateSigningService
byte[] message = factory.CreateCoseSign1MessageBytes(
    payload,
    contentType: "application/json",
    options: options
);
```

### 4. Update Validation Code

#### Basic Validation

**V1:**
```csharp
var handler = new CoseHandler();
var result = handler.Validate(signedMessage);

if (result.Success)
{
    // Signature is valid
}
```

**V2:**
```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Extensions;

var message = CoseMessage.DecodeSign1(signedMessage);
bool isValid = message.VerifySignature();

if (isValid)
{
    // Signature is valid
}
```

#### Validation with Custom Rules

**V1:**
```csharp
var handler = new CoseHandler();
var options = new CoseSign1ValidationOptions
{
    ValidateExpiration = true,
    ValidateEku = new[] { "1.3.6.1.5.5.7.3.3" }
};

var result = handler.Validate(signedMessage, options);
```

**V2:**
```csharp
using CoseSign1.Validation;
using CoseSign1.Certificates.Validation;

var validator = new CoseMessageValidationBuilder()
    .AddCertificateValidator(builder => builder
        .ValidateSignature()
        .ValidateExpiration()
        .ValidateEku("1.3.6.1.5.5.7.3.3")
    )
    .Build();

var message = CoseMessage.DecodeSign1(signedMessage);
var result = await validator.ValidateAsync(message);

if (result.IsValid)
{
    // All validations passed
}
else
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"Validation failed: {failure.Message}");
    }
}
```

### 5. Working with Certificates

#### Certificate Store Access

**V1:**
```csharp
var cert = CoseHandler.FindCertificate(
    StoreLocation.CurrentUser,
    StoreName.My,
    X509FindType.FindByThumbprint,
    "thumbprint"
);
```

**V2:**
```csharp
using CoseSign1.Certificates.Local;

var source = new WindowsCertificateStoreCertificateSource(
    StoreLocation.CurrentUser,
    StoreName.My
);

using var cert = source.GetCertificate(cert => 
    cert.Thumbprint == "thumbprint"
);
```

#### Certificate Chain

**V1:**
```csharp
// Chain was implicit or required manual setup
var chain = new X509Certificate2Collection();
chain.Add(leafCert);
chain.Add(intermediateCert);
```

**V2:**
```csharp
using CoseSign1.Certificates.ChainBuilders;

// Automatic chain building
var chainBuilder = new X509ChainBuilder();

// Or explicit chain
var explicitChain = new ExplicitCertificateChainBuilder(
    new[] { leafCert, intermediateCert, rootCert }
);

using var signingService = new LocalCertificateSigningService(
    leafCert,
    chainBuilder
);
```

### 6. SCITT Compliance

**V1:**
```csharp
// Manual CWT claims setup
var claims = new Dictionary<string, object>
{
    ["iss"] = "issuer",
    ["sub"] = "subject"
};
```

**V2:**
```csharp
using CoseSign1.Certificates;

// Built-in SCITT compliance
var options = new CertificateSigningOptions
{
    EnableScittCompliance = true
};

// CWT claims (iss, sub, iat, nbf) added automatically
byte[] message = factory.CreateCoseSign1MessageBytes(
    payload,
    contentType: "application/json",
    options: options
);

// Or provide custom claims
options.CustomCwtClaims = new CwtClaims
{
    Issuer = "custom-issuer",
    Subject = "custom-subject",
    IssuedAt = DateTimeOffset.UtcNow,
    NotBefore = DateTimeOffset.UtcNow
};
```

### 7. Remote Signing

#### Azure Key Vault (V1)

**V1:**
```csharp
// V1 had limited remote signing support
// Required manual Azure SDK integration
```

**V2:**
```csharp
using CoseSign1.Certificates.AzureTrustedSigning;
using Azure.Identity;

var config = new AzureTrustedSigningConfiguration
{
    Endpoint = new Uri("https://account.codesigning.azure.net"),
    AccountName = "yourAccount",
    CertificateProfile = "yourProfile"
};

var credential = new DefaultAzureCredential();
using var signingService = new AzureTrustedSigningService(config, credential);
using var factory = new DirectSignatureFactory(signingService);

byte[] message = factory.CreateCoseSign1MessageBytes(payload, "application/json");
```

### 8. Transparency Receipts

**V1:**
```csharp
// V1 had no built-in transparency support
// Required custom implementation
```

**V2:**
```csharp
using CoseSign1.Transparent.MST;

// Create signature
byte[] signedMessage = factory.CreateCoseSign1MessageBytes(payload, "application/json");

// Get MST receipt
var receiptFactory = new MstReceiptFactory(serviceEndpoint);
var receipt = await receiptFactory.CreateReceiptAsync(signedMessage);

// Validate receipt
var receiptValidator = new MstReceiptValidator();
var result = await receiptValidator.ValidateAsync(receipt);
```

### 9. Testing

**V1:**
```csharp
// Manual test certificate creation
var certReq = new CertificateRequest(/* ... */);
var cert = certReq.CreateSelfSigned(/* ... */);
```

**V2:**
```csharp
using CoseSign1.Tests.Common;

// Built-in test utilities
using var cert = TestCertificateUtils.CreateCertificate("TestCert");

// Create test chains
var chain = TestCertificateUtils.CreateTestChain(
    "TestChain",
    useEcc: true,
    keySize: 256
);
```

## Breaking Changes

### Removed Features

1. **Synchronous-only APIs**: V2 is async-first
2. **Global configuration**: Use dependency injection instead
3. **Static helpers**: Replaced with instance-based services

### Changed Behaviors

1. **Certificate chain**: Now included by default in LocalCertificateSigningService
2. **Header placement**: X5T/X5Chain in protected headers by default
3. **Error handling**: More specific exceptions with detailed messages

### New Requirements

1. **Explicit service creation**: Must create signing services explicitly
2. **Disposal**: Services implement IDisposable
3. **Options pattern**: Options passed through constructors or methods

## Common Patterns

### Pattern: Factory + Service

**Best Practice:**
```csharp
// Create once, reuse multiple times
using var signingService = new LocalCertificateSigningService(cert);
using var factory = new DirectSignatureFactory(signingService);

// Sign multiple messages
byte[] message1 = factory.CreateCoseSign1MessageBytes(payload1, "application/json");
byte[] message2 = factory.CreateCoseSign1MessageBytes(payload2, "application/xml");
```

### Pattern: Validation Builder

**Best Practice:**
```csharp
// Build once, validate multiple messages
var validator = new CoseMessageValidationBuilder()
    .AddCertificateValidator(builder => builder
        .ValidateSignature()
        .ValidateExpiration()
        .ValidateCommonName("TrustedSigner")
    )
    .Build();

// Validate multiple messages
var result1 = await validator.ValidateAsync(message1);
var result2 = await validator.ValidateAsync(message2);
```

### Pattern: Custom Header Contribution

**Best Practice:**
```csharp
public class CustomHeaderContributor : IHeaderContributor
{
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;
    
    public void ContributeProtectedHeaders(
        CoseHeaderMap headers, 
        HeaderContributorContext context)
    {
        headers.Add(
            new CoseHeaderLabel("custom-header"),
            CoseHeaderValue.FromString("custom-value")
        );
    }
    
    public void ContributeUnprotectedHeaders(
        CoseHeaderMap headers, 
        HeaderContributorContext context)
    {
        // Optionally add unprotected headers
    }
}

// Use in signing context
var contributors = new List<IHeaderContributor>
{
    new CustomHeaderContributor()
};

var context = new SigningContext(
    payload,
    "application/json",
    contributors
);
```

## Gradual Migration Strategy

1. **Phase 1**: Keep V1 running, add V2 packages
2. **Phase 2**: Create V2 implementations alongside V1
3. **Phase 3**: Test V2 implementations thoroughly
4. **Phase 4**: Switch traffic to V2 gradually
5. **Phase 5**: Remove V1 dependencies

## Support

If you encounter migration issues:

- Check the [API Documentation](../api/README.md)
- Review [Code Examples](../examples/README.md)
- Ask on [GitHub Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- Report bugs via [GitHub Issues](https://github.com/microsoft/CoseSignTool/issues)

## Next Steps

- [Quick Start Guide](quick-start.md) - Get started with V2
- [Architecture Overview](../architecture/overview.md) - Understand V2 architecture
- [Code Examples](../examples/README.md) - See V2 in action

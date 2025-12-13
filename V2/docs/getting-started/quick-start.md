# Quick Start Guide

Get started with CoseSignTool V2 in just a few minutes.

## Installation

### CLI Tool

```bash
# Install the CLI tool globally (includes all plugins)
dotnet tool install -g CoseSignTool --version 2.0.0-preview

# Verify installation
cosesigntool --version
```

### Library Packages

```bash
# Install the core library packages
dotnet add package CoseSign1.Certificates.V2 --version 2.0.0-preview
dotnet add package CoseSign1.Validation.V2 --version 2.0.0-preview
```

## CLI Quick Start

```bash
# Sign with an ephemeral test certificate (development only)
echo "Hello, COSE!" | cosesigntool sign-ephemeral -o signed.cose

# Verify the signature (allow untrusted for self-signed test certs)
cosesigntool verify signed.cose --allow-untrusted

# Sign with a PFX certificate
cosesigntool sign-pfx myfile.txt --pfx certificate.pfx --pfx-password mypassword

# Inspect a signature
cosesigntool inspect signed.cose
```

## Library Quick Start

### 1. Sign a Message with a Certificate

```csharp
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using System.Security.Cryptography.X509Certificates;

// Load your certificate
using var cert = new X509Certificate2("certificate.pfx", "password");

// Create a local signing service
using var signingService = new LocalCertificateSigningService(cert);

// Create a signature factory
using var factory = new DirectSignatureFactory(signingService);

// Sign your payload
byte[] payload = "Hello, COSE!"u8.ToArray();
byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    payload, 
    contentType: "text/plain"
);

// Save or transmit the signed message
File.WriteAllBytes("signed.cose", signedMessage);
```

### 2. Verify a Signature

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

// Load the signed message
byte[] signedMessage = File.ReadAllBytes("signed.cose");
var message = CoseMessage.DecodeSign1(signedMessage);

// Verify the signature
bool isValid = message.VerifySignature();

if (isValid)
{
    Console.WriteLine("Signature is valid!");
    Console.WriteLine($"Payload: {System.Text.Encoding.UTF8.GetString(message.Content.Value.Span)}");
}
```

### 3. Add SCITT Compliance

```csharp
using CoseSign1.Certificates;

// Create signing options with SCITT compliance
var options = new CertificateSigningOptions
{
    EnableScittCompliance = true
};

// Sign with SCITT-compliant CWT claims
byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    payload,
    contentType: "application/json",
    options: options
);
```

### 4. Validate with Custom Rules

```csharp
using CoseSign1.Validation;
using CoseSign1.Certificates.Validation;

// Build a validation pipeline
var validator = new CoseMessageValidationBuilder()
    .AddCertificateValidator(builder => builder
        .ValidateSignature()
        .ValidateExpiration()
        .ValidateCommonName("MyTrustedSigner")
        .ValidateEku("1.3.6.1.5.5.7.3.3") // Code signing EKU
    )
    .Build();

// Validate the message
var result = await validator.ValidateAsync(message);

if (result.IsValid)
{
    Console.WriteLine("All validations passed!");
}
else
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"Validation failed: {failure.Message}");
    }
}
```

## Next Steps

- [Architecture Overview](../architecture/overview.md) - Understand the V2 architecture
- [Certificate Management](../architecture/certificate-management.md) - Learn about certificate sources
- [Validation Framework](../architecture/validation-framework.md) - Deep dive into validation
- [SCITT Compliance](../guides/scitt-compliance.md) - Learn about SCITT standards
- [Code Examples](../examples/README.md) - See more examples

## Common Scenarios

### Detached Signatures

```csharp
var options = new DirectSignatureOptions 
{ 
    EmbedPayload = false 
};

byte[] detachedSignature = factory.CreateCoseSign1MessageBytes(
    payload,
    contentType: "application/octet-stream",
    options: options
);

// Verify detached signature
bool isValid = message.VerifySignature(payload);
```

### Remote Signing (Azure Trusted Signing)

```csharp
using CoseSign1.Certificates.AzureTrustedSigning;

var atsConfig = new AzureTrustedSigningConfiguration
{
    Endpoint = new Uri("https://youraccount.codesigning.azure.net"),
    AccountName = "yourAccount",
    CertificateProfile = "yourProfile"
};

using var signingService = new AzureTrustedSigningService(atsConfig, credential);
using var factory = new DirectSignatureFactory(signingService);

byte[] signedMessage = factory.CreateCoseSign1MessageBytes(payload, "application/json");
```

### Working with Transparency Receipts

```csharp
using CoseSign1.Transparent.MST;

// Create signature with MST receipt
var receiptFactory = new MstReceiptFactory(serviceEndpoint);
var receipt = await receiptFactory.CreateReceiptAsync(signedMessage);

// Validate the receipt
var receiptValidator = new MstReceiptValidator();
var result = await receiptValidator.ValidateAsync(receipt);
```

## Troubleshooting

### Certificate Not Found
Ensure your certificate has a private key and is accessible to your application.

### Signature Verification Fails
Check that:
- The payload hasn't been modified
- For detached signatures, you're providing the correct payload
- The signing certificate is trusted

### SCITT Validation Errors
Verify that:
- CWT claims are present in protected headers
- The DID:x509 issuer is correctly formatted
- Timestamps (iat, nbf) are valid

## Support

For issues and questions:
- [GitHub Issues](https://github.com/microsoft/CoseSignTool/issues)
- [API Documentation](../api/README.md)

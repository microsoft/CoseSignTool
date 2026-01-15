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
dotnet add package CoseSign1.Factories --version 2.0.0-preview
dotnet add package CoseSign1.Certificates --version 2.0.0-preview
dotnet add package CoseSign1.Validation --version 2.0.0-preview
```

## CLI Quick Start

```bash
# Sign with an ephemeral test certificate (development only)
echo "Hello, COSE!" | cosesigntool sign-ephemeral -o signed.cose

# Verify the signature (allow untrusted for self-signed test certs)
cosesigntool verify signed.cose --allow-untrusted

# Sign with a PFX certificate (password via environment variable)
export COSESIGNTOOL_PFX_PASSWORD=mypassword  # Linux/macOS
set COSESIGNTOOL_PFX_PASSWORD=mypassword     # Windows
cosesigntool sign-pfx myfile.txt --pfx certificate.pfx

# Inspect a signature
cosesigntool inspect signed.cose
```

## Library Quick Start

### 1. Sign a Message with a Certificate

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using System.Security.Cryptography.X509Certificates;

// Load your certificate
using var cert = new X509Certificate2("certificate.pfx", "password");

// Create a signing service using the factory method
using var chainBuilder = new X509ChainBuilder();
using var signingService = CertificateSigningService.Create(cert, chainBuilder);

// Create a signature factory (preferred router)
using var factory = new CoseSign1MessageFactory(signingService);

// Sign your payload
byte[] payload = "Hello, COSE!"u8.ToArray();
byte[] signedMessage = factory.CreateDirectCoseSign1MessageBytes(
    payload, 
    contentType: "text/plain"
);

// Save or transmit the signed message
File.WriteAllBytes("signed.cose", signedMessage);
```

### 2. Verify a Signature

```csharp
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;

// Load the signed message
byte[] signedMessage = File.ReadAllBytes("signed.cose");
var message = CoseMessage.DecodeSign1(signedMessage);

// Configure staged validation via DI.
// For development only: UseEmbeddedChainOnly() trusts the embedded chain without requiring a known root.
var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();
validation.EnableCertificateTrust(cert => cert.UseEmbeddedChainOnly());

using var sp = services.BuildServiceProvider();
var validator = sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create();

// Verify - returns staged results
var result = message.Validate(validator);

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature is valid!");
    Console.WriteLine($"Payload: {System.Text.Encoding.UTF8.GetString(message.Content.Value.Span)}");
}
else
{
    Console.WriteLine($"Validation failed: {result.Overall.Failures[0].Message}");
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
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Certificates.Trust.Facts;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;

// Configure validation (trust packs + explicit trust requirements)
var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();
validation.EnableCertificateTrust(cert => cert.UseSystemTrust());

// Add an explicit trust requirement: require the X.509 chain to be trusted.
var policy = TrustPlanPolicy.PrimarySigningKey(key => key.RequireFact<X509ChainTrustedFact>(
    f => f.IsTrusted,
    "X.509 certificate chain must be trusted"));
services.AddSingleton<CompiledTrustPlan>(sp => policy.Compile(sp));

using var sp = services.BuildServiceProvider();
var validator = sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create();

// Validate returns comprehensive staged results
var result = message.Validate(validator);

if (result.Overall.IsValid)
{
    Console.WriteLine("All validations passed!");
}
else
{
    // Check which stage failed
    if (!result.Trust.IsValid)
    {
        foreach (var failure in result.Trust.Failures)
        {
            Console.WriteLine($"Trust validation failed: {failure.Message}");
        }
    }
    if (!result.Signature.IsValid)
    {
        foreach (var failure in result.Signature.Failures)
        {
            Console.WriteLine($"Signature validation failed: {failure.Message}");
        }
    }
}
```

## Next Steps

- [Architecture Overview](../architecture/overview.md) - Understand the V2 architecture
- [Validation Framework](../architecture/validation-framework.md) - Deep dive into validation
- [Trust Policy Guide](../guides/trust-policy.md) - Learn about trust policies
- [Code Examples](../examples/README.md) - See more examples

## Common Scenarios

### Detached Signatures

```csharp
var options = new DirectSignatureOptions 
{ 
    EmbedPayload = false 
};

byte[] detachedSignature = factory.CreateDirectCoseSign1MessageBytes(
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
using CoseSign1.Factories;

var atsConfig = new AzureTrustedSigningConfiguration
{
    Endpoint = new Uri("https://youraccount.codesigning.azure.net"),
    AccountName = "yourAccount",
    CertificateProfile = "yourProfile"
};

using var signingService = new AzureTrustedSigningService(atsConfig, credential);
using var factory = new CoseSign1MessageFactory(signingService);

byte[] signedMessage = factory.CreateDirectCoseSign1MessageBytes(payload, "application/json");
```

### Working with Transparency Receipts

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;

// Create a signed message
var signedMessage = factory.CreateCoseSign1Message(payload, "application/json");

// Add an MST receipt (transparency proof)
var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
var provider = new MstTransparencyProvider(client);
var signedMessageWithReceipt = await provider.AddTransparencyProofAsync(signedMessage);

// Verify the receipt
var result = await provider.VerifyTransparencyProofAsync(signedMessageWithReceipt);
if (!result.IsValid)
{
    foreach (var error in result.Errors)
    {
        Console.WriteLine(error);
    }
}
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

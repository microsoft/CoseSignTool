# Examples

This section provides code examples for common CoseSignTool V2 scenarios.

## Quick Examples

### Sign a JSON File

```csharp
using CoseSign1;
using CoseSign1.Certificates;

// Load certificate
var cert = new X509Certificate2("signing-cert.pfx", password);

// Create signing service
var service = new LocalSigningService(cert);

// Create factory and sign
var factory = new DirectSignatureFactory(service);
var payload = File.ReadAllBytes("document.json");
var signature = factory.CreateCoseSign1MessageBytes(payload, "application/json");

// Save signature
File.WriteAllBytes("document.json.cose", signature);
```

### Verify a Signature

```csharp
using CoseSign1;

// Load signature
var signature = File.ReadAllBytes("document.json.cose");

// Build validator
var validator = ValidationBuilder.Create()
    .AddSignatureValidator()
    .AddCertificateChainValidator()
    .Build();

// Verify
var result = await validator.ValidateAsync(signature);

if (result.IsValid)
{
    Console.WriteLine("Signature is valid!");
}
else
{
    Console.WriteLine($"Validation failed: {result.Errors.First().Message}");
}
```

### Sign with Azure Trusted Signing

```csharp
using CoseSign1.Certificates.AzureTrustedSigning;
using Azure.Identity;

var options = new AzureTrustedSigningOptions
{
    Endpoint = new Uri("https://myaccount.codesigning.azure.net"),
    AccountName = "myaccount",
    CertificateProfileName = "myprofile",
    Credential = new DefaultAzureCredential()
};

var service = new AzureTrustedSigningService(options);
var factory = new DirectSignatureFactory(service);

var signature = await factory.CreateCoseSign1MessageBytesAsync(payload, "application/json");
```

### Create Indirect Signature for Large File

```csharp
using CoseIndirectSignature;

var factory = new IndirectSignatureFactory(signingService);

// Stream large file - memory efficient
using var stream = File.OpenRead("large-file.bin");
var signature = await factory.CreateIndirectSignatureBytesAsync(
    stream,
    HashAlgorithmName.SHA384,
    "application/octet-stream");
```

### Add Custom Headers

```csharp
public class BuildInfoHeaderContributor : IHeaderContributor
{
    private readonly string _buildId;
    
    public BuildInfoHeaderContributor(string buildId) => _buildId = buildId;
    public int Order => 50;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContext context)
    {
        headers.Add(new CoseHeaderLabel("build-id"), _buildId);
        headers.Add(new CoseHeaderLabel("build-time"), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContext context) { }
}

// Usage
var factory = new DirectSignatureFactory(
    service,
    headerContributors: new[] { new BuildInfoHeaderContributor("build-12345") });
```

### Detached Signature

```csharp
// Create detached signature (payload not embedded)
var signature = factory.CreateCoseSign1MessageBytes(
    payload,
    "application/json",
    isDetached: true);

// Verify with detached payload
var result = validator.Validate(signature, detachedPayload: payload);
```

## CLI Examples

### Sign with PFX File

```bash
# Set password in environment
set COSESIGNTOOL_PFX_PASSWORD=your-password

# Sign
CoseSignTool sign-pfx document.json --pfx-file cert.pfx --output signed.cose
```

### Sign with Certificate Store

```bash
CoseSignTool sign-certstore document.json ^
    --thumbprint ABC123DEF456... ^
    --store-name My ^
    --store-location CurrentUser ^
    --output signed.cose
```

### Verify Signature

```bash
CoseSignTool verify signed.cose
```

### Inspect Signature

```bash
CoseSignTool inspect signed.cose
```

### Create Detached Signature

```bash
CoseSignTool sign-pfx document.json ^
    --pfx-file cert.pfx ^
    --detached ^
    --output document.json.sig
```

### Verify Detached Signature

```bash
CoseSignTool verify document.json.sig --payload document.json
```

## Full Sample Applications

For complete sample applications, see the samples in the repository:

- `samples/BasicSigning` - Simple sign and verify
- `samples/AzureSigning` - Azure Trusted Signing integration
- `samples/CustomValidation` - Custom validator implementation
- `samples/TransparencyService` - MST integration

## See Also

- [Quick Start Guide](../getting-started/quick-start.md)
- [CLI Reference](../cli/README.md)
- [API Reference](../api/README.md)

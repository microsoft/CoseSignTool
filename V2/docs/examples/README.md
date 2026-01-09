# Examples

This section provides code examples for common CoseSignTool V2 scenarios.

## Quick Examples

### Sign a JSON File

```csharp
using CoseSign1;
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Direct;

// Load certificate
var cert = new X509Certificate2("signing-cert.pfx", password);

// Create signing service
using var chainBuilder = new X509ChainBuilder();
using var service = CertificateSigningService.Create(cert, chainBuilder);

// Create factory and sign
using var factory = new DirectSignatureFactory(service);
var payload = File.ReadAllBytes("document.json");
var signature = factory.CreateCoseSign1MessageBytes(payload, "application/json");

// Save signature
File.WriteAllBytes("document.json.cose", signature);
```

### Verify a Signature

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

// Load signature
var signature = File.ReadAllBytes("document.json.cose");
var message = CoseSign1Message.DecodeSign1(signature);

// Build validator - uses default trust policy from certificate validators
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .ValidateChain(allowUntrusted: false))
    .Build();  // Default policy: x509.chain.trusted

// Verify - returns staged results
var result = validator.Validate(message);

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature is valid!");
}
else
{
    // Check which stage failed
    if (!result.Trust.IsValid)
    {
        Console.WriteLine($"Trust failed: {result.Trust.Failures[0].Message}");
    }
    else if (!result.Signature.IsValid)
    {
        Console.WriteLine($"Signature failed: {result.Signature.Failures[0].Message}");
    }
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
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        headers.Add(new CoseHeaderLabel("build-id"), _buildId);
        headers.Add(new CoseHeaderLabel("build-time"), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context) { }
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

### Verify Azure Key Vault Signature

```csharp
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;
using Azure.Identity;

// Build validator with fluent AKV validation API
var validator = Cose.Sign1Message()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKey()                    // Require AKV key-only signature
        .AllowOnlineVerify()                  // Allow network calls if needed
        .WithCredential(new DefaultAzureCredential()))
    .Build();

var result = validator.Validate(message);
```

### Validate Azure Key Vault Origin (Trust Policy)

When verifying key-only signatures, you may want to ensure the signing key comes from an approved set of Key Vaults. This is particularly useful for supply chain security.

```csharp
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;

// Validate that the kid matches allowed vault patterns
var validator = Cose.Sign1Message()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()         // Enable trust validation
        .FromAllowedVaults(
            "https://production-vault.vault.azure.net/keys/*",    // Any key in this vault
            "https://signing-*.vault.azure.net/keys/release-*"))  // Wildcards supported
    .Build();

var result = validator.Validate(message);

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature is valid and key is from an approved vault!");
}
```

#### Pattern Syntax for Allowed Vaults

| Format | Example | Description |
|--------|---------|-------------|
| Exact | `https://myvault.vault.azure.net/keys/mykey` | Matches exact kid URI |
| Wildcard | `https://*.vault.azure.net/keys/*` | `*` matches any characters |
| Regex | `regex:https://.*\.vault\.azure\.net/keys/signing-.*` | Full regex (prefix with `regex:`) |

### Verify with MST Transparency

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;

var client = new CodeTransparencyClient(
    new Uri("https://dataplane.codetransparency.azure.net"));

// Build validator with fluent MST validation API
var validator = Cose.Sign1Message()
    .ValidateMst(mst => mst
        .RequireReceiptPresence()             // Check receipt exists
        .VerifyReceipt(client))               // Validate the receipt
    .OverrideDefaultTrustPolicy(TrustPolicy.Claim("mst.receipt.trusted"))
    .Build();

var result = validator.Validate(message);

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature and MST receipt are valid!");
}
```

### Combined Validation (Certificate + MST)

```csharp
// Validate certificate chain AND MST transparency receipt
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .ValidateChain())
    .ValidateMst(mst => mst
        .RequireReceiptPresence()
        .VerifyReceipt(client))
    .OverrideDefaultTrustPolicy(TrustPolicy.And(
        TrustPolicy.Claim("x509.chain.trusted"),
        TrustPolicy.Claim("mst.receipt.trusted")))
    .Build();

var result = validator.Validate(message);
```

### Combined Validation (AKV Trust + MST)

```csharp
// Validate AKV key origin AND MST transparency receipt
// Useful for supply chain scenarios with key-only signatures
var validator = Cose.Sign1Message()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()
        .FromAllowedVaults("https://release-*.vault.azure.net/keys/*")
        .AllowOnlineVerify()
        .WithCredential(new DefaultAzureCredential()))
    .ValidateMst(mst => mst
        .RequireReceiptPresence()
        .VerifyReceipt(mstClient))
    .Build();

// Trust policies from all validators are automatically aggregated
var result = validator.Validate(message);
```

### Trust Policy Aggregation

When using multiple validators that implement `IProvidesDefaultTrustPolicy`, their default trust policies are automatically combined using `TrustPolicy.And()`. This means all trust requirements must be satisfied.

```csharp
// Example: All three validators contribute default trust policies
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())      // Adds: x509.chain.trusted
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()
        .FromAllowedVaults("https://prod.vault.azure.net/keys/*"))  // Adds: akv.key.detected AND akv.kid.allowed
    .ValidateMst(mst => mst.RequireReceiptPresence())       // Adds: mst.receipt.present
    .Build();

// Effective trust policy is:
// TrustPolicy.And(
//     Claim("x509.chain.trusted"),
//     Claim("akv.key.detected"),
//     Claim("akv.kid.allowed"),
//     Claim("mst.receipt.present"))
```

### Available Trust Claims

| Source | Claim | Description |
|--------|-------|-------------|
| Certificate | `x509.chain.trusted` | Certificate chain validated successfully |
| AKV | `akv.key.detected` | kid looks like an Azure Key Vault key URI |
| AKV | `akv.kid.allowed` | kid matches one of the allowed patterns |
| MST | `mst.receipt.present` | MST receipt exists in signature |
| MST | `mst.receipt.trusted` | MST receipt verified successfully |

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
    --signature-type detached ^
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

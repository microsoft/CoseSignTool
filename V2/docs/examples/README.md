# Examples

This section provides code examples for common CoseSignTool V2 scenarios.

## Quick Examples

### Sign a JSON File

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;

// Load certificate
var cert = new X509Certificate2("signing-cert.pfx", password);

// Create signing service
using var chainBuilder = new X509ChainBuilder();
using var service = CertificateSigningService.Create(cert, chainBuilder);

// Create factory and sign (preferred router)
using var factory = new CoseSign1MessageFactory(service);
var payload = File.ReadAllBytes("document.json");
var signature = factory.CreateDirectCoseSign1MessageBytes(payload, "application/json");

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
var message = CoseMessage.DecodeSign1(signature);

// Build validator - assertion providers supply default trust requirements.
var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: CoseHeaderLocation.Any))
    .ValidateCertificate(cert => cert
        .NotExpired()
        .ValidateChain(allowUntrusted: false))
    .Build();

// Verify - returns detailed results
var result = message.Validate(validator);

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature is valid!");
}
else
{
    // Check which part failed
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
var factory = new CoseSign1MessageFactory(service);

var signature = await factory.CreateDirectCoseSign1MessageBytesAsync(payload, "application/json");
```

### Create Indirect Signature for Large File

```csharp
using CoseSign1.Factories.Indirect;

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
        headers.Add(new CoseHeaderLabel("build-id"), CoseHeaderValue.FromString(_buildId));
        headers.Add(new CoseHeaderLabel("build-time"), CoseHeaderValue.FromInt64(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context) { }
}

// Usage
var factory = new CoseSign1MessageFactory(service);

var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors = new[] { new BuildInfoHeaderContributor("build-12345") }
};

var signature = factory.CreateCoseSign1MessageBytes(payload, "application/json", options);
```

### Detached Signature

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

// Create detached signature (payload not embedded)
var signature = factory.CreateCoseSign1MessageBytes(
    payload,
    "application/json",
    new DirectSignatureOptions { EmbedPayload = false });

// Verify with detached payload
var message = CoseMessage.DecodeSign1(signature);
var result = message.Validate(builder => builder
    .WithOptions(o => o.WithDetachedPayload(payload))
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: CoseHeaderLocation.Any))
    .ValidateCertificate(cert => cert.ValidateChain()));
```

### Verify Azure Key Vault Signature

```csharp
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;

// Adds AKV trust assertions (kid pattern checks).
// You must also supply an ISigningKeyResolver to verify the cryptographic signature
// for key-only signatures (not provided by this package).
var validator = new CoseSign1ValidationBuilder()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin())
    .Build();

var result = message.Validate(validator);
```

### Validate Azure Key Vault Origin (Trust Policy)

When verifying key-only signatures, you may want to ensure the signing key comes from an approved set of Key Vaults. This is particularly useful for supply chain security.

```csharp
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;

// Validate that the kid matches allowed vault patterns
var validator = new CoseSign1ValidationBuilder()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()
        .FromAllowedVaults(
            "https://production-vault.vault.azure.net/keys/*",    // Any key in this vault
            "https://signing-*.vault.azure.net/keys/release-*"))  // Wildcards supported
    .Build();

var result = message.Validate(validator);

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
using CoseSign1.Certificates.Validation;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;

var client = new CodeTransparencyClient(
    new Uri("https://dataplane.codetransparency.azure.net"));

// Build validator with fluent MST validation API
var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: System.Security.Cryptography.Cose.CoseHeaderLocation.Any))
    .ValidateMst(mst => mst
        .RequireReceiptPresence()             // Check receipt exists
        .VerifyReceipt(client))               // Validate the receipt
    .OverrideDefaultTrustPolicy(CoseSign1.Transparent.MST.Validation.MstTrustPolicies.RequireReceiptPresentAndTrusted())
    .Build();

var result = message.Validate(validator);

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature and MST receipt are valid!");
}
```

### Combined Validation (Certificate + MST)

```csharp
// Validate certificate chain AND MST transparency receipt
var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: System.Security.Cryptography.Cose.CoseHeaderLocation.Any))
    .ValidateCertificate(cert => cert
        .NotExpired()
        .ValidateChain())
    .ValidateMst(mst => mst
        .RequireReceiptPresence()
        .VerifyReceipt(client))
    .OverrideDefaultTrustPolicy(CoseSign1.Validation.Trust.TrustPolicy.And(
        CoseSign1.Certificates.Validation.X509TrustPolicies.RequireTrustedChain(),
        CoseSign1.Transparent.MST.Validation.MstTrustPolicies.RequireReceiptPresentAndTrusted()))
    .Build();

var result = message.Validate(validator);
```

### Combined Validation (AKV Trust + MST)

```csharp
// Validate AKV key origin AND MST transparency receipt
// Useful for supply chain scenarios with key-only signatures
var validator = new CoseSign1ValidationBuilder()
    // Required: add an ISigningKeyResolver appropriate to your signature shape.
    // For X.509-backed signatures use CertificateSigningKeyResolver; for key-only you must supply your own.
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: System.Security.Cryptography.Cose.CoseHeaderLocation.Any))
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()
        .FromAllowedVaults("https://release-*.vault.azure.net/keys/*"))
    .ValidateMst(mst => mst
        .RequireReceiptPresence()
        .VerifyReceipt(mstClient))
    .Build();

var result = message.Validate(validator);
```

### Trust Policy Aggregation

In V2, trust is evaluated by a `TrustPolicy` against the set of typed assertions emitted by your `ISigningKeyAssertionProvider` components.

If you don't override the policy, `CoseSign1ValidationBuilder` defaults to `TrustPolicy.FromAssertionDefaults()`, which effectively ANDs the default trust policies for the assertions that are present.

```csharp
var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: System.Security.Cryptography.Cose.CoseHeaderLocation.Any))
    .ValidateCertificate(cert => cert.ValidateChain())
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()
        .FromAllowedVaults("https://prod.vault.azure.net/keys/*"))
    .ValidateMst(mst => mst.RequireReceiptPresence())
    .Build();
```

For more details (including how to build explicit policies with `TrustPolicy.Require<T>`), see the Trust Policy guide.

## CLI Examples

### Sign with PFX File

```bash
# Set password in environment
set COSESIGNTOOL_PFX_PASSWORD=your-password

# Sign
CoseSignTool sign-pfx document.json --pfx cert.pfx --output signed.cose

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
    --pfx cert.pfx ^
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

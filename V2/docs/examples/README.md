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
var signature = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(payload, "application/json");

// Save signature
File.WriteAllBytes("document.json.cose", signature);
```

### Verify a Signature

```csharp
using CoseSign1.Validation.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;

// Load signature
var signature = File.ReadAllBytes("document.json.cose");
var message = CoseMessage.DecodeSign1(signature);

// Configure validation via DI.
var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

// Adds x5chain/x5t key resolution + certificate trust defaults.
validation.EnableCertificateSupport(cert => cert
    .UseSystemTrust()
    );

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();

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
using CoseSign1.Factories.Direct;

var options = new AzureTrustedSigningOptions
{
    Endpoint = new Uri("https://myaccount.codesigning.azure.net"),
    AccountName = "myaccount",
    CertificateProfileName = "myprofile",
    Credential = new DefaultAzureCredential()
};

var service = new AzureTrustedSigningService(options);
var factory = new CoseSign1MessageFactory(service);

var signature = await factory.CreateCoseSign1MessageBytesAsync<DirectSignatureOptions>(payload, "application/json");
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
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;

// Create detached signature (payload not embedded)
var signature = factory.CreateCoseSign1MessageBytes(
    payload,
    "application/json",
    new DirectSignatureOptions { EmbedPayload = false });

// Verify with detached payload
var message = CoseMessage.DecodeSign1(signature);

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();
validation.EnableCertificateSupport(cert => cert
    .UseSystemTrust()
    );

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var options = new CoseSign1ValidationOptions().WithDetachedPayload(new MemoryStream(payload));

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create(options: options);

var result = message.Validate(validator);
```

### Verify Azure Key Vault Signature

```csharp
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

// Registers AKV signing-key resolvers (offline COSE_Key and optional online) + fact producers.
validation.EnableAzureKeyVaultSupport(akv => akv
    .RequireAzureKeyVaultKid()
    .AllowKidPatterns(new[] { "https://production-vault.vault.azure.net/keys/*" })
    .OfflineOnly());

// AKV trust-pack defaults do not enforce requirements by default.
// Register an explicit trust plan policy for your deployment.
var trustPolicy = TrustPlanPolicy.Message(m => m
    .RequireFact<AzureKeyVaultKidAllowedFact>(f => f.IsAllowed, "AKV kid must match an allowed pattern"));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();

var result = message.Validate(validator);
```

### Validate Azure Key Vault Origin (Trust Policy)

When verifying key-only signatures, you may want to ensure the signing key comes from an approved set of Key Vaults. This is particularly useful for supply chain security.

```csharp
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableAzureKeyVaultSupport(akv => akv
    .RequireAzureKeyVaultKid()
    .AllowKidPatterns(new[]
    {
        "https://production-vault.vault.azure.net/keys/*",
        "https://signing-*.vault.azure.net/keys/release-*",
    })
    .OfflineOnly());

var trustPolicy = TrustPlanPolicy.Message(m => m
    .RequireFact<AzureKeyVaultKidAllowedFact>(f => f.IsAllowed, "AKV kid must match an allowed pattern"));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();

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
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

var client = new CodeTransparencyClient(
    new Uri("https://dataplane.codetransparency.azure.net"));

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableCertificateSupport(cert => cert.UseSystemTrust());
validation.EnableMstSupport(mst => mst.VerifyReceipts(new Uri("https://dataplane.codetransparency.azure.net")));

// Require both a trusted certificate chain and a verified MST receipt.
var trustPolicy = TrustPlanPolicy.PrimarySigningKey(k => k
        .RequireFact<X509ChainTrustedFact>(f => f.IsTrusted, "Signing certificate chain must be trusted"))
    .And(TrustPlanPolicy.AnyCounterSignature(cs => cs
        .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt must be present")
        .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must verify")));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();

var result = message.Validate(validator);

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature and MST receipt are valid!");
}
```

### Combined Validation (Certificate + MST)

```csharp
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableCertificateSupport(cert => cert.UseSystemTrust());
validation.EnableMstSupport(mst => mst.VerifyReceipts(new Uri("https://dataplane.codetransparency.azure.net")));

var trustPolicy = TrustPlanPolicy.PrimarySigningKey(k => k
        .RequireFact<X509ChainTrustedFact>(f => f.IsTrusted, "Signing certificate chain must be trusted"))
    .And(TrustPlanPolicy.AnyCounterSignature(cs => cs
        .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt must be present")
        .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must verify")));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();

var result = message.Validate(validator);
```

### Combined Validation (AKV Trust + MST)

```csharp
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableAzureKeyVaultSupport(akv => akv
    .RequireAzureKeyVaultKid()
    .AllowKidPatterns(new[] { "https://release-*.vault.azure.net/keys/*" })
    .OfflineOnly());

validation.EnableMstSupport(mst => mst.VerifyReceipts(new Uri("https://dataplane.codetransparency.azure.net")));

var trustPolicy = TrustPlanPolicy.Message(m => m
    .RequireFact<AzureKeyVaultKidAllowedFact>(f => f.IsAllowed, "AKV kid must match an allowed pattern"))
    .And(TrustPlanPolicy.AnyCounterSignature(cs => cs
    .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt must be present")
    .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must verify")));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();

var result = message.Validate(validator);
```

### Trust Policy Aggregation

In V2, trust is evaluated by a compiled trust plan (`CompiledTrustPlan`) over facts produced by enabled trust packs (`ITrustPack`).

Some packs provide secure defaults (for example, certificate trust defaults require a trusted chain); others only produce facts and require you to supply an explicit `TrustPlanPolicy` (for example, Azure Key Vault).

```csharp
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableCertificateSupport(cert => cert.UseSystemTrust());
validation.EnableAzureKeyVaultSupport(akv => akv.AllowKidPatterns(new[] { "https://prod.vault.azure.net/keys/*" }).OfflineOnly());
validation.EnableMstSupport(mst => mst.VerifyReceipts(new Uri("https://dataplane.codetransparency.azure.net")));

var trustPolicy = TrustPlanPolicy.PrimarySigningKey(k => k
        .RequireFact<X509ChainTrustedFact>(f => f.IsTrusted, "Signing certificate chain must be trusted"))
    .And(TrustPlanPolicy.Message(m => m
        .RequireFact<AzureKeyVaultKidAllowedFact>(f => f.IsAllowed, "AKV kid must match an allowed pattern")))
    .And(TrustPlanPolicy.AnyCounterSignature(cs => cs
        .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt must be present")
        .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must verify")));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();
```

For more details, see the Trust Policy guide.

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

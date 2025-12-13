# CoseSign1.Certificates.AzureTrustedSigning

Azure Trusted Signing integration for COSE Sign1 message signing.

## Installation

```bash
dotnet add package CoseSign1.Certificates.AzureTrustedSigning --version 2.0.0-preview
```

## Overview

Integrates with Microsoft Azure Trusted Signing service for cloud-based, HSM-backed code signing. Provides enterprise-grade security with FIPS 140-2 Level 3 compliance.

## Key Features

- ✅ **Cloud-Based Signing** - No local private keys required
- ✅ **HSM Protection** - Keys secured in FIPS 140-2 Level 3 hardware
- ✅ **Certificate Management** - Automatic certificate lifecycle
- ✅ **Azure Identity** - Seamless authentication with managed identities
- ✅ **DID:x509 Support** - Automatic DID generation from Azure certificates
- ✅ **High Availability** - Built for enterprise reliability

## Quick Start

### Basic Setup

```csharp
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.AzureTrustedSigning;
using CoseSign1.Direct;

// Create Azure signing context
var signContext = new AzSignContext(
    endpoint: new Uri("https://myaccount.codesigning.azure.net"),
    accountName: "myaccount",
    certificateProfileName: "myprofile");

// Create signing service
using var signingService = new AzureTrustedSigningService(signContext);

// Create factory and sign
using var factory = new DirectSignatureFactory(signingService);

byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    payload: myPayload,
    contentType: "application/json");
```

### With Custom Authentication

```csharp
using Azure.Identity;

// Use specific Azure credentials
var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
{
    ExcludeVisualStudioCredential = true,
    ExcludeVisualStudioCodeCredential = true,
    ManagedIdentityClientId = "your-managed-identity-client-id"
});

var signContext = new AzSignContext(
    endpoint: new Uri("https://myaccount.codesigning.azure.net"),
    accountName: "myaccount",
    certificateProfileName: "myprofile",
    credential: credential);

using var signingService = new AzureTrustedSigningService(signContext);
```

### With Service Principal

```csharp
using Azure.Identity;

var credential = new ClientSecretCredential(
    tenantId: "your-tenant-id",
    clientId: "your-client-id",
    clientSecret: "your-client-secret");

var signContext = new AzSignContext(
    endpoint: new Uri("https://myaccount.codesigning.azure.net"),
    accountName: "myaccount",
    certificateProfileName: "myprofile",
    credential: credential);

using var signingService = new AzureTrustedSigningService(signContext);
```

## Components

### AzureTrustedSigningService

Main signing service that implements `ISigningService<CertificateSigningOptions>`:

```csharp
public class AzureTrustedSigningService : CertificateSigningService
{
    public AzureTrustedSigningService(
        AzSignContext signContext,
        ICertificateChainBuilder? chainBuilder = null,
        SigningServiceMetadata? serviceMetadata = null);
}
```

### AzureTrustedSigningCertificateSource

Certificate source for Azure Trusted Signing certificates:

```csharp
public class AzureTrustedSigningCertificateSource : ICertificateSource
{
    // Provides certificate chain from Azure Trusted Signing
}
```

### AzureTrustedSigningDidX509

DID:x509 integration for Azure certificates:

```csharp
// Generate DID:x509 from Azure certificate
var did = await AzureTrustedSigningDidX509.CreateDidAsync(signingService);
Console.WriteLine(did.ToUri());
// Output: did:x509:0:sha256:base64cert::subject:CN:My%20Signer
```

## Azure Setup

### Prerequisites

1. **Azure Subscription** with Azure Trusted Signing access
2. **Trusted Signing Account** in Azure
3. **Certificate Profile** configured

### Create Trusted Signing Account

```bash
# Create via Azure CLI
az resource create \
    --resource-group myResourceGroup \
    --resource-type Microsoft.CodeSigning/codeSigningAccounts \
    --name mySigningAccount \
    --location eastus \
    --properties '{}'
```

### Configure Certificate Profile

Configure in Azure Portal:
1. Navigate to your Trusted Signing account
2. Create a Certificate Profile
3. Choose certificate type (Public Trust, Private Trust)
4. Configure key properties

### Assign Permissions

```bash
# Assign signer role
az role assignment create \
    --role "Code Signing Certificate Profile Signer" \
    --assignee your-principal-id \
    --scope /subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.CodeSigning/codeSigningAccounts/myAccount
```

## Authentication Methods

### Managed Identity (Recommended)

```csharp
// In Azure environments, managed identity is automatic
var signContext = new AzSignContext(
    endpoint: new Uri("https://myaccount.codesigning.azure.net"),
    accountName: "myaccount",
    certificateProfileName: "myprofile");
```

### Azure CLI

```bash
# Login first
az login

# Then use default credentials
var credential = new AzureCliCredential();
```

### Environment Variables

```bash
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
```

## SCITT Compliance

Azure Trusted Signing with CWT claims for SCITT:

```csharp
using CoseSign1.Headers;

var claims = new CwtClaims
{
    Subject = "pkg:npm/my-package@1.0.0",
    IssuedAt = DateTimeOffset.UtcNow
};

var contributor = new CwtClaimsHeaderContributor(
    claims,
    autoGenerateIssuer: true);  // DID:x509 from Azure cert

var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: new[] { contributor });
```

## Supported Algorithms

Azure Trusted Signing supports:

| Key Type | COSE Algorithm | Notes |
|----------|----------------|-------|
| RSA 2048 | PS256 | RSASSA-PSS with SHA-256 |
| RSA 3072 | PS384 | RSASSA-PSS with SHA-384 |
| RSA 4096 | PS512 | RSASSA-PSS with SHA-512 |
| ECDSA P-256 | ES256 | Recommended for most use cases |
| ECDSA P-384 | ES384 | Higher security |

Algorithm selection is based on your certificate profile configuration.

## Error Handling

```csharp
try
{
    using var service = new AzureTrustedSigningService(signContext);
    // ... signing operations
}
catch (Azure.RequestFailedException ex) when (ex.Status == 403)
{
    Console.WriteLine("Access denied. Check role assignments.");
}
catch (Azure.RequestFailedException ex) when (ex.Status == 404)
{
    Console.WriteLine("Account or profile not found. Check configuration.");
}
catch (Azure.Identity.AuthenticationFailedException ex)
{
    Console.WriteLine($"Authentication failed: {ex.Message}");
}
```

## Testing

For unit testing, mock the signing service:

```csharp
var mockService = new Mock<ISigningService<CertificateSigningOptions>>();
mockService.Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
    .Returns(testCoseSigner);

var factory = new DirectSignatureFactory(mockService.Object);
```

## See Also

- [CoseSign1.Certificates](../CoseSign1.Certificates/README.md) - Local certificate signing
- [Azure Trusted Signing Documentation](https://learn.microsoft.com/azure/trusted-signing/)
- [CLI Azure Plugin](../docs/plugins/azure-plugin.md) - Command-line integration

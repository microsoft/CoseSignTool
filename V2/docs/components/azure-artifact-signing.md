# CoseSign1.Certificates.AzureArtifactSigning

Azure Artifact Signing integration for CoseSignTool V2.

## Overview

This package provides integration with [Azure Artifact Signing](https://learn.microsoft.com/azure/trusted-signing/), enabling cloud-based COSE signing with managed certificates and HSM-backed keys.

## Installation

```bash
dotnet add package CoseSign1.Certificates.AzureArtifactSigning --version 2.0.0-preview
```

## Key Features

- ✅ **Azure Integration** - Native Azure SDK integration
- ✅ **HSM-Backed Keys** - Private keys never leave Azure
- ✅ **Managed Certificates** - Azure manages certificate lifecycle
- ✅ **EV Certificates** - Extended Validation certificate support

## Quick Start

```csharp
using CoseSign1.Certificates.AzureArtifactSigning;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using Azure.Identity;

// Configure Azure Artifact Signing
var options = new AzureArtifactSigningOptions
{
    Endpoint = new Uri("https://myaccount.codesigning.azure.net"),
    AccountName = "myaccount",
    CertificateProfileName = "myprofile",
    Credential = new DefaultAzureCredential()
};

// Create signing service
var service = new AzureArtifactSigningService(options);

// Use with signature factory
var factory = new CoseSign1MessageFactory(service);
byte[] signature = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(payload, "application/json");
```

## Configuration

### AzureArtifactSigningOptions

| Property | Description | Required |
|----------|-------------|----------|
| `Endpoint` | Azure Artifact Signing endpoint URI | Yes |
| `AccountName` | Code signing account name | Yes |
| `CertificateProfileName` | Certificate profile name | Yes |
| `Credential` | Azure credential for authentication | Yes |

### Authentication

The service supports all Azure Identity credential types:

```csharp
// Default Azure Credential (recommended for most scenarios)
var credential = new DefaultAzureCredential();

// Managed Identity (Azure VMs, App Service, etc.)
var credential = new ManagedIdentityCredential();

// Service Principal
var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);

// Interactive browser (development)
var credential = new InteractiveBrowserCredential();
```

## Certificate Source

For scenarios where you need just the certificate:

```csharp
var source = new AzureArtifactSigningCertificateSource(options);
var cert = await source.GetCertificateAsync();
```

## CLI Usage

With the Azure Artifact Signing plugin:

```bash
# Sign with Azure Artifact Signing
CoseSignTool sign-azure document.json \
    --ats-endpoint https://myaccount.codesigning.azure.net \
    --ats-account-name myaccount \
    --ats-cert-profile-name myprofile
```

## Security Considerations

- Private keys are managed by Azure and never leave the HSM
- Use Managed Identity in Azure environments
- Store credentials securely (never in source control)
- Use least-privilege access policies

## See Also

- [Azure Artifact Signing Documentation](https://learn.microsoft.com/azure/trusted-signing/)
- [Azure Plugin](../plugins/azure-plugin.md)
- [Certificate Management](../architecture/certificate-management.md)

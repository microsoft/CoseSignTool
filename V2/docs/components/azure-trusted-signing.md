# CoseSign1.Certificates.AzureTrustedSigning

Azure Trusted Signing integration for CoseSignTool V2.

## Overview

This package provides integration with [Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/), enabling cloud-based COSE signing with managed certificates and HSM-backed keys.

## Installation

```bash
dotnet add package CoseSign1.Certificates.AzureTrustedSigning --version 2.0.0-preview
```

## Key Features

- ✅ **Azure Integration** - Native Azure SDK integration
- ✅ **HSM-Backed Keys** - Private keys never leave Azure
- ✅ **Managed Certificates** - Azure manages certificate lifecycle
- ✅ **EV Certificates** - Extended Validation certificate support

## Quick Start

```csharp
using CoseSign1.Certificates.AzureTrustedSigning;
using CoseSign1.Factories;
using Azure.Identity;

// Configure Azure Trusted Signing
var options = new AzureTrustedSigningOptions
{
    Endpoint = new Uri("https://myaccount.codesigning.azure.net"),
    AccountName = "myaccount",
    CertificateProfileName = "myprofile",
    Credential = new DefaultAzureCredential()
};

// Create signing service
var service = new AzureTrustedSigningService(options);

// Use with signature factory
var factory = new CoseSign1MessageFactory(service);
byte[] signature = factory.CreateDirectCoseSign1MessageBytes(payload, "application/json");
```

## Configuration

### AzureTrustedSigningOptions

| Property | Description | Required |
|----------|-------------|----------|
| `Endpoint` | Azure Trusted Signing endpoint URI | Yes |
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
var source = new AzureTrustedSigningCertificateSource(options);
var cert = await source.GetCertificateAsync();
```

## CLI Usage

With the Azure Trusted Signing plugin:

```bash
# Sign with Azure Trusted Signing
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

- [Azure Trusted Signing Documentation](https://learn.microsoft.com/azure/trusted-signing/)
- [Azure Plugin](../plugins/azure-plugin.md)
- [Certificate Management](../architecture/certificate-management.md)

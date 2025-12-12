# CoseSignTool.AzureTrustedSigning.Plugin

**Package**: `CoseSignTool.AzureTrustedSigning.Plugin`  
**Purpose**: Azure Trusted Signing integration for the CoseSignTool CLI

## Overview

This plugin enables cloud-based code signing using Azure Trusted Signing service. Azure Trusted Signing provides:
- Managed certificate lifecycle
- Hardware Security Module (HSM) protected keys
- Compliance with industry standards
- Audit logging and access control

## Prerequisites

1. **Azure Subscription** with Azure Trusted Signing enabled
2. **Trusted Signing Account** configured in Azure
3. **Certificate Profile** created in your Trusted Signing account
4. **Azure Authentication** configured (managed identity, Azure CLI, or service principal)

## Commands

### sign-azure

Sign a payload using Azure Trusted Signing service.

```bash
CoseSignTool sign-azure <payload> --ats-endpoint <url> --ats-account-name <name> --ats-cert-profile-name <profile> [options]
```

**Options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--ats-endpoint` | Yes | Azure Trusted Signing service endpoint URL |
| `--ats-account-name` | Yes | Name of your Trusted Signing account |
| `--ats-cert-profile-name` | Yes | Name of the certificate profile to use |
| `--output`, `-o` | No | Output path for signature file |
| `--detached`, `-d` | No | Create detached signature |
| `--signature-type`, `-t` | No | Signature type: direct, embedded, indirect |
| `--content-type`, `-c` | No | MIME type of payload |

**Examples**:
```bash
# Sign with Azure Trusted Signing
CoseSignTool sign-azure document.json \
    --ats-endpoint https://myaccount.codesigning.azure.net \
    --ats-account-name myaccount \
    --ats-cert-profile-name production

# Create indirect signature
CoseSignTool sign-azure document.json \
    --ats-endpoint https://myaccount.codesigning.azure.net \
    --ats-account-name myaccount \
    --ats-cert-profile-name production \
    --signature-type indirect
```

## Authentication

The plugin uses Azure Identity for authentication. The following authentication methods are supported (in order of precedence):

1. **Managed Identity** - Recommended for Azure-hosted environments
2. **Azure CLI** - Uses `az login` credentials
3. **Environment Variables** - Service principal credentials
4. **Visual Studio** - Developer authentication

### Using Managed Identity (Azure VMs, App Service, etc.)

No additional configuration needed. The plugin automatically uses the managed identity.

### Using Azure CLI

```bash
# Login to Azure
az login

# Run signing command
CoseSignTool sign-azure document.json --ats-endpoint ... --ats-account-name ... --ats-cert-profile-name ...
```

### Using Service Principal

Set environment variables:
```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

## Azure Setup

### 1. Create a Trusted Signing Account

```bash
az resource create \
    --resource-group myResourceGroup \
    --resource-type Microsoft.CodeSigning/codeSigningAccounts \
    --name mySigningAccount \
    --location eastus \
    --properties '{}'
```

### 2. Create a Certificate Profile

Configure through Azure Portal or ARM template:
- Choose certificate type (Public Trust, Private Trust)
- Set validity period
- Configure key properties

### 3. Grant Access

Assign the "Code Signing Certificate Profile Signer" role:
```bash
az role assignment create \
    --role "Code Signing Certificate Profile Signer" \
    --assignee your-identity-principal-id \
    --scope /subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.CodeSigning/codeSigningAccounts/mySigningAccount
```

## Error Handling

| Error | Cause | Solution |
|-------|-------|----------|
| `AuthenticationError` | Invalid credentials | Check Azure login or service principal |
| `Forbidden` | Insufficient permissions | Verify role assignment |
| `NotFound` | Invalid account or profile | Check account and profile names |
| `InvalidEndpoint` | Malformed endpoint URL | Use full endpoint URL |

## Security Best Practices

1. **Use Managed Identity** when running in Azure
2. **Least Privilege** - Only grant signing permissions to required identities
3. **Audit Logging** - Enable Azure Monitor for signing operations
4. **Network Security** - Use private endpoints when possible
5. **Key Rotation** - Let Azure manage certificate lifecycle

## Supported Algorithms

Azure Trusted Signing supports:
- **RSA**: PS256, PS384, PS512 (RSASSA-PSS)
- **ECDSA**: ES256, ES384, ES512

The algorithm is determined by your certificate profile configuration.

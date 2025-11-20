# Certificate Provider Plugin Architecture

CoseSignTool supports an extensible **Certificate Provider Plugin Architecture** that allows you to use different signing key sources beyond local PFX files and certificate stores. This enables integration with cloud-based signing services, hardware security modules (HSMs), and other certificate providers.

## Table of Contents
- [Overview](#overview)
- [Built-in Providers](#built-in-providers)
- [Using Certificate Providers](#using-certificate-providers)
- [Azure Trusted Signing](#azure-trusted-signing)
  - [Prerequisites](#prerequisites)
  - [Authentication](#authentication)
  - [Usage Examples](#usage-examples)
- [Creating Custom Certificate Providers](#creating-custom-certificate-providers)
  - [Plugin Interface](#plugin-interface)
  - [Implementing a Provider](#implementing-a-provider)
  - [Deployment](#deployment)
- [Security Best Practices](#security-best-practices)

## Overview

Certificate provider plugins extend CoseSignTool's signing capabilities by implementing the `ICertificateProviderPlugin` interface. Each plugin provides:
- A unique provider name
- Configuration parameters
- A factory method to create signing key providers

The plugin architecture automatically:
- Discovers plugins from `*.Plugin.dll` assemblies
- Merges provider-specific options with command options
- Validates configuration before creating providers
- Provides consistent error handling and logging

## Built-in Providers

### Local Certificate Provider (Default)
When no `--cert-provider` is specified, CoseSignTool uses local certificate loading:
- **PFX files**: Load certificates with private keys from `.pfx` files
- **Certificate stores**: Access certificates from Windows/macOS/Linux certificate stores

### Azure Trusted Signing
Microsoft's cloud-based signing service providing:
- **Managed certificates**: Microsoft-managed certificate lifecycle
- **Compliance**: FIPS 140-2 Level 3 HSM-backed signing
- **Integration**: Seamless Azure DevOps and GitHub Actions integration

See [Azure Trusted Signing](#azure-trusted-signing) section for details.

## Using Certificate Providers

### Basic Syntax
```bash
CoseSignTool sign --payload <file> --cert-provider <provider-name> [provider-options]
```

### List Available Providers
```bash
CoseSignTool sign --help
# Shows all available certificate providers and their parameters
```

### Example with Azure Trusted Signing
```bash
CoseSignTool sign \
  --payload payload.txt \
  --signature signature.cose \
  --cert-provider azure-trusted-signing \
  --ats-endpoint https://contoso.codesigning.azure.net \
  --ats-account-name ContosoAccount \
  --ats-cert-profile-name ContosoProfile
```

## Azure Trusted Signing

Azure Trusted Signing is Microsoft's cloud-based code signing service that provides secure, compliant signing without managing certificates locally.

### Prerequisites

1. **Azure Subscription**: Active Azure subscription with billing enabled
2. **Azure Trusted Signing Account**: Created in Azure Portal
3. **Certificate Profile**: Configured with appropriate certificate type
4. **Permissions**: Your Azure identity must have:
   - `Code Signing Certificate Profile Signer` role on the certificate profile
   - Access to the Azure Trusted Signing account

### Authentication

Azure Trusted Signing uses **Azure DefaultAzureCredential** for authentication, which automatically tries authentication methods in this order:

1. **Environment Variables** (recommended for CI/CD)
   ```bash
   export AZURE_TENANT_ID="your-tenant-id"
   export AZURE_CLIENT_ID="your-client-id"
   export AZURE_CLIENT_SECRET="your-client-secret"
   ```

2. **Managed Identity** (recommended for Azure VMs/containers)
   - System-assigned or user-assigned managed identity
   - Automatically available in Azure environments

3. **Azure CLI** (recommended for local development)
   ```bash
   az login
   az account show  # Verify correct subscription
   ```

4. **Azure PowerShell**
   ```powershell
   Connect-AzAccount
   ```

5. **Visual Studio** / **Visual Studio Code**
   - Sign in to Azure through IDE

**Security Note**: DefaultAzureCredential **excludes** interactive browser authentication by default to prevent accidental prompts in unattended scenarios.

### Usage Examples

#### Basic Signing
```bash
# Using Azure CLI authentication (local development)
az login

CoseSignTool sign \
  --payload document.pdf \
  --signature document.pdf.cose \
  --cert-provider azure-trusted-signing \
  --ats-endpoint https://contoso.codesigning.azure.net \
  --ats-account-name ContosoAccount \
  --ats-cert-profile-name ContosoProfile
```

#### CI/CD Pipeline (GitHub Actions)
```yaml
name: Sign Release
on:
  release:
    types: [created]

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Sign artifacts
        env:
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
        run: |
          CoseSignTool sign \
            --payload release-artifact.bin \
            --signature release-artifact.bin.cose \
            --cert-provider azure-trusted-signing \
            --ats-endpoint ${{ secrets.ATS_ENDPOINT }} \
            --ats-account-name ${{ secrets.ATS_ACCOUNT_NAME }} \
            --ats-cert-profile-name ${{ secrets.ATS_CERT_PROFILE_NAME }}
```

#### Azure DevOps Pipeline
```yaml
trigger:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: AzureCLI@2
  inputs:
    azureSubscription: 'MyServiceConnection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      CoseSignTool sign \
        --payload $(Build.ArtifactStagingDirectory)/artifact.bin \
        --signature $(Build.ArtifactStagingDirectory)/artifact.bin.cose \
        --cert-provider azure-trusted-signing \
        --ats-endpoint $(ATS_ENDPOINT) \
        --ats-account-name $(ATS_ACCOUNT_NAME) \
        --ats-cert-profile-name $(ATS_CERT_PROFILE_NAME)
```

#### Embedded Signature with SCITT Claims
```bash
CoseSignTool sign \
  --payload payload.txt \
  --signature payload.csm \
  --embed-payload \
  --cert-provider azure-trusted-signing \
  --ats-endpoint https://contoso.codesigning.azure.net \
  --ats-account-name ContosoAccount \
  --ats-cert-profile-name ContosoProfile \
  --cwt-subject "software.release.v2.0" \
  --cwt-audience "production.systems" \
  --cwt-claims "exp:2025-12-31T23:59:59Z"
```

#### Batch Signing with Environment Variables
```bash
# Set Azure Trusted Signing configuration
export ATS_ENDPOINT="https://contoso.codesigning.azure.net"
export ATS_ACCOUNT_NAME="ContosoAccount"
export ATS_CERT_PROFILE_NAME="ContosoProfile"

# Azure authentication (service principal)
export AZURE_TENANT_ID="00000000-0000-0000-0000-000000000000"
export AZURE_CLIENT_ID="00000000-0000-0000-0000-000000000000"
export AZURE_CLIENT_SECRET="your-client-secret"

# Sign multiple files
for file in *.bin; do
  CoseSignTool sign \
    --payload "$file" \
    --signature "${file}.cose" \
    --cert-provider azure-trusted-signing \
    --ats-endpoint "$ATS_ENDPOINT" \
    --ats-account-name "$ATS_ACCOUNT_NAME" \
    --ats-cert-profile-name "$ATS_CERT_PROFILE_NAME"
done
```

### Azure Trusted Signing Parameters

| Parameter | Alias | Required | Description |
|-----------|-------|----------|-------------|
| `--ats-endpoint` | `-e` | Yes | Azure Trusted Signing endpoint URL (e.g., `https://contoso.codesigning.azure.net`) |
| `--ats-account-name` | `-a` | Yes | Azure Trusted Signing account name |
| `--ats-cert-profile-name` | `-p` | Yes | Certificate profile name within the account |

### Troubleshooting Azure Trusted Signing

#### Authentication Failures
```
Error: Azure.Identity.AuthenticationFailedException
```
**Solution**: Verify authentication method is configured correctly
```bash
# Check Azure CLI authentication
az account show

# Check environment variables
echo $AZURE_TENANT_ID
echo $AZURE_CLIENT_ID

# Test service principal authentication
az login --service-principal \
  --username $AZURE_CLIENT_ID \
  --password $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID
```

#### Permission Denied
```
Error: Authorization failed. User does not have permission.
```
**Solution**: Verify RBAC role assignment
```bash
# Check role assignments
az role assignment list \
  --assignee $AZURE_CLIENT_ID \
  --query "[?roleDefinitionName=='Code Signing Certificate Profile Signer']"
```

#### Invalid Parameters
```
Error: Certificate provider 'azure-trusted-signing' cannot create a provider with the given configuration.
```
**Solution**: Verify all required parameters are provided
```bash
CoseSignTool sign \
  --cert-provider azure-trusted-signing \
  --ats-endpoint "https://your-endpoint.codesigning.azure.net" \
  --ats-account-name "YourAccount" \
  --ats-cert-profile-name "YourProfile" \
  --payload test.txt
```

## Creating Custom Certificate Providers

### Plugin Interface

All certificate provider plugins must implement `ICertificateProviderPlugin`:

```csharp
public interface ICertificateProviderPlugin
{
    /// <summary>
    /// Gets the unique name of this certificate provider (e.g., "azure-trusted-signing").
    /// Used with the --cert-provider command line parameter.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Gets the available command-line options for this provider.
    /// Keys are option names (e.g., "--ats-endpoint"), values are descriptions.
    /// </summary>
    IReadOnlyDictionary<string, string> GetProviderOptions();

    /// <summary>
    /// Determines if this provider can create a signing key provider with the given configuration.
    /// Used for validation before attempting to create the provider.
    /// </summary>
    /// <param name="configuration">Configuration containing command-line parameters.</param>
    /// <returns>True if all required parameters are present, false otherwise.</returns>
    bool CanCreateProvider(IConfiguration configuration);

    /// <summary>
    /// Creates a signing key provider instance using the provided configuration.
    /// </summary>
    /// <param name="configuration">Configuration containing command-line parameters.</param>
    /// <param name="logger">Optional logger for diagnostic messages.</param>
    /// <returns>An ICoseSigningKeyProvider instance ready for signing operations.</returns>
    ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null);
}
```

### Implementing a Provider

Here's a complete example of a custom HSM certificate provider plugin:

```csharp
using CoseSign1.Abstractions.Interfaces;
using CoseSignTool.Abstractions.Interfaces;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace MyCompany.Hsm.Plugin
{
    /// <summary>
    /// Certificate provider plugin for hardware security modules (HSMs).
    /// </summary>
    public class HsmCertificateProviderPlugin : ICertificateProviderPlugin
    {
        /// <inheritdoc/>
        public string ProviderName => "hsm";

        /// <inheritdoc/>
        public IReadOnlyDictionary<string, string> GetProviderOptions()
        {
            return new Dictionary<string, string>
            {
                ["--hsm-slot"] = "HSM slot number (required)",
                ["--hsm-pin"] = "HSM PIN for authentication (required)",
                ["--hsm-key-label"] = "Key label within the HSM (required)",
                ["--hsm-library-path"] = "Path to PKCS#11 library (optional, uses system default if not specified)"
            };
        }

        /// <inheritdoc/>
        public bool CanCreateProvider(IConfiguration configuration)
        {
            // Validate required parameters
            return !string.IsNullOrWhiteSpace(configuration["hsm-slot"]) &&
                   !string.IsNullOrWhiteSpace(configuration["hsm-pin"]) &&
                   !string.IsNullOrWhiteSpace(configuration["hsm-key-label"]);
        }

        /// <inheritdoc/>
        public ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null)
        {
            logger?.LogInformation("Creating HSM certificate provider");

            // Extract configuration
            string slot = configuration["hsm-slot"]!;
            string pin = configuration["hsm-pin"]!;
            string keyLabel = configuration["hsm-key-label"]!;
            string? libraryPath = configuration["hsm-library-path"];

            // Create and return the provider
            return new HsmCoseSigningKeyProvider(slot, pin, keyLabel, libraryPath, logger);
        }
    }

    /// <summary>
    /// Signing key provider implementation for HSM.
    /// </summary>
    internal class HsmCoseSigningKeyProvider : ICoseSigningKeyProvider
    {
        private readonly string _slot;
        private readonly string _pin;
        private readonly string _keyLabel;
        private readonly string? _libraryPath;
        private readonly IPluginLogger? _logger;

        public HsmCoseSigningKeyProvider(
            string slot,
            string pin,
            string keyLabel,
            string? libraryPath,
            IPluginLogger? logger)
        {
            _slot = slot;
            _pin = pin;
            _keyLabel = keyLabel;
            _libraryPath = libraryPath;
            _logger = logger;
        }

        public X509Certificate2? GetSigningCertificate()
        {
            _logger?.LogInformation($"Retrieving certificate for key '{_keyLabel}' from HSM slot {_slot}");
            
            // Initialize PKCS#11 library and retrieve certificate
            // Implementation depends on your HSM provider's library
            var pkcs11 = InitializePkcs11(_libraryPath);
            var session = pkcs11.OpenSession(_slot, _pin);
            var certificate = session.GetCertificate(_keyLabel);
            
            return certificate;
        }

        public List<X509Certificate2>? GetCertificateChain()
        {
            _logger?.LogInformation("Retrieving certificate chain from HSM");
            
            // Retrieve additional certificates from HSM if available
            var pkcs11 = InitializePkcs11(_libraryPath);
            var session = pkcs11.OpenSession(_slot, _pin);
            var chain = session.GetCertificateChain(_keyLabel);
            
            return chain;
        }

        public RSA? ProvideRSAKey(PublicKey? publicKey = null)
        {
            _logger?.LogInformation($"Providing RSA key for '{_keyLabel}' from HSM");
            
            // Create RSA wrapper that delegates to HSM
            var pkcs11 = InitializePkcs11(_libraryPath);
            var session = pkcs11.OpenSession(_slot, _pin);
            var rsaKey = session.GetRsaKey(_keyLabel);
            
            return rsaKey;
        }

        private IPkcs11Library InitializePkcs11(string? libraryPath)
        {
            // Initialize PKCS#11 library
            // This is a placeholder - actual implementation depends on your HSM
            throw new NotImplementedException("Initialize your PKCS#11 library here");
        }
    }
}
```

### Project Structure

Create a plugin project following the naming convention for automatic CI/CD packaging:

```xml
<!-- MyCompany.Hsm.Plugin.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>MyCompany.Hsm.Plugin</AssemblyName>
    <!-- Important: Assembly name must end with .Plugin.dll -->
  </PropertyGroup>

  <ItemGroup>
    <!-- Reference CoseSignTool.Abstractions for plugin interfaces -->
    <ProjectReference Include="..\CoseSignTool.Abstractions\CoseSignTool.Abstractions.csproj" />
    
    <!-- Add your HSM library dependencies -->
    <PackageReference Include="Net.Pkcs11Interop" Version="5.1.2" />
  </ItemGroup>
</Project>
```

### Deployment

#### Option 1: Manual Deployment
1. Build your plugin project
2. Copy the compiled `*.Plugin.dll` and dependencies to the `plugins` directory next to `CoseSignTool.exe`
3. Run CoseSignTool - it will automatically discover your plugin

```bash
# Build plugin
dotnet build MyCompany.Hsm.Plugin/MyCompany.Hsm.Plugin.csproj -c Release

# Deploy to CoseSignTool plugins directory
cp MyCompany.Hsm.Plugin/bin/Release/net8.0/*.dll /path/to/CoseSignTool/plugins/
```

#### Option 2: Automatic CI/CD Packaging
Follow the naming convention in [PluginNamingConventions.md](./PluginNamingConventions.md):
- Project file: `MyCompany.Hsm.Plugin.csproj`
- Assembly name: `MyCompany.Hsm.Plugin.dll`

GitHub Actions will automatically include your plugin in releases!

### Testing Your Plugin

Create unit tests for your plugin:

```csharp
[TestFixture]
public class HsmCertificateProviderPluginTests
{
    [Test]
    public void ProviderName_ReturnsExpectedValue()
    {
        var plugin = new HsmCertificateProviderPlugin();
        Assert.That(plugin.ProviderName, Is.EqualTo("hsm"));
    }

    [Test]
    public void CanCreateProvider_WithAllRequiredParameters_ReturnsTrue()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["hsm-slot"] = "0",
                ["hsm-pin"] = "1234",
                ["hsm-key-label"] = "signing-key"
            })
            .Build();

        var plugin = new HsmCertificateProviderPlugin();
        Assert.That(plugin.CanCreateProvider(configuration), Is.True);
    }

    [Test]
    public void CanCreateProvider_MissingRequiredParameter_ReturnsFalse()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["hsm-slot"] = "0"
                // Missing pin and key-label
            })
            .Build();

        var plugin = new HsmCertificateProviderPlugin();
        Assert.That(plugin.CanCreateProvider(configuration), Is.False);
    }

    [Test]
    public void CreateProvider_WithValidConfiguration_ReturnsProvider()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["hsm-slot"] = "0",
                ["hsm-pin"] = "1234",
                ["hsm-key-label"] = "signing-key"
            })
            .Build();

        var plugin = new HsmCertificateProviderPlugin();
        var provider = plugin.CreateProvider(configuration);
        
        Assert.That(provider, Is.Not.Null);
        Assert.That(provider, Is.InstanceOf<ICoseSigningKeyProvider>());
    }
}
```

## Security Best Practices

### 1. Never Hardcode Credentials
❌ **Bad**:
```csharp
public ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null)
{
    string clientSecret = "hardcoded-secret-value"; // NEVER DO THIS!
    // ...
}
```

✅ **Good**:
```csharp
public ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null)
{
    // Read from configuration (environment variables, Azure Key Vault, etc.)
    string? clientSecret = configuration["client-secret"];
    // ...
}
```

### 2. Use Azure DefaultAzureCredential Pattern
For Azure integrations, use `DefaultAzureCredential` with appropriate exclusions:

```csharp
var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
{
    // Exclude interactive browser to prevent prompts in CI/CD
    ExcludeInteractiveBrowserCredential = true
});
```

### 3. Validate All Configuration Inputs
```csharp
public bool CanCreateProvider(IConfiguration configuration)
{
    string? endpoint = configuration["endpoint"];
    
    // Validate format
    if (string.IsNullOrWhiteSpace(endpoint))
        return false;
    
    // Validate URL format
    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out _))
        return false;
    
    // Validate scheme
    if (!endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        return false;
    
    return true;
}
```

### 4. Handle Sensitive Data Securely
- Use `SecureString` for passwords when possible
- Clear sensitive data from memory after use
- Never log credentials or tokens
- Use Azure Key Vault or similar for secret storage

```csharp
public ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null)
{
    string? pin = configuration["hsm-pin"];
    
    try
    {
        // Use the PIN
        var provider = new HsmProvider(pin);
        return provider;
    }
    finally
    {
        // Clear sensitive data
        if (pin != null)
        {
            // Zero out the string in memory if possible
            // In production, consider using SecureString
        }
    }
}
```

### 5. Use Minimal Permissions
- Request only the permissions your plugin needs
- For Azure: Use specific RBAC roles, not Owner/Contributor
- For HSMs: Use dedicated slots/partitions with limited access
- Implement least privilege principle

### 6. Implement Proper Error Handling
```csharp
public ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null)
{
    try
    {
        // Create provider
        return new MyProvider(configuration);
    }
    catch (AuthenticationException ex)
    {
        // Don't expose sensitive auth details in error messages
        logger?.LogError("Authentication failed. Verify credentials are configured correctly.");
        throw new InvalidOperationException("Failed to authenticate with certificate provider.", ex);
    }
    catch (Exception ex)
    {
        logger?.LogError($"Unexpected error creating provider: {ex.Message}");
        throw;
    }
}
```

### 7. Audit and Logging
- Log all signing operations (without sensitive data)
- Track who, what, when for compliance
- Monitor for unusual patterns
- Retain logs per compliance requirements

```csharp
logger?.LogInformation($"Signing operation initiated for certificate profile: {profileName}");
logger?.LogInformation($"Certificate thumbprint: {cert.Thumbprint}");
// Never log: tokens, secrets, PINs, private keys
```

## See Also

- [CoseSignTool.md](./CoseSignTool.md) - Main CoseSignTool documentation
- [Plugins.md](./Plugins.md) - General plugin development guide
- [PluginNamingConventions.md](./PluginNamingConventions.md) - Plugin naming requirements
- [CoseSign1.Certificates.AzureTrustedSigning.md](./CoseSign1.Certificates.AzureTrustedSigning.md) - Azure Trusted Signing API documentation
- [SCITTCompliance.md](./SCITTCompliance.md) - SCITT compliance features

# CoseSignTool Plugin System

CoseSignTool supports a plugin architecture that allows developers to extend the tool's functionality with custom commands and integrations. This document provides a comprehensive guide for creating, deploying, and using plugins with CoseSignTool.

## Overview

The plugin system enables:
- **Custom Commands**: Add new commands beyond the built-in `sign`, `validate`, and `get` commands
- **Certificate Provider Plugins**: Extend signing capabilities with custom certificate sources (cloud HSMs, remote signing services, hardware tokens)
- **Third-party Integrations**: Connect with external services, APIs, and workflows
- **Extensible Architecture**: Maintain separation between core functionality and specialized features
- **Security**: Plugins are only loaded from the secure `plugins` subdirectory

## Plugin Types

CoseSignTool supports two types of plugins:

### 1. Command Plugins (`ICoseSignToolPlugin`)
Add new top-level commands to CoseSignTool (e.g., `mst_register`, `indirect-sign`). These plugins:
- Provide standalone commands with their own parameters and behavior
- Are executed as: `CoseSignTool <command-name> [options]`
- Integrate with the main command dispatcher
- Appear in the main help output under "Plugin Commands"

### 2. Certificate Provider Plugins (`ICertificateProviderPlugin`)
Extend the `sign` and `indirect-sign` commands with custom certificate sources. These plugins:
- Provide signing key providers for certificate-based operations
- Are used via: `CoseSignTool sign --cert-provider <provider-name> [provider-options]`
- Integrate directly with the signing workflow
- Appear in help output under "Certificate Providers"
- Enable signing with cloud HSMs, hardware tokens, remote signing services, etc.

> **📖 Detailed Documentation**: For comprehensive certificate provider plugin documentation, see [CertificateProviders.md](CertificateProviders.md).

## Plugin Architecture

### Core Interfaces

The plugin system is built around several key interfaces defined in the `CoseSignTool.Abstractions` namespace:

#### ICoseSignToolPlugin (Command Plugins)
The main plugin interface for command plugins:

```csharp
public interface ICoseSignToolPlugin
{
    string Name { get; }                           // Plugin display name
    string Version { get; }                        // Plugin version (semver recommended)
    string Description { get; }                    // Brief description for help output
    IEnumerable<IPluginCommand> Commands { get; }  // Commands provided by this plugin
    void Initialize(IConfiguration? configuration = null); // Plugin initialization
}
```

#### ICertificateProviderPlugin (Certificate Provider Plugins)
The interface for certificate provider plugins that extend signing capabilities:

```csharp
public interface ICertificateProviderPlugin
{
    string ProviderName { get; }                   // Unique provider identifier (e.g., "azure-trusted-signing")
    string Description { get; }                    // Provider description for help output
    IDictionary<string, string> GetProviderOptions(); // Provider-specific command-line options
    bool CanCreateProvider(IConfiguration configuration); // Check if required parameters are present
    ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null); // Create signing key provider
}
```

**Key Concepts:**
- **Provider Name**: Lowercase, hyphenated identifier used with `--cert-provider` parameter
- **Provider Options**: Custom command-line parameters specific to the provider (e.g., `--ats-endpoint`)
- **Signing Key Provider**: Returns an `ICoseSigningKeyProvider` for certificate-based signing operations
- **Configuration-Based**: Uses `IConfiguration` to access command-line parameters and settings

**Integration with Sign Commands:**
Certificate provider plugins integrate seamlessly with the built-in `sign` and plugin-based `indirect-sign` commands:

```bash
# Using with built-in sign command
CoseSignTool sign --payload file.txt --cert-provider azure-trusted-signing --ats-endpoint https://... --ats-account-name myaccount

# Using with indirect-sign plugin command
CoseSignTool indirect-sign --payload file.txt --signature file.cose --cert-provider azure-trusted-signing --ats-endpoint https://...
```

#### IPluginCommand
Interface for individual commands within a plugin:

```csharp
public interface IPluginCommand
{
    string Name { get; }                           // Command name (e.g., "register", "verify")
    string Description { get; }                    // Command description for help
    string Usage { get; }                          // Usage instructions
    IDictionary<string, string> Options { get; }  // Command-line options mapping
    Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default);
}
```

#### PluginCommandBase
Abstract base class providing common functionality for plugin commands:

```csharp
public abstract class PluginCommandBase : IPluginCommand
{
    // Abstract members to implement
    public abstract string Name { get; }
    public abstract string Description { get; }
    public abstract string Usage { get; }
    public abstract IDictionary<string, string> Options { get; }
    public abstract Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default);
    
    // Helper methods
    protected static string GetRequiredValue(IConfiguration configuration, string key);
    protected static string? GetOptionalValue(IConfiguration configuration, string key, string? defaultValue = null);
}
```

### Exit Codes

Plugins use the `PluginExitCode` enum to indicate command execution results:

- `Success` (0): Command completed successfully
- `HelpRequested` (1): User requested help for the command
- `MissingRequiredOption` (2): A required command-line option was missing
- `UnknownArgument` (3): An unrecognized command-line argument was provided
- `InvalidArgumentValue` (4): A command-line argument had an invalid value
- `MissingArgumentValue` (5): A required argument value was missing
- `UserSpecifiedFileNotFound` (6): A user-specified file was not found
- `UnknownError` (10): An unexpected error occurred

## Creating a Plugin

### Step 1: Create the Plugin Project

Create a new .NET 8.0 class library project:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <AssemblyName>YourCompany.YourService.Plugin</AssemblyName>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\..\CoseSignTool.Abstractions\CoseSignTool.Abstractions.csproj" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.Extensions.Configuration" Version="8.0.0" />
    <PackageReference Include="Microsoft.Extensions.Configuration.Abstractions" Version="8.0.0" />
  </ItemGroup>
</Project>
```

## ⚠️ **Important**: Naming Conventions for Automatic Packaging

### **Assembly Naming Requirements**
- **Runtime Discovery**: The assembly name must end with `.Plugin.dll` for automatic discovery by CoseSignTool
- **CI/CD Auto-Packaging**: The project file must end with `.Plugin.csproj` for automatic inclusion in CI/CD builds

### **CI/CD Auto-Packaging Convention**
The CoseSignTool CI/CD pipeline automatically discovers and packages **any project following this naming pattern**:

```
<ProjectName>.Plugin.csproj
```

#### ✅ **Examples of Auto-Packaged Projects:**
- `CoseSignTool.MST.Plugin.csproj` → Automatically built and deployed
- `CoseSignTool.IndirectSignature.Plugin.csproj` → Automatically built and deployed  
- `YourCompany.CustomSigning.Plugin.csproj` → **Would be automatically built and deployed**
- `AzureKeyVault.Integration.Plugin.csproj` → **Would be automatically built and deployed**

#### ❌ **Examples NOT Auto-Packaged:**
- `CoseSignTool.Utilities.csproj` → Not a plugin (missing `.Plugin` suffix)
- `CustomSigningTool.csproj` → Not a plugin (missing `.Plugin` suffix)
- `MyPlugin.csproj` → Not a plugin (missing `.Plugin` suffix)

### **Zero-Maintenance Plugin Deployment**
When you follow the `.Plugin.csproj` naming convention:

✅ **Automatic CI/CD Integration**: No manual updates needed to build scripts  
✅ **Automatic Packaging**: Plugin included in all releases automatically  
✅ **Automatic Discovery**: Plugin commands appear in CoseSignTool help  
✅ **Automatic Testing**: Plugin included in CI/CD test runs  

### **How It Works**
The CI/CD pipeline uses this discovery command:
```bash
# Automatically finds all plugin projects
PLUGIN_PROJECTS=($(find . -name "*.Plugin.csproj" -type f))
```

This means **adding a new plugin requires no maintenance** - just follow the naming convention!

### Step 2: Implement the Plugin Class

```csharp
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Configuration;

namespace YourCompany.YourService.Plugin;

public class YourServicePlugin : ICoseSignToolPlugin
{
    private readonly List<IPluginCommand> _commands;

    public YourServicePlugin()
    {
        _commands = new List<IPluginCommand>
        {
            new RegisterCommand(),
            new VerifyCommand(),
            new StatusCommand()
        };
    }

    public string Name => "Your Service Integration";

    public string Version => 
        System.Reflection.Assembly.GetExecutingAssembly()
            .GetName()
            .Version?
            .ToString() ?? "1.0.0";

    public string Description => "Provides integration with Your Service for COSE signatures.";

    public IEnumerable<IPluginCommand> Commands => _commands;

    public void Initialize(IConfiguration? configuration = null)
    {
        // Perform plugin initialization
        // - Validate service connectivity
        // - Load default configurations
        // - Set up logging
    }
}
```

### Step 3: Implement Plugin Commands

```csharp
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Configuration;

namespace YourCompany.YourService.Plugin;

public class RegisterCommand : PluginCommandBase
{
    public override string Name => "your_register";

    public override string Description => "Register a COSE signature with Your Service";

    public override string Usage => @"
your_register - Register a COSE signature with Your Service

Usage:
    CoseSignTool your_register --endpoint <url> --payload <file> --signature <file> [options]

Required Options:
    --endpoint     Your Service endpoint URL
    --payload      Path to the original payload file
    --signature    Path to the COSE signature file

Optional Options:
    --timeout      Request timeout in seconds (default: 30)
    --credential   Authentication credential type (default: default)
    --output       Output file for service response
    --metadata     Additional metadata as JSON string
";

    public override IDictionary<string, string> Options => new Dictionary<string, string>
    {
        ["--endpoint"] = "endpoint",
        ["--payload"] = "payload",
        ["--signature"] = "signature",
        ["--timeout"] = "timeout",
        ["--credential"] = "credential",
        ["--output"] = "output",
        ["--metadata"] = "metadata"
    };

    public override async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        try
        {
            // Check for cancellation
            if (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            // Get required configuration values
            string endpoint = GetRequiredValue(configuration, "endpoint");
            string payloadPath = GetRequiredValue(configuration, "payload");
            string signaturePath = GetRequiredValue(configuration, "signature");

            // Get optional configuration values
            string? timeoutStr = GetOptionalValue(configuration, "timeout", "30");
            string credential = GetOptionalValue(configuration, "credential", "default") ?? "default";
            string? outputPath = GetOptionalValue(configuration, "output");
            string? metadata = GetOptionalValue(configuration, "metadata");

            // Validate inputs
            if (!File.Exists(payloadPath))
            {
                Console.Error.WriteLine($"Payload file not found: {payloadPath}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }

            if (!File.Exists(signaturePath))
            {
                Console.Error.WriteLine($"Signature file not found: {signaturePath}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }

            if (!int.TryParse(timeoutStr, out int timeout) || timeout <= 0)
            {
                Console.Error.WriteLine($"Invalid timeout value: {timeoutStr}");
                return PluginExitCode.InvalidArgumentValue;
            }

            // Check for cancellation before expensive operations
            cancellationToken.ThrowIfCancellationRequested();

            // Implement your service integration logic here
            var result = await RegisterWithYourService(
                endpoint, payloadPath, signaturePath, 
                timeout, credential, metadata, cancellationToken);

            // Handle output
            if (!string.IsNullOrEmpty(outputPath))
            {
                await File.WriteAllTextAsync(outputPath, result, cancellationToken);
                Console.WriteLine($"Service response written to: {outputPath}");
            }
            else
            {
                Console.WriteLine("Registration successful");
                Console.WriteLine(result);
            }

            return PluginExitCode.Success;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Operation was cancelled");
            return PluginExitCode.UnknownError;
        }
        catch (ArgumentNullException ex)
        {
            Console.Error.WriteLine($"Missing required option: {ex.ParamName}");
            return PluginExitCode.MissingRequiredOption;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error during registration: {ex.Message}");
            return PluginExitCode.UnknownError;
        }
    }

    private async Task<string> RegisterWithYourService(string endpoint, string payloadPath, 
        string signaturePath, int timeout, string credential, string? metadata, 
        CancellationToken cancellationToken)
    {
        // Implement your service-specific registration logic
        // - Read payload and signature files
        // - Make HTTP requests to your service
        // - Handle authentication
        // - Process service responses
        // - Respect cancellation token
        
        throw new NotImplementedException("Implement your service integration here");
    }
}
```

## Creating a Certificate Provider Plugin

Certificate provider plugins extend the signing capabilities of CoseSignTool by integrating custom certificate sources such as cloud HSMs, hardware security tokens, remote signing services, or proprietary key management systems.

### Use Cases

Certificate provider plugins are ideal for:
- **Cloud HSM Integration**: Azure Key Vault, AWS KMS, Google Cloud KMS
- **Remote Signing Services**: Azure Trusted Signing, DigiCert ONE, GlobalSign DSS
- **Hardware Security Modules**: Thales Luna, Utimaco, nCipher
- **Smart Cards and Tokens**: YubiKey, TPM, PIV cards
- **Custom Key Management**: Proprietary key storage and signing infrastructure

### Step 1: Create the Certificate Provider Plugin Project

Create a .NET 8.0 class library with the certificate provider dependencies:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>YourCompany.YourCertProvider.Plugin</AssemblyName>
    
    <!-- Required for plugin dependency isolation -->
    <CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies>
    <PreserveCompilationContext>true</PreserveCompilationContext>
    <GenerateRuntimeConfigurationFiles>true</GenerateRuntimeConfigurationFiles>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\..\CoseSignTool.Abstractions\CoseSignTool.Abstractions.csproj" />
    <ProjectReference Include="..\..\CoseSign1.Certificates\CoseSign1.Certificates.csproj" />
  </ItemGroup>

  <ItemGroup>
    <!-- Mark all external dependencies for copying -->
    <PackageReference Include="YourHSM.Client" Version="1.0.0">
      <Private>true</Private>
    </PackageReference>
    <PackageReference Include="YourAuth.Library" Version="2.0.0">
      <Private>true</Private>
    </PackageReference>
  </ItemGroup>
</Project>
```

### Step 2: Implement the Certificate Provider Plugin

```csharp
using CoseSign1.Abstractions.Interfaces;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Configuration;

namespace YourCompany.YourCertProvider.Plugin;

/// <summary>
/// Certificate provider plugin for Your HSM/Service integration.
/// </summary>
public class YourCertProviderPlugin : ICertificateProviderPlugin
{
    /// <summary>
    /// Unique identifier for this provider (used with --cert-provider parameter).
    /// Use lowercase with hyphens for multiple words.
    /// </summary>
    public string ProviderName => "your-cert-provider";

    /// <summary>
    /// Human-readable description shown in help output.
    /// </summary>
    public string Description => "Your HSM/Service certificate provider integration";

    /// <summary>
    /// Defines provider-specific command-line options.
    /// These are merged into sign/indirect-sign commands when this provider is selected.
    /// </summary>
    public IDictionary<string, string> GetProviderOptions()
    {
        return new Dictionary<string, string>
        {
            // Use a provider-specific prefix to avoid conflicts
            ["--your-endpoint"] = "your-endpoint",
            ["--your-key-id"] = "your-key-id",
            ["--your-account"] = "your-account",
            ["--your-auth-method"] = "your-auth-method",
            ["-ye"] = "your-endpoint",  // Short aliases
            ["-yk"] = "your-key-id"
        };
    }

    /// <summary>
    /// Checks if the configuration contains all required parameters.
    /// Called before CreateProvider to validate inputs quickly.
    /// </summary>
    public bool CanCreateProvider(IConfiguration configuration)
    {
        // Check for required parameters
        string? endpoint = configuration["your-endpoint"];
        string? keyId = configuration["your-key-id"];
        
        return !string.IsNullOrWhiteSpace(endpoint) && 
               !string.IsNullOrWhiteSpace(keyId);
    }

    /// <summary>
    /// Creates the signing key provider instance.
    /// Called when the user specifies --cert-provider your-cert-provider.
    /// </summary>
    public ICoseSigningKeyProvider CreateProvider(
        IConfiguration configuration, 
        IPluginLogger? logger = null)
    {
        // Extract configuration
        string endpoint = configuration["your-endpoint"] 
            ?? throw new ArgumentException("Missing required parameter: --your-endpoint");
        string keyId = configuration["your-key-id"] 
            ?? throw new ArgumentException("Missing required parameter: --your-key-id");
        string? account = configuration["your-account"];
        string authMethod = configuration["your-auth-method"] ?? "default";

        logger?.LogVerbose($"Creating signing key provider for endpoint: {endpoint}");
        logger?.LogVerbose($"Key ID: {keyId}");
        logger?.LogVerbose($"Authentication method: {authMethod}");

        // Create and return your signing key provider
        return new YourCertProviderSigningKeyProvider(
            endpoint, keyId, account, authMethod, logger);
    }
}
```

### Step 3: Implement the Signing Key Provider

```csharp
using CoseSign1.Abstractions.Interfaces;
using CoseSignTool.Abstractions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace YourCompany.YourCertProvider.Plugin;

/// <summary>
/// Signing key provider that connects to your HSM/service.
/// </summary>
public class YourCertProviderSigningKeyProvider : ICoseSigningKeyProvider
{
    private readonly string _endpoint;
    private readonly string _keyId;
    private readonly string? _account;
    private readonly string _authMethod;
    private readonly IPluginLogger? _logger;
    private X509Certificate2? _certificate;
    private AsymmetricAlgorithm? _privateKey;

    public YourCertProviderSigningKeyProvider(
        string endpoint,
        string keyId,
        string? account,
        string authMethod,
        IPluginLogger? logger)
    {
        _endpoint = endpoint;
        _keyId = keyId;
        _account = account;
        _authMethod = authMethod;
        _logger = logger;
    }

    /// <summary>
    /// Gets the signing certificate (public key portion).
    /// Called by CoseSignTool to obtain the certificate for the signature.
    /// </summary>
    public X509Certificate2 Certificate
    {
        get
        {
            if (_certificate == null)
            {
                _logger?.LogInformation("Retrieving certificate from HSM/service...");
                _certificate = RetrieveCertificateFromService();
            }
            return _certificate;
        }
    }

    /// <summary>
    /// Gets the hash algorithm name supported by this provider.
    /// </summary>
    public HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;

    /// <summary>
    /// Gets the private key for signing operations.
    /// This is typically a remote key that delegates signing to your HSM/service.
    /// </summary>
    public AsymmetricAlgorithm PrivateKey
    {
        get
        {
            if (_privateKey == null)
            {
                _logger?.LogVerbose("Creating remote signing key wrapper...");
                _privateKey = CreateRemoteSigningKey();
            }
            return _privateKey;
        }
    }

    /// <summary>
    /// Gets additional certificates in the certificate chain (optional).
    /// </summary>
    public List<X509Certificate2>? AdditionalCertificates => null;

    /// <summary>
    /// Gets the issuer identifier for this signing key provider (optional).
    /// For certificate-based providers, this can be a DID:X509 identifier.
    /// </summary>
    public string? Issuer => null;

    /// <summary>
    /// Retrieves the certificate from your HSM/service.
    /// </summary>
    private X509Certificate2 RetrieveCertificateFromService()
    {
        try
        {
            // TODO: Implement your service-specific logic to retrieve the certificate
            // Example: Call your HSM API to get the certificate by key ID
            
            // For demonstration:
            // var client = new YourHSMClient(_endpoint, GetCredentials());
            // var certBytes = await client.GetCertificateAsync(_keyId);
            // return new X509Certificate2(certBytes);
            
            throw new NotImplementedException("Implement certificate retrieval from your HSM/service");
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to retrieve certificate: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Creates a signing key wrapper that delegates to your HSM/service.
    /// </summary>
    private AsymmetricAlgorithm CreateRemoteSigningKey()
    {
        // TODO: Create a custom AsymmetricAlgorithm implementation
        // that delegates SignHash() calls to your HSM/service
        
        // Example implementation structure:
        // return new YourRemoteRSA(
        //     _endpoint,
        //     _keyId,
        //     GetCredentials(),
        //     _logger);
        
        throw new NotImplementedException("Implement remote signing key wrapper");
    }

    /// <summary>
    /// Gets credentials for authentication with your HSM/service.
    /// SECURITY: Use secure credential mechanisms (DefaultAzureCredential, environment variables, etc.)
    /// NEVER accept credentials directly on the command line.
    /// </summary>
    private object GetCredentials()
    {
        // TODO: Implement secure credential retrieval
        // Examples:
        // - Use DefaultAzureCredential for Azure services
        // - Read from secure environment variables
        // - Use certificate-based authentication
        // - Use Windows Credential Manager
        // - Use OAuth2 flows
        
        switch (_authMethod.ToLowerInvariant())
        {
            case "azure":
                // return new DefaultAzureCredential();
                throw new NotImplementedException("Implement Azure authentication");
            
            case "certificate":
                // Load client certificate for mutual TLS
                throw new NotImplementedException("Implement certificate authentication");
            
            case "default":
            default:
                // Default authentication method
                throw new NotImplementedException("Implement default authentication");
        }
    }

    public void Dispose()
    {
        _certificate?.Dispose();
        _privateKey?.Dispose();
    }
}
```

### Step 4: Implement Remote Signing (Example for RSA)

For HSM/remote signing scenarios, you need a custom `AsymmetricAlgorithm` implementation:

```csharp
using System.Security.Cryptography;

namespace YourCompany.YourCertProvider.Plugin;

/// <summary>
/// RSA implementation that delegates signing operations to a remote HSM/service.
/// </summary>
internal class YourRemoteRSA : RSA
{
    private readonly string _endpoint;
    private readonly string _keyId;
    private readonly object _credentials;
    private readonly IPluginLogger? _logger;
    private RSAParameters? _publicKeyParameters;

    public YourRemoteRSA(
        string endpoint,
        string keyId,
        object credentials,
        IPluginLogger? logger)
    {
        _endpoint = endpoint;
        _keyId = keyId;
        _credentials = credentials;
        _logger = logger;
    }

    /// <summary>
    /// Signs data by calling the remote HSM/service.
    /// This is the critical method called by the signing workflow.
    /// </summary>
    public override byte[] SignHash(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding)
    {
        try
        {
            _logger?.LogVerbose($"Signing hash with remote key: {_keyId}");
            _logger?.LogVerbose($"Hash algorithm: {hashAlgorithm.Name}, Padding: {padding}");

            // TODO: Implement remote signing call to your HSM/service
            // Example:
            // var client = new YourHSMClient(_endpoint, _credentials);
            // var signature = await client.SignHashAsync(_keyId, hash, hashAlgorithm, padding);
            // return signature;

            throw new NotImplementedException("Implement remote hash signing");
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Remote signing failed: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Exports the public key parameters.
    /// Required for signature verification.
    /// </summary>
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException("Cannot export private parameters from remote key");
        }

        if (_publicKeyParameters == null)
        {
            // TODO: Retrieve public key parameters from your HSM/service
            throw new NotImplementedException("Implement public key parameter export");
        }

        return _publicKeyParameters.Value;
    }

    public override void ImportParameters(RSAParameters parameters)
    {
        throw new NotSupportedException("Cannot import parameters to a remote key");
    }

    // Implement other required RSA methods as needed...
}
```

### Security Best Practices for Certificate Provider Plugins

1. **Never Accept Secrets on Command Line**:
   ```csharp
   // ❌ BAD: Direct credential parameters
   ["--api-key"] = "api-key"  // Don't do this!
   
   // ✅ GOOD: Secure credential mechanisms
   ["--credential-source"] = "credential-source"  // Options: "azure", "env-var", "keychain"
   ```

2. **Use Secure Credential Storage**:
   - Azure: `DefaultAzureCredential`
   - AWS: `DefaultAWSCredentialsProviderChain`
   - Environment variables for CI/CD
   - Windows Credential Manager
   - OS keychains (macOS Keychain, GNOME Keyring)

3. **Validate All Inputs**:
   ```csharp
   public bool CanCreateProvider(IConfiguration configuration)
   {
       string? endpoint = configuration["your-endpoint"];
       
       // Validate endpoint format
       if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) ||
           (uri.Scheme != "https" && uri.Scheme != "http"))
       {
           return false;
       }
       
       return true;
   }
   ```

4. **Handle Sensitive Data Carefully**:
   ```csharp
   // Clear sensitive data when no longer needed
   public void Dispose()
   {
       _certificate?.Dispose();
       _privateKey?.Dispose();
       // Clear any cached credentials
   }
   ```

5. **Use Timeouts and Retries**:
   ```csharp
   private async Task<byte[]> SignHashWithRetry(byte[] hash)
   {
       int maxRetries = 3;
       for (int i = 0; i < maxRetries; i++)
       {
           try
           {
               using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
               return await SignHashAsync(hash, cts.Token);
           }
           catch (TimeoutException) when (i < maxRetries - 1)
           {
               _logger?.LogWarning($"Signing timeout, retry {i + 1}/{maxRetries}");
               await Task.Delay(1000 * (i + 1)); // Exponential backoff
           }
       }
       throw new Exception("Signing failed after retries");
   }
   ```

### Testing Your Certificate Provider Plugin

```csharp
[TestClass]
public class YourCertProviderPluginTests
{
    [TestMethod]
    public void ProviderName_ShouldBeKebabCase()
    {
        var plugin = new YourCertProviderPlugin();
        Assert.AreEqual("your-cert-provider", plugin.ProviderName);
    }

    [TestMethod]
    public void GetProviderOptions_ShouldReturnRequiredOptions()
    {
        var plugin = new YourCertProviderPlugin();
        var options = plugin.GetProviderOptions();
        
        Assert.IsTrue(options.ContainsKey("--your-endpoint"));
        Assert.IsTrue(options.ContainsKey("--your-key-id"));
    }

    [TestMethod]
    public void CanCreateProvider_WithMissingEndpoint_ShouldReturnFalse()
    {
        var plugin = new YourCertProviderPlugin();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["your-key-id"] = "test-key"
                // Missing endpoint
            })
            .Build();

        Assert.IsFalse(plugin.CanCreateProvider(config));
    }

    [TestMethod]
    public void CanCreateProvider_WithAllRequired_ShouldReturnTrue()
    {
        var plugin = new YourCertProviderPlugin();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["your-endpoint"] = "https://test.example.com",
                ["your-key-id"] = "test-key"
            })
            .Build();

        Assert.IsTrue(plugin.CanCreateProvider(config));
    }
}
```

### Example: Azure Trusted Signing Certificate Provider

For a complete, production-ready example of a certificate provider plugin, see:
- **Source Code**: `CoseSignTool.AzureTrustedSigning.Plugin/`
- **Documentation**: [CertificateProviders.md](CertificateProviders.md)
- **Usage Guide**: [CoseSign1.Certificates.AzureTrustedSigning.md](CoseSign1.Certificates.AzureTrustedSigning.md)

The Azure Trusted Signing plugin demonstrates:
- Integration with Azure cloud-based signing service
- DefaultAzureCredential authentication
- Comprehensive error handling
- Provider-specific parameters (`--ats-endpoint`, `--ats-account-name`, `--ats-cert-profile-name`)
- Full test coverage

## Plugin Security Model

### Directory Restrictions

For security reasons, CoseSignTool only loads plugins from the `plugins` subdirectory of the executable. Since version 2.0, CoseSignTool supports both legacy flat and enhanced subdirectory-based plugin architectures:

**Enhanced Subdirectory Architecture (Recommended):**
```
CoseSignTool.exe
└── plugins/
    ├── YourCompany.YourService.Plugin/
    │   ├── YourCompany.YourService.Plugin.dll
    │   ├── YourSpecificDependency.dll
    │   ├── AnotherDependency.dll
    │   └── ...
    ├── AnotherCompany.AnotherService.Plugin/
    │   ├── AnotherCompany.AnotherService.Plugin.dll
    │   ├── SpecificDependencyV1.dll
    │   └── ...
    └── [legacy flat files for backward compatibility]
```

**Legacy Flat Architecture (Supported):**
```
CoseSignTool.exe
└── plugins/
    ├── YourCompany.YourService.Plugin.dll
    ├── AnotherCompany.AnotherService.Plugin.dll
    ├── SharedDependency.dll
    └── ...
```

**Key Benefits of Subdirectory Architecture:**
- **Dependency Isolation**: Each plugin has its own dependency context, preventing version conflicts
- **Self-Contained Deployment**: All plugin dependencies are contained within the plugin's subdirectory
- **Easier Distribution**: Plugins can be packaged as complete, self-contained units
- **Better Maintainability**: Clear separation between different plugins and their dependencies
- **Concurrent Versions**: Multiple plugins can use different versions of the same dependency

**Security Features:**
- **Path validation**: The `PluginLoader.ValidatePluginDirectory()` method ensures plugins are only loaded from the authorized directory
- **Path normalization**: Handles different path formats and prevents directory traversal attacks
- **Exception throwing**: Attempts to load plugins from unauthorized locations throw `UnauthorizedAccessException`

### Plugin Discovery

The plugin discovery process supports both legacy flat and modern subdirectory structures:

**Enhanced Discovery Process (Version 2.0+):**
1. **Directory existence**: Check if the `plugins` directory exists
2. **Security validation**: Verify the directory is authorized for plugin loading
3. **Subdirectory scanning**: 
   - Search subdirectories for `*.Plugin.dll` files
   - Create isolated AssemblyLoadContext for each plugin
   - Load plugin dependencies from plugin-specific subdirectory
4. **Legacy fallback**: 
   - Search for `*.Plugin.dll` files in the main plugins directory
   - Load using default AssemblyLoadContext for backward compatibility
5. **Type discovery**: Find types implementing `ICoseSignToolPlugin`
6. **Instance creation**: Create plugin instances using `Activator.CreateInstance()`

**Plugin Load Context:**
- Each plugin in a subdirectory gets its own `PluginLoadContext` (derived from `AssemblyLoadContext`)
- Dependencies are resolved first from the plugin's subdirectory
- Shared framework assemblies (System.*, Microsoft.Extensions.*) are resolved from the main application context
- This prevents dependency conflicts between plugins while maintaining shared framework compatibility

### Error Handling

The plugin system includes comprehensive error handling:

- **Assembly loading errors**: Handled gracefully with warning messages
- **Type loading errors**: Reported without stopping other plugin loading
- **Plugin initialization errors**: Logged but don't prevent tool startup
- **Command conflicts**: Warn about duplicate command names

## Deploying Plugins

### Local Development

**Enhanced Subdirectory Deployment (Recommended):**

1. Build your plugin project with dependency copying enabled:
   ```xml
   <PropertyGroup>
     <CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies>
     <PreserveCompilationContext>true</PreserveCompilationContext>
     <GenerateRuntimeConfigurationFiles>true</GenerateRuntimeConfigurationFiles>
   </PropertyGroup>
   
   <ItemGroup>
     <PackageReference Include="YourDependency" Version="1.0.0">
       <Private>true</Private>
       <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
     </PackageReference>
   </ItemGroup>
   ```

2. Create a subdirectory named after your plugin:
   ```bash
   mkdir plugins/YourCompany.YourService.Plugin
   ```

3. Copy your plugin assembly and all its dependencies to the subdirectory:
   ```bash
   # Copy main plugin assembly
   cp bin/Debug/net8.0/YourCompany.YourService.Plugin.dll plugins/YourCompany.YourService.Plugin/
   
   # Copy all dependencies
   cp bin/Debug/net8.0/*.dll plugins/YourCompany.YourService.Plugin/
   ```

**Legacy Flat Deployment (Backward Compatibility):**

1. Build your plugin project
2. Copy the resulting `.dll` file to the `plugins` directory next to `CoseSignTool.exe`
3. Include any required dependencies (but be careful about conflicts with CoseSignTool dependencies)

### Automated Deployment with MSBuild

For automated plugin deployment, you can use MSBuild targets like those used in the CoseSignTool project:

```xml
<Target Name="DeployYourPlugin" AfterTargets="Build" Condition="'$(DeployPlugins)' == 'true'">
  <PropertyGroup>
    <PluginsDir>$(OutputPath)plugins</PluginsDir>
    <YourPluginSubDir>$(PluginsDir)\YourCompany.YourService.Plugin</YourPluginSubDir>
    <YourPluginDir>$(MSBuildProjectDirectory)\..\YourCompany.YourService.Plugin\bin\$(Configuration)\net8.0</YourPluginDir>
  </PropertyGroup>
  
  <MakeDir Directories="$(YourPluginSubDir)" />
  
  <ItemGroup>
    <YourPluginFiles Include="$(YourPluginDir)\**\*.*" />
  </ItemGroup>
  
  <Copy SourceFiles="@(YourPluginFiles)" DestinationFolder="$(YourPluginSubDir)" />
  
  <Message Text="Your Plugin deployed to: $(YourPluginSubDir)" Importance="high" />
</Target>
```

### Distribution

For distributing plugins, you now have improved options:

1. **Self-Contained ZIP Archive**: Package the plugin subdirectory with all dependencies
   ```
   YourPlugin.zip
   └── YourCompany.YourService.Plugin/
       ├── YourCompany.YourService.Plugin.dll
       ├── dependency1.dll
       ├── dependency2.dll
       └── ...
   ```

2. **NuGet Package**: Create a package that includes the subdirectory structure

3. **Installer**: Create an installer that creates the subdirectory and places all files correctly

4. **Container/Docker**: Include plugins in container images with proper directory structure

### Dependencies

**Included with CoseSignTool:**
- Microsoft.Extensions.Configuration
- Microsoft.Extensions.Configuration.Abstractions
- System.Text.Json
- .NET 8.0 Base Class Library

**Plugin-specific dependencies:**

**Enhanced Subdirectory Architecture:**
- **Complete Isolation**: Package all dependencies with your plugin in its subdirectory
- **Version Freedom**: Use any version of dependencies without conflicts
- **Self-Contained**: Plugin works independently of other plugins' dependencies
- **Shared Framework**: Common .NET and Microsoft.Extensions assemblies are still shared for efficiency

**Legacy Flat Architecture:**
- Package them with your plugin in the main plugins directory
- Ensure version compatibility with CoseSignTool and other plugins
- Document any external dependencies
- Be careful about dependency conflicts

**Recommended Dependency Management:**
```xml
<!-- In your plugin .csproj file -->
<ItemGroup>
  <!-- External dependencies with explicit copying -->
  <PackageReference Include="Newtonsoft.Json" Version="13.0.3">
    <Private>true</Private>
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  </PackageReference>
  
  <!-- Azure dependencies isolated in plugin subdirectory -->
  <PackageReference Include="Azure.Core" Version="1.46.1">
    <Private>true</Private>
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  </PackageReference>
</ItemGroup>
```

## Using Plugins

### Command Discovery

When CoseSignTool starts, it automatically:

1. Scans the `plugins` directory for plugin assemblies
2. Loads and initializes discovered plugins
3. Registers plugin commands with the main command dispatcher
4. Includes plugin commands in help output

### Command Execution

Plugin commands are executed just like built-in commands:

```bash
# Built-in command
CoseSignTool sign --payload myfile.txt --certificate mycert.pfx

# Plugin command
CoseSignTool your_register --endpoint https://yourservice.com --payload myfile.txt --signature myfile.txt.cose
```

### Help System Integration

Plugins are automatically included in the help system:

**Command Plugins:**
```bash
# General help shows all plugin commands under "Plugin Commands"
CoseSignTool --help
# Output:
#   Plugin Commands:
#     mst_register    Register a COSE Sign1 message with Microsoft's Signing Transparency (MST)
#     indirect-sign   Creates an indirect COSE Sign1 signature for a payload file

# Plugin command help
CoseSignTool your_register --help
```

**Certificate Provider Plugins:**
```bash
# General help shows all certificate providers under "Certificate Providers"
CoseSignTool --help
# Output:
#   Certificate Providers:
#     azure-trusted-signing    Azure Trusted Signing cloud-based certificate provider

# Sign command help shows certificate providers
CoseSignTool sign --help
# Output includes:
#   Certificate Providers:
#     The following certificate provider plugins are available for signing:
#     azure-trusted-signing    Azure Trusted Signing cloud-based certificate provider
#       Usage: CoseSignTool sign <payload> --cert-provider azure-trusted-signing [options]
#       Options:
#         --ats-endpoint
#         --ats-account-name
#         --ats-cert-profile-name

# Indirect-sign command help also shows certificate providers
CoseSignTool indirect-sign --help
```

### Configuration

Plugin commands receive configuration through the standard .NET `IConfiguration` interface:

- **Command-line arguments**: Parsed and mapped according to the plugin's `Options` dictionary
- **Environment variables**: Available through the configuration system
- **Configuration files**: Can be loaded by plugins during initialization

## Example Plugins

### Command Plugin: Azure Code Transparency Service

The CoseSignTool includes a reference implementation for Azure Code Transparency Service integration.

> **📖 Complete Documentation**: For comprehensive MST plugin documentation, including detailed authentication options, CI/CD integration examples, and troubleshooting, see [MST.md](MST.md).

### Quick Start

The Microsoft's Signing Transparency (MST) plugin provides two main commands:
- `mst_register` - Register signatures with Microsoft's Signing Transparency (MST)
- `mst_verify` - Verify signatures against Microsoft's Signing Transparency (MST)

### Plugin Structure
```
CoseSignTool.MST.Plugin/
├── MstPlugin.cs           # Main plugin class
├── RegisterCommand.cs          # Command to register signatures
├── VerifyCommand.cs           # Command to verify signatures
└── CoseSignTool.MST.Plugin.csproj
```

### Usage Examples

```bash
# Register a signature with Microsoft's Signing Transparency (MST) using default environment variable
export MST_TOKEN="your-access-token"
CoseSignTool mst_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose

# Register a signature with Microsoft's Signing Transparency (MST) using custom environment variable
export MY_MST_TOKEN="your-access-token"
CoseSignTool mst_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --token-env-var MY_MST_TOKEN

# Verify a signature with Microsoft's Signing Transparency (MST)
export MST_TOKEN="your-access-token"
CoseSignTool mst_verify \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --receipt receipt.json

# Using Azure DefaultCredential when no token is provided
CoseSignTool mst_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose
```

### Authentication

The MST plugin supports multiple authentication methods with the following priority:

1. **Environment Variable Token**: Uses an access token from an environment variable
   - `--token-env-var` specifies the environment variable name
   - If not specified, defaults to `MST_TOKEN`
   - This is the recommended approach for CI/CD environments

2. **Azure DefaultCredential**: Falls back to Azure DefaultCredential when no token is found
   - Automatically uses available Azure credentials (managed identity, Azure CLI, etc.)
   - Ideal for local development and Azure-hosted environments

#### Authentication Examples

```bash
# Using default environment variable
export MST_TOKEN="your-access-token"
CoseSignTool mst_register --endpoint https://your-cts-instance.azure.com --payload file.txt --signature file.cose

# Using custom environment variable
export MY_CUSTOM_TOKEN="your-access-token"
CoseSignTool mst_register --endpoint https://your-mst-instance.azure.com --payload file.txt --signature file.cose --token-env-var MY_CUSTOM_TOKEN

# Using Azure DefaultCredential (no token environment variable set)
# Requires Azure CLI login, managed identity, or other Azure credential
CoseSignTool mst_register --endpoint https://your-cts-instance.azure.com --payload file.txt --signature file.cose
```

### Certificate Provider Plugin: Azure Trusted Signing

The CoseSignTool includes a production-ready certificate provider plugin for Azure Trusted Signing, demonstrating best practices for cloud-based signing services.

> **📖 Complete Documentation**: For comprehensive Azure Trusted Signing documentation, including setup, authentication, and advanced scenarios, see [CertificateProviders.md](CertificateProviders.md) and [CoseSign1.Certificates.AzureTrustedSigning.md](CoseSign1.Certificates.AzureTrustedSigning.md).

#### Quick Start

The Azure Trusted Signing plugin integrates with the `sign` and `indirect-sign` commands:

```bash
# Sign with Azure Trusted Signing (using DefaultAzureCredential)
CoseSignTool sign --payload myfile.txt \
    --cert-provider azure-trusted-signing \
    --ats-endpoint https://myaccount.codesigning.azure.net \
    --ats-account-name myaccount \
    --ats-cert-profile-name myprofile

# Indirect sign with Azure Trusted Signing
CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose \
    --cert-provider azure-trusted-signing \
    --ats-endpoint https://myaccount.codesigning.azure.net \
    --ats-account-name myaccount \
    --ats-cert-profile-name myprofile
```

#### Plugin Structure
```
CoseSignTool.AzureTrustedSigning.Plugin/
├── AzureTrustedSigningPlugin.cs                          # Main plugin implementation (ICertificateProviderPlugin)
├── CoseSignTool.AzureTrustedSigning.Plugin.csproj       # Project with dependency isolation
└── [Dependencies copied to plugins/CoseSignTool.AzureTrustedSigning.Plugin/]
    ├── Azure.CodeSigning.dll
    ├── Azure.Core.dll
    ├── Azure.Developer.TrustedSigning.CryptoProvider.dll
    └── ...
```

#### Key Features Demonstrated

1. **Dependency Isolation**: All Azure dependencies packaged in plugin subdirectory
2. **Secure Authentication**: DefaultAzureCredential for passwordless auth
3. **Provider-Specific Options**: Custom parameters (`--ats-*`) with prefix to avoid conflicts
4. **Integration with CoseSign1.Certificates**: Uses `AzureTrustedSigningCoseSigningKeyProvider`
5. **Comprehensive Testing**: Full unit test coverage demonstrating plugin testing patterns

#### Authentication Flow

```csharp
// Azure Trusted Signing uses DefaultAzureCredential:
// 1. Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
// 2. Managed Identity (when running in Azure)
// 3. Visual Studio / VS Code credentials
// 4. Azure CLI credentials (az login)
// 5. Azure PowerShell credentials

// Never requires credentials on command line
CoseSignTool sign --payload file.txt \
    --cert-provider azure-trusted-signing \
    --ats-endpoint https://myaccount.codesigning.azure.net \
    --ats-account-name myaccount \
    --ats-cert-profile-name myprofile
```

#### Usage in CI/CD

**GitHub Actions:**
```yaml
- uses: azure/login@v1
  with:
    creds: ${{ secrets.AZURE_CREDENTIALS }}

- name: Sign with Azure Trusted Signing
  run: |
    CoseSignTool sign --payload artifact.bin \
      --cert-provider azure-trusted-signing \
      --ats-endpoint ${{ secrets.ATS_ENDPOINT }} \
      --ats-account-name ${{ secrets.ATS_ACCOUNT }} \
      --ats-cert-profile-name ${{ secrets.ATS_PROFILE }}
```

**Azure DevOps:**
```yaml
- task: AzureCLI@2
  displayName: 'Sign with Azure Trusted Signing'
  inputs:
    azureSubscription: 'MyServiceConnection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      CoseSignTool sign --payload artifact.bin \
        --cert-provider azure-trusted-signing \
        --ats-endpoint $(ATS_ENDPOINT) \
        --ats-account-name $(ATS_ACCOUNT) \
        --ats-cert-profile-name $(ATS_PROFILE)
```

## Best Practices

### Plugin Development

1. **Error Handling**: Use appropriate `PluginExitCode` values for different error scenarios
2. **Cancellation Support**: Always respect the `CancellationToken` in async operations
3. **Input Validation**: Validate all user inputs and provide clear error messages
4. **Resource Management**: Properly dispose of resources and handle cleanup
5. **Security**: Never trust user input; validate and sanitize all data
6. **Logging**: Use Console.Error for error messages and Console.Out for regular output

### Certificate Provider Plugin Development

1. **Secure Credentials**: Use `DefaultAzureCredential`, environment variables, or OS credential stores - never command-line parameters
2. **Provider Naming**: Use lowercase with hyphens (e.g., `azure-trusted-signing`, not `AzureTrustedSigning`)
3. **Option Prefixing**: Prefix provider-specific options to avoid conflicts (e.g., `--ats-endpoint`, not `--endpoint`)
4. **Validation**: Implement `CanCreateProvider` to quickly validate required parameters
5. **Remote Signing**: Implement custom `AsymmetricAlgorithm` subclass for HSM/remote signing
6. **Certificate Chains**: Include intermediate certificates via `AdditionalCertificates` property
7. **Timeout Handling**: Implement timeouts and retries for network operations
8. **Logging**: Use `IPluginLogger` for diagnostic output (Verbose, Information, Warning, Error)

### Command Design

1. **Naming**: Use descriptive, consistent command names (e.g., `service_action`)
2. **Options**: Provide both long names and short aliases for common options
3. **Help**: Include comprehensive usage information and examples
4. **Backwards Compatibility**: Maintain API compatibility across plugin versions

### Testing

1. **Unit Tests**: Test individual command logic thoroughly
2. **Integration Tests**: Test plugin loading and command execution
3. **Error Cases**: Test all error scenarios and exit codes
4. **Cancellation**: Test cancellation token handling
5. **Security**: Test path validation and input sanitization

### Performance

1. **Async Operations**: Use async/await for I/O operations
2. **Resource Usage**: Minimize memory usage for large files
3. **Timeouts**: Implement reasonable timeouts for external operations
4. **Caching**: Cache expensive operations when appropriate

## Troubleshooting

### Common Issues

**Plugin not discovered:**
- Verify the assembly name ends with `.Plugin.dll`
- Check that the file is in the `plugins` directory
- Ensure the assembly implements `ICoseSignToolPlugin`

**Security errors:**
- Verify plugins are in the correct `plugins` subdirectory
- Check that the path doesn't contain traversal attempts (e.g., `../`)

**Command conflicts:**
- Check for duplicate command names across plugins
- Review console warnings during startup

**Runtime errors:**
- Check plugin dependencies are available
- Verify .NET 8.0 compatibility
- Review error messages in console output

### Debugging

1. **Console Output**: Check startup warnings and error messages
2. **Plugin Loading**: Verify plugin discovery and initialization
3. **Command Execution**: Test commands with various inputs and edge cases
4. **Configuration**: Ensure command-line options are properly mapped

## Migration Guide

### From Built-in Extensions to Plugins

If you have custom extensions built into CoseSignTool, you can migrate them to plugins:

1. **Extract Code**: Move your extension code to a separate project
2. **Implement Interfaces**: Implement the plugin interfaces
3. **Update Dependencies**: Reference `CoseSignTool.Abstractions`
4. **Test Integration**: Verify the plugin loads and functions correctly

### Version Compatibility

Plugins should target the same .NET version as CoseSignTool and use compatible versions of shared dependencies. The plugin system is designed to be forward-compatible within major versions.

## Contributing

When contributing plugins or improvements to the plugin system:

1. **Follow Conventions**: Use established patterns and naming conventions
2. **Add Tests**: Include comprehensive tests for new functionality
3. **Update Documentation**: Keep this documentation current with changes
4. **Security Review**: Consider security implications of changes
5. **Backwards Compatibility**: Avoid breaking changes to the plugin API

For more information, see the main [CONTRIBUTING.md](CONTRIBUTING.md) guide.


# CoseSignTool CLI Plugins

The CoseSignTool V2 CLI supports a plugin architecture that allows extending the tool with additional signing providers and transparency services.

## Overview

Plugins provide:
- **Signing Command Providers**: Add new signing commands (e.g., `sign-pfx`, `sign-azure`)
- **Verification Providers**: Add validators and verification metadata to the `verify` command
- **Transparency Provider Contributors**: Add transparency receipt support to signing operations

## Available Plugins

### [CoseSignTool.Local.Plugin](local-plugin.md)

Local certificate signing using certificates stored on the local machine.

**Commands Added**:
- `sign-pfx` - Sign with a PFX/PKCS#12 certificate file
- `sign-certstore` - Sign with a certificate from Windows or Linux certificate store
- `sign-pem` - Sign with PEM-encoded certificate and key files
- `sign-ephemeral` - Sign with an ephemeral test certificate (development only)

**Use When**: You have certificates available locally (development, on-premises signing).

---

### [CoseSignTool.AzureTrustedSigning.Plugin](azure-plugin.md)

Cloud-based signing using Azure Trusted Signing service.

**Commands Added**:
- `sign-azure` - Sign using Azure Trusted Signing

**Use When**: Using Azure for centralized, managed code signing.

---

### [CoseSignTool.AzureKeyVault.Plugin](azure-keyvault-plugin.md)

Azure Key Vault signing and verification.

**Commands Added**:
- `sign-akv-cert` - Sign using an Azure Key Vault certificate
- `sign-akv-key` - Sign using an Azure Key Vault key (key-only)

**Verification**:
- Contributes a signature validator for key-only signatures when the message identifies an Azure Key Vault key (via `kid`), enabling verification without requiring Key Vault access.

**Use When**: Using Key Vault for HSM-backed signing keys/certificates.

---

### [CoseSignTool.MST.Plugin](mst-plugin.md)

Microsoft's Signing Transparency (MST) verification.

**Options Added to `verify` Command**:
- `--require-receipt` - Require MST receipt for verification
- `--mst-endpoint` - MST service endpoint URL
- `--verify-receipt` - Verify the MST receipt

**Transparency Support**: Automatically adds MST receipts to signed messages.

**Use When**: Implementing supply chain transparency with MST.

---

## Plugin Architecture

### Plugin Interface

All plugins implement `IPlugin`:

```csharp
public interface IPlugin
{
    string Name { get; }
    string Version { get; }
    string Description { get; }
    
    PluginExtensions GetExtensions();
    void RegisterCommands(Command rootCommand);
    Task InitializeAsync(IDictionary<string, string>? configuration = null);
}
```

### Plugin Extensions Model

Plugins return all their capabilities through `PluginExtensions`:

```csharp
public sealed class PluginExtensions
{
    public PluginExtensions(
        IEnumerable<ISigningCommandProvider> signingCommandProviders,
        IEnumerable<IVerificationProvider> verificationProviders,
        IEnumerable<ITransparencyProviderContributor> transparencyProviders);
    
    public IEnumerable<ISigningCommandProvider> SigningCommandProviders { get; }
    public IEnumerable<IVerificationProvider> VerificationProviders { get; }
    public IEnumerable<ITransparencyProviderContributor> TransparencyProviders { get; }
    
    public static PluginExtensions None => new();
}
```

### Signing Command Provider

Providers implement `ISigningCommandProvider`:

```csharp
public interface ISigningCommandProvider
{
    string CommandName { get; }
    string CommandDescription { get; }
    string ExampleUsage { get; }
    
    void AddCommandOptions(Command command);
    Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(
        IDictionary<string, object?> options);
    IDictionary<string, string> GetSigningMetadata();
}
```

### Verification Provider

Verification providers implement `IVerificationProvider`:

```csharp
public interface IVerificationProvider
{
    string ProviderName { get; }
    string Description { get; }
    int Priority { get; }
    
    void AddVerificationOptions(Command command);
    bool IsActivated(ParseResult parseResult);
    IEnumerable<IValidator> CreateValidators(ParseResult parseResult);
    IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult);
}
```

#### Context-Aware Verification Providers

Some verification providers need additional runtime context (for example, detached payload bytes) to build correct validators. These providers can implement `IVerificationProviderWithContext`:

```csharp
public interface IVerificationProviderWithContext : IVerificationProvider
{
    IEnumerable<IValidator> CreateValidators(ParseResult parseResult, VerificationContext context);
}
```

#### Trust policies

Verification providers can optionally contribute a `TrustPolicy` by implementing `IVerificationProviderWithTrustPolicy`.
When multiple active providers return a policy, the CLI requires **all** policies to be satisfied (logical AND).

The `verify` command passes a `VerificationContext` that can include the detached payload bytes when a `--payload` file is supplied.

### Transparency Provider Contributor

Contributors implement `ITransparencyProviderContributor`:

```csharp
public interface ITransparencyProviderContributor
{
    string ProviderName { get; }
    string ProviderDescription { get; }
    
    Task<ITransparencyProvider> CreateTransparencyProviderAsync(
        IDictionary<string, object?> options,
        CancellationToken cancellationToken = default);
}
```

## Creating Custom Plugins

See the [Creating CLI Plugins Guide](../guides/cli-plugins.md) for detailed instructions on building custom plugins.

## Plugin Loading

Plugins are loaded at runtime from the `plugins` directory relative to the CoseSignTool executable. Each plugin is loaded in an isolated assembly load context for proper isolation.

```
CoseSignTool/
├── CoseSignTool.exe
└── plugins/
    ├── CoseSignTool.Local.Plugin/
    │   └── CoseSignTool.Local.Plugin.dll
    ├── CoseSignTool.AzureTrustedSigning.Plugin/
    │   └── CoseSignTool.AzureTrustedSigning.Plugin.dll
    └── CoseSignTool.MST.Plugin/
        └── CoseSignTool.MST.Plugin.dll
```

# CoseSignTool CLI Plugins

The CoseSignTool V2 CLI supports a plugin architecture that allows extending the tool with additional signing providers and transparency services.

## Overview

Plugins provide:
- **Signing Command Providers**: Add new signing commands (e.g., `sign-pfx`, `sign-azure`)
- **Transparency Provider Contributors**: Add transparency receipt support to signing operations

## Available Plugins

### [CoseSignTool.Local.Plugin](local-plugin.md)

Local certificate signing using certificates stored on the local machine.

**Commands Added**:
- `sign-pfx` - Sign with a PFX/PKCS#12 certificate file
- `sign-cert-store` - Sign with a certificate from Windows certificate store
- `sign-pem` - Sign with PEM-encoded certificate and key files
- `sign-linux-store` - Sign with a certificate from Linux certificate store

**Use When**: You have certificates available locally (development, on-premises signing).

---

### [CoseSignTool.AzureTrustedSigning.Plugin](azure-plugin.md)

Cloud-based signing using Azure Trusted Signing service.

**Commands Added**:
- `sign-azure` - Sign using Azure Trusted Signing

**Use When**: Using Azure for centralized, managed code signing.

---

### [CoseSignTool.MST.Plugin](mst-plugin.md)

Microsoft Signing Transparency (MST) verification.

**Commands Added**:
- `verify-mst` - Verify a signature against Microsoft Signing Transparency service

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
    
    Task InitializeAsync(IDictionary<string, string>? options = null);
    IEnumerable<ISigningCommandProvider> GetSigningCommandProviders();
    IEnumerable<ITransparencyProviderContributor> GetTransparencyProviderContributors();
    void RegisterCommands(Command rootCommand);
}
```

### Signing Command Provider

Providers implement `ISigningCommandProvider`:

```csharp
public interface ISigningCommandProvider
{
    string CommandName { get; }
    string CommandDescription { get; }
    
    void AddCommandOptions(Command command);
    Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(
        IDictionary<string, object?> options);
    IDictionary<string, string> GetSigningMetadata();
}
```

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

# Plugin Development Guide

CoseSignTool V2 features a robust plugin architecture that allows extending the CLI with custom signing providers, verification providers, and transparency services.

## Overview

Plugins can contribute:

| Extension Type | Interface | Purpose |
|---------------|-----------|---------|
| **Signing Commands** | `ISigningCommandProvider` | Add new `sign-*` commands |
| **Verification Providers** | `IVerificationProvider` | Add custom validators to verify |
| **Transparency Providers** | `ITransparencyProviderContributor` | Add transparency proof services |
| **Custom Commands** | Direct registration | Add arbitrary CLI commands |

---

## Plugin Architecture

### Plugin Discovery

Plugins are discovered at startup from the `plugins/` subdirectory:

```
CoseSignTool.exe
plugins/
+-- CoseSignTool.Local.Plugin/
|   +-- CoseSignTool.Local.Plugin.dll    <-- Plugin assembly
|   +-- <dependencies>.dll
+-- CoseSignTool.AzureKeyVault.Plugin/
|   +-- CoseSignTool.AzureKeyVault.Plugin.dll
|   +-- <dependencies>.dll
+-- MyCustom.Plugin/
    +-- MyCustom.Plugin.dll
    +-- <dependencies>.dll
```

**Rules:**
- Each plugin must be in its own subdirectory
- Plugin DLLs must match pattern `*.Plugin.dll`
- Dependencies are isolated per plugin via `AssemblyLoadContext`

### Additional Plugin Directories

Load plugins from additional locations:

```bash
cosesigntool --additional-plugin-dir /custom/plugins verify document.cose
```

### Plugin Lifecycle

```
1. Discovery    -> Scan plugins/ directory for *.Plugin.dll assemblies
2. Loading      -> Load assembly in isolated AssemblyLoadContext
3. Instantiation -> Create instances of IPlugin implementations
4. Initialization -> Call plugin.InitializeAsync()
5. Registration -> Call plugin.GetExtensions() and plugin.RegisterCommands()
6. Execution    -> Commands use plugin-provided services
```

---

## Core Interfaces

### IPlugin

The main plugin entry point:

```csharp
public interface IPlugin
{
    /// <summary>Plugin display name.</summary>
    string Name { get; }
    
    /// <summary>Plugin version string.</summary>
    string Version { get; }
    
    /// <summary>Plugin description.</summary>
    string Description { get; }
    
    /// <summary>Returns extension contributions.</summary>
    PluginExtensions GetExtensions();
    
    /// <summary>Register custom commands directly on the root command.</summary>
    void RegisterCommands(Command rootCommand);
    
    /// <summary>Initialize the plugin (async configuration loading, etc).</summary>
    Task InitializeAsync(IDictionary<string, string>? configuration = null);
}
```

### PluginExtensions

Container for all extension contributions:

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
    
    /// <summary>Empty extensions (no contributions).</summary>
    public static PluginExtensions None { get; }
}
```

---

## Creating a Signing Command Provider

Signing command providers add new `sign-*` commands to the CLI.

### ISigningCommandProvider Interface

```csharp
public interface ISigningCommandProvider
{
    /// <summary>Command name (e.g., "sign-pfx", "sign-hsm").</summary>
    string CommandName { get; }
    
    /// <summary>Command description for help text.</summary>
    string CommandDescription { get; }
    
    /// <summary>Example usage for help text.</summary>
    string ExampleUsage { get; }
    
    /// <summary>Add command-specific options.</summary>
    void AddCommandOptions(Command command);
    
    /// <summary>Create signing service from parsed options.</summary>
    Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(
        IDictionary<string, object?> options);
    
    /// <summary>Get metadata for display after signing.</summary>
    IDictionary<string, string> GetSigningMetadata();
}
```

### Implementation Example

```csharp
public class HsmSigningCommandProvider : ISigningCommandProvider
{
    public string CommandName => "sign-hsm";
    public string CommandDescription => "Sign using Hardware Security Module";
    public string ExampleUsage => "--hsm-slot 0 --key-label signing-key";

    // Store parsed values for metadata
    private string? SlotId;
    private string? KeyLabel;

    public void AddCommandOptions(Command command)
    {
        // Add HSM-specific options only
        // Standard options (--output, --payload, etc.) are added automatically
        
        command.AddOption(new Option<int>(
            "--hsm-slot",
            "HSM slot number")
        { IsRequired = true });
        
        command.AddOption(new Option<string>(
            "--key-label",
            "Key label in HSM")
        { IsRequired = true });
        
        command.AddOption(new Option<string?>(
            "--pin",
            "HSM PIN (or use --pin-file)"));
        
        command.AddOption(new Option<FileInfo?>(
            "--pin-file",
            "File containing HSM PIN"));
    }

    public async Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(
        IDictionary<string, object?> options)
    {
        // Extract parsed option values
        // Keys are option names without leading dashes
        SlotId = options["hsm-slot"]?.ToString();
        KeyLabel = options["key-label"] as string;
        var pin = options["pin"] as string;
        var pinFile = options["pin-file"] as FileInfo;
        
        // Read PIN from file if provided
        if (pinFile != null)
        {
            pin = await File.ReadAllTextAsync(pinFile.FullName);
        }
        
        // Initialize HSM connection
        var hsmClient = new HsmClient(SlotId, pin);
        
        // Get certificate and create signing service
        var certificate = await hsmClient.GetCertificateAsync(KeyLabel);
        var chain = await hsmClient.BuildChainAsync(certificate);
        
        return new HsmSigningService(hsmClient, KeyLabel, certificate, chain);
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            ["HSM Slot"] = SlotId ?? "Unknown",
            ["Key Label"] = KeyLabel ?? "Unknown",
            ["Certificate Subject"] = _certificate?.Subject ?? "Unknown"
        };
    }
}
```

### Standard Options (Provided by Main Executable)

The following options are automatically added to all signing commands:

| Option | Description |
|--------|-------------|
| `payload` | Payload to sign (argument) |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | `indirect`, `embedded`, or `detached` |
| `--content-type`, `-c` | Content type header |
| `--quiet`, `-q` | Suppress output |
| `--output-format`, `-f` | Output format |

Your provider should **not** add these options.

---

## Advanced: Owning COSE message creation end-to-end

`ISigningCommandProvider` is designed to be a narrow plugin boundary: it returns an `ISigningService<SigningOptions>`, and the main executable owns I/O + the built-in signature strategies (`direct`/`indirect`).

If you want to go beyond extending key material / digest signing and instead take over **all aspects** of producing the final COSE output (bytes or `CoseSign1Message`), implement and register a custom `ICoseSign1MessageFactory<TOptions>` and route to it via `ICoseSign1MessageFactoryRouter`.

Because the built-in `sign-*` commands are assembled by the host, the way to do this from a CLI plugin is to register your own command via `IPlugin.RegisterCommands(...)`.

Example sketch:

```csharp
using System.CommandLine;
using CoseSign1.Abstractions;
using CoseSign1.Factories;
using Microsoft.Extensions.DependencyInjection;

public void RegisterCommands(Command rootCommand)
{
    var cmd = new Command("sign-custom-cose", "Sign using a custom COSE factory");

    cmd.SetHandler(async () =>
    {
        var services = new ServiceCollection();

        // Register whatever your factory needs (HTTP clients, options, etc.)
        services.AddTransient<ICoseSign1MessageFactory<MySigningOptions>, MySigningFactory>();

        // Register the router so you can call the generic CreateCoseSign1Message* APIs.
        services.AddTransient<ICoseSign1MessageFactoryRouter, CoseSign1MessageFactory>();

        using var provider = services.BuildServiceProvider();
        var router = provider.GetRequiredService<ICoseSign1MessageFactoryRouter>();

        // router.CreateCoseSign1MessageBytes<MySigningOptions>(...)
        // Write output wherever your command decides.
    });

    rootCommand.AddCommand(cmd);
}
```

See [Factory Extension Packages](../guides/factory-extension-packages.md) for the full pattern (options type, factory implementation, DI registration, and override strategies).

---

## Creating a Verification Provider

Verification providers contribute staged validation services and (optionally) trust-plan requirements to the `verify` command.

### IVerificationProvider Interface

```csharp
public interface IVerificationProvider
{
    /// <summary>Provider name for display.</summary>
    string ProviderName { get; }
    
    /// <summary>Provider description.</summary>
    string Description { get; }
    
    /// <summary>Execution priority (lower runs first).</summary>
    int Priority { get; }
    
    /// <summary>Add provider-specific verify options.</summary>
    void AddVerificationOptions(Command command);
    
    /// <summary>Check if provider should activate based on parsed options.</summary>
    bool IsActivated(ParseResult parseResult);
    
    /// <summary>
    /// Configures staged validation services for this provider.
    /// Providers should register trust packs, signing key resolvers, and post-signature validators into the supplied builder.
    /// </summary>
    void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context);
    
    /// <summary>Get metadata for display after verification.</summary>
    IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult);
}
```

### Optional interfaces

Providers can optionally implement additional interfaces:

- `IVerificationProviderWithTrustPlanPolicy` to contribute a `TrustPlanPolicy` fragment (policies from active providers are AND-ed).

Trust packs and other services should be registered via `ConfigureValidation(...)`.

### Priority Guidelines

`Priority` controls ordering when multiple providers contribute components and trust requirements.
Within validation, the orchestrator runs components by stage:

1. Key material resolution (`ISigningKeyResolver`)
2. Trust evaluation (`CompiledTrustPlan`)
3. Signature verification (crypto)
4. Post-signature checks (`IPostSignatureValidator`)

### Implementation Example

```csharp
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using Microsoft.Extensions.DependencyInjection;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSignTool.Abstractions;

public class CustomTrustVerificationProvider : IVerificationProviderWithTrustPlanPolicy
{
    public string ProviderName => "CustomTrust";
    public string Description => "Custom organizational trust validation";
    public int Priority => 15; // Trust requirements

    // Store options for later access
    private Option<bool> RequireTrustedChainOption = null!;

    public void AddVerificationOptions(Command command)
    {
        RequireTrustedChainOption = new Option<bool>(
            "--require-trusted-chain",
            getDefaultValue: () => false,
            description: "Require the signing certificate chain to be trusted");
        command.AddOption(RequireTrustedChainOption);
    }

    public bool IsActivated(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(RequireTrustedChainOption);
    }

    public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
    {
        // Register staged services and trust packs into the shared builder.
        // In this example we enable certificate trust (x5chain/x5t resolution + certificate trust facts).
        if (IsActivated(parseResult))
        {
            validationBuilder.EnableCertificateTrust(cert => cert.UseSystemTrust());
        }
    }

    public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
    {
        // Contribute additional requirements as a TrustPlanPolicy fragment.
        // This fragment is AND-ed with fragments from other active providers.
        if (!IsActivated(parseResult))
        {
            return null;
        }

        return TrustPlanPolicy.PrimarySigningKey(key =>
            key.RequireFact<X509ChainTrustedFact>(
                f => f.IsTrusted,
                "X.509 certificate chain must be trusted"));
    }

    public IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult)
    {
        return new Dictionary<string, object?>
        {
            ["Custom Trust Checked"] = IsActivated(parseResult),
            ["Require Trusted Chain"] = parseResult.GetValueForOption(RequireTrustedChainOption)
        };
    }
}
```

---

## Creating a Transparency Provider

Transparency providers add transparency proofs (e.g., MST receipts) to signatures.

### ITransparencyProviderContributor Interface

```csharp
public interface ITransparencyProviderContributor
{
    /// <summary>Provider name.</summary>
    string ProviderName { get; }
    
    /// <summary>Provider description.</summary>
    string ProviderDescription { get; }
    
    /// <summary>Create the transparency provider instance.</summary>
    Task<ITransparencyProvider> CreateTransparencyProviderAsync(
        IDictionary<string, object?> options,
        CancellationToken cancellationToken = default);
}
```

---

## Complete Plugin Example

### Project Structure

```
MyCompany.CoseSignTool.Plugin/
+-- MyCompany.CoseSignTool.Plugin.csproj
+-- MyCompanyPlugin.cs
+-- Signing/
|   +-- HsmSigningCommandProvider.cs
+-- Verification/
|   +-- CustomTrustVerificationProvider.cs
+-- Transparency/
    +-- LedgerTransparencyContributor.cs
```

### Main Plugin Class

```csharp
using System.CommandLine;
using CoseSignTool.Abstractions;

namespace MyCompany.CoseSignTool.Plugin;

public sealed class MyCompanyPlugin : IPlugin
{
    public string Name => "MyCompany Plugin";
    public string Version => "1.0.0";
    public string Description => "HSM signing and custom organizational trust validation";

    public Task InitializeAsync(IDictionary<string, string>? configuration = null)
    {
        return Task.CompletedTask;
    }

    public PluginExtensions GetExtensions()
    {
        return new PluginExtensions(
            signingCommandProviders: new ISigningCommandProvider[]
            {
                new HsmSigningCommandProvider()
            },
            verificationProviders: new IVerificationProvider[]
            {
                new CustomTrustVerificationProvider()
            },
            transparencyProviders: new ITransparencyProviderContributor[]
            {
                new LedgerTransparencyContributor()
            }
        );
    }

    public void RegisterCommands(Command rootCommand)
    {
        // Add custom utility commands
        var configCommand = new Command("my-config", "Configure MyCompany plugin");
        rootCommand.AddCommand(configCommand);
    }
}
```

---

## Bundled Plugins

CoseSignTool V2 includes the following bundled plugins:

| Plugin | Commands | Description |
|--------|----------|-------------|
| `CoseSignTool.Local.Plugin` | `sign-pfx`, `sign-pem`, `sign-certstore`, `sign-ephemeral` | Local certificate signing |
| `CoseSignTool.AzureKeyVault.Plugin` | `sign-akv-cert` | Azure Key Vault signing |
| `CoseSignTool.AzureTrustedSigning.Plugin` | `sign-azure` | Azure Trusted Signing |
| `CoseSignTool.MST.Plugin` | (verification only) | MST transparency verification |

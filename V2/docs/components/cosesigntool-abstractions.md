# CoseSignTool.Abstractions

Plugin abstraction interfaces for extending CoseSignTool with custom signing, verification, and transparency providers.

## Overview

The `CoseSignTool.Abstractions` package defines the plugin architecture for CoseSignTool V2. Plugins implement these interfaces to extend the CLI tool with:

- Custom signing commands (e.g., `sign-pfx`, `sign-azure`)
- Custom verification providers
- Transparency service integrations
- Secure password handling utilities

## Package Information

| Property | Value |
|----------|-------|
| Package | `CoseSignTool.Abstractions` |
| Target Frameworks | .NET 10.0, .NET Standard 2.0 |
| Dependencies | `CoseSign1.Abstractions`, `CoseSign1.Validation`, `System.CommandLine` |

## Core Interfaces

### IPlugin

The main entry point for all plugins:

```csharp
public interface IPlugin
{
    /// <summary>Gets the unique name of the plugin.</summary>
    string Name { get; }

    /// <summary>Gets the version of the plugin.</summary>
    string Version { get; }

    /// <summary>Gets the description of the plugin.</summary>
    string Description { get; }

    /// <summary>Gets all extension points this plugin provides.</summary>
    PluginExtensions GetExtensions();

    /// <summary>Registers additional commands with the root command.</summary>
    void RegisterCommands(Command rootCommand);

    /// <summary>Initializes the plugin with the given configuration.</summary>
    Task InitializeAsync(IDictionary<string, string>? configuration = null);
}
```

### PluginExtensions

A model containing all the extension points a plugin can contribute:

```csharp
public sealed class PluginExtensions
{
    /// <summary>Creates an empty extensions instance.</summary>
    public PluginExtensions();

    /// <summary>Creates extensions with the specified providers.</summary>
    public PluginExtensions(
        IEnumerable<ISigningCommandProvider> signingCommandProviders,
        IEnumerable<IVerificationProvider> verificationProviders,
        IEnumerable<ITransparencyProviderContributor> transparencyProviders);

    /// <summary>Gets the signing command providers.</summary>
    public IEnumerable<ISigningCommandProvider> SigningCommandProviders { get; }

    /// <summary>Gets the verification providers.</summary>
    public IEnumerable<IVerificationProvider> VerificationProviders { get; }

    /// <summary>Gets the transparency providers.</summary>
    public IEnumerable<ITransparencyProviderContributor> TransparencyProviders { get; }

    /// <summary>Returns an empty extensions instance.</summary>
    public static PluginExtensions None => new();
}
```

### ISigningCommandProvider

Interface for plugins that add signing commands to CoseSignTool:

```csharp
public interface ISigningCommandProvider
{
    /// <summary>Gets the command name (e.g., "sign-pfx", "sign-azure").</summary>
    string CommandName { get; }

    /// <summary>Gets the command description for help text.</summary>
    string CommandDescription { get; }

    /// <summary>Gets example usage for help text.</summary>
    string ExampleUsage { get; }

    /// <summary>Adds command-specific options to the command.</summary>
    void AddCommandOptions(Command command);

    /// <summary>Creates a signing service from parsed options.</summary>
    Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(
        IDictionary<string, object?> options);

    /// <summary>Gets metadata about the signing operation.</summary>
    IDictionary<string, string> GetSigningMetadata();
}
```

### IVerificationProvider

Interface for plugins that add verification capabilities:

```csharp
public interface IVerificationProvider
{
    /// <summary>Gets the provider name (e.g., "X509", "MST").</summary>
    string ProviderName { get; }

    /// <summary>Gets a short description of what this provider verifies.</summary>
    string Description { get; }

    /// <summary>Gets the priority order (lower runs first).</summary>
    int Priority { get; }

    /// <summary>Adds verification options to the verify command.</summary>
    void AddVerificationOptions(Command command);

    /// <summary>Determines if this provider is activated.</summary>
    bool IsActivated(ParseResult parseResult);

    /// <summary>Creates validation components based on options.</summary>
    IEnumerable<IValidationComponent> CreateValidators(ParseResult parseResult);

    /// <summary>Gets metadata about the verification result.</summary>
    IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult);
}
```

### IVerificationProviderWithTrustPolicy

Verification providers can optionally contribute a trust policy (used by the staged verifier to decide whether the signing key material is trusted):

```csharp
public interface IVerificationProviderWithTrustPolicy : IVerificationProvider
{
    TrustPolicy? CreateTrustPolicy(ParseResult parseResult, VerificationContext context);
}
```

### ITransparencyProviderContributor

Interface for plugins that integrate transparency services:

```csharp
public interface ITransparencyProviderContributor
{
    /// <summary>Gets the transparency provider name.</summary>
    string ProviderName { get; }

    /// <summary>Gets a description of the provider.</summary>
    string ProviderDescription { get; }

    /// <summary>Adds transparency options to signing commands.</summary>
    void AddTransparencyOptions(Command command);

    /// <summary>Determines if this provider is activated.</summary>
    bool IsActivated(ParseResult parseResult);

    /// <summary>Creates the transparency provider.</summary>
    Task<ITransparencyProvider> CreateTransparencyProviderAsync(
        IDictionary<string, object?> options,
        CancellationToken cancellationToken = default);
}
```

## Design Principles

### Model-Based Extensions

The `PluginExtensions` class uses a model-based approach instead of multiple interface methods:

```csharp
// Plugin returns all extensions at once
public PluginExtensions GetExtensions()
{
    return new PluginExtensions(
        signingCommandProviders: new[] { new LocalSigningProvider() },
        verificationProviders: Array.Empty<IVerificationProvider>(),
        transparencyProviders: Array.Empty<ITransparencyProviderContributor>()
    );
}
```

**Benefits:**
- Adding new extension points doesn't break existing plugins
- Plugins only implement what they need
- Clear separation between plugin discovery and extension points

### Constructor-Based Initialization

`PluginExtensions` uses constructor-based initialization for compatibility with .NET Standard 2.0:

```csharp
// ✓ Works with netstandard2.0
public PluginExtensions(
    IEnumerable<ISigningCommandProvider> signingCommandProviders,
    IEnumerable<IVerificationProvider> verificationProviders,
    IEnumerable<ITransparencyProviderContributor> transparencyProviders)
{
    SigningCommandProviders = signingCommandProviders ?? [];
    VerificationProviders = verificationProviders ?? [];
    TransparencyProviders = transparencyProviders ?? [];
}

// ✗ 'init' setters require C# 9+ and aren't available in netstandard2.0
// public IEnumerable<ISigningCommandProvider> SigningCommandProviders { get; init; }
```

### Priority-Based Verification

Verification providers declare a `Priority` property to control execution order:

| Priority Range | Use Case |
|---------------|----------|
| 0-9 | Signature validation |
| 10-19 | Certificate chain validation |
| 20-49 | Certificate property validation |
| 50-99 | Custom business logic |
| 100+ | Transparency/audit validation |

## Available Plugins

| Plugin | Commands | Verification | Transparency |
|--------|----------|--------------|--------------|
| `CoseSignTool.Local.Plugin` | `sign-pfx`, `sign-certstore`, `sign-pem`, `sign-ephemeral` | X509 verification | - |
| `CoseSignTool.AzureTrustedSigning.Plugin` | `sign-azure` | - | - |
| `CoseSignTool.MST.Plugin` | - | MST receipt verification | MST receipt generation |

## Security Utilities

### SecurePasswordProvider

The `SecurePasswordProvider` class provides secure password handling for CLI applications. It uses `SecureString` throughout to minimize password exposure in memory.

```csharp
using CoseSignTool.Abstractions.Security;

// Use the default instance (uses system console)
var provider = SecurePasswordProvider.Default;

// Get password using priority order: env var → file → interactive prompt
var password = provider.GetPassword(
    passwordFilePath: "/path/to/password.txt",
    environmentVariableName: "MY_PASSWORD_VAR",
    prompt: "Enter password: ");

// Read password interactively with masked input
var password = provider.ReadPasswordFromConsole("Enter PFX password: ");

// Check if interactive input is available
if (provider.IsInteractiveInputAvailable())
{
    // Safe to prompt user
}
```

**Static Methods** (don't require console access):
- `GetPasswordFromEnvironment(string envVarName)` - Read from environment variable
- `ReadPasswordFromFile(string filePath)` - Read from secure file
- `ConvertToSecureString(string? value)` - Convert plain string to SecureString
- `ConvertToPlainString(SecureString? secure)` - Convert SecureString to plain string
- `Copy(SecureString? source)` - Create a copy of a SecureString

**Instance Methods** (require console for interactive input):
- `ReadPasswordFromConsole(string prompt)` - Masked password input
- `GetPassword(...)` - Priority-based password retrieval
- `IsInteractiveInputAvailable()` - Check if console input is available

### IConsole Interface

For testability, console operations are abstracted through the `IConsole` interface:

```csharp
public interface IConsole
{
    void Write(string? value);
    void WriteLine();
    void WriteLine(string? value);
    ConsoleKeyInfo ReadKey(bool intercept);
    string? ReadLine();
    bool IsInputRedirected { get; }
    bool IsUserInteractive { get; }
}
```

**Testing with Mock Console**:
```csharp
var mockConsole = new Mock<IConsole>();
mockConsole.SetupSequence(c => c.ReadKey(true))
    .Returns(new ConsoleKeyInfo('p', ConsoleKey.P, false, false, false))
    .Returns(new ConsoleKeyInfo('w', ConsoleKey.W, false, false, false))
    .Returns(new ConsoleKeyInfo('d', ConsoleKey.D, false, false, false))
    .Returns(new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false));

var provider = new SecurePasswordProvider(mockConsole.Object);
var password = provider.ReadPasswordFromConsole();
// password = "pwd"
```

The `SystemConsole` class provides the default implementation that wraps `System.Console`. It is marked with `[ExcludeFromCodeCoverage]` as it's a thin wrapper with no testable logic.

## See Also

- [Plugin Documentation](../plugins/README.md) - Plugin development guide
- [Architecture Overview](../architecture/overview.md) - V2 architecture
- [Creating CLI Plugins](../guides/cli-plugins.md) - Step-by-step plugin creation

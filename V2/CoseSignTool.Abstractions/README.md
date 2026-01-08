# CoseSignTool.Abstractions

Plugin abstraction interfaces for extending CoseSignTool with custom signing, verification, and transparency providers.

## Overview

This package defines the core interfaces that plugins must implement to extend CoseSignTool. It provides a model-based extension system that allows plugins to contribute:

- **Signing Commands**: Add custom signing commands (e.g., `sign-pfx`, `sign-azure`)
- **Verification Providers**: Add custom validation logic to the verify command
- **Transparency Providers**: Integrate with transparency services (e.g., MST)

## Installation

```bash
dotnet add package CoseSignTool.Abstractions --version 2.0.0-preview
```

## Core Interfaces

### IPlugin

The main interface that all plugins must implement:

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

### PluginExtensions

The model containing all extension points a plugin provides:

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

### ISigningCommandProvider

Interface for plugins that add signing commands:

```csharp
public interface ISigningCommandProvider
{
    string CommandName { get; }
    string CommandDescription { get; }
    string ExampleUsage { get; }
    
    void AddCommandOptions(Command command);
    Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options);
    IDictionary<string, string> GetSigningMetadata();
}
```

### IVerificationProvider

Interface for plugins that add verification capabilities:

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

Verification providers return stage-aware validators (`IValidator`). The CLI partitions validators by `ValidationStage` and runs them in a secure-by-default order:

1. Key material resolution
2. Key material trust (including trust policy evaluation)
3. Signature verification
4. Post-signature validation

### ITransparencyProviderContributor

Interface for plugins that integrate transparency services:

```csharp
public interface ITransparencyProviderContributor
{
    string ProviderName { get; }
    string ProviderDescription { get; }
    
    void AddTransparencyOptions(Command command);
    bool IsActivated(ParseResult parseResult);
    Task<ITransparencyProvider> CreateTransparencyProviderAsync(
        IDictionary<string, object?> options,
        CancellationToken cancellationToken = default);
}
```

## Creating a Plugin

### Basic Plugin Structure

```csharp
public class MyPlugin : IPlugin
{
    public string Name => "MyPlugin";
    public string Version => "1.0.0";
    public string Description => "A custom plugin for CoseSignTool";

    public PluginExtensions GetExtensions()
    {
        return new PluginExtensions(
            signingCommandProviders: new[] { new MySigningProvider() },
            verificationProviders: new[] { new MyVerificationProvider() },
            transparencyProviders: Array.Empty<ITransparencyProviderContributor>()
        );
    }

    public void RegisterCommands(Command rootCommand)
    {
        // Register any utility commands that don't fit the standard pattern
    }

    public Task InitializeAsync(IDictionary<string, string>? configuration = null)
    {
        // Initialize plugin resources
        return Task.CompletedTask;
    }
}
```

### Signing Command Provider Example

```csharp
public class MySigningProvider : ISigningCommandProvider
{
    public string CommandName => "sign-my";
    public string CommandDescription => "Sign using my custom signing service";
    public string ExampleUsage => "--my-option value";

    public void AddCommandOptions(Command command)
    {
        command.AddOption(new Option<string>("--my-option", "My custom option"));
    }

    public Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(
        IDictionary<string, object?> options)
    {
        var myOption = options["my-option"] as string;
        return Task.FromResult<ISigningService<SigningOptions>>(
            new MySigningService(myOption));
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            { "Provider", "MyProvider" }
        };
    }
}
```

### Verification Provider Example

```csharp
public class MyVerificationProvider : IVerificationProvider
{
    public string ProviderName => "MyVerifier";
    public string Description => "Custom verification logic";
    public int Priority => 50; // Run after signature validation (0) but before chain validation

    private Option<string>? _myOption;

    public void AddVerificationOptions(Command command)
    {
        _myOption = new Option<string>("--my-verify-option", "Custom verification option");
        command.AddOption(_myOption);
    }

    public bool IsActivated(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(_myOption) != null;
    }

    public IEnumerable<IValidator> CreateValidators(ParseResult parseResult)
    {
        var optionValue = parseResult.GetValueForOption(_myOption);
        yield return new MyCustomValidator(optionValue);
    }

    public IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult)
    {
        return new Dictionary<string, object?>
        {
            { "CustomVerification", "Passed" }
        };
    }
}
```

### Optional: trust policies

Providers can optionally contribute a trust policy by implementing `IVerificationProviderWithTrustPolicy`. When multiple active providers contribute policies, the CLI requires all of them to be satisfied (logical AND).

## Available Plugins

| Plugin | Package | Description |
|--------|---------|-------------|
| Local | `CoseSignTool.Local.Plugin` | Local certificate signing (PFX, cert stores) |
| Azure | `CoseSignTool.AzureTrustedSigning.Plugin` | Azure Trusted Signing integration |
| MST | `CoseSignTool.MST.Plugin` | Microsoft's Signing Transparency |

## Dependencies

- `CoseSign1.Abstractions` - Core signing abstractions
- `CoseSign1.Validation` - Validation framework
- `System.CommandLine` - Command-line parsing

## Target Frameworks

- .NET 10.0
- .NET Standard 2.0 (for broader compatibility)

## License

MIT License - see [LICENSE](../LICENSE) for details.

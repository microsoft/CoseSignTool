# CLI Plugins Guide

This guide explains how CLI plugins work in CoseSignTool V2 and how to create custom plugins.

## Overview

CoseSignTool V2 uses a plugin architecture to extend CLI functionality. Plugins can add new commands, options, and integrate with external services without modifying the core tool.

## Built-in Plugins

### Local Signing Plugin

Provides commands for local certificate-based signing:

| Command | Description |
|---------|-------------|
| `sign-pfx` | Sign using a PFX/PKCS#12 file |
| `sign-certstore` | Sign using Windows Certificate Store |
| `sign-pem` | Sign using PEM certificate/key files |
| `sign-ephemeral` | Sign using a temporary self-signed certificate |

### Azure Trusted Signing Plugin

Provides cloud signing integration:

| Command | Description |
|---------|-------------|
| `sign-azure` | Sign using Azure Trusted Signing |

### MST Plugin

Adds Microsoft's Signing Transparency options to verification:

| Options | Description |
|---------|-------------|
| `--mst-service-uri` | MST service endpoint |
| `--verify-mst-receipt` | Verify MST receipt on signature |
| `--require-mst-receipt` | Fail if no valid MST receipt |

### Indirect Signature Plugin

Adds indirect (hash envelope) signature support:

| Options | Description |
|---------|-------------|
| `--signature-type indirect` | Create indirect signature |
| `--hash-algorithm` | Hash algorithm for indirect signatures |

## Plugin Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CoseSignTool CLI                          │
│                     (Core Commands)                          │
├─────────────────────────────────────────────────────────────┤
│  verify  │  inspect  │  help  │  version                     │
└─────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
     ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
     │   Local     │ │   Azure     │ │    MST      │
     │   Plugin    │ │   Plugin    │ │   Plugin    │
     ├─────────────┤ ├─────────────┤ ├─────────────┤
     │ sign-pfx    │ │ sign-azure  │ │ --verify-   │
     │ sign-cert-  │ │             │ │   mst-      │
     │   store     │ │             │ │   receipt   │
     │ sign-pem    │ │             │ │             │
     │ sign-       │ │             │ │             │
     │   ephemeral │ │             │ │             │
     └─────────────┘ └─────────────┘ └─────────────┘
```

## Creating a Custom Plugin

### 1. Create Plugin Project

```bash
dotnet new classlib -n CoseSignTool.MyPlugin
cd CoseSignTool.MyPlugin
dotnet add reference ../CoseSignTool.Abstractions/CoseSignTool.Abstractions.csproj
```

### 2. Implement ICliPlugin

```csharp
using CoseSignTool.Abstractions;
using System.CommandLine;

public class MyPlugin : ICliPlugin
{
    public string Name => "My Custom Plugin";
    public string Description => "Adds custom signing functionality";
    public Version Version => new Version(1, 0, 0);

    public void RegisterCommands(RootCommand rootCommand)
    {
        var myCommand = new Command("sign-custom", "Sign using custom method");
        
        var inputOption = new Option<string>(
            "--input",
            "Input file to sign") { IsRequired = true };
        
        var outputOption = new Option<string>(
            "--output",
            "Output signature file") { IsRequired = true };
        
        myCommand.AddOption(inputOption);
        myCommand.AddOption(outputOption);
        
        myCommand.SetHandler(async (input, output) =>
        {
            await SignCustomAsync(input, output);
        }, inputOption, outputOption);
        
        rootCommand.AddCommand(myCommand);
    }

    public void RegisterOptions(Command command)
    {
        // Add options to existing commands (like verify)
        if (command.Name == "verify")
        {
            var customOption = new Option<bool>(
                "--verify-custom",
                "Enable custom verification");
            command.AddOption(customOption);
        }
    }

    private async Task SignCustomAsync(string input, string output)
    {
        // Implementation
    }
}
```

### 3. Register Plugin

Plugins are discovered via assembly scanning or explicit registration:

```csharp
// In Program.cs or startup
var builder = new CliBuilder();
builder.AddPlugin<MyPlugin>();
var cli = builder.Build();
```

## Plugin Interfaces

### ICliPlugin

Main plugin interface:

```csharp
public interface ICliPlugin
{
    string Name { get; }
    string Description { get; }
    Version Version { get; }
    
    void RegisterCommands(RootCommand rootCommand);
    void RegisterOptions(Command command);
}
```

### ISigningPlugin

For plugins that provide signing services:

```csharp
public interface ISigningPlugin : ICliPlugin
{
    ISigningService CreateSigningService(SigningOptions options);
}
```

### IValidationPlugin

For plugins that add validation:

```csharp
public interface IValidationPlugin : ICliPlugin
{
    IValidator CreateValidator(ValidationOptions options);
}
```

## Adding Options to Existing Commands

Plugins can add options to existing commands:

```csharp
public void RegisterOptions(Command command)
{
    switch (command.Name)
    {
        case "verify":
            AddVerifyOptions(command);
            break;
        case "inspect":
            AddInspectOptions(command);
            break;
    }
}

private void AddVerifyOptions(Command command)
{
    command.AddOption(new Option<string>(
        "--custom-root",
        "Custom root certificate for validation"));
}
```

## Plugin Configuration

Plugins can access configuration:

```csharp
public class ConfigurablePlugin : ICliPlugin
{
    private readonly MyPluginOptions _options;
    
    public ConfigurablePlugin(IOptions<MyPluginOptions> options)
    {
        _options = options.Value;
    }
    
    // Plugin implementation using _options
}
```

Configuration in appsettings.json:

```json
{
  "Plugins": {
    "MyPlugin": {
      "ServiceUrl": "https://example.com",
      "ApiKey": "..."
    }
  }
}
```

## Plugin Discovery

### Assembly Scanning

Plugins can be discovered automatically:

```csharp
var pluginPath = Path.Combine(AppContext.BaseDirectory, "plugins");
var plugins = PluginLoader.LoadPlugins(pluginPath);

foreach (var plugin in plugins)
{
    builder.AddPlugin(plugin);
}
```

### NuGet Packages

Distribute plugins as NuGet packages:

```xml
<PackageReference Include="CoseSignTool.MyPlugin" Version="1.0.0" />
```

## Error Handling

Plugins should handle errors gracefully:

```csharp
myCommand.SetHandler(async (input, output) =>
{
    try
    {
        await SignCustomAsync(input, output);
        return 0; // Success
    }
    catch (FileNotFoundException ex)
    {
        Console.Error.WriteLine($"File not found: {ex.FileName}");
        return 1;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error: {ex.Message}");
        return 1;
    }
});
```

## Testing Plugins

```csharp
[TestClass]
public class MyPluginTests
{
    [TestMethod]
    public void RegisterCommands_AddsSignCustomCommand()
    {
        // Arrange
        var plugin = new MyPlugin();
        var rootCommand = new RootCommand();
        
        // Act
        plugin.RegisterCommands(rootCommand);
        
        // Assert
        var command = rootCommand.Children
            .OfType<Command>()
            .FirstOrDefault(c => c.Name == "sign-custom");
        Assert.IsNotNull(command);
    }
}
```

## See Also

- [CLI Reference](../cli/README.md)
- [Local Plugin](../plugins/local-plugin.md)
- [Azure Plugin](../plugins/azure-plugin.md)
- [MST Plugin](../plugins/mst-plugin.md)

# CLI Plugins Guide

This guide explains how CLI plugins work in CoseSignTool V2, how built-in plugins are loaded, and how to build your own plugin.

For the plugin authoring model (interfaces and extension points), see the [Plugin Development Guide](../plugins/README.md).

## What plugins can do

Plugins implement `CoseSignTool.Abstractions.IPlugin` and can contribute functionality via:

- **Signing commands** (e.g., `sign-pfx`, `sign-azure`) via `ISigningCommandProvider`
- **Verification providers** (extra verification behaviors and/or options surfaced by `verify`) via `IVerificationProvider`
- **Transparency providers** (e.g., MST) via `ITransparencyProviderContributor`

In V2, **all signing commands are provided by plugins**. The core CLI provides the built-in `verify` and `inspect` commands.

## Built-in plugins

The default distribution includes these plugins (each has its own documentation page):

- **Local signing**: [Local plugin](../plugins/local-plugin.md)
  - Commands: `sign-pfx`, `sign-pem`, `sign-certstore`, `sign-ephemeral`
- **Azure Key Vault**: [Azure Key Vault plugin](../plugins/azure-keyvault-plugin.md)
  - Commands: `sign-akv-cert`, `sign-akv-key`
- **Azure Trusted Signing**: [Azure plugin](../plugins/azure-plugin.md)
  - Command: `sign-azure`
- **Microsoft Signing Transparency (MST)**: [MST plugin](../plugins/mst-plugin.md)
  - Adds verification options (for example `--require-receipt`, `--mst-endpoint`, `--mst-trust-mode`)
- **Indirect signatures**: [Indirect plugin](../plugins/indirect-plugin.md)
  - Adds signing options (for example `--signature-type indirect`, `--hash-algorithm`)

This guide intentionally links to the plugin-specific docs above rather than duplicating every command/option detail.

## How plugin discovery works

By default, CoseSignTool loads plugins from a `plugins` directory next to the executable.

- The tool scans **subdirectories** under `plugins/`.
- Each plugin must live in its **own subdirectory** (dependency isolation).
- Plugin assemblies are discovered by filename suffix: `*.Plugin.dll`.
- Each `*.Plugin.dll` is loaded into an isolated `AssemblyLoadContext`.
- Types implementing `IPlugin` are instantiated via a **parameterless constructor** and registered.

You can also load plugins from additional locations:

```text
--additional-plugin-dir <dir>
```

`--additional-plugin-dir` may be provided multiple times. Each additional directory is expected to have the same structure (subdirectory-per-plugin).

## Creating a custom plugin

### 1. Create a plugin project

```bash
dotnet new classlib -n CoseSignTool.MyPlugin
cd CoseSignTool.MyPlugin
dotnet add reference ../CoseSignTool.Abstractions/CoseSignTool.Abstractions.csproj
```

### 2. Implement `IPlugin`

Minimal skeleton:

```csharp
using System.CommandLine;
using CoseSignTool.Abstractions;

public sealed class MyPlugin : IPlugin
{
    public string Name => "my-plugin";
    public string Version => "1.0.0";
    public string Description => "Example plugin";

    public Task InitializeAsync(IDictionary<string, string>? configuration = null)
        => Task.CompletedTask;

    public PluginExtensions GetExtensions()
        => PluginExtensions.None;

    public void RegisterCommands(Command rootCommand)
    {
        // Optional: register standalone utility commands.
        // Signing commands and verify providers should typically be exposed via GetExtensions().
    }
}
```

Then add your signing commands / verification providers using the extension points described in [Plugin Development Guide](../plugins/README.md).

### 3. Package the plugin for loading

To be discoverable by the default loader:

- Ensure your output assembly name ends with `.Plugin.dll`.
- Create a dedicated directory for the plugin under `plugins/`.
- Copy the plugin DLL and all dependencies into that directory.

Example layout:

```text
<cosesigntool>/
  CoseSignTool.exe
  plugins/
    MyPlugin/
      CoseSignTool.MyPlugin.Plugin.dll
      <dependencies>.dll
```

To load from a different location, place the plugin under a directory you pass via `--additional-plugin-dir`, still using the subdirectory-per-plugin layout.

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
using NUnit.Framework;

[TestFixture]
public class MyPluginTests
{
    [Test]
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
        Assert.That(command, Is.Not.Null);
    }
}
```

## See Also

- [CLI Reference](../cli/README.md)
- [Local Plugin](../plugins/local-plugin.md)
- [Azure Plugin](../plugins/azure-plugin.md)
- [MST Plugin](../plugins/mst-plugin.md)

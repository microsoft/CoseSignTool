# Plugin API Reference

This document provides a complete API reference for the CoseSignTool plugin system.

## Namespace: CoseSignTool.Abstractions

All plugin interfaces and base classes are contained in the `CoseSignTool.Abstractions` namespace.

### Assembly Requirements

- **Target Framework**: .NET 8.0
- **Assembly Naming**: Must end with `.Plugin.dll` for automatic discovery
- **Project Naming**: Must end with `.Plugin.csproj` for automatic CI/CD packaging
- **Location**: Must be placed in the `plugins` subdirectory of CoseSignTool

### 🚨 **Critical Naming Conventions**

For full automatic integration with CoseSignTool:

#### **Project File Naming** (CI/CD Auto-Packaging)
```
<ProjectName>.Plugin.csproj
```
**Examples:**
- ✅ `YourCompany.CustomSigning.Plugin.csproj` → Automatically packaged in releases
- ✅ `AzureKeyVault.Integration.Plugin.csproj` → Automatically packaged in releases
- ❌ `CustomSigningTool.csproj` → NOT automatically packaged

#### **Assembly Naming** (Runtime Discovery)
```xml
<AssemblyName>YourCompany.CustomSigning.Plugin</AssemblyName>
```
**Results in**: `YourCompany.CustomSigning.Plugin.dll` → Automatically discovered at runtime

#### **Benefits of Following Conventions**
- ✅ **Zero CI/CD Maintenance**: No manual updates to build scripts
- ✅ **Automatic Packaging**: Included in all releases automatically
- ✅ **Automatic Discovery**: Commands appear in CoseSignTool help
- ✅ **Future-Proof**: Works with any number of plugins

## Interfaces

### ICoseSignToolPlugin

Main interface that all plugins must implement.

```csharp
public interface ICoseSignToolPlugin
{
    string Name { get; }
    string Version { get; }
    string Description { get; }
    IEnumerable<IPluginCommand> Commands { get; }
    void Initialize(IConfiguration? configuration = null);
}
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `Name` | `string` | Display name of the plugin (e.g., "Azure Code Transparency Service") |
| `Version` | `string` | Version string (semantic versioning recommended) |
| `Description` | `string` | Brief description shown in help output |
| `Commands` | `IEnumerable<IPluginCommand>` | Collection of commands provided by this plugin |

#### Methods

| Method | Description |
|--------|-------------|
| `Initialize(IConfiguration?)` | Called once when plugin is loaded. Use for setup, validation, and configuration |

**Example Implementation:**
```csharp
public class MyPlugin : ICoseSignToolPlugin
{
    public string Name => "My Service Plugin";
    public string Version => Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0";
    public string Description => "Integration with My Service";
    public IEnumerable<IPluginCommand> Commands => new[] { new MyCommand() };
    
    public void Initialize(IConfiguration? configuration = null)
    {
        // Plugin initialization logic
    }
}
```

### IPluginCommand

Interface for individual commands within a plugin.

```csharp
public interface IPluginCommand
{
    string Name { get; }
    string Description { get; }
    string Usage { get; }
    IDictionary<string, string> Options { get; }
    Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default);
}
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `Name` | `string` | Command name used on command line (e.g., "register", "verify") |
| `Description` | `string` | Short description for help output |
| `Usage` | `string` | Detailed usage instructions with examples |
| `Options` | `IDictionary<string, string>` | Maps command-line options to configuration keys |

#### Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `ExecuteAsync(IConfiguration, CancellationToken)` | `Task<PluginExitCode>` | Executes the command with provided configuration |

**Example Implementation:**
```csharp
public class MyCommand : IPluginCommand
{
    public string Name => "mycommand";
    public string Description => "Does something useful";
    public string Usage => "Usage: CoseSignTool mycommand --option value";
    public IDictionary<string, string> Options => new Dictionary<string, string>
    {
        ["--option"] = "option",
        ["-o"] = "option"
    };
    
    public async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        // Command implementation
        return PluginExitCode.Success;
    }
}
```

## Base Classes

### PluginCommandBase

Abstract base class providing common functionality for plugin commands.

```csharp
public abstract class PluginCommandBase : IPluginCommand
{
    public abstract string Name { get; }
    public abstract string Description { get; }
    public abstract string Usage { get; }
    public abstract IDictionary<string, string> Options { get; }
    public abstract Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default);
    
    protected static string GetRequiredValue(IConfiguration configuration, string key);
    protected static string? GetOptionalValue(IConfiguration configuration, string key, string? defaultValue = null);
}
```

#### Helper Methods

| Method | Description |
|--------|-------------|
| `GetRequiredValue(IConfiguration, string)` | Gets a required configuration value, throws if missing |
| `GetOptionalValue(IConfiguration, string, string?)` | Gets an optional configuration value with default |

**Example Usage:**
```csharp
public class MyCommand : PluginCommandBase
{
    public override async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken)
    {
        try
        {
            string required = GetRequiredValue(configuration, "endpoint");
            string optional = GetOptionalValue(configuration, "timeout", "30") ?? "30";
            
            // Command logic here
            return PluginExitCode.Success;
        }
        catch (ArgumentNullException ex)
        {
            Console.Error.WriteLine($"Missing required option: {ex.ParamName}");
            return PluginExitCode.MissingRequiredOption;
        }
    }
}
```

## Enumerations

### PluginExitCode

Represents the result of executing a plugin command.

```csharp
public enum PluginExitCode
{
    Success = 0,
    HelpRequested = 1,
    MissingRequiredOption = 2,
    UnknownArgument = 3,
    InvalidArgumentValue = 4,
    MissingArgumentValue = 5,
    UserSpecifiedFileNotFound = 6,
    UnknownError = 10
}
```

#### Values

| Value | Code | Description | When to Use |
|-------|------|-------------|-------------|
| `Success` | 0 | Command completed successfully | Normal completion |
| `HelpRequested` | 1 | User requested help | When `--help` or similar is detected |
| `MissingRequiredOption` | 2 | Required option missing | Required command-line option not provided |
| `UnknownArgument` | 3 | Unrecognized argument | Invalid command-line option |
| `InvalidArgumentValue` | 4 | Invalid argument value | Option value is invalid format/range |
| `MissingArgumentValue` | 5 | Missing argument value | Option provided without required value |
| `UserSpecifiedFileNotFound` | 6 | File not found | User-specified file doesn't exist |
| `UnknownError` | 10 | Unexpected error | Unhandled exceptions or unexpected conditions |

## Static Classes

### PluginLoader

Provides functionality to discover and load plugins.

```csharp
public static class PluginLoader
{
    public static IEnumerable<ICoseSignToolPlugin> DiscoverPlugins(string pluginDirectory);
    public static void ValidatePluginDirectory(string pluginDirectory);
    public static ICoseSignToolPlugin? LoadPlugin(string assemblyPath);
    public static ICoseSignToolPlugin? LoadPlugin(Assembly assembly);
}
```

#### Methods

| Method | Description |
|--------|-------------|
| `DiscoverPlugins(string)` | Discovers all plugins in the specified directory |
| `ValidatePluginDirectory(string)` | Validates directory is authorized for plugin loading |
| `LoadPlugin(string)` | Loads a plugin from an assembly file path |
| `LoadPlugin(Assembly)` | Loads a plugin from an Assembly object |

**Security Note**: `ValidatePluginDirectory` throws `UnauthorizedAccessException` if the directory is not the authorized `plugins` subdirectory.

## Configuration System

### IConfiguration Interface

Plugin commands receive configuration through the standard .NET `IConfiguration` interface.

**Common Patterns:**

```csharp
// Get string value
string? value = configuration["key"];

// Get with indexer
string? value = configuration["section:subsection"];

// Check if exists
bool exists = configuration.GetSection("key").Exists();

// Get typed value
int timeout = configuration.GetValue<int>("timeout", 30);
```

### Option Mapping

The `Options` dictionary maps command-line arguments to configuration keys:

```csharp
public IDictionary<string, string> Options => new Dictionary<string, string>
{
    ["--endpoint"] = "endpoint",        // --endpoint value -> configuration["endpoint"]
    ["-e"] = "endpoint",                // -e value -> configuration["endpoint"] (alias)
    ["--timeout"] = "timeout",          // --timeout value -> configuration["timeout"]
    ["--verbose"] = "verbose"           // --verbose -> configuration["verbose"] = "true"
};
```

## Error Handling Patterns

### Exception Handling

```csharp
public async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken)
{
    try
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        // Command logic here
        
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
    catch (FileNotFoundException ex)
    {
        Console.Error.WriteLine($"File not found: {ex.FileName}");
        return PluginExitCode.UserSpecifiedFileNotFound;
    }
    catch (ArgumentException ex)
    {
        Console.Error.WriteLine($"Invalid argument: {ex.Message}");
        return PluginExitCode.InvalidArgumentValue;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Unexpected error: {ex.Message}");
        return PluginExitCode.UnknownError;
    }
}
```

### Input Validation

```csharp
// Required parameter validation
string endpoint = GetRequiredValue(configuration, "endpoint");
if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri))
{
    Console.Error.WriteLine($"Invalid endpoint URL: {endpoint}");
    return PluginExitCode.InvalidArgumentValue;
}

// File existence validation
string filePath = GetRequiredValue(configuration, "file");
if (!File.Exists(filePath))
{
    Console.Error.WriteLine($"File not found: {filePath}");
    return PluginExitCode.UserSpecifiedFileNotFound;
}

// Numeric validation
string timeoutStr = GetOptionalValue(configuration, "timeout", "30") ?? "30";
if (!int.TryParse(timeoutStr, out int timeout) || timeout <= 0)
{
    Console.Error.WriteLine($"Invalid timeout value: {timeoutStr}");
    return PluginExitCode.InvalidArgumentValue;
}
```

## Best Practices

### Cancellation Token Handling

Always support cancellation in async operations:

```csharp
// Check before expensive operations
cancellationToken.ThrowIfCancellationRequested();

// Pass to async methods
await httpClient.SendAsync(request, cancellationToken);

// Use in loops
foreach (var item in items)
{
    cancellationToken.ThrowIfCancellationRequested();
    await ProcessItem(item, cancellationToken);
}
```

### Resource Management

Properly dispose of resources:

```csharp
public async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken)
{
    using var httpClient = new HttpClient();
    using var fileStream = File.OpenRead(filePath);
    
    try
    {
        // Use resources
        return PluginExitCode.Success;
    }
    finally
    {
        // Resources automatically disposed
    }
}
```

### Logging and Output

Use appropriate output streams:

```csharp
// Normal output
Console.WriteLine("Operation completed successfully");

// Error output
Console.Error.WriteLine("Error: Invalid input");

// Diagnostic output (when verbose)
if (verbose)
{
    Console.WriteLine($"Processing file: {fileName}");
}
```

### Security Considerations

1. **Validate all inputs**: Never trust user-provided data
2. **Sanitize file paths**: Prevent directory traversal attacks
3. **Limit file access**: Only access files explicitly provided by user
4. **Handle secrets carefully**: Don't log sensitive information

```csharp
// Safe file path handling
string userPath = GetRequiredValue(configuration, "file");
string fullPath = Path.GetFullPath(userPath);

// Validate the file is in expected location
if (!fullPath.StartsWith(allowedDirectory, StringComparison.OrdinalIgnoreCase))
{
    Console.Error.WriteLine("File access denied");
    return PluginExitCode.InvalidArgumentValue;
}
```

## Version Compatibility

### Assembly Version

Extract version information safely:

```csharp
public string Version => 
    System.Reflection.Assembly.GetExecutingAssembly()
        .GetName()
        .Version?
        .ToString() ?? "1.0.0";
```

### Dependency Management

- Target .NET 8.0
- Use compatible versions of Microsoft.Extensions.* packages
- Avoid conflicts with CoseSignTool dependencies
- Package additional dependencies with your plugin

## Testing

### Unit Testing

```csharp
[Test]
public async Task ExecuteAsync_ValidInput_ReturnsSuccess()
{
    // Arrange
    var command = new MyCommand();
    var configuration = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string>
        {
            ["endpoint"] = "https://example.com",
            ["timeout"] = "30"
        })
        .Build();

    // Act
    var result = await command.ExecuteAsync(configuration);

    // Assert
    Assert.AreEqual(PluginExitCode.Success, result);
}
```

### Integration Testing

```csharp
[Test]
public void PluginLoader_DiscoverPlugins_FindsTestPlugin()
{
    // Arrange
    string pluginDirectory = CreateTestPluginDirectory();

    // Act
    var plugins = PluginLoader.DiscoverPlugins(pluginDirectory);

    // Assert
    Assert.IsTrue(plugins.Any());
    Assert.AreEqual("Test Plugin", plugins.First().Name);
}
```

## Migration Guide

### From Version 1.x to 2.x

If breaking changes are introduced, migration steps will be documented here.

### Deprecated APIs

No deprecated APIs currently. Check this section for future deprecations.

## Troubleshooting

### Common Issues

**Plugin not discovered:**
- Assembly name must end with `.Plugin.dll`
- Must implement `ICoseSignToolPlugin`
- Must be in `plugins` directory

**Runtime errors:**
- Check .NET 8.0 compatibility
- Verify all dependencies are available
- Check console output for detailed error messages

**Command not working:**
- Verify `Options` dictionary mapping
- Check command name uniqueness
- Validate input parameters

For more troubleshooting information, see the main [Plugins.md](Plugins.md) documentation.

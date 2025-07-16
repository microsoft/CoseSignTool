# CoseSignTool Plugin System

CoseSignTool supports a plugin architecture that allows developers to extend the tool's functionality with custom commands and integrations. This document provides a comprehensive guide for creating, deploying, and using plugins with CoseSignTool.

## Overview

The plugin system enables:
- **Custom Commands**: Add new commands beyond the built-in `sign`, `validate`, and `get` commands
- **Third-party Integrations**: Connect with external services, APIs, and workflows
- **Extensible Architecture**: Maintain separation between core functionality and specialized features
- **Security**: Plugins are only loaded from the secure `plugins` subdirectory

## Plugin Architecture

### Core Interfaces

The plugin system is built around several key interfaces defined in the `CoseSignTool.Abstractions` namespace:

#### ICoseSignToolPlugin
The main plugin interface that all plugins must implement:

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

**Important**: The assembly name must end with `.Plugin.dll` for automatic discovery.

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

## Plugin Security Model

### Directory Restrictions

For security reasons, CoseSignTool only loads plugins from the `plugins` subdirectory of the executable:

```
CoseSignTool.exe
└── plugins/
    ├── YourCompany.YourService.Plugin.dll
    ├── AnotherCompany.AnotherService.Plugin.dll
    └── ...
```

**Security Features:**
- **Path validation**: The `PluginLoader.ValidatePluginDirectory()` method ensures plugins are only loaded from the authorized directory
- **Path normalization**: Handles different path formats and prevents directory traversal attacks
- **Exception throwing**: Attempts to load plugins from unauthorized locations throw `UnauthorizedAccessException`

### Plugin Discovery

The plugin discovery process:

1. **Directory existence**: Check if the `plugins` directory exists
2. **Security validation**: Verify the directory is authorized for plugin loading
3. **File scanning**: Search for `*.Plugin.dll` files in the directory (top-level only)
4. **Assembly loading**: Load each plugin assembly using `Assembly.LoadFrom()`
5. **Type discovery**: Find types implementing `ICoseSignToolPlugin`
6. **Instance creation**: Create plugin instances using `Activator.CreateInstance()`

### Error Handling

The plugin system includes comprehensive error handling:

- **Assembly loading errors**: Handled gracefully with warning messages
- **Type loading errors**: Reported without stopping other plugin loading
- **Plugin initialization errors**: Logged but don't prevent tool startup
- **Command conflicts**: Warn about duplicate command names

## Deploying Plugins

### Local Development

1. Build your plugin project
2. Copy the resulting `.dll` file to the `plugins` directory next to `CoseSignTool.exe`
3. Include any required dependencies (but avoid conflicts with CoseSignTool dependencies)

### Distribution

For distributing plugins:

1. **NuGet Package**: Create a NuGet package containing the plugin assembly
2. **ZIP Archive**: Package the plugin and dependencies in a ZIP file
3. **Installer**: Create an installer that places files in the correct location
4. **Documentation**: Include usage instructions and examples

### Dependencies

**Included with CoseSignTool:**
- Microsoft.Extensions.Configuration
- Microsoft.Extensions.Configuration.Abstractions
- System.Text.Json
- .NET 8.0 Base Class Library

**Plugin-specific dependencies:**
- Package them with your plugin
- Ensure version compatibility
- Document any external dependencies

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

Plugin commands are automatically included in the help system:

```bash
# General help shows all commands including plugins
CoseSignTool --help

# Plugin command help
CoseSignTool your_register --help
```

### Configuration

Plugin commands receive configuration through the standard .NET `IConfiguration` interface:

- **Command-line arguments**: Parsed and mapped according to the plugin's `Options` dictionary
- **Environment variables**: Available through the configuration system
- **Configuration files**: Can be loaded by plugins during initialization

## Example: Azure Code Transparency Service Plugin

The CoseSignTool includes a reference implementation for Azure Code Transparency Service integration:

### Plugin Structure
```
CoseSignTool.CTS.Plugin/
├── AzureCtsPlugin.cs           # Main plugin class
├── RegisterCommand.cs          # Command to register signatures
├── VerifyCommand.cs           # Command to verify signatures
└── CoseSignTool.CTS.Plugin.csproj
```

### Usage Examples

```bash
# Register a signature with Azure CTS
CoseSignTool cts_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --credential default

# Verify a signature with Azure CTS
CoseSignTool cts_verify \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --receipt receipt.json
```

## Best Practices

### Plugin Development

1. **Error Handling**: Use appropriate `PluginExitCode` values for different error scenarios
2. **Cancellation Support**: Always respect the `CancellationToken` in async operations
3. **Input Validation**: Validate all user inputs and provide clear error messages
4. **Resource Management**: Properly dispose of resources and handle cleanup
5. **Security**: Never trust user input; validate and sanitize all data
6. **Logging**: Use Console.Error for error messages and Console.Out for regular output

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

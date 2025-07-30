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
- `CoseSignTool.CTS.Plugin.csproj` → Automatically built and deployed
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

The CoseSignTool includes a reference implementation for Azure Code Transparency Service integration.

> **📖 Complete Documentation**: For comprehensive Azure CTS plugin documentation, including detailed authentication options, CI/CD integration examples, and troubleshooting, see [AzureCTS.md](AzureCTS.md).

### Quick Start

The Azure CTS plugin provides two main commands:
- `cts_register` - Register signatures with Azure CTS
- `cts_verify` - Verify signatures against Azure CTS

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
# Register a signature with Azure CTS using default environment variable
export AZURE_CTS_TOKEN="your-access-token"
CoseSignTool cts_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose

# Register a signature with Azure CTS using custom environment variable
export MY_CTS_TOKEN="your-access-token"
CoseSignTool cts_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --token-env-var MY_CTS_TOKEN

# Verify a signature with Azure CTS
export AZURE_CTS_TOKEN="your-access-token"
CoseSignTool cts_verify \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --receipt receipt.json

# Using Azure DefaultCredential when no token is provided
CoseSignTool cts_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose
```

### Authentication

The Azure CTS plugin supports multiple authentication methods with the following priority:

1. **Environment Variable Token**: Uses an access token from an environment variable
   - `--token-env-var` specifies the environment variable name
   - If not specified, defaults to `AZURE_CTS_TOKEN`
   - This is the recommended approach for CI/CD environments

2. **Azure DefaultCredential**: Falls back to Azure DefaultCredential when no token is found
   - Automatically uses available Azure credentials (managed identity, Azure CLI, etc.)
   - Ideal for local development and Azure-hosted environments

#### Authentication Examples

```bash
# Using default environment variable
export AZURE_CTS_TOKEN="your-access-token"
CoseSignTool cts_register --endpoint https://your-cts-instance.azure.com --payload file.txt --signature file.cose

# Using custom environment variable
export MY_CUSTOM_TOKEN="your-access-token"
CoseSignTool cts_register --endpoint https://your-cts-instance.azure.com --payload file.txt --signature file.cose --token-env-var MY_CUSTOM_TOKEN

# Using Azure DefaultCredential (no token environment variable set)
# Requires Azure CLI login, managed identity, or other Azure credential
CoseSignTool cts_register --endpoint https://your-cts-instance.azure.com --payload file.txt --signature file.cose
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

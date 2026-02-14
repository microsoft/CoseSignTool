# Plugin Build and Deployment Guide

This document explains how plugins are built, deployed, and packaged with CoseSignTool using the enhanced subdirectory architecture introduced in version 2.0.

## Overview

The CoseSignTool plugin system includes automated build and deployment processes for both local development and CI/CD pipelines. The system supports:

- **🚀 Automatic Plugin Discovery**: Zero-maintenance CI/CD packaging using naming conventions
- **Enhanced Subdirectory Architecture**: Each plugin gets its own subdirectory with isolated dependencies
- **Legacy Flat Architecture**: Backward compatibility with older plugin deployment methods
- **Dependency Isolation**: Plugins can use different versions of the same dependencies without conflicts
- **Automated Deployment**: MSBuild targets handle complex dependency copying automatically

The Microsoft's Signing Transparency (MST) plugin and Indirect Signature plugin are included as reference implementations and are automatically built and deployed with CoseSignTool releases.

## 🎯 **Automatic Plugin Discovery and Packaging**

### **Convention-Based Auto-Packaging**
The CI/CD pipeline automatically discovers and packages **any project** following this naming pattern:

```
<ProjectName>.Plugin.csproj
```

### **How Automatic Discovery Works**
The GitHub Actions workflow uses this command to find all plugins:
```bash
# Discovers all plugin projects automatically
PLUGIN_PROJECTS=($(find . -name "*.Plugin.csproj" -type f | sed 's|^\./||' | sed 's|/[^/]*\.csproj$||'))
```

### **✅ Current Auto-Packaged Plugins**
- `CoseSignTool.MST.Plugin.csproj` → **Automatically packaged**
- `CoseSignTool.IndirectSignature.Plugin.csproj` → **Automatically packaged**

### **✅ Adding New Plugins (Zero Maintenance)**
To add a new plugin to automatic CI/CD packaging:

1. **Name your project with `.Plugin.csproj` suffix**:
   ```
   YourCompany.CustomSigning.Plugin.csproj
   AzureKeyVault.Integration.Plugin.csproj
   ```

2. **That's it!** No other changes needed:
   - ✅ Automatically discovered by CI/CD
   - ✅ Automatically built with proper versioning
   - ✅ Automatically deployed to release packages
   - ✅ Automatically tested in CI pipeline

### **❌ Projects NOT Auto-Packaged**
Projects not following the convention are ignored:
- `CoseSignTool.Utilities.csproj` → Not packaged (missing `.Plugin` suffix)
- `CustomTool.csproj` → Not packaged (missing `.Plugin` suffix)

### **🚀 Benefits of Auto-Discovery**
- **Zero Maintenance**: No manual updates to CI/CD scripts
- **Fail-Safe**: Cannot forget to include a plugin in deployment
- **Scalable**: Works with 2 plugins or 20 plugins
- **Convention-Based**: Clear, predictable naming rules

## Build Process

### CI/CD Pipeline (.github/workflows/dotnet.yml)

The GitHub Actions workflow handles plugin deployment in the release process:

1. **Build Phase**:
   - Builds the entire solution including all plugins
   - Tests all projects including plugin tests
   - Publishes the main CoseSignTool application

2. **Plugin Deployment Phase**:
   - Builds the CTS plugin with the same version as the main application
   - Creates `plugins` directories in both debug and release outputs
   - Copies the plugin DLL and its dependencies
   - Verifies plugin deployment and discovery

3. **Verification Phase**:
   - Lists plugin directory contents
   - Tests plugin command discovery in help output
   - Ensures plugins are properly integrated

### Local Development

For local development, plugins are automatically built and deployed with the main application:

```bash
# Build CoseSignTool - plugins are automatically built and deployed (default)
dotnet build CoseSignTool

# To build WITHOUT plugins (faster for quick iterations)
dotnet build CoseSignTool -p:NoPlugins=true

# This automatically:
# - Discovers all *.Plugin.csproj projects
# - Builds each plugin project
# - Creates plugins/CoseSignTool.MST.Plugin/ subdirectory
# - Creates plugins/CoseSignTool.IndirectSignature.Plugin/ subdirectory  
# - Copies each plugin and its dependencies to respective subdirectories
```

**What happens during plugin deployment:**
- **Plugin Discovery**: All `*.Plugin.csproj` projects are automatically found
- **Build**: Each plugin is built with the same Configuration and RuntimeIdentifier
- **MST Plugin**: Deployed to `plugins/CoseSignTool.MST.Plugin/` with Azure dependencies
- **Indirect Signature Plugin**: Deployed to `plugins/CoseSignTool.IndirectSignature.Plugin/` with minimal dependencies
- **Dependency Isolation**: Each plugin's dependencies are isolated in its subdirectory

## Plugin Deployment Structure

After deployment with the enhanced subdirectory architecture, the directory structure looks like:

```
CoseSignTool/
├── bin/
│   └── [Debug|Release]/
│       └── net8.0/
│           ├── CoseSignTool.exe                    # Main application
│           ├── CoseSignTool.dll                    # Main library
│           ├── [other shared dependencies...]
│           └── plugins/                            # Plugin directory
│               ├── CoseSignTool.MST.Plugin/        # MST plugin subdirectory
│               │   ├── CoseSignTool.MST.Plugin.dll
│               │   ├── CoseSignTool.MST.Plugin.deps.json
│               │   ├── Azure.Security.CodeTransparency.dll
│               │   ├── Azure.Core.dll
│               │   ├── Azure.Identity.dll
│               │   ├── Azure.Security.KeyVault.Keys.dll
│               │   ├── Microsoft.Bcl.AsyncInterfaces.dll
│               │   ├── Microsoft.Extensions.Configuration.CommandLine.dll
│               │   ├── Microsoft.Identity.Client.dll
│               │   ├── Newtonsoft.Json.dll
│               │   ├── System.ClientModel.dll
│               │   └── [other CTS-specific dependencies...]
│               ├── CoseSignTool.IndirectSignature.Plugin/  # Indirect Signature plugin subdirectory
│               │   ├── CoseSignTool.IndirectSignature.Plugin.dll
│               │   ├── CoseSignTool.IndirectSignature.Plugin.deps.json
│               │   └── [minimal plugin-specific dependencies...]
│               └── [legacy flat files for backward compatibility]
│                   ├── CoseSignTool.MST.Plugin.dll
│                   ├── CoseSignTool.IndirectSignature.Plugin.dll
│                   └── [shared dependencies...]
```

**Key Features:**
- **Dependency Isolation**: Each plugin subdirectory contains all its required dependencies
- **Version Independence**: Plugins can use different versions of the same dependency
- **Self-Contained**: Each plugin directory is a complete, deployable unit
- **Backward Compatibility**: Legacy flat structure is maintained for older deployment methods

## Dependency Management

### Enhanced Subdirectory Architecture (Version 2.0+)

The enhanced plugin system provides sophisticated dependency management:

1. **Isolated Loading**: Each plugin loads in its own `AssemblyLoadContext` 
2. **Plugin-Specific Dependencies**: Dependencies are resolved first from the plugin's subdirectory
3. **Shared Framework**: Common .NET and Microsoft.Extensions assemblies are resolved from the main application
4. **Version Flexibility**: Different plugins can use different versions of the same dependency
5. **Conflict Prevention**: Dependencies in one plugin cannot interfere with another plugin

**AssemblyLoadContext Resolution Order:**
1. Check if assembly is a shared framework assembly (System.*, Microsoft.Extensions.*, etc.)
   - If yes: Delegate to default context (shared with main application)
   - If no: Continue to plugin-specific resolution
2. Look for assembly in plugin's subdirectory
3. Use AssemblyDependencyResolver to find dependencies
4. Fall back to default context if not found

### Legacy Flat Architecture (Backward Compatibility)

For plugins deployed in the flat structure:

1. **Shared Dependencies**: Libraries already included in the main application are not duplicated
2. **Plugin-Specific Dependencies**: Libraries unique to plugins are copied to the plugins directory
3. **Conflict Risk**: Multiple plugins using different versions of the same dependency may conflict
4. **Manual Management**: Developers must carefully manage dependency versions

### Plugin Dependency Configuration

For optimal compatibility with the subdirectory architecture, configure your plugin project:

```xml
<PropertyGroup>
  <!-- Ensure all dependencies are copied to output -->
  <CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies>
  <PreserveCompilationContext>true</PreserveCompilationContext>
  <GenerateRuntimeConfigurationFiles>true</GenerateRuntimeConfigurationFiles>
</PropertyGroup>

<ItemGroup>
  <!-- Explicitly mark plugin-specific dependencies for copying -->
  <PackageReference Include="Azure.Core" Version="1.46.1">
    <Private>true</Private>
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  </PackageReference>
</ItemGroup>
```

## Adding New Plugins

To add a new plugin to the automated build process:

### 1. Create the Plugin Project

Ensure your plugin project:
- Targets .NET 8.0
- Has an assembly name ending with `.Plugin.dll`
- Implements `ICoseSignToolPlugin`
- Is included in the solution

### 2. Update Build Pipeline

Add your plugin to the CI/CD pipeline in `.github/workflows/dotnet.yml`:

```yaml
# In the "Build and deploy CTS plugin" step
- name: Build and deploy plugins
  run: |
    # Build your plugin
    dotnet build --configuration Debug --property:FileVersion=$VERSION YourPlugin/YourPlugin.csproj
    dotnet build --configuration Release --property:FileVersion=$VERSION YourPlugin/YourPlugin.csproj
    
    # Copy plugin DLL
    cp YourPlugin/bin/Debug/net8.0/YourPlugin.Plugin.dll published/debug/plugins/
    cp YourPlugin/bin/Release/net8.0/YourPlugin.Plugin.dll published/release/plugins/
    
    # Copy plugin-specific dependencies
    copy_if_exists "YourPlugin/bin/Debug/net8.0/YourSpecificDependency.dll" "published/debug/plugins/"
    copy_if_exists "YourPlugin/bin/Release/net8.0/YourSpecificDependency.dll" "published/release/plugins/"
```

### 3. Automatic Deployment (No Manual Configuration Needed)

If your plugin project follows the `*.Plugin.csproj` naming convention and is located anywhere under the CoseSignTool solution directory, it will be **automatically discovered, built, and deployed**.

The consolidated plugin discovery in `CoseSignTool.csproj` handles everything:

```xml
<!--Consolidated plugin discovery - reused by all plugin targets-->
<ItemGroup Condition="'$(DeployPlugins)' == 'true'">
    <PluginProjects Include="$(MSBuildProjectDirectory)\..\**\*.Plugin.csproj" />
    <PluginNames Include="@(PluginProjects->'%(Filename)')" />
</ItemGroup>
```

**No changes to CoseSignTool.csproj are required** - just name your project correctly and it will be included automatically.

### 4. Update Tests

Add your plugin tests to the CI/CD pipeline:

```yaml
# In the "Build and Test debug" step
dotnet test --no-restore YourPlugin.Tests/YourPlugin.Tests.csproj
```

## Testing Plugin Deployment

### Automated Testing

The CI/CD pipeline includes automated verification:

1. **Directory Verification**: Checks that plugins directory exists and contains expected files
2. **Discovery Testing**: Runs CoseSignTool with `--help` to verify plugin commands appear
3. **Integration Testing**: Plugin tests ensure functionality works correctly

### Manual Testing

For manual verification:

```bash
# Build with plugins (default behavior)
dotnet build CoseSignTool

# Build without plugins (faster)
dotnet build CoseSignTool -p:NoPlugins=true

# Navigate to output directory
cd CoseSignTool/bin/Debug/net8.0

# Verify plugins directory exists
ls -la plugins/

# Test plugin discovery
./CoseSignTool --help

# Test specific plugin command
./CoseSignTool mst_register --help
```

## Troubleshooting

### Common Issues

**Plugin not found:**
- Verify assembly name ends with `.Plugin.dll`
- Check that plugin is in the `plugins` directory
- Ensure plugin implements `ICoseSignToolPlugin`

**Missing dependencies:**
- Check if plugin-specific dependencies are copied
- Verify dependency versions are compatible
- Look for dependency loading errors in console output

**Plugin commands not appearing:**
- Check plugin initialization doesn't throw exceptions
- Verify command names don't conflict with existing commands
- Review plugin discovery process in console output

### Debug Information

Enable debug output to see plugin loading details:

```bash
# Set environment variable for detailed plugin loading
export COSESIGNTOOL_DEBUG_PLUGINS=true
./CoseSignTool --help
```

## Security Considerations

### Plugin Security

The build process maintains plugin security:

1. **Authorized Directory**: Plugins are only loaded from the `plugins` subdirectory
2. **Signed Assemblies**: Plugin assemblies use the same strong name signing as the main application
3. **Dependency Isolation**: Plugin dependencies are isolated in the plugins directory

### Build Security

The CI/CD pipeline includes security measures:

1. **Version Consistency**: All components built with the same version number
2. **Dependency Validation**: Only known, necessary dependencies are copied
3. **Verification Steps**: Automated checks ensure deployment integrity

## Performance Considerations

### Build Performance

The plugin build process is optimized for:

1. **Parallel Builds**: Plugins can be built in parallel with the main application
2. **Incremental Builds**: Only changed plugins are rebuilt in local development
3. **Selective Copying**: Only necessary dependencies are copied to reduce package size

### Runtime Performance

Plugin deployment affects runtime:

1. **Load Time**: Plugins are loaded at startup (minimal impact)
2. **Memory Usage**: Plugin assemblies are loaded into memory when discovered
3. **Startup Time**: Plugin discovery adds small overhead to application startup

## Maintenance

### Regular Tasks

1. **Dependency Updates**: Keep plugin dependencies up to date with main application
2. **Version Alignment**: Ensure plugin versions align with main application releases
3. **Test Coverage**: Maintain test coverage for plugin build and deployment process

### Monitoring

Monitor the following in CI/CD:

1. **Build Times**: Track if plugin builds are impacting overall build performance
2. **Package Sizes**: Monitor if plugin dependencies are significantly increasing package size
3. **Test Results**: Ensure plugin tests continue to pass in all environments

For more information about developing plugins, see:
- [Plugins.md](Plugins.md) - Complete plugin development guide
- [PluginQuickStart.md](PluginQuickStart.md) - Quick start guide for developers
- [PluginAPI.md](PluginAPI.md) - Complete API reference

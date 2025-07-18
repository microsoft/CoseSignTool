# Plugin Build and Deployment Guide

This document explains how plugins are built, deployed, and packaged with CoseSignTool.

## Overview

The CoseSignTool plugin system includes automated build and deployment processes for both local development and CI/CD pipelines. The Azure Code Transparency Service (CTS) plugin is included as a reference implementation and is automatically built and deployed with CoseSignTool releases.

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

For local development, you can use MSBuild targets to automatically deploy plugins:

```bash
# Build and deploy all plugins automatically
dotnet build CoseSignTool --target BuildAndDeployPlugins

# Build with automatic plugin deployment
dotnet build CoseSignTool -p:DeployPlugins=true
```

This will:
- Build the CTS plugin
- Create a `plugins` directory in the CoseSignTool output
- Copy the plugin DLL to the plugins directory

## Plugin Deployment Structure

After deployment, the directory structure looks like:

```
CoseSignTool/
├── bin/
│   └── [Debug|Release]/
│       └── net8.0/
│           ├── CoseSignTool.exe                    # Main application
│           ├── CoseSignTool.dll                    # Main library
│           ├── [other dependencies...]
│           └── plugins/                            # Plugin directory
│               ├── CoseSignTool.CTS.Plugin.dll     # CTS plugin
│               ├── Azure.Security.CodeTransparency.dll  # Plugin dependencies
│               ├── Azure.dll
│               ├── Azure.Identity.dll
│               └── Azure.Core.dll
```

## Dependency Management

### Plugin Dependencies

The build process handles plugin dependencies intelligently:

1. **Shared Dependencies**: Libraries already included in the main application are not duplicated
2. **Plugin-Specific Dependencies**: Libraries unique to plugins (like Azure SDK components) are copied to the plugins directory
3. **Automatic Detection**: The build script attempts to copy known plugin-specific dependencies and logs what was found/copied

### Dependency Resolution

When CoseSignTool loads plugins:

1. **Main Dependencies**: Resolved from the main application directory
2. **Plugin Dependencies**: Resolved from the plugins directory
3. **Fallback**: .NET runtime handles standard library resolution

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

### 3. Update Local Development Targets

Add your plugin to the MSBuild targets in `CoseSignTool.csproj`:

```xml
<Target Name="DeployYourPlugin" AfterTargets="Build" Condition="'$(DeployPlugins)' == 'true'">
  <PropertyGroup>
    <YourPluginPath>$(MSBuildProjectDirectory)\..\YourPlugin\bin\$(Configuration)\net8.0\YourPlugin.Plugin.dll</YourPluginPath>
  </PropertyGroup>
  
  <Copy SourceFiles="$(YourPluginPath)" 
        DestinationFolder="$(PluginsDir)" 
        Condition="Exists('$(YourPluginPath)')" />
</Target>

<!-- Update BuildAndDeployPlugins target -->
<Target Name="BuildAndDeployPlugins">
  <MSBuild Projects="..\YourPlugin\YourPlugin.csproj" 
           Properties="Configuration=$(Configuration)" />
  <!-- Add to existing targets -->
  <MSBuild Projects="$(MSBuildProjectFile)" 
           Properties="DeployPlugins=true;Configuration=$(Configuration)" 
           Targets="DeployYourPlugin" />
</Target>
```

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
# Build with plugins
dotnet build CoseSignTool --target BuildAndDeployPlugins

# Navigate to output directory
cd CoseSignTool/bin/Debug/net8.0

# Verify plugins directory exists
ls -la plugins/

# Test plugin discovery
./CoseSignTool --help

# Test specific plugin command
./CoseSignTool cts_register --help
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

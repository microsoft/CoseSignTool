# Plugin Architecture Migration Guide

This guide explains the migration from the legacy flat plugin architecture to the enhanced subdirectory-based plugin architecture introduced in CoseSignTool 2.0.

## Overview

CoseSignTool 2.0 introduces an enhanced plugin architecture that provides better dependency isolation and management while maintaining backward compatibility with the legacy flat structure.

## Architecture Changes

### Legacy Flat Architecture (v1.x)

```
CoseSignTool.exe
└── plugins/
    ├── Plugin1.dll
    ├── Plugin2.dll
    ├── SharedDependency.dll
    ├── AzureDependency.dll
    └── ...
```

**Limitations:**
- Dependency conflicts between plugins
- Difficult to manage different versions of the same dependency
- No isolation between plugin dependencies
- Manual dependency management required

### Enhanced Subdirectory Architecture (v2.0+)

```
CoseSignTool.exe
└── plugins/
    ├── Plugin1.Name/
    │   ├── Plugin1.dll
    │   ├── Plugin1Dependency.dll
    │   └── ...
    ├── Plugin2.Name/
    │   ├── Plugin2.dll
    │   ├── Plugin2Dependency.dll
    │   └── ...
    └── [legacy flat files for backward compatibility]
```

**Benefits:**
- Complete dependency isolation between plugins
- Different plugins can use different versions of the same dependency
- Self-contained plugin deployment
- Easier distribution and management
- Better security through isolated loading contexts

## Migration Process

### For Plugin Developers

#### 1. Update Project Configuration

Add these properties to your plugin's `.csproj` file:

```xml
<PropertyGroup>
  <!-- Ensure all dependencies are copied to output -->
  <CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies>
  <PreserveCompilationContext>true</PreserveCompilationContext>
  <GenerateRuntimeConfigurationFiles>true</GenerateRuntimeConfigurationFiles>
</PropertyGroup>

<ItemGroup>
  <!-- Explicitly mark plugin-specific dependencies for copying -->
  <PackageReference Include="YourDependency" Version="1.0.0">
    <Private>true</Private>
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  </PackageReference>
</ItemGroup>
```

#### 2. Update Build/Deployment Scripts

**Old deployment:**
```bash
copy bin/Debug/net8.0/MyPlugin.dll ../CoseSignTool/plugins/
```

**New deployment:**
```bash
mkdir ../CoseSignTool/plugins/MyPlugin/
copy bin/Debug/net8.0/*.* ../CoseSignTool/plugins/MyPlugin/
```

#### 3. Update MSBuild Targets

**Enhanced deployment target:**
```xml
<Target Name="DeployMyPlugin" AfterTargets="Build" Condition="'$(DeployPlugins)' == 'true'">
  <PropertyGroup>
    <PluginsDir>$(OutputPath)plugins</PluginsDir>
    <MyPluginSubDir>$(PluginsDir)\MyPlugin</MyPluginSubDir>
    <MyPluginDir>$(MSBuildProjectDirectory)\bin\$(Configuration)\net8.0</MyPluginDir>
  </PropertyGroup>
  
  <MakeDir Directories="$(MyPluginSubDir)" />
  
  <ItemGroup>
    <MyPluginFiles Include="$(MyPluginDir)\**\*.*" />
  </ItemGroup>
  
  <Copy SourceFiles="@(MyPluginFiles)" DestinationFolder="$(MyPluginSubDir)" />
  
  <Message Text="MyPlugin deployed to: $(MyPluginSubDir)" Importance="high" />
</Target>
```

### For End Users

#### No Action Required

The enhanced plugin system automatically supports both architectures:

1. **Subdirectory plugins** are loaded with isolated AssemblyLoadContext
2. **Legacy flat plugins** continue to work with the default context
3. **Discovery** works for both structures simultaneously

### For CI/CD Pipelines

#### Update Deployment Scripts

**Legacy script:**
```bash
# Copy plugin DLLs to flat structure
cp Plugin1/bin/Release/net8.0/Plugin1.dll published/plugins/
cp Plugin2/bin/Release/net8.0/Plugin2.dll published/plugins/
```

**Enhanced script:**
```bash
# Create subdirectories and copy all dependencies
mkdir -p published/plugins/Plugin1/
mkdir -p published/plugins/Plugin2/

cp Plugin1/bin/Release/net8.0/* published/plugins/Plugin1/
cp Plugin2/bin/Release/net8.0/* published/plugins/Plugin2/
```

## Compatibility Matrix

| Plugin Type | v1.x Support | v2.0+ Support | Loading Method |
|-------------|--------------|---------------|----------------|
| Legacy Flat | ✅ | ✅ | Default AssemblyLoadContext |
| Subdirectory | ❌ | ✅ | Isolated PluginLoadContext |

## Technical Implementation Details

### AssemblyLoadContext Usage

The enhanced system uses custom `PluginLoadContext` for subdirectory plugins:

```csharp
public class PluginLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;
    private readonly string _pluginDirectory;

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        // Check for shared framework assemblies first
        if (IsSharedFrameworkAssembly(assemblyName))
            return null; // Use default context
            
        // Try to load from plugin subdirectory
        string expectedPath = Path.Join(_pluginDirectory, $"{assemblyName.Name}.dll");
        if (File.Exists(expectedPath))
            return LoadFromAssemblyPath(expectedPath);
            
        return null; // Fall back to default context
    }
}
```

### Discovery Process

The plugin loader discovers both types:

```csharp
public static IEnumerable<ICoseSignToolPlugin> DiscoverPlugins(string pluginDirectory)
{
    // Enhanced: Load from subdirectories with isolation
    foreach (var plugin in DiscoverPluginsInSubdirectories(pluginDirectory))
        yield return plugin;
        
    // Legacy: Load from flat structure for backward compatibility  
    foreach (var plugin in DiscoverPluginsFlat(pluginDirectory))
        yield return plugin;
}
```

## Best Practices

### For New Plugins

1. **Use subdirectory architecture** for new plugin development
2. **Include all dependencies** in the plugin subdirectory
3. **Use proper MSBuild targets** for automated deployment
4. **Test both development and release** configurations

### For Existing Plugins

1. **Migrate gradually** - both architectures work simultaneously
2. **Update build scripts** to support subdirectory deployment
3. **Test thoroughly** in both deployment modes
4. **Update documentation** for users and contributors

### For Large Deployments

1. **Use subdirectory architecture** for better isolation
2. **Automate deployment** with MSBuild or CI/CD scripts
3. **Monitor dependency sizes** to optimize distribution
4. **Consider containerization** with the new architecture

## Troubleshooting

### Common Issues

**Plugin not discovered:**
- Ensure the assembly name ends with `.Plugin.dll`
- Verify the subdirectory name matches the plugin name
- Check that all dependencies are in the subdirectory

**Dependency loading errors:**
- Ensure `CopyLocalLockFileAssemblies=true` in the project file
- Verify all required dependencies are copied to the subdirectory
- Check for missing native dependencies

**Mixed architecture conflicts:**
- Remove legacy flat files when using subdirectory deployment
- Ensure consistent deployment method across all plugins
- Check for duplicate plugin loading from both structures

### Migration Checklist

- [ ] Update `.csproj` file with dependency copying properties
- [ ] Create subdirectory deployment scripts
- [ ] Test plugin loading in development environment
- [ ] Update CI/CD pipeline for subdirectory deployment
- [ ] Verify all dependencies are correctly isolated
- [ ] Update user documentation and deployment guides
- [ ] Remove legacy flat deployment once migration is complete

## Future Considerations

The enhanced subdirectory architecture is designed to be:

- **Extensible**: Support for additional isolation features
- **Performant**: Efficient dependency resolution and caching
- **Secure**: Better isolation and sandbox capabilities
- **Compatible**: Continued support for migration scenarios

Consider migrating to the subdirectory architecture for new deployments while maintaining legacy support for existing installations.

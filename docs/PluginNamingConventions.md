# Plugin Naming Conventions and Auto-Packaging Guide

This document consolidates all naming conventions required for automatic plugin discovery and CI/CD packaging in CoseSignTool.

## 🎯 **Quick Reference**

For a plugin to be **automatically discovered and packaged**, follow these conventions:

| Requirement | Convention | Example | Purpose |
|-------------|------------|---------|---------|
| **Project File** | `<Name>.Plugin.csproj` | `MyCompany.CustomSigning.Plugin.csproj` | CI/CD auto-packaging |
| **Assembly Name** | `<Name>.Plugin.dll` | `MyCompany.CustomSigning.Plugin.dll` | Runtime discovery |
| **Namespace** | `<Name>.Plugin` | `MyCompany.CustomSigning.Plugin` | Code organization |

## 🚀 **Automatic CI/CD Packaging**

### **How It Works**
The GitHub Actions workflow automatically discovers plugins using:
```bash
PLUGIN_PROJECTS=($(find . -name "*.Plugin.csproj" -type f))
```

### **✅ Current Auto-Packaged Plugins**
- `CoseSignTool.MST.Plugin.csproj` → Microsoft's Signing Transparency (MST) plugin
- `CoseSignTool.IndirectSignature.Plugin.csproj` → Indirect signature plugin

### **✅ Adding New Plugins (Zero Maintenance)**
To add a new plugin that gets automatically built and packaged:

1. **Create project with correct naming**:
   ```bash
   dotnet new classlib -n YourCompany.Feature.Plugin
   ```

2. **Configure project file** (`YourCompany.Feature.Plugin.csproj`):
   ```xml
   <Project Sdk="Microsoft.NET.Sdk">
     <PropertyGroup>
       <TargetFramework>net10.0</TargetFramework>
       <AssemblyName>YourCompany.Feature.Plugin</AssemblyName>
     </PropertyGroup>
     <ItemGroup>
       <ProjectReference Include="..\..\CoseSignTool.Abstractions\CoseSignTool.Abstractions.csproj" />
     </ItemGroup>
   </Project>
   ```

3. **That's it!** No other changes needed:
   - ✅ Automatically discovered by CI/CD
   - ✅ Automatically built with versioning
   - ✅ Automatically packaged in releases
   - ✅ Automatically tested in CI pipeline

## 📋 **Naming Examples**

### **✅ Correct Naming (Auto-Packaged)**
```
ProjectFile: AzureKeyVault.Integration.Plugin.csproj
AssemblyName: AzureKeyVault.Integration.Plugin.dll
Namespace: AzureKeyVault.Integration.Plugin
```

```
ProjectFile: SecureSign.Enterprise.Plugin.csproj  
AssemblyName: SecureSign.Enterprise.Plugin.dll
Namespace: SecureSign.Enterprise.Plugin
```

```
ProjectFile: CloudHSM.Provider.Plugin.csproj
AssemblyName: CloudHSM.Provider.Plugin.dll  
Namespace: CloudHSM.Provider.Plugin
```

### **❌ Incorrect Naming (NOT Auto-Packaged)**
```
❌ CustomSigningTool.csproj         → Missing .Plugin suffix
❌ MyPlugin.csproj                  → Missing .Plugin suffix  
❌ CoseSignTool.Utilities.csproj    → Not a plugin (utilities)
❌ SigningHelper.csproj             → Missing .Plugin suffix
```

## 🏗️ **Project Structure Template**

```
YourCompany.Feature.Plugin/
├── YourCompany.Feature.Plugin.csproj    # ← Must end with .Plugin.csproj
├── YourFeaturePlugin.cs                 # ← Main plugin class
├── Commands/
│   ├── SignCommand.cs
│   ├── VerifyCommand.cs
│   └── StatusCommand.cs
└── README.md
```

## 🔄 **Migration from Manual to Auto-Packaging**

If you have existing plugins not following the convention:

### **Step 1: Rename Project File**
```bash
# Before
MyCustomPlugin.csproj

# After  
MyCustom.Plugin.csproj
```

### **Step 2: Update Assembly Name**
```xml
<PropertyGroup>
  <AssemblyName>MyCustom.Plugin</AssemblyName>
</PropertyGroup>
```

### **Step 3: No CI/CD Changes Needed**
The plugin will be automatically discovered on the next build!

## 🎉 **Benefits Summary**

Following the `.Plugin.csproj` naming convention provides:

- ✅ **Zero Maintenance**: No manual CI/CD script updates  
- ✅ **Automatic Packaging**: Included in all releases
- ✅ **Automatic Discovery**: Runtime plugin loading
- ✅ **Automatic Testing**: CI/CD test execution
- ✅ **Future-Proof**: Works with unlimited plugins
- ✅ **Fail-Safe**: Cannot forget to include in deployment
- ✅ **Convention-Based**: Clear, predictable rules

## 📚 **Related Documentation**

- [Plugin Quick Start Guide](PluginQuickStart.md) - Step-by-step plugin creation
- [Plugin API Reference](PluginAPI.md) - Complete interface documentation  
- [Plugin Build and Deploy Guide](PluginBuildDeploy.md) - Detailed build process
- [Main Plugins Documentation](Plugins.md) - Comprehensive plugin system guide

---

**🚀 Ready to create a plugin?** Start with the [Plugin Quick Start Guide](PluginQuickStart.md) using the correct naming conventions!

# Installation Guide

This guide covers installing and setting up CoseSignTool V2 in your project.

## Prerequisites

- **.NET 10.0 or later** (preview versions supported)
- **C# 13** or later
- **NuGet package manager** (built into Visual Studio, dotnet CLI, or standalone)

## Package Overview

CoseSignTool V2 is distributed as multiple NuGet packages for maximum modularity:

### CLI Tool

| Package | Description | When to Use |
|---------|-------------|-------------|
| `CoseSignTool` | CLI tool with bundled plugins | Command-line signing and verification |

### Core Library Packages

| Package | Description | When to Use |
|---------|-------------|-------------|
| `CoseSign1.Abstractions` | Core interfaces and abstractions | Always (transitive dependency) |
| `CoseSign1` | Direct and indirect signature factories | Basic signing operations |
| `CoseSign1.Certificates` | Certificate-based signing | Certificate signing (most common) |
| `CoseSign1.Validation` | Validation framework | Message validation |
| `CoseSign1.Headers` | Header management, CWT claims | SCITT compliance, custom headers |

### Extended Functionality

| Package | Description | When to Use |
|---------|-------------|-------------|
| `CoseSign1.Certificates.AzureTrustedSigning` | Azure Trusted Signing integration | Cloud-based signing with Azure |
| `CoseSign1.Transparent.MST` | Microsoft's Signing Transparency receipts | Transparency with MST |
| `DIDx509` | DID:x509 resolution and validation | Decentralized identifiers |

### Plugin Packages (standalone installation)

| Package | Description | When to Use |
|---------|-------------|-------------|
| `CoseSignTool.Abstractions` | Plugin interfaces | Building custom CLI plugins |
| `CoseSignTool.Local.Plugin` | Local certificate signing | Standalone plugin usage |
| `CoseSignTool.MST.Plugin` | MST transparency verification | Standalone plugin usage |
| `CoseSignTool.AzureTrustedSigning.Plugin` | Azure Trusted Signing | Standalone plugin usage |

### Testing Utilities

| Package | Description | When to Use |
|---------|-------------|-------------|
| `CoseSign1.Tests.Common` | Test certificate utilities | Unit testing |

## Installation Methods

### Using .NET CLI

```bash
# Install CLI tool (includes all plugins)
dotnet tool install -g CoseSignTool --version 2.0.0-preview

# Most common scenario: certificate-based signing and validation
dotnet add package CoseSign1.Certificates --version 2.0.0-preview
dotnet add package CoseSign1.Validation --version 2.0.0-preview

# For Azure Trusted Signing
dotnet add package CoseSign1.Certificates.AzureTrustedSigning --version 2.0.0-preview

# For SCITT compliance (CWT claims)
dotnet add package CoseSign1.Headers --version 2.0.0-preview

# For transparency receipts
dotnet add package CoseSign1.Transparent.MST --version 2.0.0-preview

# For DID:x509 support
dotnet add package DIDx509 --version 2.0.0-preview
```

### Using Package Manager Console (Visual Studio)

```powershell
# Install CLI tool
dotnet tool install -g CoseSignTool -Version 2.0.0-preview

# Install library packages
Install-Package CoseSign1.Certificates -Version 2.0.0-preview
Install-Package CoseSign1.Validation -Version 2.0.0-preview
```

### Using PackageReference (csproj)

```xml
<ItemGroup>
  <PackageReference Include="CoseSign1.Certificates" Version="2.0.0-preview" />
  <PackageReference Include="CoseSign1.Validation" Version="2.0.0-preview" />
  <PackageReference Include="CoseSign1.Headers" Version="2.0.0-preview" />
</ItemGroup>
```

### Using Central Package Management

For solutions with many projects, use Central Package Management:

**Directory.Packages.props:**
```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  
  <ItemGroup>
    <PackageVersion Include="CoseSign1.Certificates" Version="2.0.0-preview" />
    <PackageVersion Include="CoseSign1.Validation" Version="2.0.0-preview" />
    <PackageVersion Include="CoseSign1.Headers" Version="2.0.0-preview" />
  </ItemGroup>
</Project>
```

**Project.csproj:**
```xml
<ItemGroup>
  <PackageReference Include="CoseSign1.Certificates" />
  <PackageReference Include="CoseSign1.Validation" />
</ItemGroup>
```

## Version Policy

### Preview Releases

Current V2 packages are in **preview** status:
- **Semantic versioning**: `2.0.0-preview`, `2.0.0-preview.1`, etc.
- **API stability**: APIs may change between previews
- **Production use**: Not recommended for production until stable release
- **Feedback**: Please report issues and suggestions

### Stable Releases (Future)

When V2 reaches stable:
- **Version format**: `2.x.y` (no preview suffix)
- **Semantic versioning**: Breaking changes = major, features = minor, fixes = patch
- **LTS support**: Long-term support for stable versions
- **Migration path**: Clear upgrade guides for breaking changes

## Post-Installation Setup

### 1. Verify Installation

Create a simple test file to verify installation:

```csharp
using CoseSign1.Certificates;
using CoseSign1.Direct;
using System.Security.Cryptography.X509Certificates;

Console.WriteLine("CoseSignTool V2 is installed!");

// Test basic functionality
using var cert = new X509Certificate2(/* your cert */);
using var service = CertificateSigningService.Create(cert);
using var factory = new DirectSignatureFactory(service);

Console.WriteLine("All packages loaded successfully!");
```

Run with:
```bash
dotnet run
```

### 2. Configure Global Usings (Optional)

Add common namespaces to `GlobalUsings.cs`:

```csharp
global using System.Security.Cryptography.Cose;
global using System.Security.Cryptography.X509Certificates;
global using CoseSign1.Certificates;
global using CoseSign1.Certificates.Extensions;
global using CoseSign1.Direct;
global using CoseSign1.Validation;
```

### 3. Enable Nullable Reference Types (Recommended)

V2 fully supports nullable reference types. Enable in your csproj:

```xml
<PropertyGroup>
  <Nullable>enable</Nullable>
</PropertyGroup>
```

### 4. Set Language Version

V2 uses modern C# features:

```xml
<PropertyGroup>
  <LangVersion>latest</LangVersion>
</PropertyGroup>
```

## Development Environment Setup

### Visual Studio 2022

1. **Install** Visual Studio 2022 (17.12 or later)
2. **Workload**: .NET desktop development
3. **Individual components**:
   - .NET 10.0 Runtime (preview)
   - .NET 10.0 SDK (preview)

### Visual Studio Code

1. **Install** [VS Code](https://code.visualstudio.com/)
2. **Extensions**:
   - C# Dev Kit
   - .NET Install Tool
3. **Install .NET 10 SDK**: [Download](https://dotnet.microsoft.com/download/dotnet/10.0)

### Command Line Only

```bash
# Install .NET 10 SDK
winget install Microsoft.DotNet.SDK.Preview

# Or download from https://dotnet.microsoft.com/download/dotnet/10.0

# Verify installation
dotnet --version
# Should show 10.x.x
```

## Platform-Specific Considerations

### Windows

- **Certificate stores**: Full support for Windows certificate stores
- **ML-DSA**: Preview support (requires .NET 10) ✅
- **Azure integration**: Native Azure SDK support

### Linux

- **Certificate stores**: Linux certificate store support
- **OpenSSL**: May require OpenSSL 3.0+ for some features
- **ML-DSA**: Not currently supported (Windows only in .NET 10)

### macOS

- **Certificate stores**: Keychain support
- **ML-DSA**: Not currently supported (Windows only in .NET 10)
- **Azure integration**: Full Azure SDK support

## Troubleshooting

### Package Not Found

**Error**: `Package 'CoseSign1.Certificates 2.0.0-preview' is not found`

**Solutions**:
1. Ensure you're using the preview feed:
   ```bash
   dotnet nuget list source
   ```
2. Add preview feed if missing:
   ```bash
   dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org
   ```
3. Clear package cache:
   ```bash
   dotnet nuget locals all --clear
   ```

### Version Conflicts

**Error**: Multiple versions of packages referenced

**Solution**: Use Central Package Management (see above) or ensure consistent versions:
```bash
dotnet list package --include-transitive
```

### Runtime Errors

**Error**: `Could not load file or assembly`

**Solutions**:
1. Verify .NET version: `dotnet --version`
2. Clean and rebuild: `dotnet clean && dotnet build`
3. Delete bin/obj folders manually

### Certificate Issues

**Error**: Certificate not found or access denied

**Solutions**:
1. Verify certificate path and password
2. Check certificate store permissions
3. Ensure certificate has private key:
   ```csharp
   if (!cert.HasPrivateKey)
       throw new Exception("Certificate requires private key");
   ```

## Next Steps

- [Quick Start Guide](quick-start.md) - Begin using V2
- [Architecture Overview](../architecture/overview.md) - Understand the design
- [Code Examples](../examples/README.md) - See practical examples

## Support

For installation issues:
- [GitHub Issues](https://github.com/microsoft/CoseSignTool/issues)
- [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/cosesigntool)

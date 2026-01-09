# Development Setup

This guide explains how to set up a development environment for CoseSignTool V2.

## Prerequisites

### Required Software

| Software | Version | Notes |
|----------|---------|-------|
| .NET SDK | 9.0+ | Required for building and testing |
| Git | Latest | For source control |
| Visual Studio 2022 | 17.8+ | Recommended IDE (optional) |
| VS Code | Latest | Alternative IDE (optional) |

### Optional Software

| Software | Purpose |
|----------|---------|
| Docker | Container testing |
| Azure CLI | Azure service testing |
| OpenSSL | Certificate generation |

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/microsoft/CoseSignTool.git
cd CoseSignTool
```

### Build the Solution

```bash
dotnet build CoseSignTool.sln
```

### Run Tests

```bash
dotnet test CoseSignTool.sln
```

### Run Tests with Coverage

```bash
dotnet test CoseSignTool.sln --collect:"XPlat Code Coverage"
```

## Project Structure

```
CoseSignTool/
├── V2/                           # V2 implementation
│   ├── CoseSign1.Abstractions/   # Core interfaces
│   ├── CoseSign1/                # Direct signatures
│   ├── CoseIndirectSignature/    # Indirect signatures
│   ├── CoseSign1.Certificates/   # Certificate handling
│   ├── CoseSign1.Headers/        # Header contributors
│   ├── CoseSign1.Transparent/    # Transparency abstractions
│   ├── CoseSign1.Transparent.MST/# MST integration
│   ├── CoseSignTool/             # CLI application
│   ├── CoseSignTool.Abstractions/# Plugin interfaces
│   └── docs/                     # Documentation
├── CoseHandler/                  # V1 compatibility layer
└── docs/                         # Root documentation
```

## IDE Setup

### Visual Studio 2022

1. Open `CoseSignTool.sln`
2. Install recommended extensions:
   - .NET Compiler Platform SDK
   - CodeMaid (optional, for code cleanup)

### VS Code

1. Open the repository folder
2. Install recommended extensions:
   - C# Dev Kit
   - .NET Extension Pack
   - GitLens

Configuration is in `.vscode/` folder.

## Development Workflow

### Creating a Branch

```bash
git checkout -b feature/my-feature
```

### Building

```bash
# Build all
dotnet build

# Build specific project
dotnet build V2/CoseSign1/CoseSign1.csproj
```

### Running Tests

```bash
# All tests
dotnet test

# Specific test project
dotnet test V2/CoseSign1.Tests/CoseSign1.Tests.csproj

# With filter
dotnet test --filter "FullyQualifiedName~SigningTests"

# Specific category
dotnet test --filter "TestCategory=Unit"
```

### Running the CLI

```bash
cd V2/CoseSignTool
dotnet run -- help
dotnet run -- sign-ephemeral test.json --output test.cose
```

## Configuration

### Directory.Build.props

Solution-wide MSBuild properties are in `Directory.Build.props`:

```xml
<Project>
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
</Project>
```

### Directory.Packages.props

Centralized package versions in `Directory.Packages.props`:

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Microsoft.Extensions.Logging" Version="9.0.0" />
    <!-- ... -->
  </ItemGroup>
</Project>
```

## Debugging

### Visual Studio

1. Set breakpoints
2. Press F5 to start debugging
3. Use Debug Console for expressions

### VS Code

1. Set breakpoints
2. Use `.vscode/launch.json` configurations
3. Press F5 to start debugging

### CLI Debugging

```bash
# Enable detailed logging
set COSESIGNTOOL_LOG_LEVEL=Debug
dotnet run -- verify test.cose
```

## Code Style

### Formatting

The project uses `.editorconfig` for consistent formatting:

- Indentation: 4 spaces
- Line endings: LF
- Encoding: UTF-8

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Public types | PascalCase | `DirectSignatureFactory` |
| Private fields | _camelCase | `_signingService` |
| Parameters | camelCase | `signingService` |
| Constants | PascalCase | `DefaultTimeout` |
| Interfaces | IPascalCase | `ISigningService` |

### Code Analysis

The solution uses .NET analyzers:

```xml
<PropertyGroup>
  <EnableNETAnalyzers>true</EnableNETAnalyzers>
  <AnalysisLevel>latest</AnalysisLevel>
</PropertyGroup>
```

### Logging Best Practices

For high-performance logging in hot paths, use the `[LoggerMessage]` source generator:

```csharp
public partial class MyValidator
{
    private readonly ILogger<MyValidator> _logger;

    [LoggerMessage(Level = LogLevel.Debug, EventId = 1001, Message = "Validating item {ItemName}")]
    private partial void LogValidatingItem(string itemName);
}
```

See [Logging and Diagnostics Guide](../guides/logging-diagnostics.md#high-performance-logging-pattern) for:
- When to use `[LoggerMessage]` vs standard logging
- EventId allocation guidelines
- Code examples and anti-patterns

## Creating Test Certificates

### Using PowerShell

```powershell
# Self-signed certificate
$cert = New-SelfSignedCertificate `
    -Subject "CN=Test Certificate" `
    -KeyAlgorithm ECDSA_nistP384 `
    -KeyUsage DigitalSignature `
    -CertStoreLocation "Cert:\CurrentUser\My"

# Export to PFX
$password = ConvertTo-SecureString -String "test" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "test.pfx" -Password $password
```

### Using OpenSSL

```bash
# Generate key
openssl ecparam -name prime256v1 -genkey -noout -out test.key

# Generate certificate
openssl req -new -x509 -key test.key -out test.crt -days 365 -subj "/CN=Test"

# Create PFX
openssl pkcs12 -export -out test.pfx -inkey test.key -in test.crt
```

## Troubleshooting

### Common Issues

**Build fails with missing SDK**
```
Install .NET 9.0 SDK from https://dotnet.microsoft.com/download
```

**Tests fail with certificate errors**
```
Create test certificates as shown above
```

**PQC tests skipped on non-Windows**
```
ML-DSA support is Windows-only - this is expected
```

## See Also

- [Testing Guide](testing.md)
- [Coverage Guide](coverage.md)
- [Contributing Guidelines](../../CONTRIBUTING.md)

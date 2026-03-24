# CoseSignTool Architecture & Developer Training Guide

This guide provides a comprehensive overview of the CoseSignTool repository for developers who want to understand, maintain, or extend the codebase.

## Table of Contents

1. [Overview](#overview)
2. [Project Structure](#project-structure)
3. [Architecture Layers](#architecture-layers)
4. [Core Abstractions](#core-abstractions)
5. [Design Patterns](#design-patterns)
6. [Data Flow](#data-flow)
7. [Key Components Deep Dive](#key-components-deep-dive)
8. [Plugin System](#plugin-system)
9. [SCITT Compliance](#scitt-compliance)
10. [Transparency Services](#transparency-services)
11. [Testing Strategy](#testing-strategy)
12. [Development Workflows](#development-workflows)
13. [Common Tasks](#common-tasks)
14. [Troubleshooting Guide](#troubleshooting-guide)

---

## Overview

CoseSignTool is a Microsoft project for creating and validating **COSE (CBOR Object Signing and Encryption)** signatures, primarily used for:

- Signing Software Bills of Materials (SBOMs)
- Supply chain integrity (SCITT compliance)
- IoT device authentication
- General-purpose cryptographic signing

The repository provides:
- **CLI tool** (`CoseSignTool`) for command-line operations
- **.NET libraries** for programmatic access
- **Plugin system** for extensibility
- **Transparency service integration** (Microsoft Signing Transparency)

### Key Technologies

| Technology | Purpose |
|------------|---------|
| `System.Security.Cryptography.Cose` | Native COSE implementation (.NET 7+) |
| `System.Formats.Cbor` | CBOR encoding/decoding |
| Azure SDK (`Azure.Core`, `Azure.Identity`) | Cloud service integration |
| NUnit/Moq | Testing framework |

---

## Project Structure

```
CoseSignTool3/
├── 📦 Core Libraries (NuGet packages)
│   ├── CoseSign1.Abstractions/     # Interfaces & base types
│   ├── CoseSign1/                  # Factory implementations
│   ├── CoseSign1.Headers/          # CWT Claims & header extensions
│   ├── CoseSign1.Certificates/     # X.509 certificate integration
│   └── CoseHandler/                # High-level static API
│
├── 📦 Extended Libraries
│   ├── CoseIndirectSignature/      # Large payload support
│   ├── CoseSign1.Transparent/      # Transparency service base
│   └── CoseSign1.Transparent.MST/  # Microsoft Signing Transparency
│
├── 🔧 CLI Application
│   ├── CoseSignTool/               # Main executable
│   └── CoseSignTool.Abstractions/  # Plugin interfaces
│
├── 🔌 Plugins
│   ├── CoseSignTool.IndirectSignature.Plugin/
│   ├── CoseSignTool.MST.Plugin/
│   ├── CoseSignTool.AzureArtifactSigning.Plugin/
│   └── CoseSign1.Certificates.AzureArtifactSigning/
│
├── 🧪 Test Projects (17+ projects)
│   ├── CoseSign1.Tests/
│   ├── CoseHandler.Tests/
│   ├── CoseSign1.Transparent.MST.Tests/
│   └── ... (one test project per library)
│
├── 📚 Documentation
│   └── docs/                       # 27 markdown files
│
└── 🔧 Build Configuration
    ├── Directory.Build.props       # Shared MSBuild settings
    ├── Directory.Packages.props    # Central package versions
    └── CoseSignTool.sln           # Solution file
```

### Target Frameworks

| Project Type | Targets |
|--------------|---------|
| Libraries | `netstandard2.0` + `net8.0` |
| CLI & Plugins | `net8.0` only |
| Tests | `net8.0` only |

---

## Architecture Layers

```
┌───────────────────────────────────────────────────────────────┐
│                      CLI / Applications                       │
│  ┌─────────────┐  ┌───────────────┐  ┌─────────────────────┐  │
│  │ CoseSignTool│  │ Custom Apps   │  │ Plugins             │  │
│  │ (CLI)       │  │ (Your Code)   │  │ (MST, Indirect, etc)│  │
│  └──────┬──────┘  └───────┬───────┘  └──────────┬──────────┘  │
└─────────┼─────────────────┼─────────────────────┼─────────────┘
          │                 │                     │
          ▼                 ▼                     ▼
┌───────────────────────────────────────────────────────────────┐
│                     High-Level API Layer                      │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                       CoseHandler                       │  │
│  │           Sign() | Validate() | GetPayload()            │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
          │
          ▼
┌───────────────────────────────────────────────────────────────┐
│                   Core Implementation Layer                   │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │ CoseSign1    │  │ CoseSign1    │  │ CoseIndirect        │  │
│  │ (Factory/    │  │ .Certificates│  │ Signature           │  │
│  │  Builder)    │  │ (X.509 Keys) │  │ (Hash Envelopes)    │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬──────────┘  │
│         │                 │                     │             │
│         └─────────────────┼─────────────────────┘             │
│                           │                                   │
│  ┌────────────────────────┴────────────────────────────────┐  │
│  │                   CoseSign1.Headers                     │  │
│  │             (CWT Claims, Header Extenders)              │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
          │
          ▼
┌───────────────────────────────────────────────────────────────┐
│                       Abstraction Layer                       │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                 CoseSign1.Abstractions                  │  │
│  │ ICoseSigningKeyProvider | ICoseHeaderExtender | Validators │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
          │
          ▼
┌───────────────────────────────────────────────────────────────┐
│                      .NET BCL / Azure SDK                     │
│ System.Security.Cryptography.Cose | Azure.Core | Azure.Identity │
└───────────────────────────────────────────────────────────────┘
```

---

## Core Abstractions

### ICoseSigningKeyProvider

The **primary abstraction** for all signing operations. Any key source (certificate, HSM, cloud) must implement this interface.

```csharp
public interface ICoseSigningKeyProvider
{
    // Key material
    RSA? GetRSAKey(bool publicKey = false);
    ECDsa? GetECDsaKey(bool publicKey = false);
    
    // Algorithm selection
    HashAlgorithmName HashAlgorithm { get; }
    
    // Certificate chain (for X.509 scenarios)
    IEnumerable<X509Certificate2>? GetCertificateChain();
    
    // SCITT compliance
    string? Issuer { get; }
    
    // Validation
    bool IsRSA { get; }
    IEnumerable<byte[]>? GetProtectedHeaders();
    IEnumerable<byte[]>? GetUnprotectedHeaders();
}
```

**Implementations:**
- `X509Certificate2CoseSigningKeyProvider` - Local certificate files
- `AzureArtifactSigningCoseSigningKeyProvider` - Azure cloud signing

### ICoseHeaderExtender

Adds custom headers to COSE messages before signing.

```csharp
public interface ICoseHeaderExtender
{
    void ExtendProtectedHeaders(CoseHeaderMap protectedHeaders);
    void ExtendUnprotectedHeaders(CoseHeaderMap unprotectedHeaders);
}
```

**Key Implementation:** `CWTClaimsHeaderExtender` - Adds SCITT-compliant CWT claims

### CoseSign1MessageValidator

Abstract base for validation chains (Chain of Responsibility pattern).

```csharp
public abstract class CoseSign1MessageValidator
{
    public CoseSign1MessageValidator? NextValidator { get; set; }
    
    public abstract CoseSign1ValidationResult Validate(
        CoseSign1Message message, 
        ReadOnlyMemory<byte>? payload);
}
```

---

## Design Patterns

### 1. Factory Pattern

**Where:** `CoseSign1MessageFactory`, `IndirectSignatureFactory`

```csharp
// Create messages with consistent configuration
var factory = new CoseSign1MessageFactory();
CoseSign1Message msg = factory.CreateCoseSign1Message(payload, keyProvider);
```

### 2. Builder Pattern

**Where:** `CoseSign1MessageBuilder`

```csharp
// Fluent API for complex configuration
var message = new CoseSign1MessageBuilder()
    .SetPayloadBytes(payload)
    .SetContentType("application/spdx+json")
    .ExtendCoseHeader(new CWTClaimsHeaderExtender().SetSubject("release.v1"))
    .Build(keyProvider);
```

### 3. Chain of Responsibility

**Where:** `CoseSign1MessageValidator` and derived validators

```csharp
// Compose validators as a linked list
var validator = new SignatureValidator
{
    NextValidator = new CertificateChainValidator
    {
        NextValidator = new ExpirationValidator()
    }
};
var result = validator.Validate(message, payload);
```

### 4. Strategy Pattern

**Where:** `ICoseSigningKeyProvider`, `ICoseHeaderExtender`

```csharp
// Swap signing strategies at runtime
ICoseSigningKeyProvider keyProvider = useCloud 
    ? new AzureArtifactSigningProvider(...) 
    : new X509Certificate2CoseSigningKeyProvider(cert);
```

### 5. Decorator Pattern

**Where:** Header extenders

```csharp
// Layer header modifications
var extender = new X509CertificateWithCWTClaimsHeaderExtender(
    certProvider,
    new CWTClaimsHeaderExtender()
        .SetSubject("my-app")
        .SetAudience("prod-cluster"));
```

### 6. Plugin Architecture

**Where:** `CoseSignTool.Abstractions`

```csharp
// Two extension points
public interface ICoseSignToolPlugin { ... }      // Add commands
public interface ICertificateProviderPlugin { ... } // Add key sources
```

---

## Data Flow

### Signing Flow

```
┌─────────┐    ┌──────────────┐    ┌────────────────┐    ┌──────────┐
│ Payload │───▶│ KeyProvider  │───▶│ HeaderExtender │───▶│ Factory  │
│ (bytes) │    │ (keys+chain) │    │ (CWT claims)   │    │ (create) │
└─────────┘    └──────────────┘    └────────────────┘    └────┬─────┘
                                                              │
                                                              ▼
                                                      ┌──────────────┐
                                                      │ CoseSign1    │
                                                      │ Message      │
                                                      │ (signature)  │
                                                      └──────────────┘
```

### Validation Flow

```
┌──────────────┐    ┌────────────────┐    ┌────────────────┐
│ CoseSign1    │───▶│ Validator      │───▶│ Next Validator │───▶ ...
│ Message      │    │ Chain Head     │    │ (chain link)   │
└──────────────┘    └────────────────┘    └────────────────┘
                            │
                            ▼
                    ┌────────────────────┐
                    │ ValidationResult   │
                    │ (pass/fail+details)│
                    └────────────────────┘
```

---

## Key Components Deep Dive

### CoseHandler (High-Level API)

The simplest entry point for most scenarios:

```csharp
// Sign a file
byte[] signature = CoseHandler.Sign(
    payloadBytes,
    certificate,
    embedPayload: false);

// Validate a signature
ValidationResult result = CoseHandler.Validate(
    signatureBytes,
    payloadBytes);

// Extract embedded payload
byte[] payload = CoseHandler.GetPayload(signatureBytes);
```

**30+ overloads** support different input combinations (files, streams, certificates, thumbprints).

### CoseSign1.Certificates

Bridges X.509 certificates to COSE signing:

```csharp
// From PFX file
var provider = new X509Certificate2CoseSigningKeyProvider(
    new X509Certificate2("cert.pfx", "password"));

// With custom chain builder
var provider = new X509Certificate2CoseSigningKeyProvider(
    new X509ChainBuilder(customRoots),
    certificate);

// Auto-generates:
// - x5t header (thumbprint)
// - x5chain header (certificate chain)
// - DID:x509 issuer (for SCITT)
```

### CoseSign1.Headers (SCITT Compliance)

```csharp
// Automatic CWT claims via certificate provider
var provider = new X509Certificate2CoseSigningKeyProvider(cert)
{
    EnableScittCompliance = true  // Default: true
};

// Manual CWT claims
var extender = new CWTClaimsHeaderExtender()
    .SetIssuer("did:x509:0:sha256:abc::subject:CN=My%20CA")
    .SetSubject("software.release.v1.0")
    .SetAudience("production")
    .SetExpirationTime(DateTime.UtcNow.AddYears(1))
    .SetCustomClaim(100, "custom-value");
```

### CoseIndirectSignature

For payloads too large to embed:

```csharp
// Sign hash instead of full payload
var factory = new IndirectSignatureFactory();
CoseSign1Message signature = factory.CreateIndirectSignature(
    largePayloadStream,
    keyProvider);

// Content-Type becomes: application/original-type+cose-hash-v
```

---

## Plugin System

### Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                         CoseSignTool                          │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                      PluginLoader                       │  │
│  │  Auto-discovers plugins from ./plugins/{Name}/ folders  │  │
│  └─────────────────────────────────────────────────────────┘  │
│              │                              │                 │
│              ▼                              ▼                 │
│  ┌────────────────────────┐    ┌───────────────────────────┐  │
│  │ ICoseSignToolPlugin    │    │ ICertificateProviderPlugin│  │
│  │ (add commands)         │    │ (add key sources)         │  │
│  └────────────────────────┘    └───────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

### Existing Plugins

| Plugin | Purpose | Commands Added |
|--------|---------|----------------|
| MST Plugin | Microsoft Signing Transparency | `mst:register`, `mst:verify` |
| IndirectSignature Plugin | Large file support | `indirect-sign` |
| AzureArtifactSigning Plugin | Cloud signing | Certificate provider |

### Creating a Plugin

See [PluginQuickStart.md](PluginQuickStart.md) for the complete guide.

```csharp
// Implement the interface
public class MyPlugin : ICoseSignToolPlugin
{
    public string Name => "my-plugin";
    public string Version => "1.0.0";
    public IEnumerable<IPluginCommand> Commands { get; }
    
    public void Initialize(IPluginLogger logger) { ... }
}
```

---

## SCITT Compliance

### What is SCITT?

**Supply Chain Integrity, Transparency, and Trust** - An IETF standard for verifiable supply chain signatures.

### Key Concepts

| Concept | Implementation |
|---------|----------------|
| **DID:x509** | Auto-generated issuer from certificate chain |
| **CWT Claims** | CBOR Web Token standard claims in COSE headers |
| **Transparency Log** | Optional registration with MST service |

### DID:x509 Format

```
did:x509:0:sha256:<base64url-hash>::subject:CN=<issuer-cn>
```

Example:
```
did:x509:0:sha256:WE50Zg...::subject:CN=Microsoft%20Code%20Signing%20CA
```

### Standard CWT Claims

| Claim | Key | Description |
|-------|-----|-------------|
| `iss` | 1 | Issuer (auto: DID:x509) |
| `sub` | 2 | Subject (default: "unknown.intent") |
| `aud` | 3 | Audience (optional) |
| `exp` | 4 | Expiration Time (optional) |
| `nbf` | 5 | Not Before (auto: signing time) |
| `iat` | 6 | Issued At (auto: signing time) |

---

## Transparency Services

### CoseSign1.Transparent Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                  TransparencyService (abstract)               │
│        MakeTransparentAsync() | VerifyTransparencyAsync()     │
└─────────────────────────────┬─────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌───────────────────────┐         ┌───────────────────────────┐
│ MstTransparencyService│         │ YourCustomService         │
│ (Azure Code           │         │ (implement abstract       │
│  Transparency)        │         │  methods)                 │
└───────────────────────┘         └───────────────────────────┘
```

### MST Flow

```
┌─────────────┐
│ Sign locally│
│ (COSE msg)  │
└──────┬──────┘
       │
       ▼
┌─────────────────────────┐
│ MstTransparencyService  │
│ .MakeTransparentAsync() │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐    ┌────────────────────┐
│ CreateEntryAsync (LRO)  │───▶│ Azure Code         │
│ (submit to ledger)      │    │ Transparency       │
└─────────────────────────┘    │ Service            │
           │                    └────────────────────┘
           ▼
┌─────────────────────────┐
│ GetEntryStatementAsync  │
│ (retrieve receipt)      │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ CoseSign1Message with   │
│ transparency receipt    │
└─────────────────────────┘
```

### Performance Tuning

The MST service has specific timing characteristics:

| Component | Default Timing | Tuned Timing |
|-----------|----------------|--------------|
| LRO Polling | ~1s (SDK exponential) | ~100ms (fixed) |
| 503 Retry (TransactionNotCached) | ~1s (Retry-After) | ~100ms (fast retry) |
| **Total** | **~3 seconds** | **~600ms** |

```csharp
// Apply both tuning strategies
var options = new CodeTransparencyClientOptions();
options.ConfigureMstPerformanceOptimizations(
    retryDelay: TimeSpan.FromMilliseconds(100),
    maxRetries: 8);

var pollingOptions = new MstPollingOptions
{
    PollingInterval = TimeSpan.FromMilliseconds(100)
};

var service = new MstTransparencyService(client, pollingOptions);
```

---

## Testing Strategy

### Test Organization

```
Tests/
├── Unit Tests (fast, isolated)
│   ├── CoseSign1.Tests
│   ├── CoseSign1.Headers.Tests
│   └── CoseSign1.Certificates.Tests
│
├── Integration Tests (slower, external deps)
│   ├── CoseHandler.Tests
│   ├── CoseSignTool.Tests
│   └── CoseSign1.Transparent.MST.Tests
│
└── Test Utilities
    ├── CoseSign1.Tests.Common      # Shared helpers
    └── Azure.Core.TestCommon       # Mock HTTP transport
```

### Test Patterns

**Unit Test Example:**
```csharp
[Test]
public void Factory_CreateMessage_WithValidPayload_Succeeds()
{
    // Arrange
    var factory = new CoseSign1MessageFactory();
    var keyProvider = CreateTestKeyProvider();
    var payload = Encoding.UTF8.GetBytes("test");
    
    // Act
    var message = factory.CreateCoseSign1Message(payload, keyProvider);
    
    // Assert
    Assert.That(message, Is.Not.Null);
    Assert.That(message.Content.HasValue, Is.True);
}
```

**Mock HTTP Transport (for Azure SDK):**
```csharp
var transport = MockTransport.FromMessageCallback(msg =>
{
    if (msg.Request.Uri.ToUri().AbsoluteUri.Contains("/entries/"))
    {
        return new MockResponse(503)
            .AddHeader("Retry-After", "1")
            .SetContent(CreateCborErrorBody("TransactionNotCached"));
    }
    return new MockResponse(200);
});
```

### Running Tests

```bash
# All tests
dotnet test

# Specific project
dotnet test CoseSign1.Tests/CoseSign1.Tests.csproj

# With filter
dotnet test --filter "ClassName~MstTransparencyService"

# With coverage
dotnet test --collect:"XPlat Code Coverage"
```

---

## Development Workflows

### Building the Solution

```bash
# Full build
dotnet build CoseSignTool.sln

# Release build
dotnet build CoseSignTool.sln -c Release

# Specific project
dotnet build CoseSign1/CoseSign1.csproj
```

### Publishing CLI

```bash
# Self-contained executable (no .NET required)
dotnet publish CoseSignTool/CoseSignTool.csproj \
    -c Release \
    -r win-x64 \
    --self-contained true \
    -p:PublishSingleFile=true
```

### Adding a New Library

1. Create project in appropriate folder
2. Add to `CoseSignTool.sln`
3. Reference `CoseSign1.Abstractions` for core interfaces
4. Create corresponding test project
5. Add documentation in `docs/`

### Making Breaking Changes

1. Update version in `.csproj`
2. Document in `CHANGELOG.md`
3. Update affected documentation
4. Ensure backward compatibility tests pass (if applicable)

---

## Common Tasks

### Adding a Custom Header Extender

```csharp
public class MyHeaderExtender : ICoseHeaderExtender
{
    public void ExtendProtectedHeaders(CoseHeaderMap headers)
    {
        // Add your protected claims
        headers.Add(new CoseHeaderLabel(100), "my-value");
    }
    
    public void ExtendUnprotectedHeaders(CoseHeaderMap headers)
    {
        // Unprotected headers (visible without verification)
    }
}

// Usage
var message = new CoseSign1MessageBuilder()
    .SetPayloadBytes(payload)
    .ExtendCoseHeader(new MyHeaderExtender())
    .Build(keyProvider);
```

### Creating a Custom Validator

```csharp
public class MyValidator : CoseSign1MessageValidator
{
    public override CoseSign1ValidationResult Validate(
        CoseSign1Message message,
        ReadOnlyMemory<byte>? payload)
    {
        // Your validation logic
        if (!IsValid(message))
        {
            return new CoseSign1ValidationResult(
                ValidationResultCode.Failed,
                "My validation failed");
        }
        
        // Pass to next validator
        return NextValidator?.Validate(message, payload) 
            ?? CoseSign1ValidationResult.Success;
    }
}
```

### Using Stream-Based Signing (for large files)

```csharp
await using var payloadStream = File.OpenRead("large-file.bin");

var message = await factory.CreateCoseSign1MessageAsync(
    payloadStream,
    keyProvider,
    contentType: "application/octet-stream");
```

---

## Troubleshooting Guide

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Certificate chain validation failed" | Missing intermediate/root certs | Use `--Roots` option or install certs |
| "Private key not found" | Certificate without private key | Export with private key or use HSM |
| SCITT claims missing | `EnableScittCompliance = false` | Set to `true` or add extender manually |
| MST registration slow (~3s) | SDK default polling | Apply `MstPollingOptions` tuning |
| Plugin not loading | Wrong folder structure | Use `plugins/{Name}/{Name}.dll` |

### Debugging Tips

1. **Enable verbose logging:** `--Verbose` in CLI
2. **Check certificate chain:** `--ShowCertificateDetails`
3. **Inspect COSE message:** Use `cbor.me` online decoder
4. **Test key provider:** Call `GetRSAKey()`/`GetECDsaKey()` directly

### Getting Help

- [Troubleshooting.md](Troubleshooting.md) - Common issues
- [GitHub Issues](https://github.com/microsoft/CoseSignTool/issues)
- [SUPPORT.md](SUPPORT.md) - Support channels

---

## Quick Reference

### CLI Commands

```bash
# Sign
CoseSignTool sign --p payload.txt --pfx cert.pfx --sf signature.cose

# Validate
CoseSignTool validate --sf signature.cose --p payload.txt

# Extract payload
CoseSignTool get --sf embedded.cose --sa payload.txt
```

### .NET Quick Start

```csharp
// Minimal signing
var cert = new X509Certificate2("cert.pfx", "password");
var provider = new X509Certificate2CoseSigningKeyProvider(cert);
var signature = CoseHandler.Sign(payload, cert);

// Minimal validation
var result = CoseHandler.Validate(signature, payload);
```

### Key Files

| File | Purpose |
|------|---------|
| `Directory.Build.props` | Shared build settings |
| `Directory.Packages.props` | Central package versions |
| `CHANGELOG.md` | Version history |
| `docs/` | All documentation |

---

## Further Reading

- [CoseSignTool.md](CoseSignTool.md) - Complete CLI reference
- [CoseHandler.md](CoseHandler.md) - High-level API guide
- [Advanced.md](Advanced.md) - Async operations, custom validators
- [SCITTCompliance.md](SCITTCompliance.md) - SCITT & CWT Claims
- [Plugins.md](Plugins.md) - Plugin development guide
- [MST.md](MST.md) - Microsoft Signing Transparency

---

*Last updated: March 2026*

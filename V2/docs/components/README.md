# Component Documentation

This section provides comprehensive documentation for each NuGet package in the CoseSignTool V2 ecosystem.

## Core Packages

### [CoseSign1.Abstractions](abstractions.md)
**Foundation package** containing interfaces and contracts for the entire V2 architecture.

**Key Features**:
- `ISigningService` - Core signing abstraction
- `ICoseSign1MessageFactory` - Message creation interface
- `IHeaderContributor` - Header extensibility
- `ISigningKey` - Key abstraction
- Transparency service interfaces

**Use When**: Creating custom implementations, testing, or extending the framework.

---

### [CoseSign1](cosesign1.md)
**Core implementation** package for creating COSE Sign1 messages.

**Key Features**:
- `DirectSignatureFactory` - Embedded payload signatures
- `IndirectSignatureFactory` - Hash-based signatures
- Detached signature support
- Message encoding/decoding utilities

**Use When**: Creating any COSE Sign1 signatures.

---

### [CoseSign1.Certificates](certificates.md)
**Certificate-based signing** and validation with full X.509 support.

**Key Features**:
- `LocalCertificateSigningService` - Local certificate signing
- `RemoteCertificateSigningService` - Remote signing base
- Certificate sources (File, Store, Base64)
- Certificate chain building and validation
- EKU and SAN policy validators
- Certificate expiration validation

**Use When**: Using X.509 certificates for signing or validation.

---

### [CoseSign1.Validation](validation.md)
**Comprehensive validation framework** with composable validators.

**Key Features**:
- `CompositeValidator` - Combine multiple validators
- `ValidatorBuilder` - Fluent validation pipeline creation
- `FunctionValidator` - Custom validation logic
- Signature, chain, EKU, SAN validators
- Validation reporting

**Use When**: Validating COSE Sign1 messages, implementing custom validation logic.

---

### [CoseSign1.Headers](headers.md)
**SCITT compliance** with CWT claims and header management.

**Key Features**:
- `CwtClaims` - CBOR Web Token claims
- `CwtClaimsHeaderContributor` - SCITT-compliant headers
- Standard claim validation
- Subject identifier patterns

**Use When**: Creating SCITT-compliant signatures, supply chain attestations.

---

## Extended Functionality

### [CoseSign1.Certificates.AzureTrustedSigning](azure-trusted-signing.md)
**Azure integration** for cloud-based signing with Azure Trusted Signing service.

**Key Features**:
- Azure Trusted Signing integration
- Managed identity support
- Certificate lifecycle management
- High availability signing

**Use When**: Using Azure Trusted Signing for cloud-based code signing.

---

### [DIDx509](didx509.md)
**Decentralized identifiers** with DID:x509 support.

**Key Features**:
- DID:x509 URI parsing and resolution
- X.509 certificate chain to DID conversion
- DID document creation
- Certificate-based DID validation

**Use When**: Working with decentralized identifiers, Web3 integration, self-sovereign identity.

---

### [CoseSign1.Transparent.MST](transparency-mst.md)
**Merkle Search Tree** transparency receipts.

**Key Features**:
- MST receipt generation
- Receipt verification
- Inclusion proof creation
- Sparse Merkle tree support

**Use When**: Implementing transparency logs with MST, SCITT transparency.

---

## CLI Tool Plugins

### [CoseSignTool.Local.Plugin](../plugins/local-plugin.md)
**Local certificate signing** for the CLI tool.

**Commands Added**:
- `sign-pfx` - Sign with PFX certificate file
- `sign-cert-store` - Sign with Windows certificate store
- `sign-pem` - Sign with PEM files
- `sign-linux-store` - Sign with Linux certificate store

**Use When**: Signing with locally stored certificates via CLI.

---

### [CoseSignTool.AzureTrustedSigning.Plugin](../plugins/azure-plugin.md)
**Azure Trusted Signing** integration for the CLI tool.

**Commands Added**:
- `sign-azure` - Sign using Azure Trusted Signing

**Use When**: Cloud-based signing with Azure via CLI.

---

### [CoseSignTool.MST.Plugin](../plugins/mst-plugin.md)
**Microsoft Signing Transparency** for the CLI tool.

**Commands Added**:
- `verify-mst` - Verify MST transparency receipts

**Use When**: Verifying supply chain transparency via CLI.

---

## Testing Utilities

### [CoseSign1.Tests.Common](tests-common.md)
**Test helpers** and utilities for unit testing.

**Key Features**:
- Test certificate generation
- Mock signing services
- Test data builders
- Assertion helpers

**Use When**: Writing unit tests for code using CoseSignTool.

---

## Package Selection Guide

### I want to...

#### **Sign documents with a certificate**
```
CoseSign1.Certificates
```

#### **Validate signed messages**
```
CoseSign1.Validation
```

#### **Create SCITT-compliant attestations**
```
CoseSign1 + CoseSign1.Headers + CoseSign1.Certificates
```

#### **Use Azure Trusted Signing**
```
CoseSign1.Certificates.AzureTrustedSigning
```

#### **Work with DID:x509 identifiers**
```
DIDx509
```

#### **Add transparency receipts**
```
CoseSign1.Transparent.MST
```

#### **Create custom signing service**
```
CoseSign1.Abstractions (implement ISigningService)
```

#### **Build custom validators**
```
CoseSign1.Validation (use ValidatorBuilder or FunctionValidator)
```

#### **Use CLI for local certificate signing**
```
CoseSignTool + CoseSignTool.Local.Plugin
```

#### **Use CLI with Azure Trusted Signing**
```
CoseSignTool + CoseSignTool.AzureTrustedSigning.Plugin
```

---

## Common Package Combinations

### Basic Signing & Validation
```xml
<PackageReference Include="CoseSign1.Certificates" />
<PackageReference Include="CoseSign1.Validation" />
```

### SCITT Compliance
```xml
<PackageReference Include="CoseSign1.Certificates" />
<PackageReference Include="CoseSign1.Headers" />
<PackageReference Include="CoseSign1.Validation" />
```

### Cloud Signing with Azure
```xml
<PackageReference Include="CoseSign1.Certificates.AzureTrustedSigning" />
<PackageReference Include="CoseSign1.Headers" />
```

### Transparency & Auditability
```xml
<PackageReference Include="CoseSign1.Certificates" />
<PackageReference Include="CoseSign1.Headers" />
<PackageReference Include="CoseSign1.Transparent.MST" />
```

### Full Stack (All Features)
```xml
<PackageReference Include="CoseSign1.Certificates" />
<PackageReference Include="CoseSign1.Certificates.AzureTrustedSigning" />
<PackageReference Include="CoseSign1.Headers" />
<PackageReference Include="CoseSign1.Validation" />
<PackageReference Include="CoseSign1.Transparent.MST" />
<PackageReference Include="DIDx509" />
```

---

## Dependency Graph

```
CoseSign1.Abstractions (Core interfaces)
    ↓
    ├── CoseSign1 (Message creation)
    │   ├── CoseSign1.Headers (CWT claims)
    │   └── CoseSign1.Validation (Validators)
    │
    ├── CoseSign1.Certificates (X.509 support)
    │   ├── CoseSign1.Certificates.AzureTrustedSigning
    │   └── DIDx509
    │
    └── CoseSign1.Transparent.MST (Transparency)
```

---

## Version Compatibility

All V2 packages share the same version number and are tested together:

- **Current Version**: 2.0.0-preview
- **Compatibility**: All packages with the same major.minor version are compatible
- **Recommendation**: Use the same version for all packages

```xml
<!-- Central Package Management (Recommended) -->
<ItemGroup>
  <PackageVersion Include="CoseSign1.Certificates" Version="2.0.0-preview" />
  <PackageVersion Include="CoseSign1.Validation" Version="2.0.0-preview" />
  <PackageVersion Include="CoseSign1.Headers" Version="2.0.0-preview" />
</ItemGroup>
```

---

## Platform Support

All packages target **.NET 10** and support:

- ✅ Windows (x64, ARM64)
- ✅ Linux (x64, ARM64)
- ✅ macOS (x64, ARM64)

Special features by platform:
- **Windows**: Full certificate store integration
- **Linux**: Linux certificate store support
- **macOS**: Keychain integration
- **All platforms**: ML-DSA (post-quantum) preview support

---

## Performance Characteristics

| Package | Memory | CPU | Network | Notes |
|---------|--------|-----|---------|-------|
| Abstractions | Minimal | Minimal | No | Interfaces only |
| CoseSign1 | Low | Medium | No | Cryptographic operations |
| Certificates | Medium | Medium-High | Optional | Chain building, revocation checking |
| Validation | Low | Medium | Optional | Depends on validators used |
| Headers | Low | Low | No | Header manipulation |
| AzureTrustedSigning | Low | Low | Yes | Remote signing service |
| DIDx509 | Low | Medium | Optional | DID resolution may need network |
| Transparent.MST | Medium | Medium-High | Yes | Merkle tree operations |

---

## Next Steps

1. **Getting Started**: Read the [Installation Guide](../getting-started/installation.md)
2. **Quick Start**: Try the [Quick Start Guide](../getting-started/quick-start.md)
3. **Architecture**: Understand [Core Concepts](../architecture/core-concepts.md)
4. **Examples**: Explore [Code Examples](../examples/README.md)
5. **Guides**: Read task-specific [How-To Guides](../guides/README.md)

---

## Support

- 📖 [Documentation](../README.md)
- 🐛 [GitHub Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 [Email Support](mailto:cosesigntool@microsoft.com)

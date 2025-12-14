# CoseSignTool V2 Documentation

Welcome to the CoseSignTool V2 documentation. V2 is a complete architectural redesign that provides a modern, modular, and extensible framework for COSE (CBOR Object Signing and Encryption) signing operations.

## Documentation Index

### Getting Started
- [Quick Start Guide](getting-started/quick-start.md) - Get up and running in 5 minutes
- [Migration from V1](getting-started/migration-from-v1.md) - How to migrate from V1 to V2
- [Installation](getting-started/installation.md) - Installation and setup instructions

### Architecture
- [Architecture Overview](architecture/overview.md) - High-level architecture and design principles
- [Core Concepts](architecture/core-concepts.md) - Key abstractions and patterns
- [Signing Services](architecture/signing-services.md) - Local vs Remote signing services
- [Certificate Management](architecture/certificate-management.md) - Certificate sources and chain building
- [Header Contributors](architecture/header-contributors.md) - Extensible header contribution system
- [Validation Framework](architecture/validation-framework.md) - Composable validation architecture

### Components

#### Core Libraries
- [CoseSign1.Abstractions](components/abstractions.md) - Core abstractions and interfaces
- [CoseSign1](components/cosesign1.md) - Direct and indirect signature factories
- [CoseSign1.Headers](components/headers.md) - Header management and CWT claims
- [CoseSign1.Validation](components/validation.md) - Validation framework

#### CLI Tool Abstractions
- [CoseSignTool.Abstractions](components/cosesigntool-abstractions.md) - Plugin interfaces for extending the CLI tool

#### Certificate Support
- [CoseSign1.Certificates](components/certificates.md) - Certificate-based signing
- [CoseSign1.Certificates.Local](components/certificates-local.md) - Ephemeral certificate generation and local key management
- [CoseSign1.Certificates.AzureTrustedSigning](components/azure-trusted-signing.md) - Azure Trusted Signing integration
- [DIDx509](components/didx509.md) - DID:x509 resolution and validation

#### Transparency & Receipts
- [CoseSign1.Transparent](components/transparent.md) - Transparency architecture
- [CoseSign1.Transparent.MST](components/mst.md) - Microsoft's Signing Transparency receipts

### CoseSignTool CLI

The V2 CLI tool (`CoseSignTool`) provides command-line signing and verification with a plugin architecture:

#### Core Commands
- `verify` - Verify a COSE Sign1 signature
- `inspect` - Inspect COSE Sign1 signature details

#### Plugin Commands (via Local Plugin)
- `sign-ephemeral` - Sign with an ephemeral test certificate (development only)
- `sign-pfx` - Sign with a PFX/PKCS#12 certificate file
- `sign-certstore` - Sign with a certificate from Windows/Linux certificate store
- `sign-pem` - Sign with PEM-encoded certificate and key files

#### Command Reference
- [Inspect Command](cli/inspect.md) - Detailed inspect command documentation
- [Output Formats](cli/output-formats.md) - JSON, text, XML, and quiet output formats

#### CLI Plugins
- [CoseSignTool.Local.Plugin](plugins/local-plugin.md) - Local certificate signing (PFX, PEM, Windows/Linux cert stores)
- [CoseSignTool.AzureTrustedSigning.Plugin](plugins/azure-plugin.md) - Azure Trusted Signing integration
- [CoseSignTool.MST.Plugin](plugins/mst-plugin.md) - Microsoft's Signing Transparency verification

### Guides

#### Development
- [Creating Custom Validators](guides/custom-validators.md) - Build custom validation logic
- [Custom Header Contributors](guides/custom-headers.md) - Extend header contribution
- [Certificate Sources](guides/certificate-sources.md) - Implement custom certificate sources
- [Remote Signing](guides/remote-signing.md) - Integrate with remote signing services
- [Creating CLI Plugins](guides/cli-plugins.md) - Build custom CoseSignTool plugins

#### Security & Compliance
- [SCITT Compliance](guides/scitt-compliance.md) - Supply Chain Integrity, Transparency and Trust
- [Security Best Practices](guides/security.md) - Security recommendations
- [Post-Quantum Cryptography](guides/post-quantum.md) - ML-DSA support (Windows only)

#### Advanced Topics
- [Direct vs Indirect Signatures](guides/direct-vs-indirect.md) - When to use each approach
- [Detached Signatures](guides/detached-signatures.md) - Working with detached payloads
- [Certificate Chain Validation](guides/chain-validation.md) - Custom chain validation
- [Testing](guides/testing.md) - Testing strategies and utilities

### API Reference
- [API Documentation](api/README.md) - Complete API reference
- [Code Examples](examples/README.md) - Practical code examples

### Contributing
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute
- [Development Setup](development/setup.md) - Setting up your development environment
- [Testing Guide](development/testing.md) - Running and writing tests
- [Code Coverage](development/coverage.md) - Coverage requirements and reporting

## Key Differences from V1

V2 represents a fundamental redesign with these major improvements:

1. **Modular Architecture**: Clear separation of concerns with well-defined abstractions
2. **Extensibility**: Plugin-based header contributors, validators, and CLI commands
3. **Modern .NET**: Built for .NET 10+ with modern C# patterns
4. **Validation Framework**: Composable, testable validation pipeline
5. **Transparency Support**: First-class support for transparency receipts (MST)
6. **DID:x509 Integration**: Native support for decentralized identifiers
7. **SCITT Compliance**: Built-in support for SCITT standards
8. **Post-Quantum Ready**: ML-DSA (FIPS 204) support (Windows only in .NET 10)
9. **CLI Plugin System**: Extensible command-line tool with pluggable signing providers

## Version Status

**Current Version**: 2.0.0-preview  
**Status**: Preview - API surface may change  
**Target Release**: Q1 2026  

### Package Names

V2 packages use semantic versioning (2.x.x) to distinguish from V1 (1.x.x):

#### Library Packages

| Package | Description |
|---------|-------------|
| `CoseSign1.Abstractions` | Core interfaces and abstractions |
| `CoseSign1` | Direct and indirect signature factories |
| `CoseSign1.Certificates` | Certificate-based signing services |
| `CoseSign1.Certificates.Local` | Local certificate sources (PFX, PEM, stores) |
| `CoseSign1.Certificates.AzureTrustedSigning` | Azure Trusted Signing integration |
| `CoseSign1.Validation` | Composable validation framework |
| `CoseSign1.Headers` | Header management and CWT claims |
| `CoseSign1.Transparent.MST` | Microsoft's Signing Transparency receipts |
| `DIDx509` | DID:x509 resolution and validation |

#### CLI Tool & Plugins

| Package | Description |
|---------|-------------|
| `CoseSignTool` | CLI tool |
| `CoseSignTool.Abstractions` | Plugin interfaces |
| `CoseSignTool.Local.Plugin` | Local certificate signing plugin |
| `CoseSignTool.AzureTrustedSigning.Plugin` | Azure Trusted Signing plugin |
| `CoseSignTool.MST.Plugin` | Microsoft's Signing Transparency plugin |

#### Testing Utilities

| Package | Description |
|---------|-------------|
| `CoseSign1.Tests.Common` | Shared test utilities and certificate generation |

V2 is currently in preview (2.0.0-preview) and will eventually replace V1 entirely. Both versions are maintained during the transition period.

## Support

- **Issues**: [GitHub Issues](https://github.com/microsoft/CoseSignTool/issues)
- **Discussions**: [GitHub Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- **Security**: See [SECURITY.md](../../docs/SECURITY.md)

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

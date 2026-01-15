# CoseSignTool V2 Documentation

Welcome to the CoseSignTool V2 documentation. This guide covers all aspects of using and extending the toolkit.

## Getting Started

- [Installation](getting-started/installation.md) - Install the CLI and NuGet packages
- [Quick Start](../README.md#quick-start) - Basic signing and verification examples

## Architecture

- [Overview](architecture/overview.md) - Package structure, design principles, data flows
- [Sequence Diagrams](architecture/sequence-diagrams.md) - Runtime call ordering (signing, validation, discovery, CLI plugins)
- [Validation Framework](architecture/validation-framework.md) - Staged validation pipeline
- [Core Concepts](architecture/core-concepts.md) - Trust, stages, signature types, policies
- [Signing Services](architecture/signing-services.md) - Local and remote signing services
- [Certificate Management](architecture/certificate-management.md) - Certificate sources and chain building
- [Header Contributors](architecture/header-contributors.md) - Extensible header contribution model

## Guides

- [Direct vs Indirect](guides/direct-vs-indirect.md) - Choose the right signature strategy
- [Detached Signatures](guides/detached-signatures.md) - Detached payload workflows
- [SCITT Compliance](guides/scitt-compliance.md) - SCITT-friendly signing and verification
- [Trust Policy](guides/trust-policy.md) - Declarative trust policies deep-dive
- [Audit and Replay](guides/audit-and-replay.md) - Trust decision audits and replay guidance
- [Chain Validation](guides/chain-validation.md) - Chain-building and trust roots
- [Certificate Sources](guides/certificate-sources.md) - PFX/PEM/Store and remote sources
- [Remote Signing](guides/remote-signing.md) - Azure Trusted Signing and other remote services
- [Post-Quantum](guides/post-quantum.md) - PQC signing options and constraints
- [Custom Headers](guides/custom-headers.md) - Add and validate custom headers
- [Custom Validators](guides/custom-validators.md) - Extend validation stages
- [Validation Extension Packages](guides/validation-extension-packages.md) - Author trust-pack and staged validation extensions
- [Logging and Diagnostics](guides/logging-diagnostics.md) - Verbosity, log files, structured output
- [Security](guides/security.md) - Security guidance and recommended defaults

## CLI Reference

- [CLI Overview](cli/README.md) - Command reference
- [Verify Command](cli/verify.md) - Signature verification
- [Sign Commands](cli/sign.md) - Signing commands
- [Inspect Command](cli/inspect.md) - Message inspection
- [Output Formats](cli/output-formats.md) - JSON, XML, text output

## Plugin Development

- [Plugin Guide](plugins/README.md) - Creating custom plugins
- [ISigningCommandProvider](plugins/README.md#creating-a-signing-command-provider) - Custom signing commands
- [IVerificationProvider](plugins/README.md#creating-a-verification-provider) - Custom verification
- [CLI Plugins Guide](guides/cli-plugins.md) - How the CLI discovers and loads plugins

## Package Documentation

### Core Packages

| Package | Description |
|---------|-------------|
| [CoseSign1.Factories](components/cosesign1.factories.md) | Signature creation factories (direct + indirect) |
| [CoseSign1.Abstractions](components/abstractions.md) | Shared interfaces |
| [CoseSign1.Validation](components/validation.md) | Staged validation framework |
| [CoseSign1.Certificates](components/certificates.md) | Certificate infrastructure |

### Certificate Providers

| Package | Description |
|---------|-------------|
| [CoseSign1.Certificates.Local](components/certificates-local.md) | PFX, PEM, Certificate Store |
| [CoseSign1.Certificates.AzureTrustedSigning](components/azure-trusted-signing.md) | Azure Trusted Signing |

### Extensions

| Package | Description |
|---------|-------------|
| [CoseSign1.Headers](components/headers.md) | COSE header extensions |
| [CoseSign1.Transparent.MST](components/mst.md) | Merkle Signature Tree transparency |
| [DIDx509](components/didx509.md) | DID:x509 identifier support |

## API Reference

- [API Documentation](api/README.md) - Generated API reference

## Examples

- [Examples](examples/README.md) - End-to-end code examples and snippets

## Development

- [Development Setup](development/setup.md)
- [Running Tests](development/testing.md)
- [Code Coverage](development/coverage.md)

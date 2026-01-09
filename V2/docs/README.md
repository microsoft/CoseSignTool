# CoseSignTool V2 Documentation

Welcome to the CoseSignTool V2 documentation. This guide covers all aspects of using and extending the toolkit.

## Getting Started

- [Installation](getting-started/installation.md) - Install the CLI and NuGet packages
- [Quick Start](../README.md#quick-start) - Basic signing and verification examples

## Architecture

- [Overview](architecture/overview.md) - Package structure, design principles, data flows
- [Validation Framework](architecture/validation-framework.md) - Staged validation pipeline

## Guides

- [Trust Policy](guides/trust-policy.md) - Declarative trust policies deep-dive
- [Logging and Diagnostics](guides/logging-diagnostics.md) - Verbosity, log files, structured output

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

## Package Documentation

### Core Packages

| Package | Description |
|---------|-------------|
| [CoseSign1](components/cosesign1.md) | Core signing with CoseSign1MessageFactory |
| [CoseSign1.Abstractions](components/abstractions.md) | Shared interfaces |
| [CoseSign1.Validation](components/validation.md) | Staged validation framework |
| [CoseSign1.Certificates](components/certificates.md) | Certificate infrastructure |

### Certificate Providers

| Package | Description |
|---------|-------------|
| [CoseSign1.Certificates.Local](components/certificates-local.md) | PFX, PEM, Certificate Store |
| [CoseSign1.Certificates.AzureKeyVault](components/azure-keyvault.md) | Azure Key Vault |
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

- [Basic Signing](examples/signing.md)
- [Basic Verification](examples/verification.md)
- [Advanced Trust Policies](examples/trust-policies.md)
- [Custom Validators](examples/custom-validators.md)

## Development

- [Building from Source](development/building.md)
- [Running Tests](development/testing.md)
- [Contributing](development/contributing.md)

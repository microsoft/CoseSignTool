# CoseSignTool V2 - Modern COSE Signing Architecture

This is the V2 implementation of CoseSignTool, featuring a clean, modern architecture based on the V3 design principles.

## Overview

V2 provides a simplified, caller-centric API for creating and verifying COSE (CBOR Object Signing and Encryption) signatures with support for:

- **Direct signatures** (embedded and detached payloads)
- **Indirect signatures** (Hash-V and Hash Envelope patterns)
- **Local certificate signing** (Windows Store, PFX files, in-memory certificates)
- **Remote certificate signing** (Azure Trusted Signing, Azure Key Vault)
- **Post-Quantum Cryptography (PQC)** support via ML-DSA algorithms
- **Dynamic key acquisition** with certificate rotation detection
- **Service-level metadata** for compliance (SCITT, transparency logs)

## Key Design Principles

1. **Caller Simplicity**: Create service → Pass to factory → Get signed message
2. **Dynamic Key Acquisition**: Keys fetched per operation via `GetSigningKey(context)`
3. **Leverage .NET Runtime**: Uses Microsoft's battle-tested `CoseSigner` and `CoseKey` directly
4. **Service Metadata**: Enables compliance features through `SigningServiceMetadata`
5. **Extensibility**: Easy to add new services, keys, and header contributors

## Projects

- **CoseSign1.Abstractions**: Core interfaces (`ISigningKey`, `ISigningService`, `IHeaderContributor`)
- **CoseSign1**: Factory implementations (`DirectSignatureFactory`, `IndirectSignatureFactory`)
- **CoseSign1.Certificates**: Certificate-based signing services (local and remote)

## Architecture

See the [V3_CoseSigner_Architecture.md](../docs/architecture/V3_CoseSigner_Architecture.md) documentation for comprehensive implementation details.

### Quick Example

```csharp
// Create signing service
var signingService = LocalCertificateSigningService.FromWindowsStore(
    thumbprint: "ABC123...",
    storeName: StoreName.My);

// Create factory
var factory = new DirectSignatureFactory(signingService, embedPayload: true);

// Sign payload
var payload = Encoding.UTF8.GetBytes("Hello, World!");
var signedMessage = factory.Sign(payload, contentType: "application/json");
```

## Requirements

- **.NET Standard 2.0** for library projects
- **.NET 10.0** for test projects and binaries
- **System.Security.Cryptography.Cose 10.0.0-preview** for PQC support

## Development

This is a clean-slate implementation isolated from V1 to allow iterative development with TDD approach.

## Status

🚧 **Work in Progress** - This is the V2 architecture under active development.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for more information.

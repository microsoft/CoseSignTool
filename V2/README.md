# CoseSignTool V2

A modern, modular .NET library for creating, signing, and validating COSE Sign1 messages with full SCITT compliance.

[![Build](https://github.com/microsoft/CoseSignTool/workflows/Build/badge.svg)](https://github.com/microsoft/CoseSignTool/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET-10.0-blue.svg)](https://dotnet.microsoft.com/)

## Overview

CoseSignTool V2 is a complete architectural redesign of the original CoseSignTool library, providing:

- **Modular Architecture** - Clean separation of concerns with well-defined abstractions
- **Extensible Design** - Plugin-based headers, validators, and CLI commands
- **Modern .NET** - Built for .NET 10+ with contemporary C# patterns
- **SCITT Compliance** - Native support for Supply Chain Integrity, Transparency and Trust
- **Transparency Support** - First-class support for MST transparency receipts
- **DID:x509 Integration** - Native decentralized identifier support
- **Post-Quantum Ready** - ML-DSA (FIPS 204) algorithm support

## Quick Start

### Installation

```bash
dotnet add package CoseSign1.Certificates --version 2.0.0-preview
dotnet add package CoseSign1.Validation --version 2.0.0-preview
```

### Sign a Message

```csharp
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using System.Security.Cryptography.X509Certificates;

// Load your certificate
using var cert = new X509Certificate2("certificate.pfx", "password");

// Create signing service and factory
using var signingService = new LocalCertificateSigningService(cert);
using var factory = new DirectSignatureFactory(signingService);

// Sign your payload
byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    payload: "Hello, COSE!"u8.ToArray(), 
    contentType: "text/plain"
);
```

### Verify a Signature

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(signedMessage);
bool isValid = message.VerifySignature();
```

## Packages

| Package | Description |
|---------|-------------|
| [CoseSign1.Abstractions](CoseSign1.Abstractions/README.md) | Core interfaces and abstractions |
| [CoseSign1](CoseSign1/README.md) | Direct and indirect signature factories |
| [CoseSign1.Certificates](CoseSign1.Certificates/README.md) | Certificate-based signing services |
| [CoseSign1.Validation](CoseSign1.Validation/README.md) | Composable validation framework |
| [CoseSign1.Headers](CoseSign1.Headers/README.md) | CWT claims and SCITT headers |
| [CoseSign1.Transparent.MST](CoseSign1.Transparent.MST/README.md) | MST transparency receipts |
| [DIDx509](DIDx509/README.md) | DID:x509 resolution and validation |

## Architecture

V2 follows a layered architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                             │
│                  (Your Application Code)                         │
├─────────────────────────────────────────────────────────────────┤
│                    Factory Layer                                 │
│     DirectSignatureFactory    IndirectSignatureFactory           │
├─────────────────────────────────────────────────────────────────┤
│                   Service Layer                                  │
│    LocalCertificateSigningService   AzureTrustedSigningService   │
├─────────────────────────────────────────────────────────────────┤
│                 Abstractions Layer                               │
│   ISigningService   ICoseSign1MessageFactory   IHeaderContributor│
└─────────────────────────────────────────────────────────────────┘
```

## Documentation

- **[Getting Started](docs/getting-started/quick-start.md)** - Quick start guide
- **[Architecture](docs/architecture/overview.md)** - Architecture overview
- **[Installation](docs/getting-started/installation.md)** - Detailed installation guide
- **[Migration from V1](docs/getting-started/migration-from-v1.md)** - V1 to V2 migration guide
- **[Full Documentation](docs/README.md)** - Complete documentation index

## Features

### Signing Options

```csharp
// Direct signature (embedded payload)
using var directFactory = new DirectSignatureFactory(signingService);
byte[] embedded = directFactory.CreateCoseSign1MessageBytes(payload, "text/plain");

// Indirect signature (hash-only, SCITT compliant)
using var indirectFactory = new IndirectSignatureFactory(signingService);
byte[] indirect = indirectFactory.CreateCoseSign1MessageBytes(payload, "text/plain");

// Detached signature
var options = new DirectSignatureOptions { EmbedPayload = false };
byte[] detached = directFactory.CreateCoseSign1MessageBytes(payload, "text/plain", options);
```

### SCITT Compliance

```csharp
using CoseSign1.Headers;

var claims = new CwtClaims
{
    Issuer = "https://build.example.com",
    Subject = "pkg:npm/my-package@1.0.0",
    IssuedAt = DateTimeOffset.UtcNow
};

var contributor = new CwtClaimsHeaderContributor(claims, autoGenerateIssuer: true);
var factory = new DirectSignatureFactory(signingService, headerContributors: new[] { contributor });
```

### Validation Pipeline

```csharp
using CoseSign1.Validation;

var validator = Cose.Sign1Message()
    .ValidateCertificateSignature()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Trusted Signer")
        .HasEku(Oids.CodeSigning))
    .Build();

var result = validator.Validate(message);
```

### Transparency Receipts

```csharp
using CoseSign1.Transparent.MST;

var transparencyProvider = new MstTransparencyProvider(client);
var messageWithReceipt = await transparencyProvider.AddTransparencyProofAsync(signedMessage);
```

## CLI Tool

CoseSignTool V2 includes a command-line interface with plugin architecture:

```bash
# Sign with PFX certificate
CoseSignTool sign-pfx document.json --pfx cert.pfx --password mypassword

# Sign with Azure Trusted Signing
CoseSignTool sign-azure document.json --ats-endpoint https://myaccount.codesigning.azure.net \
    --ats-account-name myaccount --ats-cert-profile-name production

# Verify signature
CoseSignTool verify signed.cose

# Verify MST transparency
CoseSignTool verify-mst signed.cose
```

See [CLI Plugin Documentation](docs/plugins/README.md) for more details.

## Requirements

- .NET 10.0 or later
- C# 13 or later

## Test Coverage

V2 maintains high test coverage: **95.5%** with 1,732 tests.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Related Projects

- [Microsoft COSE](https://github.com/microsoft/dotnet-cose) - .NET COSE implementation
- [Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/) - Azure cloud signing service
- [SCITT](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) - Supply Chain Integrity architecture

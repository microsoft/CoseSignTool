# CoseSignTool V2

**CBOR Object Signing and Encryption (COSE) Signing and Verification Toolkit**

CoseSignTool V2 is a comprehensive .NET library and command-line tool for creating, verifying, and inspecting COSE Sign1 messages per [RFC 9052](https://datatracker.ietf.org/doc/rfc9052/).

[![Build Status](https://github.com/microsoft/CoseSignTool/actions/workflows/build.yml/badge.svg)](https://github.com/microsoft/CoseSignTool/actions)
[![NuGet](https://img.shields.io/nuget/v/CoseSign1.svg)](https://www.nuget.org/packages/CoseSign1/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Features

### Core Capabilities
- **Sign** payloads with X.509 certificates (PFX, PEM, Windows Certificate Store)
- **Verify** COSE Sign1 message signatures with comprehensive validation
- **Inspect** COSE Sign1 messages to examine structure and metadata
- **Direct signatures**: Sign payload directly (embedded or detached)
- **Indirect signatures**: Sign payload hash (hash envelope pattern)

### Security Defaults
- **Deny-by-default trust**: Explicit trust policy required
- **Staged validation**: Trust established before cryptographic verification
- **Declarative trust policies**: Composable boolean policy expressions
- **Secure key material handling**: HSM and cloud provider support

### Enterprise Features
- **Plugin architecture**: Extend CLI with custom signing and verification providers
- **Azure integration**: Azure Key Vault and Azure Trusted Signing support
- **Transparency**: Merkle Signature Tree (MST) transparency proofs
- **Rich diagnostics**: Structured logging with JSON/XML/Text output

---

## Quick Start

### Installation

#### CLI Tool
```bash
# Install globally
dotnet tool install -g CoseSignTool

# Or download from releases
```

#### NuGet Packages
```bash
# Core signing library
dotnet add package CoseSign1

# Validation framework
dotnet add package CoseSign1.Validation

# Certificate support
dotnet add package CoseSign1.Certificates
dotnet add package CoseSign1.Certificates.Local
```

### Sign a File

```bash
# Sign with PFX certificate
cosesigntool sign-pfx --pfx mycert.pfx --payload document.txt --output document.cose

# Sign with embedded payload
cosesigntool sign-pfx --pfx mycert.pfx --payload document.txt --signature-type embedded --output document.cose

# Sign with detached payload (signature only)
cosesigntool sign-pfx --pfx mycert.pfx --payload document.txt --signature-type detached --output document.sig
```

### Verify a Signature

```bash
# Verify with automatic certificate extraction
cosesigntool verify document.cose

# Verify detached signature
cosesigntool verify document.sig --payload document.txt

# Verify with custom trust roots
cosesigntool verify document.cose --trust-roots ca-bundle.pem

# JSON output for automation
cosesigntool verify document.cose --output-format json
```

### Inspect a Signature

```bash
# View signature details
cosesigntool inspect document.cose

# Extract embedded payload
cosesigntool inspect document.cose --extract-payload extracted.txt
```

---

## Library Usage

### Creating Signatures

```csharp
using CoseSign1;
using CoseSign1.Certificates.Local;

// Load certificate
var certSource = new PfxCertificateSource("mycert.pfx", password);
var signingCert = certSource.GetSigningCertificate();
var chainBuilder = certSource.GetChainBuilder();

// Create signing service
var signingService = CertificateSigningService.Create(signingCert, chainBuilder);

// Create message factory (preferred entry point)
var factory = new CoseSign1MessageFactory(signingService);

// Sign payload
byte[] payload = File.ReadAllBytes("document.txt");
byte[] signature = await factory.CreateCoseSign1MessageAsync(
    payload,
    contentType: "application/octet-stream",
    options: new DirectSignatureOptions { EmbedPayload = true });
```

### Verifying Signatures

```csharp
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

// Decode the COSE message
byte[] signatureBytes = File.ReadAllBytes("document.cose");
var message = CoseSign1Message.DecodeSign1(signatureBytes);

// Shorthand: Validate with inline configuration
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Trusted Signer")
        .ValidateChain()));

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature verified!");
}
else
{
    foreach (var failure in result.Overall.Failures)
    {
        Console.WriteLine($"Error: {failure.ErrorCode} - {failure.Message}");
    }
}

// Or build a reusable validator for multiple messages
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();

var result = message.Validate(validator);
```

### Custom Trust Policies

```csharp
// Combine multiple requirements with TrustPolicy.And()
// OverrideDefaultTrustPolicy replaces all validator defaults
var policy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Or(
        TrustPolicy.Claim("issuer.internal"),
        TrustPolicy.And(
            TrustPolicy.Claim("issuer.partner"),
            TrustPolicy.Claim("partner.certified")
        )
    )
);

var validator = Cose.Sign1Message()
    .AddCertificateValidators()
    .OverrideDefaultTrustPolicy(policy)  // Single call with combined policy
    .Build();
```

---

## Architecture

### Package Structure

| Package | Purpose |
|---------|---------|
| `CoseSign1` | Core signing with `CoseSign1MessageFactory` |
| `CoseSign1.Abstractions` | Shared interfaces and models |
| `CoseSign1.Validation` | Staged validation framework |
| `CoseSign1.Certificates` | Certificate infrastructure |
| `CoseSign1.Certificates.Local` | Local certificate sources (PFX, PEM, Store) |
| `CoseSign1.Certificates.AzureKeyVault` | Azure Key Vault certificate source |
| `CoseSign1.Certificates.AzureTrustedSigning` | Azure Trusted Signing integration |
| `CoseSign1.Headers` | COSE header extensions |
| `CoseSignTool` | CLI application |
| `CoseSignTool.Abstractions` | Plugin interfaces |

### Validation Stages

V2 enforces a **secure-by-default** validation order:

```
1. Key Material Resolution  -> Extract certificates from headers
2. Key Material Trust       -> Evaluate trust policy against claims
3. Signature Verification   -> Cryptographic signature check
4. Post-Signature Policy    -> Additional business rules
```

Trust is evaluated **before** signature verification to prevent oracle attacks.

---

## CLI Reference

### Global Options

| Option | Description |
|--------|-------------|
| `-q`, `--quiet` | Suppress all output except errors |
| `-vv` | Debug verbosity |
| `-vvv` | Trace verbosity |
| `--verbosity N` | Set verbosity level (0-4) |
| `--log-file <path>` | Write logs to file |
| `--log-file-append` | Append to existing log file |
| `--output-format` | Output format: text, json, xml, quiet |
| `--additional-plugin-dir` | Additional plugin directory |

### Commands

- **`sign-pfx`** - Sign with PFX certificate
- **`sign-pem`** - Sign with PEM certificate
- **`sign-cert-store`** - Sign with Windows Certificate Store
- **`sign-ephemeral`** - Sign with temporary test certificate
- **`sign-akv-cert`** - Sign with Azure Key Vault certificate
- **`sign-ats`** - Sign with Azure Trusted Signing
- **`verify`** - Verify a signature
- **`inspect`** - Inspect signature details

See [CLI Documentation](docs/cli/README.md) for detailed command reference.

---

## Documentation

- [Getting Started](docs/getting-started/installation.md)
- [Architecture Overview](docs/architecture/overview.md)
- [Validation Framework](docs/architecture/validation-framework.md)
- [Trust Policy Guide](docs/guides/trust-policy.md)
- [Plugin Development](docs/plugins/README.md)
- [Logging and Diagnostics](docs/guides/logging-diagnostics.md)
- [CLI Reference](docs/cli/README.md)
- [API Reference](docs/api/README.md)

---

## Building from Source

### Prerequisites
- .NET 10.0 SDK or later
- Visual Studio 2022+ or VS Code

### Build
```bash
cd V2
dotnet build CoseSignToolV2.sln
```

### Test
```bash
dotnet test CoseSignToolV2.sln
```

### Package
```bash
dotnet pack CoseSignToolV2.sln -c Release
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](../docs/CONTRIBUTING.md) for guidelines.

## Security

For security issues, please see [SECURITY.md](../SECURITY.md).

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

---

*CoseSignTool is maintained by Microsoft and the open-source community.*

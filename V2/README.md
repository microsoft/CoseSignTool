# CoseSignTool V2

**CBOR Object Signing and Encryption (COSE) Signing and Verification Toolkit**

CoseSignTool V2 is a comprehensive .NET library and command-line tool for creating, verifying, and inspecting COSE Sign1 messages per [RFC 9052](https://datatracker.ietf.org/doc/rfc9052/).

[![Build Status](https://github.com/microsoft/CoseSignTool/actions/workflows/build.yml/badge.svg)](https://github.com/microsoft/CoseSignTool/actions)
[![NuGet](https://img.shields.io/nuget/v/CoseSign1.Factories.svg)](https://www.nuget.org/packages/CoseSign1.Factories/)
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
# Signature creation factories (direct + indirect)
dotnet add package CoseSign1.Factories

# Validation framework
dotnet add package CoseSign1.Validation

# Certificate support
dotnet add package CoseSign1.Certificates
dotnet add package CoseSign1.Certificates.Local
```

### Sign a File

```bash
# Sign with PFX certificate (indirect signature - default)
cosesigntool sign x509 pfx document.txt --pfx mycert.pfx --output document.cose

# Sign with embedded payload
cosesigntool sign x509 pfx document.txt --pfx mycert.pfx --signature-type embedded --output document.cose

# Sign with detached payload (signature only)
cosesigntool sign x509 pfx document.txt --pfx mycert.pfx --signature-type detached --output document.sig

# Sign with payload location URI (indirect signatures only)
cosesigntool sign x509 pfx document.txt --pfx mycert.pfx --payload-location https://example.com/docs/document.txt --output document.cose
```

### Verify a Signature

```bash
# Verify with automatic certificate extraction
cosesigntool verify x509 document.cose

# Verify detached signature
cosesigntool verify x509 document.sig --payload document.txt

# Verify with custom trust roots
cosesigntool verify x509 document.cose --trust-roots ca-bundle.pem

# JSON output for automation
cosesigntool verify x509 document.cose --output-format json
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
using CoseSign1.Certificates.Local;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;
using System.Security.Cryptography;

// Load certificate
var certSource = new PfxCertificateSource("mycert.pfx", password);
var signingCert = certSource.GetSigningCertificate();
var chainBuilder = certSource.GetChainBuilder();

// Create signing service
var signingService = CertificateSigningService.Create(signingCert, chainBuilder);

// Preferred V2 entry point: use the explicit direct/indirect overloads.
// (The generic CreateCoseSign1MessageBytes* overloads still exist for dynamic routing.)
using var factory = new CoseSign1MessageFactory(signingService);

// Sign payload
byte[] payload = File.ReadAllBytes("document.txt");
byte[] directSignature = await factory.CreateDirectCoseSign1MessageBytesAsync(
    payload,
    contentType: "application/octet-stream");

byte[] indirectSignature = await factory.CreateIndirectCoseSign1MessageBytesAsync(
    payload,
    contentType: "application/octet-stream");

// Underlying factories are also available (advanced scenarios):
// using var directFactory = new DirectSignatureFactory(signingService);
// using var indirectFactory = new IndirectSignatureFactory(signingService);
```

### Verifying Signatures

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

// Decode the COSE message
byte[] signatureBytes = File.ReadAllBytes("document.cose");
var message = CoseMessage.DecodeSign1(signatureBytes);

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
var validator = new CoseSign1ValidationBuilder()
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();

var result2 = message.Validate(validator);
```

### Custom Trust Policies

```csharp
using CoseSign1.Certificates.Validation;

// Trust policies are boolean expressions over typed assertions.
// OverrideDefaultTrustPolicy replaces all validator defaults.

var policy = TrustPolicy.And(
    // Require a trusted chain (x5chain validated to roots)
    X509TrustPolicies.RequireTrustedChain(),

    // Require one of the configured issuer checks to match
    TrustPolicy.Or(
        TrustPolicy.Require<X509IssuerAssertion>(a => a.Matches, "Issuer must match an allowed value")
    )
);

var validator = new CoseSign1ValidationBuilder()
    .ValidateCertificate(cert => cert
        .IsIssuedBy("CN=issuer.internal")
        .ValidateChain())
    .OverrideDefaultTrustPolicy(policy)  // Single call with combined policy
    .Build();
```

---

## Architecture

### Package Structure

| Package | Purpose |
|---------|---------|
| `CoseSign1.Factories` | Signature creation factories (direct + indirect) |
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
| `--output-format`, `-f` | Output format: text, json, xml, quiet |
| `--verbose` | Show verbose help output |
| `--verbosity N` | Set logging verbosity level (0=quiet .. 4=trace) |
| `-vv` | Debug verbosity (equivalent to `--verbosity 3`) |
| `-vvv` | Trace verbosity (equivalent to `--verbosity 4`) |
| `--log-file <path>` | Write logs to file |
| `--log-file-append` | Append to existing log file |
| `--log-file-overwrite` | Overwrite existing log file (default) |
| `--additional-plugin-dir <dir>` | Additional plugin directory |

### Commands

- **`sign x509 pfx`** - Sign with PFX certificate
- **`sign x509 pem`** - Sign with PEM certificate
- **`sign x509 certstore`** - Sign with Windows/Linux certificate store
- **`sign x509 ephemeral`** - Sign with temporary test certificate
- **`sign x509 akv-cert`** - Sign with Azure Key Vault certificate
- **`sign akv akv-key`** - Sign with Azure Key Vault key (no X.509 chain)
- **`sign x509 ats`** - Sign with Azure Trusted Signing
- **`verify x509`** - Verify using X.509 trust
- **`verify akv`** - Verify using Azure Key Vault key trust
- **`verify mst`** - Verify using MST receipt trust
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

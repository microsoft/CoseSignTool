# CoseSign1.Certificates Package

**NuGet**: `CoseSign1.Certificates`  \
**Purpose**: X.509 certificate signing services, chain building helpers, and certificate-oriented validators  \
**Dependencies**: `CoseSign1.Abstractions`, `CoseSign1.Validation`

## Overview

This package standardizes certificate-backed signing around a single `CertificateSigningService` (an `ISigningService<CertificateSigningOptions>`). It also provides:

- Chain builder implementations (`ICertificateChainBuilder`)
- Local and remote certificate sources
- Validation helpers/validators for signatures and certificate policy
- Extensions for extracting certificate information from a `CoseSign1Message`

## Signing

### CertificateSigningService

`CertificateSigningService` is the entry point for certificate-based signing.

Factory methods:

```csharp
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;

// Local certificate + chain builder (required)
CertificateSigningService.Create(X509Certificate2 certificate, ICertificateChainBuilder chainBuilder);

// Local certificate + explicit chain (must include the signing certificate)
CertificateSigningService.Create(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> certificateChain);

// Remote signing (Azure Key Vault / ATS / HSM / etc.)
CertificateSigningService.Create(RemoteCertificateSource source);
```

**Local certificate example (automatic chain building):**

```csharp
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Direct;

using var cert = new X509Certificate2("cert.pfx", "password");
using var chainBuilder = new X509ChainBuilder();
using var signingService = CertificateSigningService.Create(cert, chainBuilder);

using var factory = new DirectSignatureFactory(signingService);
byte[] coseBytes = factory.CreateCoseSign1MessageBytes(Encoding.UTF8.GetBytes("hello"), "text/plain");
```

### CertificateSigningOptions (SCITT)

`CertificateSigningService` supports certificate-specific options via `CertificateSigningOptions`, including:

- `EnableScittCompliance`
- `CustomCwtClaims`

These options are intended to be passed as *service options* to the concrete signature factory overloads that accept `serviceOptions`.

## Chain Building

Local certificate signing requires either:

- an `ICertificateChainBuilder`, or
- an explicit chain list (which must include the signing certificate).

Provided chain builder implementations:

- `X509ChainBuilder`: wraps `X509Chain` and uses a configurable `X509ChainPolicy` (defaults to online revocation checking).
- `ExplicitCertificateChainBuilder`: validates and orders an explicitly provided chain.

## Certificate Sources

The package includes certificate sources that implement `ICertificateSource`:

- `PfxCertificateSource`
- `WindowsCertificateStoreCertificateSource` / `LinuxCertificateStoreCertificateSource`
- `RemoteCertificateSource` (base type for remote signing backends)

## Validation

This package includes certificate-focused validators for `CoseSign1Message`.

### Signature validation

`CertificateSignatureValidator` verifies the COSE signature using the certificate found via `x5t` + `x5chain` headers.

- Implements `IValidator` and participates in the `ValidationStage.Signature` stage
- Typically implemented as an `IConditionalValidator` so it can be skipped when X.509 headers are not present
- Handles embedded vs detached signatures:
  - Embedded: uses `message.Content`
  - Detached: requires a payload passed to the constructor

### Other certificate validators

- `CertificateChainValidator`
- `CertificateExpirationValidator`
- `CertificateKeyUsageValidator`
- `CertificateCommonNameValidator`
- `CertificatePredicateValidator`

## Extensions

`CoseSign1.Certificates.Extensions` includes helpers for extracting certificate data from headers, such as:

- `CoseSign1Message.TryGetSigningCertificate(out X509Certificate2? certificate, bool allowUnprotected = false)`
- `CoseSign1Message.TryGetCertificateChain(out X509Certificate2Collection? chain, bool allowUnprotected = false)`
- `CoseSign1Message.TryGetCertificateThumbprint(out CoseX509Thumbprint? thumbprint, bool allowUnprotected = false)`

## See Also

- [CoseSign1 Package](cosesign1.md)
- [Validation Package](validation.md)
- [Chain Validation Guide](../guides/chain-validation.md)
- [Remote Signing Guide](../guides/remote-signing.md)

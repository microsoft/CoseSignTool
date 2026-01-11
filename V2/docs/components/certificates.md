# CoseSign1.Certificates Package

**NuGet**: `CoseSign1.Certificates`  \
**Purpose**: X.509 certificate signing services, chain building helpers, and certificate-oriented validators  \
**Dependencies**: `CoseSign1.Abstractions`, `CoseSign1.Validation`

## Overview

This package standardizes certificate-backed signing around a single `CertificateSigningService` (an `ISigningService<CertificateSigningOptions>`). It also provides:

- Chain builder implementations (`ICertificateChainBuilder`)
- Local and remote certificate sources
- Validation helpers for X.509-backed COSE Sign1 messages (signing key resolution + certificate assertions)
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
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;

using var cert = new X509Certificate2("cert.pfx", "password");
using var chainBuilder = new X509ChainBuilder();
using var signingService = CertificateSigningService.Create(cert, chainBuilder);

// Preferred: route via CoseSign1MessageFactory
using var factory = new CoseSign1MessageFactory(signingService);
byte[] coseBytes = factory.CreateDirectCoseSign1MessageBytes(
  Encoding.UTF8.GetBytes("hello"),
  "text/plain",
  new DirectSignatureOptions());
```

### CertificateSigningOptions (SCITT)

`CertificateSigningService` supports certificate-specific options via `CertificateSigningOptions`, including:

- `EnableScittCompliance` - Controls whether SCITT-compliant CWT claims are automatically added to signatures. **Default: `true`**
- `CustomCwtClaims` - Custom CWT claims to use instead of auto-generated defaults

When `EnableScittCompliance` is `true` (the default), the following CWT claims are automatically added:
- **Issuer (iss)**: DID:x509 identifier derived from the certificate chain
- **Subject (sub)**: Defaults to "unknown.intent"  
- **IssuedAt (iat)**: Current timestamp
- **NotBefore (nbf)**: Current timestamp

Set `EnableScittCompliance = false` if you don't need SCITT compliance.

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

This package contributes certificate-focused *validation components* to the V2 validation pipeline:

- `CertificateSigningKeyResolver` (`ISigningKeyResolver`) extracts and parses X.509 key material from `x5t` + `x5chain` headers.
- Certificate assertion providers (`ISigningKeyAssertionProvider`) emit typed assertions such as:
  - `X509ChainTrustedAssertion`
  - `X509ValidityAssertion`
  - `X509IssuerAssertion`
  - `X509CommonNameAssertion`
  - `X509KeyUsageAssertion`

Signature verification itself is performed by the core validator once a signing key is resolved and the trust policy is satisfied.

### Quick signature check (no trust)

If you only want to check the cryptographic signature (and you understand this does **not** establish trust), use:

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Extensions;

CoseSign1Message message = CoseMessage.DecodeSign1(coseSign1Bytes);
bool ok = message.VerifySignature();
```

### Full validation (recommended)

Use `message.Validate(...)` / `ValidateAsync(...)` from `CoseSign1.Validation`.

**Auto-discovery:** if you reference `CoseSign1.Certificates`, its default components are discovered automatically (via an assembly-level default component provider).

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;

CoseSign1Message message = CoseMessage.DecodeSign1(coseSign1Bytes);
var result = message.Validate();

if (!result.Overall.IsValid)
{
    // See result.Resolution / result.Trust / result.Signature / result.PostSignaturePolicy for details.
}
```

**Custom certificate requirements:** build a validator (or inline-configure one) and add certificate assertion providers.

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;

var validator = new CoseSign1ValidationBuilder()
    // Required for certificate-backed validation
    .AddComponent(new CertificateSigningKeyResolver())

    // Add X.509 assertion providers
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("My Trusted Signer")
        .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")
        .ValidateChain())
    .Build();

CoseSign1Message message = CoseMessage.DecodeSign1(coseSign1Bytes);
var result = message.Validate(validator);
```

### Detached payloads

If the COSE_Sign1 has a detached payload, provide it via `CoseSign1ValidationOptions`:

```csharp
using CoseSign1.Validation;

var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver())
    .WithOptions(o => o.WithDetachedPayload(detachedPayloadBytes))
    .Build();
```

## Extensions

`CoseSign1.Certificates.Extensions` includes helpers for extracting certificate data from headers, such as:

- `CoseSign1Message.TryGetSigningCertificate(out X509Certificate2? certificate, bool allowUnprotected = false)`
- `CoseSign1Message.TryGetCertificateChain(out X509Certificate2Collection? chain, bool allowUnprotected = false)`
- `CoseSign1Message.TryGetCertificateThumbprint(out CoseX509Thumbprint? thumbprint, bool allowUnprotected = false)`

## See Also

- [CoseSign1.Factories Package](cosesign1.factories.md)
- [Validation Package](validation.md)
- [Chain Validation Guide](../guides/chain-validation.md)
- [Remote Signing Guide](../guides/remote-signing.md)

# Post-Quantum Cryptography Guide

This guide explains post-quantum cryptography (PQC) support in CoseSignTool V2.

## Overview

Post-quantum cryptography uses algorithms designed to be secure against both classical and quantum computer attacks. CoseSignTool V2 supports ML-DSA (Module-Lattice Digital Signature Algorithm) as specified in FIPS 204.

> **Important:** PQC support is currently **Windows-only** and requires the V2 toolchain/runtime (net10.0 / .NET 10+).

## Why Post-Quantum?

Current cryptographic algorithms (RSA, ECDSA) may be vulnerable to attacks from future quantum computers running Shor's algorithm. Post-quantum algorithms are designed to resist these attacks.

### Timeline Considerations

```
┌─────────────────────────────────────────────────────────────┐
│               Cryptographic Transition Timeline             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Today ─────────────────────────────▶ Quantum Threat       │
│    │                                         │              │
│    ▼                                         ▼              │
│  Dual signatures                     PQC-only signatures    │
│  (two independent signatures)                               │
│                                                             │
│  Recommended: Plan for algorithm agility                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Supported Algorithms

### ML-DSA (FIPS 204)

ML-DSA is supported via the `MLDSA` key algorithm, with parameter sets selected via key size.

| Parameter Set | `--key-size` | Notes |
|--------------|--------------|-------|
| ML-DSA-44 | 44 | Smaller signatures/keys |
| ML-DSA-65 | 65 | Default/recommended in V2 presets |
| ML-DSA-87 | 87 | Largest signatures/keys |

### Algorithm Selection

```csharp
// Security level recommendations:
// Level 2 (ML-DSA-44): General purpose, smallest signatures
// Level 3 (ML-DSA-65): Recommended for most applications
// Level 5 (ML-DSA-87): Highest security, largest signatures
```

## Platform Requirements

| Requirement | Value |
|-------------|-------|
| Operating System | Windows only |
| .NET Version | .NET 10+ |
| CNG Provider | Windows CNG with ML-DSA support |

### Checking Availability

There is no dedicated "PQC availability" API. In practice, attempt to create/use an ML-DSA key/certificate and handle `PlatformNotSupportedException` / `NotSupportedException`.

## Usage

### Signing with ML-DSA

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Factories.Direct;

// Create an ephemeral ML-DSA certificate (Windows-only)
using var cert = new EphemeralCertificateFactory().CreateCertificate(o => o
    .WithSubjectName("CN=Test ML-DSA Certificate")
    .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
    .WithKeySize(65));

using var chainBuilder = new X509ChainBuilder();
using var signingService = CertificateSigningService.Create(cert, chainBuilder);
using var factory = new CoseSign1MessageFactory(signingService);

var signature = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(payload, "application/json");
```

### CLI Usage

```bash
# Sign with an ephemeral ML-DSA certificate (testing only)
CoseSignTool sign-ephemeral document.json ^
    --algorithm MLDSA ^
    --key-size 65 ^
    --output signed.cose

# Verify ML-DSA signature
CoseSignTool verify signed.cose
```

## Hybrid / Dual Signatures

CoseSignTool V2 does not provide a first-class "countersignature" or "hybrid signature" feature in the library surface.

If you need both classical + post-quantum assurances today, the simplest approach is to produce two independent signatures over the same payload (for example, one ECDSA signature and one ML-DSA signature) and ship them side-by-side.

## Verification

### Verifying ML-DSA Signatures

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(signature);

// Automatically verifies RSA, ECDSA, and (on supported platforms) ML-DSA certificates.
bool isValid = message.VerifySignature();

if (isValid)
{
    Console.WriteLine("Signature verified successfully");
}
```

### Algorithm Negotiation

In most scenarios, the algorithm is determined by the COSE `alg` header and the signing certificate's key type.
If you need to enforce a specific policy (for example, requiring ML-DSA), implement a custom validator that inspects the message headers/certificate metadata.

## Cross-Platform Considerations

Since ML-DSA is Windows-only, design for graceful degradation (for example, select ECDSA/RSA on non-Windows, and enable ML-DSA only where the platform supports it).

## Size Impact

ML-DSA signatures are significantly larger than classical signatures. Consider:
- Storage requirements
- Network bandwidth
- Embedding in constrained environments

## Security Considerations

### Algorithm Maturity

ML-DSA (FIPS 204) is a NIST-standardized algorithm, but:
- Implementation experience is limited
- Interoperability is still developing
- Side-channel protections vary by implementation

### Key Management

- Protect ML-DSA private keys as carefully as classical keys
- Use HSM support when available
- Plan for algorithm agility

## Testing

The repository uses NUnit for V2 tests. To keep ML-DSA tests stable across OS/runtime combinations, use the shared helper:

```csharp
using CoseSign1.Tests.Common;
using NUnit.Framework;

[TestFixture]
public class MlDsaSigningTests
{
    [Test]
    public void SignAndVerify_WithMlDsa65_Succeeds()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Test implementation
    }
}
```

## Migration Path

### Phase 1: Preparation (Now)
- Update to CoseSignTool V2
- Test ML-DSA in development
- Identify affected systems

### Phase 2: Hybrid (Near-term)
- Deploy hybrid signatures
- Verify both classical and PQC
- Monitor for issues

### Phase 3: PQC-Only (Future)
- Phase out classical algorithms
- Full PQC deployment
- Continue monitoring standards

## See Also

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [Security Guide](security.md)
- [Certificate Sources](certificate-sources.md)

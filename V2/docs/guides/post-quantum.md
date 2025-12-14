# Post-Quantum Cryptography Guide

This guide explains post-quantum cryptography (PQC) support in CoseSignTool V2.

## Overview

Post-quantum cryptography uses algorithms designed to be secure against both classical and quantum computer attacks. CoseSignTool V2 supports ML-DSA (Module-Lattice Digital Signature Algorithm) as specified in FIPS 204.

> **Important:** PQC support is currently **Windows-only** and requires .NET 9 or later.

## Why Post-Quantum?

Current cryptographic algorithms (RSA, ECDSA) may be vulnerable to attacks from future quantum computers running Shor's algorithm. Post-quantum algorithms are designed to resist these attacks.

### Timeline Considerations

```
┌─────────────────────────────────────────────────────────────┐
│               Cryptographic Transition Timeline              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Today ─────────────────────────────▶ Quantum Threat         │
│    │                                         │               │
│    ▼                                         ▼               │
│  Hybrid signatures                    PQC-only signatures    │
│  (Classical + PQC)                                           │
│                                                              │
│  Recommended: Start hybrid signatures now                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Supported Algorithms

### ML-DSA (FIPS 204)

| Algorithm | Security Level | Signature Size | Public Key Size |
|-----------|---------------|----------------|-----------------|
| ML-DSA-44 | NIST Level 2 | ~2,420 bytes | ~1,312 bytes |
| ML-DSA-65 | NIST Level 3 | ~3,293 bytes | ~1,952 bytes |
| ML-DSA-87 | NIST Level 5 | ~4,595 bytes | ~2,592 bytes |

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
| .NET Version | .NET 9+ |
| CNG Provider | Windows CNG with ML-DSA support |

### Checking Availability

```csharp
using CoseSign1.Abstractions;

// Check if PQC is available
if (PqcSupport.IsAvailable)
{
    Console.WriteLine("ML-DSA is available");
}
else
{
    Console.WriteLine($"ML-DSA not available: {PqcSupport.UnavailableReason}");
}
```

## Usage

### Signing with ML-DSA

```csharp
using CoseSign1.Certificates.Pqc;

// Create ML-DSA key provider
var keyProvider = new MlDsaKeyProvider(MlDsaParameterSet.MlDsa65);

// Generate key pair
var keyPair = keyProvider.GenerateKeyPair();

// Create signing service
var signingService = new MlDsaSigningService(keyPair);

// Create signature factory
var factory = new DirectSignatureFactory(signingService);

// Sign payload
var signature = factory.CreateCoseSign1MessageBytes(payload, "application/json");
```

### Creating ML-DSA Certificates

```csharp
// Generate ML-DSA certificate for testing
var certProvider = new MlDsaCertificateProvider();
var cert = certProvider.GenerateSelfSignedCertificate(
    "CN=Test ML-DSA Certificate",
    MlDsaParameterSet.MlDsa65);
```

### CLI Usage

```bash
# Sign with ephemeral ML-DSA certificate (testing only)
CoseSignTool sign-ephemeral document.json ^
    --algorithm ML-DSA-65 ^
    --output signed.cose

# Verify ML-DSA signature
CoseSignTool verify signed.cose
```

## Hybrid Signatures

During the transition period, consider using hybrid signatures that combine classical and post-quantum algorithms.

### Approach 1: Dual Signatures

```csharp
// Create classical signature
var classicalFactory = new DirectSignatureFactory(ecdsaService);
var classicalSig = classicalFactory.CreateCoseSign1MessageBytes(payload);

// Create PQC counter-signature
var pqcFactory = new DirectSignatureFactory(mldsaService);
var hybridSig = pqcFactory.AddCounterSignature(classicalSig);
```

### Approach 2: Combined Headers

```csharp
// Add both algorithms to header
var contributor = new HybridAlgorithmHeaderContributor(
    primaryAlgorithm: CoseAlgorithm.ES384,
    secondaryAlgorithm: CoseAlgorithm.MlDsa65);
```

## Verification

### Verifying ML-DSA Signatures

```csharp
var validator = ValidationBuilder.Create()
    .AddSignatureValidator()
    .AddMlDsaCertificateValidator()
    .Build();

var result = await validator.ValidateAsync(signature);

if (result.IsValid)
{
    Console.WriteLine("ML-DSA signature verified successfully");
}
```

### Algorithm Negotiation

```csharp
// Accept multiple algorithms
var acceptedAlgorithms = new[]
{
    CoseAlgorithm.ES384,      // Classical
    CoseAlgorithm.MlDsa65,    // Post-quantum
    CoseAlgorithm.MlDsa87
};

var validator = new SignatureValidator(acceptedAlgorithms);
```

## Cross-Platform Considerations

Since ML-DSA is Windows-only, design for graceful degradation:

```csharp
public ISigningService CreateSigningService()
{
    if (PqcSupport.IsAvailable)
    {
        return new MlDsaSigningService(keyPair);
    }
    else
    {
        // Fall back to classical algorithm
        return new EcdsaSigningService(ecdsaKey);
    }
}
```

### Conditional Compilation

```csharp
#if WINDOWS
    // Use ML-DSA when available
    services.AddSingleton<ISigningService, MlDsaSigningService>();
#else
    // Use classical algorithm on other platforms
    services.AddSingleton<ISigningService, EcdsaSigningService>();
#endif
```

## Performance Considerations

| Operation | ML-DSA-65 | ECDSA P-384 |
|-----------|-----------|-------------|
| Key Generation | ~1ms | ~1ms |
| Sign | ~1ms | ~1ms |
| Verify | ~1ms | ~2ms |
| Signature Size | 3,293 bytes | 96 bytes |

### Size Impact

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

### Unit Tests

```csharp
[TestClass]
[TestCategory("PQC")]
public class MlDsaSigningTests
{
    [TestMethod]
    [PlatformCondition(Platform.Windows)]
    public void SignAndVerify_WithMlDsa65_Succeeds()
    {
        // Skip if PQC not available
        if (!PqcSupport.IsAvailable)
        {
            Assert.Inconclusive("ML-DSA not available on this platform");
        }
        
        // Test implementation
    }
}
```

### Integration Tests

```csharp
[TestMethod]
public void CrossPlatformVerification_ClassicalAndPqc_BothValid()
{
    // Create signature on Windows with ML-DSA
    var signature = CreateMlDsaSignature();
    
    // Verify on any platform
    var result = validator.Validate(signature);
    
    Assert.IsTrue(result.IsValid);
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

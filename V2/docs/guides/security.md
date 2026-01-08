# Security Guide

This guide covers security best practices for using CoseSignTool V2.

## Overview

Proper security practices are essential when working with digital signatures. This guide covers key management, credential handling, and operational security.

## Key Management

### Private Key Protection

Private keys should be protected at all times:

| Method | Security Level | Use Case |
|--------|---------------|----------|
| Hardware Security Module (HSM) | Highest | Production, regulatory compliance |
| Azure Trusted Signing | High | Cloud-native applications |
| Windows Certificate Store | Medium | Desktop applications |
| PFX/PEM files | Low | Development, testing |

### Certificate Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                  Certificate Lifecycle                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Generate ──▶ Request ──▶ Issue ──▶ Deploy ──▶ Monitor      │
│     │                                              │         │
│     │                                              ▼         │
│     │                                         Renew/Revoke   │
│     │                                              │         │
│     └──────────────────────────────────────────────┘         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Rotation

Establish key rotation policies:

- **Regular rotation** - Rotate keys before expiration
- **Emergency rotation** - Have procedures for compromised keys
- **Automated rotation** - Use automated renewal when possible

## Credential Handling

### Environment Variables

Store sensitive credentials in environment variables:

```bash
# Windows
set COSESIGNTOOL_PFX_PASSWORD=your-secure-password

# PowerShell
$env:COSESIGNTOOL_PFX_PASSWORD = "your-secure-password"
```

### Never Commit Secrets

- Never commit passwords, keys, or credentials to source control
- Use `.gitignore` to exclude sensitive files
- Use secret scanning tools in CI/CD

### Azure Managed Identity

For Azure deployments, use Managed Identity:

```csharp
// No credentials in code
var credential = new ManagedIdentityCredential();
```

Benefits:
- No secrets to manage
- Automatic credential rotation
- Audit logging built-in

## Signature Verification

### Always Verify

Never trust a signature without verification:

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(signature);

var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert
        .ValidateChain())
    .Build();

var signatureResult = await validator.ValidateAsync(message, ValidationStage.Signature);
var trustResult = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

if (!signatureResult.IsValid || !trustResult.IsValid)
{
    throw new SecurityException("Signature validation failed");
}
```

### Chain Validation

Always validate the full certificate chain:

```csharp
var chainOptions = new ChainBuildOptions
{
    RevocationMode = X509RevocationMode.Online, // Check revocation
    RevocationFlag = X509RevocationFlag.EntireChain,
    VerificationFlags = X509VerificationFlags.NoFlag // Strict
};
```

### Trust Roots

Control which certificate authorities are trusted:

```csharp
var trustedRoots = new X509Certificate2Collection
{
    new X509Certificate2("trusted-root.cer")
};

var validator = new CertificateChainValidator(trustedRoots);
```

## Algorithm Security

### Recommended Algorithms

| Algorithm | Security | Notes |
|-----------|----------|-------|
| ES384 | Strong | ECDSA P-384, recommended |
| ES256 | Good | ECDSA P-256, widely supported |
| PS384 | Strong | RSA-PSS, 3072+ bit keys |
| ML-DSA-65 | Future-proof | Post-quantum (Windows only) |

### Deprecated Algorithms

Avoid using:
- RSA-PKCS1v1.5 (prefer PSS)
- Keys smaller than 2048 bits (RSA)
- SHA-1 in any context

## Post-Quantum Cryptography

### ML-DSA Support

CoseSignTool V2 supports ML-DSA (FIPS 204) algorithms:

```csharp
// ML-DSA is Windows-only currently
var algorithms = CoseAlgorithm.GetMlDsaAlgorithms();
```

> **Note:** ML-DSA is only available on Windows with .NET 9+.

### Hybrid Approach

Consider hybrid signatures during transition:
1. Sign with classical algorithm (ES384)
2. Add counter-signature with ML-DSA
3. Verify both during transition period

## Operational Security

### Audit Logging

Log all signing operations:

```csharp
public class AuditedSigningService : ISigningService
{
    private readonly ISigningService _inner;
    private readonly ILogger _logger;
    
    public async Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, ...)
    {
        _logger.LogInformation(
            "Signing operation initiated. Data size: {Size}", 
            data.Length);
        
        var result = await _inner.SignAsync(data, ...);
        
        _logger.LogInformation(
            "Signing operation completed. Signature size: {Size}",
            result.Length);
        
        return result;
    }
}
```

### Rate Limiting

Protect signing services from abuse:

```csharp
services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("signing", limiter =>
    {
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.PermitLimit = 100;
    });
});
```

### Network Security

- Use HTTPS for all remote operations
- Validate TLS certificates
- Use network isolation where possible

## Secure Development

### Dependency Management

- Keep dependencies updated
- Scan for vulnerabilities
- Use package signing verification

### Code Review

- Review security-critical code
- Check for credential exposure
- Validate input/output handling

### Testing

Include security tests:

```csharp
[TestMethod]
public void Verify_WithTamperedSignature_Fails()
{
    var signature = CreateValidSignature();
    var tamperedSignature = TamperWithSignature(signature);
    
    var result = validator.Validate(tamperedSignature);
    
    Assert.IsFalse(result.IsValid);
}
```

## Incident Response

### Compromised Key Response

1. **Revoke** the compromised certificate immediately
2. **Notify** affected parties
3. **Rotate** to new key/certificate
4. **Audit** signatures made with compromised key
5. **Re-sign** artifacts if necessary

### Security Contact

Report security issues to the appropriate security team.

## Compliance

### Regulatory Requirements

CoseSignTool V2 can help meet various compliance requirements:

| Requirement | Support |
|-------------|---------|
| Code Signing | Supported |
| Document Signing | Supported |
| Supply Chain Security | SCITT compliance |
| Timestamping | Via transparency services |
| Audit Logging | Via custom validators |

## Checklist

### Development
- [ ] Use environment variables for credentials
- [ ] Never commit secrets to source control
- [ ] Use strong algorithms (ES384, PS384)
- [ ] Validate all signatures before trusting

### Production
- [ ] Use HSM or Azure Trusted Signing
- [ ] Enable audit logging
- [ ] Implement rate limiting
- [ ] Regular key rotation
- [ ] Certificate chain validation
- [ ] Revocation checking enabled

## See Also

- [Certificate Sources](certificate-sources.md)
- [Post-Quantum Guide](post-quantum.md)
- [Remote Signing](remote-signing.md)
- [Chain Validation](chain-validation.md)

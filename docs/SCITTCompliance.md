# SCITT Compliance and CWT Claims Support

## Overview

CoseSignTool provides comprehensive support for **SCITT (Supply Chain Integrity, Transparency, and Trust)** compliance through CWT (CBOR Web Token) Claims and DID:x509 identifiers. This enables organizations to create transparent, verifiable supply chain signatures that meet emerging industry standards.

## What is SCITT?

SCITT is an IETF specification designed to provide transparency and verifiability for supply chain artifacts. It requires signatures to include standardized claims about the issuer and subject of the signature, enabling trust and auditability across supply chain systems.

For more information, see: [SCITT Architecture Draft](https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/)

## What are CWT Claims?

CWT (CBOR Web Token) Claims, defined in [RFC 8392](https://datatracker.ietf.org/doc/html/rfc8392), are standardized claim types encoded in CBOR format. In COSE signatures, CWT Claims are stored in the protected header under label 13, ensuring they are cryptographically protected.

### Standard CWT Claims

| Claim | Label | Type | Description |
|-------|-------|------|-------------|
| `iss` (Issuer) | 1 | string | The entity that issued/created the signature |
| `sub` (Subject) | 2 | string | The subject or intent of the signature |
| `aud` (Audience) | 3 | string | The intended audience/recipient |
| `exp` (Expiration Time) | 4 | integer/DateTimeOffset | When the signature expires (Unix timestamp) |
| `nbf` (Not Before) | 5 | integer/DateTimeOffset | When the signature becomes valid |
| `iat` (Issued At) | 6 | integer/DateTimeOffset | When the signature was created |
| `cti` (CWT ID) | 7 | byte[] | Unique identifier for the token |

## DID:x509 Identifiers

CoseSignTool automatically generates **DID:x509 identifiers** from your certificate chain, following the [Microsoft DID:x509 specification](https://github.com/microsoft/did-x509/blob/main/specification.md).

A DID:x509 identifier has the format:
```
did:x509:0:{algorithm}:{ca-fingerprint}::subject:{encoded-subject-fields}
```

Example:
```
did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:MyOrg:O:Example%20Corp
```

### Features:
- **Automatic generation** from certificate chains via `CertificateCoseSigningKeyProvider.Issuer` property
- **Extensible**: Derived certificate providers can override the `Issuer` property to provide custom values
- **Multiple hash algorithms** supported (SHA-256, SHA-384, SHA-512)
- **Self-signed certificate support** for testing and development purposes only (not for production SCITT ledgers)
- **Standards-compliant encoding** following RFC 3986

### Customizing the Issuer

The `CertificateCoseSigningKeyProvider` base class provides a `virtual Issuer` property that derived classes can override:

```csharp
// Default behavior: DID:x509 from certificate chain
var provider = new X509Certificate2CoseSigningKeyProvider(cert);
string? issuer = provider.Issuer;  // "did:x509:0:sha256:..."

// Custom provider with overridden issuer
public class CustomCertificateProvider : X509Certificate2CoseSigningKeyProvider
{
    public override string? Issuer => GetIssuerFromConfiguration();
    
    // ... constructor and other implementations
}

var customProvider = new CustomCertificateProvider(cert);
// Now all SCITT operations use the custom issuer
var headerExtender = customProvider.CreateHeaderExtenderWithCWTClaims();
```

## Using SCITT Compliance in CoseSignTool

### Basic Usage

SCITT compliance is **enabled by default** when signing with certificates:

```bash
# Basic signing with automatic SCITT compliance
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose
```

This automatically adds:
- **Issuer claim**: DID:x509 derived from your certificate chain
- **Subject claim**: Defaults to "unknown.intent"

### Customizing CWT Claims

#### Setting Standard Claims

```bash
# Set custom issuer and subject
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --cwt-issuer "did:example:123" \
  --cwt-subject "software.release.v1.0"

# Add audience claim
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --cwt-audience "production.systems"
```

#### Setting Timestamp Claims

Timestamp claims accept **date/time strings** or **Unix timestamps**:

```bash
# Using ISO 8601 date/time format (recommended)
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --cwt-claims "exp:2024-12-31T23:59:59Z" \
  --cwt-claims "nbf:2024-01-01T00:00:00Z" \
  --cwt-claims "iat:2024-11-19T10:30:00-05:00"

# Using Unix timestamps
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --cwt-claims "exp:1735689600"
```

#### Custom Claims

Add custom claims using integer labels or standard claim names:

```bash
# Using integer labels (custom claims)
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --cwt-claims "100:custom-value" \
  --cwt-claims "101:another-value"

# Using standard claim names
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --cwt-claims "cti:abc123" \
  --cwt-claims "aud:production"

# Combining multiple claims
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --cwt-issuer "did:example:issuer" \
  --cwt-subject "release.v2.0" \
  --cwt-claims "exp:2025-12-31T23:59:59Z" \
  --cwt-claims "cti:unique-id-12345" \
  --cwt-claims "200:custom-metadata"
```

### Disabling SCITT Compliance

If needed, you can disable automatic SCITT compliance:

```bash
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --enable-scitt false
```

## Using SCITT Compliance in CoseHandler Library

### Basic Usage with Defaults

```csharp
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Extensions;

// Create signing key provider with certificate
var cert = new X509Certificate2("mycert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);

// Create header extender with SCITT compliance (automatic DID:x509 issuer)
var headerExtender = signingKeyProvider.CreateHeaderExtenderWithCWTClaims(
    issuer: null,  // Uses DID:x509 from certificate
    subject: null  // Uses "unknown.intent"
);

// Sign with SCITT compliance
byte[] payload = File.ReadAllBytes("payload.txt");
var signature = CoseHandler.Sign(
    payload, 
    signingKeyProvider, 
    embedPayload: false,
    headerExtender: headerExtender
);
```

### Custom CWT Claims

```csharp
using CoseSign1.Headers;
using CoseSign1.Certificates.Extensions;

// Create custom CWT claims
var cwtClaims = new CWTClaimsHeaderExtender()
    .SetIssuer("did:example:custom-issuer")
    .SetSubject("software.build.v1.2.3")
    .SetAudience("production-environment")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1))
    .SetIssuedAt(DateTimeOffset.UtcNow)
    .SetCustomClaim(100, "custom-value");

// Create combined header extender
var headerExtender = new X509CertificateWithCWTClaimsHeaderExtender(
    signingKeyProvider, 
    cwtClaims
);

// Sign with custom claims
var signature = CoseHandler.Sign(
    payload,
    signingKeyProvider,
    embedPayload: false,
    headerExtender: headerExtender
);
```

### Working with DateTimeOffset

```csharp
// Set expiration time using DateTimeOffset
var extender = new CWTClaimsHeaderExtender()
    .SetExpirationTime(DateTimeOffset.UtcNow.AddMonths(6))
    .SetNotBefore(DateTimeOffset.UtcNow.AddDays(-1))
    .SetIssuedAt(DateTimeOffset.UtcNow);

// Or use Unix timestamps directly if needed
extender.SetExpirationTime(1735689600L);
```

### Accessing Active CWT Claims

```csharp
var certWithCwt = new X509CertificateWithCWTClaimsHeaderExtender(
    signingKeyProvider, 
    customClaims: null
);

// Modify the active CWT claims extender
certWithCwt.ActiveCWTClaimsExtender
    .SetAudience("specific-audience")
    .SetCustomClaim(200, "additional-metadata");
```

## Using with CoseSign1MessageBuilder

```csharp
using CoseSign1;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Extensions;

// Create builder
var builder = new CoseSign1MessageBuilder()
    .SetPayloadBytes(payloadBytes);

// Add certificate-based signing with SCITT compliance
var cert = new X509Certificate2("mycert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);

// Option 1: Use default SCITT compliance
var headerExtender = signingKeyProvider.CreateHeaderExtenderWithCWTClaims();
builder.UseHeaderExtender(headerExtender);

// Option 2: Customize claims
var cwtClaims = new CWTClaimsHeaderExtender()
    .SetSubject("my-custom-subject")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddDays(30));

var customExtender = new X509CertificateWithCWTClaimsHeaderExtender(
    signingKeyProvider,
    cwtClaims
);
builder.UseHeaderExtender(customExtender);

// Build and sign
byte[] coseSigned = builder.Sign(signingKeyProvider);
```

## Indirect Signatures with SCITT

Indirect signatures (using CoseIndirectSignature or the IndirectSign plugin) create **embedded** COSE signatures with a hash envelope instead of the full payload. These also support SCITT compliance:

```bash
# Using the indirect-sign plugin with SCITT
CoseSignTool indirect-sign \
  --payload payload.txt \
  --signature signature.cose \
  --pfx mycert.pfx \
  --cwt-subject "indirect.signature.v1" \
  --cwt-claims "exp:2025-12-31T23:59:59Z"
```

## Validation and Reading CWT Claims

When validating signatures, CoseHandler automatically validates the CWT Claims structure. To read the claims:

```csharp
using System.Security.Cryptography.Cose;
using System.Formats.Cbor;

// Read the signature
byte[] coseBytes = File.ReadAllBytes("signature.cose");
CoseSign1Message message = CoseSign1Message.DecodeSign1(coseBytes);

// Use the TryGetCwtClaims extension method
if (message.TryGetCwtClaims(out CwtClaims? claims))
{
    Console.WriteLine($"Issuer: {claims.Issuer}");
    Console.WriteLine($"Subject: {claims.Subject}");
    
    if (claims.ExpirationTime.HasValue)
    {
        Console.WriteLine($"Expires: {claims.ExpirationTime.Value}");
    }
    
    // Print all claims
    Console.WriteLine("\nAll Claims:");
    Console.WriteLine(claims.ToString());
}
else
{
    Console.WriteLine("No CWT Claims found");
}
```

For advanced scenarios requiring direct CBOR access, see the [CoseSign1.Headers documentation](CoseSign1.Headers.md).

## Best Practices

1. **Use DID:x509 for Issuer**: Let CoseSignTool automatically generate the issuer claim from your certificate for maximum verifiability.

2. **Meaningful Subjects**: Use descriptive subject claims that clearly indicate the purpose or intent of the signature:
   - `software.release.v1.2.3`
   - `container.image.production`
   - `document.approval.final`

3. **Set Expiration Times**: Always include expiration times for signatures to enable time-bound validity:
   ```bash
   --cwt-claims "exp:2025-12-31T23:59:59Z"
   ```

4. **Use ISO 8601 Format**: For timestamp claims, prefer ISO 8601 date/time strings for better readability and timezone support.

5. **Document Custom Claims**: If using custom integer labels (100+), document their meaning for your organization.

6. **Audience Specification**: Use the audience claim to specify which systems should accept the signature.

## Troubleshooting

### Common Issues

**Q: Why is my custom issuer not a DID:x509?**  
A: You can specify any issuer string. DID:x509 is only auto-generated when you don't provide a custom issuer.

**Q: Can I use SCITT compliance with self-signed certificates?**  
A: Self-signed certificates are supported for **testing and development purposes only**. Production SCITT ledgers will reject signatures from self-signed certificates as they cannot establish a trusted certificate chain. For production use, always use certificates issued by a trusted Certificate Authority (CA).

**Q: How do I verify CWT Claims are included in my signature?**  
A: Use a CBOR decoder or the validation code example above to inspect the protected headers.

**Q: What happens if I set both `--cwt-issuer` and let it auto-generate?**  
A: The `--cwt-issuer` value takes precedence over auto-generation.

**Q: Are CWT Claims validated during signature validation?**  
A: The structure is validated, but claim semantics (like expiration) require application-level validation.

## Related Documentation

- [CoseSignTool CLI Documentation](./CoseSignTool.md)
- [CoseHandler Library Documentation](./CoseHandler.md)
- [Advanced Topics](./Advanced.md)
- [Indirect Signatures](./CoseIndirectSignature.md)

## References

- [SCITT Architecture (IETF Draft)](https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/)
- [RFC 8392 - CBOR Web Token (CWT)](https://datatracker.ietf.org/doc/html/rfc8392)
- [Microsoft DID:x509 Specification](https://github.com/microsoft/did-x509/blob/main/specification.md)
- [COSE (RFC 8152)](https://datatracker.ietf.org/doc/html/rfc8152)

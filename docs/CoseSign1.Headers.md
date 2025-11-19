# [CoseSign1.Headers](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1.Headers)

**CoseSign1.Headers** is a .NET Standard 2.0 library containing header extender implementations for adding custom headers to COSE signatures. It provides strongly-typed header extenders for common use cases, particularly **CWT (CBOR Web Token) Claims** for **SCITT (Supply Chain Integrity, Transparency, and Trust)** compliance.

## Dependencies

**CoseSign1.Headers** has the following package dependencies:
* CoseSign1
* System.Formats.Cbor >= 8.0.0

## Overview

Header extenders implement the `ICoseHeaderExtender` interface and allow you to add custom headers to COSE signatures in a type-safe, fluent manner. Headers can be either:
- **Protected**: Cryptographically signed and tamper-evident
- **Unprotected**: Not signed, useful for metadata that doesn't require protection

## CWT Claims Support

### [CWTClaimsHeaderExtender](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Headers/CWTClaimsHeaderExtender.cs)

The `CWTClaimsHeaderExtender` class provides strongly-typed methods for adding CWT (CBOR Web Token) Claims to COSE signatures. CWT Claims are defined in [RFC 8392](https://datatracker.ietf.org/doc/html/rfc8392) and are required for SCITT compliance.

#### Features:
- **Fluent API**: Chain method calls for easy claim configuration
- **Type Safety**: Strongly-typed methods for all standard CWT claims
- **DateTimeOffset Support**: Accept both `DateTimeOffset` and Unix timestamps
- **Custom Claims**: Support for custom integer-labeled claims
- **Protected Headers Only**: CWT Claims are always stored in protected headers (label 13)
- **CBOR Encoding**: Claims are automatically encoded as CBOR maps

#### Standard CWT Claims:

| Claim | Label | Method | Type | Description |
|-------|-------|--------|------|-------------|
| Issuer | 1 | `SetIssuer(string)` | string | Entity that issued the signature |
| Subject | 2 | `SetSubject(string)` | string | Subject or intent of the signature |
| Audience | 3 | `SetAudience(string)` | string | Intended recipient |
| Expiration Time | 4 | `SetExpirationTime(DateTimeOffset/long)` | timestamp | When signature expires |
| Not Before | 5 | `SetNotBefore(DateTimeOffset/long)` | timestamp | When signature becomes valid |
| Issued At | 6 | `SetIssuedAt(DateTimeOffset/long)` | timestamp | When signature was created |
| CWT ID | 7 | `SetCwtId(byte[])` | bytes | Unique identifier |

#### Basic Usage:

```csharp
using CoseSign1.Headers;

// Create CWT claims header extender
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetIssuer("did:example:issuer")
    .SetSubject("software.release.v1.2.3")
    .SetAudience("production-environment");

// Use with CoseSign1MessageBuilder
var builder = new CoseSign1MessageBuilder()
    .SetPayloadBytes(payloadBytes)
    .UseHeaderExtender(cwtExtender);

byte[] signature = builder.Sign(signingKeyProvider);
```

#### Timestamp Claims with DateTimeOffset:

```csharp
// Using DateTimeOffset (recommended for better readability)
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1))
    .SetNotBefore(DateTimeOffset.UtcNow)
    .SetIssuedAt(DateTimeOffset.UtcNow);

// Or using Unix timestamps directly
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetExpirationTime(1735689600L)  // Unix timestamp
    .SetIssuedAt(DateTimeOffset.Parse("2024-11-19T10:30:00Z"));
```

#### Custom Claims:

```csharp
// Add custom claims with integer labels (100+ recommended)
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetIssuer("did:example:issuer")
    .SetSubject("document.approval")
    .SetCustomClaim(100, "build-number-12345")
    .SetCustomClaim(101, 42)  // Numeric values
    .SetCustomClaim(102, new byte[] { 0x01, 0x02, 0x03 });  // Binary data
```

#### Complete Example:

```csharp
using CoseSign1;
using CoseSign1.Headers;
using CoseSign1.Certificates.Local;

// Create signing key provider
var cert = new X509Certificate2("mycert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);

// Create comprehensive CWT claims
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetIssuer("did:x509:0:sha256:fingerprint::subject:CN:MyOrg")
    .SetSubject("software.container.v2.1.0")
    .SetAudience("kubernetes-cluster-prod")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddMonths(6))
    .SetNotBefore(DateTimeOffset.UtcNow.AddDays(-1))
    .SetIssuedAt(DateTimeOffset.UtcNow)
    .SetCustomClaim(100, "build-pipeline-azure")
    .SetCustomClaim(101, "commit-sha-abc123");

// Build and sign
byte[] payload = File.ReadAllBytes("payload.txt");
var builder = new CoseSign1MessageBuilder()
    .SetPayloadBytes(payload)
    .UseHeaderExtender(cwtExtender);

byte[] signature = builder.Sign(signingKeyProvider);
```

### [CWTClaimsHeaderLabels](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Headers/CWTClaimsHeaderLabels.cs)

Constants class containing standard CWT claim labels:

```csharp
public static class CWTClaimsHeaderLabels
{
    public const int Issuer = 1;          // iss
    public const int Subject = 2;         // sub
    public const int Audience = 3;        // aud
    public const int ExpirationTime = 4;  // exp
    public const int NotBefore = 5;       // nbf
    public const int IssuedAt = 6;        // iat
    public const int CwtId = 7;           // cti
    public const int CwtClaims = 13;      // COSE header label for CWT claims map
}
```

Usage:
```csharp
// Access claim labels programmatically
int expLabel = CWTClaimsHeaderLabels.ExpirationTime;  // 4

// The CWT claims map is stored in protected header label 13
int cwtClaimsLabel = CWTClaimsHeaderLabels.CWTClaims;  // 13
```

## Reading CWT Claims from Signatures

To read CWT Claims from an existing COSE signature, use the `TryGetCwtClaims()` extension method:

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;

// Read the COSE signature
byte[] coseBytes = File.ReadAllBytes("signature.cose");
CoseSign1Message message = CoseSign1Message.DecodeSign1(coseBytes);

// Get CWT Claims using the extension method
if (message.TryGetCwtClaims(out CwtClaims? claims))
{
    // Access standard claims as strongly-typed properties
    if (claims.Issuer != null)
        Console.WriteLine($"Issuer: {claims.Issuer}");
    
    if (claims.Subject != null)
        Console.WriteLine($"Subject: {claims.Subject}");
    
    if (claims.Audience != null)
        Console.WriteLine($"Audience: {claims.Audience}");
    
    if (claims.ExpirationTime.HasValue)
        Console.WriteLine($"Expires: {claims.ExpirationTime.Value:o}");
    
    if (claims.NotBefore.HasValue)
        Console.WriteLine($"Not Before: {claims.NotBefore.Value:o}");
    
    if (claims.IssuedAt.HasValue)
        Console.WriteLine($"Issued At: {claims.IssuedAt.Value:o}");
    
    if (claims.CwtId != null)
        Console.WriteLine($"CWT ID: {BitConverter.ToString(claims.CwtId)}");
    
    // Access custom claims
    if (claims.CustomClaims.Count > 0)
    {
        Console.WriteLine("\nCustom Claims:");
        foreach (var kvp in claims.CustomClaims)
        {
            string valueStr = kvp.Value switch
            {
                string s => s,
                long l => l.ToString(),
                byte[] b => $"[{b.Length} bytes]",
                _ => kvp.Value.ToString() ?? "[null]"
            };
            Console.WriteLine($"  Label {kvp.Key}: {valueStr}");
        }
    }
    
    // Or just print everything
    Console.WriteLine("\nAll Claims:");
    Console.WriteLine(claims.ToString());
}
else
{
    Console.WriteLine("No CWT Claims found in signature");
}
```

### Manual CBOR Parsing (Advanced)

For advanced scenarios where you need direct CBOR access, you can manually parse the claims:

```csharp
using System.Formats.Cbor;

if (message.ProtectedHeaders.TryGetValue(
    CWTClaimsHeaderLabels.CWTClaims, 
    out CoseHeaderValue cwtClaimsValue))
{
    byte[] claimsBytes = cwtClaimsValue.EncodedValue.ToArray();
    var reader = new CborReader(claimsBytes);
    reader.ReadStartMap();
    
    while (reader.PeekState() != CborReaderState.EndMap)
    {
        int label = reader.ReadInt32();
        // ... manual parsing logic
    }
    
    reader.ReadEndMap();
}
```

## Chaining Header Extenders

Multiple header extenders can be chained together using `ChainedCoseHeaderExtender`:

```csharp
using CoseSign1;
using CoseSign1.Headers;
using CoseSign1.Certificates;

// Create CWT claims extender
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetIssuer("did:example:issuer")
    .SetSubject("software.build");

// Create custom header extender
var customExtender = new MyCustomHeaderExtender();

// Chain them together
var chainedExtender = new ChainedCoseHeaderExtender(cwtExtender, customExtender);

// Or use the X509CertificateWithCWTClaimsHeaderExtender which does this automatically
var certWithCwt = new X509CertificateWithCWTClaimsHeaderExtender(
    signingKeyProvider,
    cwtExtender
);
```

## Best Practices

1. **Use DateTimeOffset**: For timestamp claims, prefer `DateTimeOffset` over Unix timestamps for better readability and timezone support.

2. **Protected Headers**: CWT Claims are always in protected headers, ensuring they are cryptographically signed.

3. **Meaningful Subjects**: Use descriptive subjects that clearly indicate the purpose:
   - `software.release.v1.2.3`
   - `container.image.production`
   - `document.approval.final`

4. **Custom Claim Labels**: Use integer labels 100+ for custom claims to avoid conflicts with future standard claims.

5. **Expiration Times**: Always include expiration times for time-bound validity:
   ```csharp
   .SetExpirationTime(DateTimeOffset.UtcNow.AddMonths(6))
   ```

6. **DID:x509 Issuers**: For certificate-based signing, use DID:x509 identifiers as the issuer claim (see `DidX509Utilities` in CoseSign1.Certificates).

## SCITT Compliance

For complete SCITT (Supply Chain Integrity, Transparency, and Trust) compliance, combine `CWTClaimsHeaderExtender` with certificate-based signing:

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.Extensions;

// Quick SCITT compliance with defaults
var headerExtender = signingKeyProvider.CreateHeaderExtenderWithCWTClaims();

// Or use X509CertificateWithCWTClaimsHeaderExtender for full control
var certWithCwt = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider);
certWithCwt.ActiveCWTClaimsExtender
    .SetSubject("custom-subject")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1));
```

For comprehensive SCITT documentation, including CLI usage, DID:x509 identifiers, and complete examples, see **[SCITTCompliance.md](./SCITTCompliance.md)**.

## Related Documentation

- [SCITTCompliance.md](./SCITTCompliance.md) - Complete SCITT compliance guide
- [CoseSign1.Certificates.md](./CoseSign1.Certificates.md) - Certificate-based signing
- [CoseHandler.md](./CoseHandler.md) - Library API usage
- [Advanced.md](./Advanced.md) - Advanced scenarios

## References

- [RFC 8392 - CBOR Web Token (CWT)](https://datatracker.ietf.org/doc/html/rfc8392)
- [SCITT Architecture (IETF Draft)](https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/)
- [COSE (RFC 8152)](https://datatracker.ietf.org/doc/html/rfc8152)

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
- **Type Safety**: Strongly-typed methods for all standard CWT claims with `DateTimeOffset` properties
- **Optional Automatic Defaults**: Certificate providers automatically add default CWT claims by default (issuer from DID:x509, subject as "unknown.intent"), but can be disabled via `EnableScittCompliance` property
- **Smart Merging**: Merge user-provided claims with defaults, or prevent merging with `preventMerge` flag
- **Flexible Placement**: Control whether claims go in protected, unprotected, or both header sections
- **Custom Header Labels**: Use non-standard header labels instead of the default label 15
- **Custom Claims**: Support for custom integer-labeled claims
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

#### Constructor Options:

```csharp
using CoseSign1.Headers;

// Default constructor - merges with existing claims in protected headers
var cwtExtender = new CWTClaimsHeaderExtender();

// Prevent merging with existing claims - throws if claims already exist
var cwtExtender = new CWTClaimsHeaderExtender(preventMerge: true);

// Place claims in unprotected headers (not recommended for SCITT)
var cwtExtender = new CWTClaimsHeaderExtender(
    headerPlacement: CwtClaimsHeaderPlacement.UnprotectedOnly);

// Place claims in both protected and unprotected headers
var cwtExtender = new CWTClaimsHeaderExtender(
    headerPlacement: CwtClaimsHeaderPlacement.Both);

// Use custom header label instead of default label 15
var customLabel = new CoseHeaderLabel(999);
var cwtExtender = new CWTClaimsHeaderExtender(
    customHeaderLabel: customLabel);

// Combine options
var cwtExtender = new CWTClaimsHeaderExtender(
    preventMerge: true,
    headerPlacement: CwtClaimsHeaderPlacement.ProtectedOnly,
    customHeaderLabel: new CoseHeaderLabel(888));
```

#### Basic Usage:

```csharp
using CoseSign1.Headers;

// Create CWT claims header extender
// Note: Certificate providers automatically add default issuer and subject
// Your values will override the defaults
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetIssuer("did:example:issuer")  // Overrides default DID:x509 from cert
    .SetSubject("software.release.v1.2.3")  // Overrides default "unknown.intent"
    .SetAudience("production-environment");

// Use with CoseSign1MessageBuilder
var builder = new CoseSign1MessageBuilder(signingKeyProvider)
    .SetPayloadBytes(payloadBytes)
    .ExtendCoseHeader(cwtExtender);

CoseSign1Message signature = builder.Build();
```

#### Timestamp Claims with DateTimeOffset:

```csharp
// Using DateTimeOffset (recommended for better readability)
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1))
    .SetNotBefore(DateTimeOffset.UtcNow)
    .SetIssuedAt(DateTimeOffset.UtcNow);

// Or using Unix timestamps directly (automatically converted to DateTimeOffset)
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetExpirationTime(1735689600L)  // Unix timestamp
    .SetIssuedAt(DateTimeOffset.Parse("2024-11-19T10:30:00Z"));

// Note: IssuedAt and NotBefore are auto-populated if not set
// They default to the current time when issuer or subject is set
```

#### Custom Claims:

```csharp
// Add custom claims with integer labels (100+ recommended to avoid conflicts)
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetIssuer("did:example:issuer")
    .SetSubject("document.approval")
    .SetCustomClaim(100, "build-number-12345")  // String values
    .SetCustomClaim(101, 42)  // Numeric values
    .SetCustomClaim(102, true)  // Boolean values
    .SetCustomClaim(103, new byte[] { 0x01, 0x02, 0x03 })  // Binary data
    .SetCustomClaim(104, 3.14);  // Double values

// Remove a custom claim
cwtExtender.RemoveClaim(100);

// Access custom claims
IReadOnlyDictionary<int, object> customClaims = cwtExtender.CustomClaims;
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
CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

// Get CWT Claims from protected headers (default)
if (message.TryGetCwtClaims(out CwtClaims? claims))
{
    // Access claims...
}

// Get CWT Claims from unprotected headers
if (message.TryGetCwtClaims(out CwtClaims? claims, useUnprotectedHeaders: true))
{
    // Access unprotected claims...
}

// Get CWT Claims from custom header label
var customLabel = new CoseHeaderLabel(999);
if (message.TryGetCwtClaims(out CwtClaims? claims, headerLabel: customLabel))
{
    // Access claims from custom label...
}

// Example with standard usage:
if (message.TryGetCwtClaims(out CwtClaims? claims))
{
    // Access standard claims as strongly-typed DateTimeOffset properties
    if (claims.Issuer != null)
        Console.WriteLine($"Issuer: {claims.Issuer}");
    
    if (claims.Subject != null)
        Console.WriteLine($"Subject: {claims.Subject}");
    
    if (claims.Audience != null)
        Console.WriteLine($"Audience: {claims.Audience}");
    
    // Timestamp properties are DateTimeOffset (not Unix long)
    if (claims.ExpirationTime.HasValue)
        Console.WriteLine($"Expires: {claims.ExpirationTime.Value:o}");
    
    if (claims.NotBefore.HasValue)
        Console.WriteLine($"Not Before: {claims.NotBefore.Value:o}");
    
    if (claims.IssuedAt.HasValue)
        Console.WriteLine($"Issued At: {claims.IssuedAt.Value:o}");
    
    if (claims.CwtId != null)
        Console.WriteLine($"CWT ID: {BitConverter.ToString(claims.CwtId)}");
    
    // Access custom claims (read-only dictionary)
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
                bool b => b.ToString(),
                double d => d.ToString(),
                _ => kvp.Value.ToString() ?? "[null]"
            };
            Console.WriteLine($"  Label {kvp.Key}: {valueStr}");
        }
    }
    
    // Check if claims are in default state (only default subject set)
    if (claims.IsDefault())
    {
        Console.WriteLine("Claims are in default state");
    }
    
    // Or just print everything with ToString()
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

Multiple header extenders can be chained together using `ChainedCoseHeaderExtender` from the `CoseSign1.Headers` namespace:

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

// Chain them together - note the namespace is CoseSign1.Headers
var chainedExtender = new CoseSign1.Headers.ChainedCoseHeaderExtender(
    new[] { cwtExtender, customExtender });

// Certificate providers automatically add default CWT claims by default (unless EnableScittCompliance is set to false)
// Your custom extender will merge with those defaults
var builder = new CoseSign1MessageBuilder(signingKeyProvider)
    .SetPayloadBytes(payload)
    .ExtendCoseHeader(chainedExtender);

CoseSign1Message message = builder.Build();
```

## Best Practices

1. **Leverage Automatic Defaults**: Certificate providers automatically add default CWT claims by default (issuer as DID:x509, subject as "unknown.intent"). Set `EnableScittCompliance = false` on the provider if you don't need SCITT compliance, or only override specific claims if you need custom values.

2. **Use DateTimeOffset**: Timestamp properties (`ExpirationTime`, `NotBefore`, `IssuedAt`) are `DateTimeOffset?` for better timezone support.

3. **Protected Headers**: Default placement is protected headers (recommended for SCITT). Only use unprotected headers for non-critical metadata.

4. **Meaningful Subjects**: Override the default subject with descriptive values:
   - `software.release.v1.2.3`
   - `container.image.production`
   - `document.approval.final`

5. **Custom Claim Labels**: Use integer labels 100+ for custom claims to avoid conflicts with future standard claims.

6. **Expiration Times**: Always include expiration times for time-bound validity:
   ```csharp
   .SetExpirationTime(DateTimeOffset.UtcNow.AddMonths(6))
   ```

7. **Prevent Unintended Merging**: Use `preventMerge: true` if you want to ensure no existing claims are present:
   ```csharp
   var cwtExtender = new CWTClaimsHeaderExtender(preventMerge: true)
       .SetIssuer("my-issuer")
       .SetSubject("my-subject");
   ```

8. **Custom Labels for Multi-Tenancy**: Use custom header labels when you need multiple independent CWT claim sets:
   ```csharp
   var tenant1Label = new CoseHeaderLabel(100);
   var tenant2Label = new CoseHeaderLabel(200);
   var cwtExtender1 = new CWTClaimsHeaderExtender(customHeaderLabel: tenant1Label);
   var cwtExtender2 = new CWTClaimsHeaderExtender(customHeaderLabel: tenant2Label);
   ```

## SCITT Compliance

For SCITT (Supply Chain Integrity, Transparency, and Trust) compliance, certificate-based signing **automatically includes default CWT claims by default** (controlled via the `EnableScittCompliance` property):

```csharp
using CoseSign1;
using CoseSign1.Headers;
using CoseSign1.Certificates.Local;

// Automatic SCITT compliance - certificate provider adds default claims by default
var cert = new X509Certificate2("mycert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);

// Default claims automatically included:
// - Issuer: DID:x509 identifier from certificate
// - Subject: "unknown.intent"
// - IssuedAt: Current timestamp
// - NotBefore: Current timestamp

var builder = new CoseSign1MessageBuilder(signingKeyProvider)
    .SetPayloadBytes(payload);

CoseSign1Message message = builder.Build();

// To customize claims, create a CWTClaimsHeaderExtender
// Your values will merge with and override the defaults
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetSubject("software.release.v1.0")  // Overrides "unknown.intent"
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1));

var customBuilder = new CoseSign1MessageBuilder(signingKeyProvider)
    .SetPayloadBytes(payload)
    .ExtendCoseHeader(cwtExtender);

CoseSign1Message customMessage = customBuilder.Build();
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

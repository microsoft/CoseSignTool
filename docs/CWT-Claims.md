# CWT Claims in CoseSignTool

## Overview

CWT (CBOR Web Token) Claims are cryptographically protected assertions about a signed payload that are embedded in the COSE (CBOR Object Signing and Encryption) protected headers. This is a requirement for SCITT (Supply Chain Integrity, Transparency and Trust) compliance.

CoseSignTool implements CWT Claims as a first-class feature with automatic defaults and extensive customization:

- **Optional Automatic Defaults**: Certificate-based signing automatically adds CWT claims by default (issuer from DID:x509, subject as "unknown.intent"), but can be disabled via `EnableScittCompliance` property or `--enable-scitt false` flag
- **Smart Merging**: Custom claims intelligently merge with defaults, allowing selective overrides
- **Flexible Placement**: Choose protected (default), unprotected, or both header sections
- **Custom Labels**: Use non-standard header labels for advanced scenarios
- **Type Safety**: Strongly-typed API with `DateTimeOffset` for timestamps

## Standards Compliance

- **RFC 8392**: CBOR Web Token (CWT) specification
- **RFC 9597**: COSE Header Parameters for CWT Claims (label 15)
- **IETF SCITT Architecture**: [https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/](https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/)
- **DID:X509 Specification**: [https://github.com/microsoft/did-x509/blob/main/specification.md](https://github.com/microsoft/did-x509/blob/main/specification.md)

## CWT Claims Structure

CWT Claims in SCITT-compliant signatures include at minimum:

- **iss (issuer)** - Label 1: A URI identifying who issued the signature (auto-generated as DID:x509 from certificate)
- **sub (subject)** - Label 2: A string identifying the subject of the signature (defaults to "unknown.intent")
- **iat (issued at)** - Label 6: Timestamp when the signature was created (auto-populated as `DateTimeOffset`)
- **nbf (not before)** - Label 5: Timestamp when the signature becomes valid (auto-populated as `DateTimeOffset`)

These claims are embedded in COSE protected header label 15 (per RFC 9597) as a CBOR map. When using certificate-based signing, these claims are **automatically added by default** by the certificate provider (controlled by the `EnableScittCompliance` property, which defaults to `true`). The `iat` and `nbf` claims are auto-populated with the current timestamp.

**Note**: Timestamp properties are stored as `DateTimeOffset?` in the API (not Unix `long` timestamps), providing better timezone and date handling support.

**Disabling Automatic Claims**: If your use case doesn't require SCITT compliance, you can disable automatic CWT claims. See the [Disabling SCITT Compliance](#disabling-scitt-compliance) section below.

## DID:X509 Identifiers

When an issuer is not explicitly specified, CoseSignTool automatically generates a DID:X509 (Decentralized Identifier based on X.509 certificates) from the signing certificate chain.

### DID:X509 Format

CoseSignTool generates DID:X509 identifiers in the following format:

```
did:x509:0:sha256:{rootCertHash}::subject:{key}:{value}:{key}:{value}...
```

Where:
- `{rootCertHash}` is the SHA256 hash of the root certificate in base64url encoding (per RFC 4648 Section 5)
- `{key}:{value}` pairs represent the certificate's subject DN fields, where:
  - Keys are standard labels (`CN`, `L`, `ST`, `O`, `OU`, `C`, `STREET`) or OIDs (dotted decimal notation)
  - Values are percent-encoded using only `ALPHA`, `DIGIT`, `-`, `.`, and `_` as allowed unencoded characters
  - Note: Tilde (`~`) is **NOT** allowed unencoded, unlike standard RFC 3986

**Example**:
```
did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:O:GitHub:CN:Example%20User
```

**Note**: The DID:X509 specification supports additional query parameters beyond `::subject:`. See the [DID:X509 specification](https://github.com/microsoft/did-x509/blob/main/specification.md) for complete details. The `DidX509Generator` class can be inherited to implement custom DID generation behaviors.

## Using CWT Claims in SignCommand

### Automatic SCITT Compliance (Default Behavior)

When signing with a certificate, CWT Claims are **automatically included by default** with default values (this can be disabled via `--enable-scitt false`):

```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx
```

This automatically includes:
- **Issuer**: Auto-generated DID:X509 from your certificate chain
- **Subject**: "unknown.intent" (default value)
- **Issued At**: Current timestamp
- **Not Before**: Current timestamp

### Basic Usage (Custom Subject)

Override the default subject with your own value:

```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-subject "myapp-v1.0"
```

This will:
1. Use auto-generated DID:X509 as the issuer (iss)
2. Use "myapp-v1.0" as the subject (sub), overriding the default
3. Auto-populate iat and nbf timestamps

### Explicit Issuer

You can override the auto-generated DID:X509 issuer with a custom issuer URI:

```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-issuer https://example.com/issuer --cwt-subject "myapp-v1.0"
```

This overrides the default DID:X509 issuer while keeping other defaults.

### Custom Issuer with Default Subject

If you don't specify a subject, it defaults to "unknown.intent":

```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-issuer https://example.com/issuer
```

This uses your custom issuer but keeps the default subject value.

### With Certificate Store

Works with certificates from the Windows certificate store:

```bash
CoseSignTool sign --payload app.bin --signature app.cose --thumbprint ABC123DEF456 --cwt-subject "myapp-v1.0"
```

### Combined with Other Headers

CWT Claims work alongside traditional headers:

```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-subject "myapp-v1.0" --int-protected-headers version=1,build=1234 --string-protected-headers environment=production
```

### Disabling SCITT Compliance

If your use case doesn't require SCITT compliance, you can disable automatic CWT claims:

```bash
# Disable SCITT - no automatic CWT claims will be added
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --enable-scitt false
```

When SCITT compliance is disabled:
- **No default CWT claims** are automatically added (no issuer, subject, timestamps)
- **Custom CWT claims still work** - you can still add explicit claims via `--cwt-issuer`, `--cwt-subject`, or `--cwt-claims`
- The signature is still valid COSE, just without the automatic SCITT metadata

```bash
# SCITT disabled but custom claims still work
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx \
  --enable-scitt false \
  --cwt-subject "custom-subject" \
  --cwt-claims "100=custom-value"
```

For more information on SCITT compliance control, see [SCITTCompliance.md](./SCITTCompliance.md).

### Adding Additional CWT Claims

You can add arbitrary CWT claims using the `--cwt-claims` option with automatic type inference. Claims support both integer and string labels:

```bash
# Add standard claims using integer labels
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-subject "myapp-v1.0" --cwt-claims "3=https://example.com/api,4=1735689600"

# Add custom claims using string labels (e.g., for domain-specific metadata)
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-subject "myapp-v1.0" --cwt-claims "svn=42,build-id=abc123,environment=production"

# Mix integer, string, and negative labels
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-subject "myapp-v1.0" --cwt-claims "3=audience,svn=2,-260=hcert,4=1735689600"

# Different value types: strings, integers, booleans, byte arrays
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-subject "myapp-v1.0" --cwt-claims "3=audience,4=1735689600,5=true,6=0x48656c6c6f"
```

**Label Types**:
- **Integer labels**: Positive (e.g., `3`, `4`, `100`) or negative (e.g., `-260`, `-65537`)
  - Example: `4=1735689600` (expiration time)
- **String labels**: Text string keys for custom claims (per CBOR map specification)
  - Example: `svn=42` (software version number)
  - Example: `build-id=abc123` (build identifier)
  - Example: `environment=production` (deployment environment)

**Supported Types**:
- **Integers**: Any numeric value (int32 or int64)
  - Example: `4=1735689600`
- **Booleans**: `true` or `false` (case-insensitive)
  - Example: `5=true`
- **Byte Arrays**: Hex strings prefixed with `0x`
  - Example: `6=0xDEADBEEF`
- **Strings**: Any other value (default type)
  - Example: `3=https://example.com`
  - Example: `svn=42` (string label with string value)

**Format**: `label=value,label2=value2`
- Labels can be integers (positive/negative) or strings
- Labels 1 (iss) and 2 (sub) are reserved - use `--cwt-issuer` and `--cwt-subject` instead
- String labels like `"iss"` and `"sub"` are also reserved
- Values cannot contain commas (comma is the delimiter)
- Multiple equals signs in a value are preserved (e.g., `3=key=value` results in `"key=value"`)

**Standard CWT Claim Labels** (RFC 8392):
- `1` - iss (issuer) - Reserved, use `--cwt-issuer`
- `2` - sub (subject) - Reserved, use `--cwt-subject`
- `3` - aud (audience) - String
- `4` - exp (expiration time) - Integer (Unix timestamp)
- `5` - nbf (not before) - Integer (Unix timestamp)
- `6` - iat (issued at) - Integer (Unix timestamp)
- `7` - cti (CWT ID) - Byte array

**Example with Standard Claims**:
```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx \\
  --cwt-issuer https://issuer.example.com \\
  --cwt-subject "app-v1.0" \\
  --cwt-claims "3=https://api.example.com,4=1735689600,6=1704067200"
```

This creates CWT Claims with:
- Issuer: `https://issuer.example.com`
- Subject: `app-v1.0`
- Audience: `https://api.example.com` (claim 3)
- Expiration: January 1, 2025 (claim 4)
- Issued At: January 1, 2024 (claim 6)

## Command-Line Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--cwt-issuer` | `-cwt-issuer` | CWT Claims issuer (iss). Must be a valid URI. | Auto-generated DID:X509 |
| `--cwt-subject` | `-cwt-subject` | CWT Claims subject (sub). Any string value. | Empty string |
| `--cwt-claims` | `-cwt-claims` | Additional CWT claims as `label=value,label2=value2`. Supports int, bool, byte[], string. | None |

## Programmatic Usage

### Automatic Default Claims

When using certificate-based signing, CWT claims are **automatically added by default** by the certificate provider (controlled via the `EnableScittCompliance` property):

```csharp
using CoseSign1;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Certificates.Local;

// Certificate provider automatically adds default CWT claims by default
var cert = new X509Certificate2("cert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);

// Sign with automatic defaults (issuer from DID:x509, subject="unknown.intent")
ReadOnlyMemory<byte> signature = CoseHandler.Sign(
    payloadStream,
    signingKeyProvider,
    embedPayload: false,
    signatureFile,
    contentType: "application/cose"
);
// Result includes automatic CWT claims in protected headers
```

### Using CWTClaimsHeaderExtender to Override Defaults

```csharp
using CoseSign1.Headers;
using CoseSign1.Abstractions.Interfaces;

// Create CWT Claims header extender to override defaults
// Your values will merge with and override the automatic defaults
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetIssuer("https://example.com/issuer")  // Overrides DID:x509
    .SetSubject("myapp-v1.0")  // Overrides "unknown.intent"
    .SetAudience("https://api.example.com")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddMonths(6));

// Sign with custom claims that merge with defaults
ReadOnlyMemory<byte> signature = CoseHandler.Sign(
    payloadStream,
    signingKeyProvider,
    embedPayload: false,
    signatureFile,
    contentType: "application/cose",
    headerExtender: cwtExtender
);
```

### Constructor Options

```csharp
using CoseSign1.Headers;

// Default: Merge with existing claims in protected headers
var cwtExtender = new CWTClaimsHeaderExtender();

// Prevent merging - throws if claims already exist
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

// Combine all options
var cwtExtender = new CWTClaimsHeaderExtender(
    preventMerge: false,
    headerPlacement: CwtClaimsHeaderPlacement.ProtectedOnly,
    customHeaderLabel: new CoseHeaderLabel(888));
```

### Fluent API with DateTimeOffset

```csharp
using CoseSign1.Headers;

// Build CWT Claims with fluent API
// Note: Timestamp methods accept DateTimeOffset (not Unix long)
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetIssuer("https://example.com/issuer")
    .SetSubject("myapp-v1.0")
    .SetAudience("production")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1))  // DateTimeOffset
    .SetNotBefore(DateTimeOffset.UtcNow)  // DateTimeOffset
    .SetIssuedAt(DateTimeOffset.UtcNow)  // DateTimeOffset
    .SetCustomClaim(100, "build-12345")
    .SetCustomClaim(101, 42)
    .SetCustomClaim(102, true);

// Or use Unix timestamps (automatically converted to DateTimeOffset)
var cwtExtender2 = new CWTClaimsHeaderExtender()
    .SetExpirationTime(1735689600L);  // Converted to DateTimeOffset internally
```

### Reading Claims with Custom Labels

```csharp
using CoseSign1.Headers.Extensions;
using System.Security.Cryptography.Cose;

// Read from default label (15)
byte[] signatureBytes = File.ReadAllBytes("signature.cose");
CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

if (message.TryGetCwtClaims(out CwtClaims? claims))
{
    Console.WriteLine($"Issuer: {claims.Issuer}");
    Console.WriteLine($"Subject: {claims.Subject}");
    
    // Timestamp properties are DateTimeOffset, not long
    if (claims.ExpirationTime.HasValue)
        Console.WriteLine($"Expires: {claims.ExpirationTime.Value:o}");
}

// Read from custom label
var customLabel = new CoseHeaderLabel(999);
if (message.TryGetCwtClaims(out CwtClaims? customClaims, headerLabel: customLabel))
{
    Console.WriteLine($"Custom label issuer: {customClaims.Issuer}");
}

// Read from unprotected headers
if (message.TryGetCwtClaims(out CwtClaims? unprotectedClaims, useUnprotectedHeaders: true))
{
    Console.WriteLine($"Unprotected issuer: {unprotectedClaims.Issuer}");
}
```

### Chaining with Other Headers

```csharp
using CoseSign1;
using CoseSign1.Headers;

// Create CWT claims extender (will merge with automatic defaults)
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetSubject("myapp-v1.0")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddMonths(6));

// Create custom header extender
ICoseHeaderExtender customExtender = /* your custom headers */;

// Chain them together - note the namespace is CoseSign1.Headers
ICoseHeaderExtender combined = new CoseSign1.Headers.ChainedCoseHeaderExtender(
    new[] { cwtExtender, customExtender });

// Sign with chained extenders
ReadOnlyMemory<byte> signature = CoseHandler.Sign(
    payloadStream,
    signingKeyProvider,
    embedPayload: false,
    signatureFile,
    contentType: "application/cose",
    headerExtender: combined
);
```

## Validation

### Issuer Requirements

Per SCITT specification, the issuer must:
- Be a valid URI (absolute URI or DID format)
- Be between 1 and 8192 characters in length
- Not be null or whitespace

Examples of valid issuers:
- `https://example.com/issuer`
- `http://example.com/issuer`
- `did:x509:0:sha256:abc123...::subject:CN:Test`
- `did:web:example.com`
- `did:key:z6Mk...`

### Subject Requirements

The subject can be any string value, including empty string. There are no length restrictions.

## Error Handling

Common errors and solutions:

### "Issuer cannot be null or whitespace"
**Cause**: No issuer provided and auto-generation failed  
**Solution**: Provide explicit `--cwt-issuer` or ensure certificate chain is available

### "Issuer must be between 1 and 8192 characters"
**Cause**: Issuer URI is too long  
**Solution**: Use a shorter URI or a DID identifier

### "Issuer must be a valid URI"
**Cause**: Issuer is not in URI format  
**Solution**: Use absolute URI (https://...) or DID format (did:...)

## Best Practices

1. **Leverage Automatic Defaults**: Certificate-based signing automatically includes SCITT-compliant CWT claims by default. Set `EnableScittCompliance = false` if you don't need SCITT compliance, or only override specific claims when you need custom values.

2. **Use DID:X509 for certificate-based issuers**: The auto-generated DID:X509 provides cryptographic proof of the issuer's identity. Override only if required.

3. **Meaningful subjects**: Override the default "unknown.intent" subject with values that identify what was signed:
   - "application-v1.0.0"
   - "release-2024-11-18"
   - "container-image-production"

4. **Use DateTimeOffset**: The API uses `DateTimeOffset` for all timestamps (not Unix `long`), providing better timezone handling.

5. **Protected headers for production**: Default placement is protected headers (cryptographically signed). Only use unprotected headers for non-critical metadata.

6. **Prevent unintended merging**: Use `preventMerge: true` when you want to ensure exclusive control:
   ```csharp
   var cwtExtender = new CWTClaimsHeaderExtender(preventMerge: true)
       .SetIssuer("my-issuer")
       .SetSubject("my-subject");
   ```

7. **Custom labels for multi-tenancy**: Use custom header labels when you need multiple independent claim sets:
   ```csharp
   var tenant1 = new CWTClaimsHeaderExtender(customHeaderLabel: new CoseHeaderLabel(100));
   var tenant2 = new CWTClaimsHeaderExtender(customHeaderLabel: new CoseHeaderLabel(200));
   ```

8. **Check for default state**: Use `IsDefault()` to determine if only defaults are present:
   ```csharp
   if (claims.IsDefault())
       Console.WriteLine("Only default claims present");
   ```

## See Also

- [SCITT Integration Guide](SCITT-Integration.md)
- [CoseSignTool README](../README.md)
- [SCITT Architecture Specification](https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/)
- [DID:X509 Method Specification](https://github.com/microsoft/did-x509)

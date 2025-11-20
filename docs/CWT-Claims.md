# CWT Claims in CoseSignTool

## Overview

CWT (CBOR Web Token) Claims are cryptographically protected assertions about a signed payload that are embedded in the COSE (CBOR Object Signing and Encryption) protected headers. This is a requirement for SCITT (Supply Chain Integrity, Transparency and Trust) compliance.

CoseSignTool implements CWT Claims as a first-class feature, making them as easy to use as other header types (protected, unprotected, raw).

## Standards Compliance

- **RFC 8392**: CBOR Web Token (CWT) specification
- **RFC 9597**: COSE Header Parameters for CWT Claims (label 15)
- **IETF SCITT Architecture**: [https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/](https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/)
- **DID:X509 Specification**: [https://github.com/microsoft/did-x509/blob/main/specification.md](https://github.com/microsoft/did-x509/blob/main/specification.md)

## CWT Claims Structure

CWT Claims in SCITT-compliant signatures include at minimum:

- **iss (issuer)** - Label 1: A URI identifying who issued the signature (1-8192 characters)
- **sub (subject)** - Label 2: A string identifying the subject of the signature
- **iat (issued at)** - Label 6: Unix timestamp when the signature was created (auto-populated)
- **nbf (not before)** - Label 5: Unix timestamp when the signature becomes valid (auto-populated)

These claims are embedded in COSE protected header label 15 (per RFC 9597) as a CBOR map. The `iat` and `nbf` claims are automatically populated with the current timestamp when issuer or subject is set.

## DID:X509 Identifiers

When an issuer is not explicitly specified, CoseSignTool automatically generates a DID:X509 (Decentralized Identifier based on X.509 certificates) from the signing certificate chain.

### DID:X509 Format

CoseSignTool generates DID:X509 identifiers in the following format:

```
did:x509:0:sha256:{rootCertHash}::subject:{encodedLeafSubject}
```

Where:
- `{rootCertHash}` is the SHA256 hash of the root certificate in hex (lowercase)
- `{encodedLeafSubject}` is the percent-encoded subject DN of the leaf certificate per RFC 3986

**Example**:
```
did:x509:0:sha256:a1b2c3d4e5f6...::subject:CN%3DExample%20Corp%2COU%3DEngineering
```

**Note**: The DID:X509 specification supports additional query parameters beyond `::subject:`. See the [DID:X509 specification](https://github.com/microsoft/did-x509/blob/main/specification.md) for complete details. The `DidX509Generator` class can be inherited to implement custom DID generation behaviors.

## Using CWT Claims in SignCommand

### Basic Usage (Auto-generated DID:X509)

The simplest way to add CWT Claims is to let CoseSignTool auto-generate the issuer from your certificate:

```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-subject "myapp-v1.0"
```

This will:
1. Build the certificate chain
2. Generate a DID:X509 identifier from the chain
3. Use the DID:X509 as the issuer (iss)
4. Use "myapp-v1.0" as the subject (sub)

### Explicit Issuer

You can specify a custom issuer URI:

```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-issuer https://example.com/issuer --cwt-subject "myapp-v1.0"
```

### Issuer Only (Empty Subject)

Subject defaults to an empty string if not specified:

```bash
CoseSignTool sign --payload app.bin --signature app.cose --pfx cert.pfx --cwt-issuer https://example.com/issuer
```

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

### Using CwtClaimsHeaderExtender

```csharp
using CoseSign1.Headers;
using CoseSign1.Abstractions.Interfaces;

// Create CWT Claims header extender
ICoseHeaderExtender cwtExtender = new CwtClaimsHeaderExtender(
    issuer: "https://example.com/issuer",
    subject: "myapp-v1.0"
);

// Use with CoseHandler
ReadOnlyMemory<byte> signature = CoseHandler.Sign(
    payloadStream,
    signingKeyProvider,
    embedPayload: false,
    signatureFile,
    contentType: "application/cose",
    headerExtender: cwtExtender
);
```

### Using CwtClaimsBuilder (Fluent API)

```csharp
using CoseSign1.Headers;

// Build CWT Claims with fluent API
ICoseHeaderExtender cwtExtender = new CwtClaimsBuilder()
    .WithIssuer("https://example.com/issuer")
    .WithSubject("myapp-v1.0")
    .WithClaim(3, "audience-value")  // Add custom claims
    .WithClaim(4, 1234567890)        // exp claim
    .Build();
```

### Generating DID:X509

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.X509Certificates;

// Create a generator instance
var generator = new DidX509Generator();

// From certificate chain
X509Certificate2 leafCert = /* your leaf certificate */;
X509Certificate2 rootCert = /* your root certificate */;
string did = generator.Generate(leafCert, rootCert);

// From certificate collection
X509Certificate2Collection chain = /* your certificate chain */;
string did = generator.GenerateFromChain(chain);

// Validate DID:X509
bool isValid = DidX509Generator.IsValidDidX509(did);
```

### Custom DID Generation

You can inherit from `DidX509Generator` to customize the DID generation behavior:

```csharp
public class CustomDidGenerator : DidX509Generator
{
    protected override string EncodeSubject(string subject)
    {
        // Custom subject encoding logic
        return base.EncodeSubject(subject);
    }

    protected override byte[] ComputeRootCertificateHash(X509Certificate2 rootCertificate)
    {
        // Use a different hash algorithm
        using var sha384 = SHA384.Create();
        return sha384.ComputeHash(rootCertificate.RawData);
    }
}
```

### Chaining with Other Headers

```csharp
using CoseSign1;

// Create multiple header extenders
ICoseHeaderExtender cwtExtender = new CwtClaimsHeaderExtender(issuer, subject);
ICoseHeaderExtender customExtender = /* your custom headers */;

// Chain them together
ICoseHeaderExtender combined = new ChainedCoseHeaderExtender(new[] 
{ 
    cwtExtender, 
    customExtender 
});

// Use combined extender
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
- `did:x509:0:sha256:abc123...::subject:CN=Test`
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

1. **Use DID:X509 for certificate-based issuers**: The auto-generated DID:X509 provides cryptographic proof of the issuer's identity based on the certificate chain.

2. **Meaningful subjects**: Use subject values that identify what was signed (e.g., "application-v1.0.0", "release-2024-11-18").

3. **Consistent issuer URIs**: Use consistent issuer URIs across your organization for easy verification.

4. **Embed additional claims**: Use the fluent API to add custom claims like audience, expiration, or custom metadata.

5. **Chain headers appropriately**: Place CWT Claims extender first in the chain to ensure they're processed before other headers.

## See Also

- [SCITT Integration Guide](SCITT-Integration.md)
- [CoseSignTool README](../README.md)
- [SCITT Architecture Specification](https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/)
- [DID:X509 Method Specification](https://github.com/microsoft/did-x509)

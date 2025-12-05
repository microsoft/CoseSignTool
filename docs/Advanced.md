## Advanced usage and the CoseSign1 libraries

#### Asynchronous Signing APIs

CoseSign1 provides async methods for signing operations, particularly useful for:
- Large payloads streamed from disk or network
- Integration with async/await patterns
- Cancellation token support for long-running operations
- Better resource utilization in async contexts

**Available Async Methods:**

1. **CoseSign1MessageFactory.CreateCoseSign1MessageAsync** - Creates a `CoseSign1Message` asynchronously
2. **CoseSign1MessageFactory.CreateCoseSign1MessageBytesAsync** - Creates signature bytes asynchronously
3. **CoseSign1MessageBuilder.BuildAsync** - Builder pattern with async support

**Example: Async Signing with Stream**

```csharp
using CoseSign1;
using CoseSign1.Certificates.Local;
using System.IO;
using System.Threading;

// Setup
var cert = new X509Certificate2("cert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);
var factory = new CoseSign1MessageFactory();

// Open a large file as a stream
using var payloadStream = File.OpenRead("large-payload.bin");

// Sign asynchronously with cancellation support
var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));

CoseSign1Message signature = await factory.CreateCoseSign1MessageAsync(
    payload: payloadStream,
    signingKeyProvider: signingKeyProvider,
    embedPayload: false,
    contentType: "application/octet-stream",
    headerExtender: null,
    cancellationToken: cts.Token);

// Or get signature bytes directly
ReadOnlyMemory<byte> signatureBytes = await factory.CreateCoseSign1MessageBytesAsync(
    payload: payloadStream,
    signingKeyProvider: signingKeyProvider,
    embedPayload: false,
    cancellationToken: cts.Token);
```

**Example: Async Builder Pattern**

```csharp
using CoseSign1;
using CoseSign1.Headers;

// Create a builder
var builder = new CoseSign1MessageBuilder(signingKeyProvider)
    .SetContentType("application/json")
    .SetEmbedPayload(false);

// Sign from stream asynchronously
using var payloadStream = File.OpenRead("data.json");
CoseSign1Message signature = await builder.BuildAsync(
    payloadStream,
    cancellationToken: CancellationToken.None);
```

**Example: Async with CWT Claims**

```csharp
using CoseSign1;
using CoseSign1.Headers;

// Setup CWT claims extender (merges with automatic defaults)
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetSubject("software.release.v2.0")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1));

// Async sign with custom claims
using var payloadStream = File.OpenRead("release.tar.gz");

ReadOnlyMemory<byte> signature = await factory.CreateCoseSign1MessageBytesAsync(
    payload: payloadStream,
    signingKeyProvider: signingKeyProvider,
    embedPayload: false,
    contentType: "application/gzip",
    headerExtender: cwtExtender,
    cancellationToken: CancellationToken.None);

File.WriteAllBytes("release.tar.gz.cose", signature.ToArray());
```

**Method Signatures:**

```csharp
// Factory methods
Task<CoseSign1Message> CreateCoseSign1MessageAsync(
    ReadOnlyMemory<byte> payload,
    ICoseSigningKeyProvider signingKeyProvider,
    bool embedPayload = false,
    string contentType = "application/cose",
    ICoseHeaderExtender? headerExtender = null,
    CancellationToken cancellationToken = default);

Task<CoseSign1Message> CreateCoseSign1MessageAsync(
    Stream payload,
    ICoseSigningKeyProvider signingKeyProvider,
    bool embedPayload = false,
    string contentType = "application/cose",
    ICoseHeaderExtender? headerExtender = null,
    CancellationToken cancellationToken = default);

Task<ReadOnlyMemory<byte>> CreateCoseSign1MessageBytesAsync(
    ReadOnlyMemory<byte> payload,
    ICoseSigningKeyProvider signingKeyProvider,
    bool embedPayload = false,
    string contentType = "application/cose",
    ICoseHeaderExtender? headerExtender = null,
    CancellationToken cancellationToken = default);

Task<ReadOnlyMemory<byte>> CreateCoseSign1MessageBytesAsync(
    Stream payload,
    ICoseSigningKeyProvider signingKeyProvider,
    bool embedPayload = false,
    string contentType = "application/cose",
    ICoseHeaderExtender? headerExtender = null,
    CancellationToken cancellationToken = default);

// Builder method
Task<CoseSign1Message> BuildAsync(
    Stream payloadStream,
    CancellationToken cancellationToken = default);
```

**Notes:**
- Async methods support both byte array and Stream payloads
- Stream payloads enable true async I/O for large files
- Cancellation tokens allow graceful cancellation of long operations
- All async methods work with CWT claims and header extenders
- Detached signatures use `SignDetachedAsync` internally for efficient streaming

#### SCITT Compliance
CoseSignTool provides comprehensive support for **SCITT (Supply Chain Integrity, Transparency, and Trust)** compliance through CWT (CBOR Web Token) Claims and DID:x509 identifiers. SCITT compliance is automatically enabled when signing with certificates, adding cryptographically-protected claims about the issuer, subject, and other metadata to your signatures.

For complete documentation on SCITT features, including:
- CWT Claims (issuer, subject, audience, expiration, custom claims)
- DID:x509 automatic generation from certificate chains
- CLI usage with `--cwt-*` arguments
- Programmatic API with `CWTClaimsHeaderExtender`
- DateTimeOffset support for timestamps
- Self-signed certificate support (testing/development only)

See **[SCITTCompliance.md](./SCITTCompliance.md)** for comprehensive documentation and examples.

Quick example:
```csharp
using CoseSign1.Certificates.Extensions;

// Create SCITT-compliant signature with automatic DID:x509 issuer
var headerExtender = signingKeyProvider.CreateHeaderExtenderWithCWTClaims(
    issuer: null,    // Auto-generates DID:x509
    subject: "software.release.v1.0",
    audience: "production"
);

byte[] signature = CoseHandler.Sign(payload, signingKeyProvider, false, headerExtender);
```

#### Indirect Signatures
COSE signing normally uses either a "detached" signature, where the signature is in a separate file from the payload, or an "embedded" signature, where a copy of the payload is inserted into the signature file. This can be cumbersome for large payloads, especially when they must be sent to a remote server for signing or validation.
Indirect signing is a feature that allows you to create and validate a signature against a hash of the payload instead of the full payload. **Indirect signatures produce embedded COSE signatures** containing a hash envelope structure rather than the full payload. This feature is available through the [CoseIndirectSignature](.\CoseIndirectSignature.md) library and the **indirect-sign** plugin command in CoseSignTool. Indirect signatures also support full SCITT compliance with CWT Claims.

See [IndirectSignaturePlugin.md](./IndirectSignaturePlugin.md) for CLI usage.

#### Timestamping
The [COSE specification](https://www.iana.org/assignments/cose/cose.xhtml) is still evolving. Originally, there were plans to support an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp solution, but the [requisite headers were never defined](https://www.ietf.org/archive/id/draft-ietf-cose-tsa-tst-header-parameter-00.html) by the standards body.
The current default behavior of COSE validation is to fail if any of the certificates in the certificate chain have expired. However, there are user scenarios where a signature needs to be considered valid even after one or more certificates have expired. Staring in version 1.2.4-pre2, you have the option to allow signatures to pass with expired certificates in the chain by passing "AllowOutdated = true" to the ChainTrustValidator constructor.
This will allow signatures to pass validation with expired certificates, so long as none of the expired certificates have a lifetime EKU.

**Note**: SCITT compliance provides standardized timestamp claims (expiration, not-before, issued-at) via CWT Claims, which can be used for time-based validation. See [SCITTCompliance.md](./SCITTCompliance.md) for details on timestamp claims.
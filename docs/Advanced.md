## Advanced usage and the CoseSign1 libraries

#### SCITT Compliance
CoseSignTool provides comprehensive support for **SCITT (Supply Chain Integrity, Transparency, and Trust)** compliance through CWT (CBOR Web Token) Claims and DID:x509 identifiers. SCITT compliance is automatically enabled when signing with certificates, adding cryptographically-protected claims about the issuer, subject, and other metadata to your signatures.

For complete documentation on SCITT features, including:
- CWT Claims (issuer, subject, audience, expiration, custom claims)
- DID:x509 automatic generation from certificate chains
- CLI usage with `--cwt-*` arguments
- Programmatic API with `CWTClaimsHeaderExtender`
- DateTimeOffset support for timestamps
- Self-signed certificate support

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
COSE signing normally uses either a "detached" signature, where the signature is in a separate file from the payload, or an "embedded" signature, where an encrypted copy of the payload is inserted into the signature file. This can be cumbersome for large payloads, especially when they must be sent to a remote server for signing or validation.
Indirect signing is a feature that allows you to create and validate a signature against a hash of the payload instead of the payload itself. This feature is available through the [CoseIndirectSignature](.\CoseIndirectSignature.md) library and the **indirect-sign** plugin command in CoseSignTool. Indirect signatures also support full SCITT compliance with CWT Claims.

See [IndirectSignaturePlugin.md](./IndirectSignaturePlugin.md) for CLI usage.

#### Timestamping
The [COSE specification](https://www.iana.org/assignments/cose/cose.xhtml) is still evolving. Originally, there were plans to support an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp solution, but the [requisite headers were never defined](https://www.ietf.org/archive/id/draft-ietf-cose-tsa-tst-header-parameter-00.html) by the standards body.
The current default behavior of COSE validation is to fail if any of the certificates in the certificate chain have expired. However, there are user scenarios where a signature needs to be considered valid even after one or more certificates have expired. Staring in version 1.2.4-pre2, you have the option to allow signatures to pass with expired certificates in the chain by passing "AllowOutdated = true" to the ChainTrustValidator constructor.
This will allow signatures to pass validation with expired certificates, so long as none of the expired certificates have a lifetime EKU.

**Note**: SCITT compliance provides standardized timestamp claims (expiration, not-before, issued-at) via CWT Claims, which can be used for time-based validation. See [SCITTCompliance.md](./SCITTCompliance.md) for details on timestamp claims.
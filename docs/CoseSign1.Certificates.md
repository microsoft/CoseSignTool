# [CoseSign1.Certificates](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1.Certificates)
**CoseSign1.Certificates** is a .NET Standard 2.0 library containing implementations and validators related to X509Certificate2 objects as signing key providers.
Most of the common logic for CoseSign1Message object creation and handling with certificates is handled in [CertificateCoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/CertificateCoseSigningKeyProvider.cs) abstract base class. A default concrete implementation can be found in [Local/X509Certificate2CoseSigningKeyProvider ](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Local/X509Certificate2CoseSigningKeyProvider.cs) which provides the interface on top of an already existing X509Certificate2 object.
## Dependencies
**CoseSign1.Certificates** has the following package dependencies
* CoseSign1
* System.Runtime.Caching >= 7.0.0
## Creation
The following classes are provide for creating a proper CoseSign1Message object which is signed by an X509Certificate2 object.
### [CertificateCoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/CertificateCoseSigningKeyProvider.cs)
This class contains all the common logic of any certificate which is used as a signing key provider for CoseSign1Message signing. It will ensure that the x5t, x5chain protected headers are populated prior to signing as well as provide the interface to either the ECDsa or the ECC key set.

#### Virtual Issuer Property

The base class provides a `public virtual string? Issuer` property that:
- **Defaults to DID:x509**: Automatically generates a DID:x509 identifier from the certificate chain using `DidX509Utilities`
- **Can be overridden**: Derived classes can override this property to provide custom issuer values (e.g., from certificate fields, configuration, or external sources)
- **Used by CWT Claims**: The `X509CertificateWithCWTClaimsHeaderExtender` and related extension methods use this property as the default issuer claim
- **Returns null on error**: If certificate chain cannot be accessed or DID:x509 generation fails, returns `null`

```csharp
// Base class provides DID:x509 by default
var provider = new X509Certificate2CoseSigningKeyProvider(cert);
string? issuer = provider.Issuer;  // "did:x509:0:sha256:..."

// Derived classes can override for custom behavior
public class CustomCertificateProvider : CertificateCoseSigningKeyProvider
{
    public override string? Issuer => "custom-issuer-from-config";
    // ... other implementations
}
```

Any derived class must implement all methods as described in each protected method.
### [Local/X509Certificate2CoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Local/X509Certificate2CoseSigningKeyProvider.cs)
This class is a concrete implementation of **CertificateCoseSigningKeyProvider** which operates on an existing X509Certificate2 object.  It leverages a instance of a [ICertificateChainBuilder](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Interfaces/ICertificateChainBuilder.cs) (specifically [X509ChainBuilder](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Local/X509ChainBuilder.cs) by default) to build the certificate chain for the certificate.
## Extraction
The following classes are provide for extracting certificate information from a CoseSign1Message object which has been thought to be signed by an certificate.
### [CoseSign1MessageExtensions](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Extensions/CoseSign1MessageExtensions.cs)
This C# extension class extends CoseSign1Message objects to provide the following functionality:
* `CoseSign1Message.TryGetSigningCertificate` - TryGet pattern for the presence of a signing certificate in the x5t header value.
* `CoseSign1Message.TryGetCertificateChain` - TryGet pattern for the certificate chain embedded in the x5chain header value.

## SCITT Compliance and CWT Claims

**CoseSign1.Certificates** provides comprehensive support for **SCITT (Supply Chain Integrity, Transparency, and Trust)** compliance through CWT Claims and DID:x509 identifiers.

### [X509CertificateWithCWTClaimsHeaderExtender](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/X509CertificateWithCWTClaimsHeaderExtender.cs)

This class combines X.509 certificate headers with CWT Claims for SCITT-compliant signatures. It is **strongly-typed** to accept `CertificateCoseSigningKeyProvider` (and its derived classes), ensuring compile-time type safety. It chains together certificate-specific headers (X5T, X5Chain) with CWT Claims to automatically add both certificate information and claims to your signatures.

#### Features:
- **Automatic DID:x509 Generation**: Issuer claim is automatically derived from the certificate provider's `Issuer` property (defaults to DID:x509 from certificate chain)
- **Extensible Issuer**: Derived certificate providers can override the `Issuer` property to provide custom issuer values
- **Default Subject**: Subject defaults to `"unknown.intent"` if not specified
- **Fluent API**: Access and modify CWT claims through the `ActiveCWTClaimsExtender` property
- **Compile-time Safety**: Requires `CertificateCoseSigningKeyProvider` type, catching type mismatches at compile time
- **Optional SCITT Compliance**: The underlying `CertificateCoseSigningKeyProvider` has an `EnableScittCompliance` property (default: `true`) that controls whether default CWT claims are automatically added

#### Basic Usage:

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;

// Create signing key provider
var cert = new X509Certificate2("mycert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);
// SCITT compliance is enabled by default (enableScittCompliance: true)

// Or explicitly disable SCITT compliance if not needed
// var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(
//     signingCertificate: cert,
//     enableScittCompliance: false
// );

// Create SCITT-compliant header extender with defaults
var headerExtender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider);
// Issuer: DID:x509 from certificate chain (when EnableScittCompliance is true)
// Subject: "unknown.intent" (when EnableScittCompliance is true)

// Use with CoseSign1MessageBuilder
var builder = new CoseSign1MessageBuilder()
    .SetPayloadBytes(payloadBytes)
    .UseHeaderExtender(headerExtender);

byte[] signature = builder.Sign(signingKeyProvider);
```

#### Custom CWT Claims:

```csharp
using CoseSign1.Headers;

// Create custom CWT claims
var cwtClaims = new CWTClaimsHeaderExtender()
    .SetSubject("software.release.v1.2.3")
    .SetAudience("production-environment")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddMonths(6));

// Create combined extender with custom claims
var headerExtender = new X509CertificateWithCWTClaimsHeaderExtender(
    signingKeyProvider,
    cwtClaims
);
```

#### Modifying Active Claims:

```csharp
// Create with defaults then modify
var headerExtender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider);

// Access and modify the active CWT claims
headerExtender.ActiveCWTClaimsExtender
    .SetSubject("custom-subject")
    .SetCustomClaim(100, "custom-value");
```

### [CoseSigningKeyProviderExtensions](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Extensions/CoseSigningKeyProviderExtensions.cs)

Extension methods for `CertificateCoseSigningKeyProvider` that provide easy SCITT compliance with certificate-based signing. These methods are **strongly-typed** to `CertificateCoseSigningKeyProvider` (and its derived classes) to ensure compile-time type safety.

#### CreateHeaderExtenderWithCWTClaims:

```csharp
using CoseSign1.Certificates.Extensions;

// Quick method to create SCITT-compliant header extender
var headerExtender = signingKeyProvider.CreateHeaderExtenderWithCWTClaims(
    issuer: null,     // Uses DID:x509 from certificate
    subject: null,    // Uses "unknown.intent"
    audience: null
);

// With custom values
var customExtender = signingKeyProvider.CreateHeaderExtenderWithCWTClaims(
    issuer: "did:example:custom",
    subject: "software.build.v1.0",
    audience: "production"
);
```

### [DidX509Generator](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Extensions/DidX509Generator.cs)

Utility class for generating **DID:x509 identifiers** from X.509 certificates following the [Microsoft DID:x509 specification](https://github.com/microsoft/did-x509/blob/main/specification.md).

#### Features:
- **Standards-Compliant**: Follows Microsoft DID:x509 specification exactly
- **Base64url Encoding**: Certificate hashes use base64url format (RFC 4648 Section 5)
- **Subject Policy Format**: Uses key:value pairs separated by colons
- **Proper Percent-Encoding**: Only ALPHA, DIGIT, '-', '.', '_' allowed unencoded (tilde NOT allowed)
- **Multiple Hash Algorithms**: Supports SHA-256, SHA-384, and SHA-512
- **Extensible**: Can be inherited to implement custom DID generation behaviors (e.g., Azure Trusted Signing's EKU-based format)

#### DID:x509 Format:
```
did:x509:0:{algorithm}:{base64url-hash}::subject:{key}:{value}:{key}:{value}...
```

Where:
- `{base64url-hash}` is the base64url-encoded certificate fingerprint (43 chars for SHA256)
- `{key}:{value}` pairs represent subject DN fields (e.g., `C:US:O:GitHub:CN:User`)
- Keys are standard labels (CN, L, ST, O, OU, C, STREET) or OIDs in dotted notation
- Values are percent-encoded per spec

Example:
```
did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:O:GitHub:CN:User
```

> **Note**: Azure Trusted Signing uses an enhanced format that includes EKU information for non-standard certificates. See [AzureTrustedSigningDidX509Generator](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates.AzureTrustedSigning/AzureTrustedSigningDidX509Generator.cs) and [CoseSign1.Certificates.AzureTrustedSigning.md](CoseSign1.Certificates.AzureTrustedSigning.md#scitt-compliance-and-didx5090-support) for details.

#### Usage:

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography;

// Create generator instance
var generator = new DidX509Generator();

// From certificate chain
List<X509Certificate2> chain = GetCertificateChain();
string did = generator.GenerateFromChain(chain);

// From individual certificates (leaf and root)
var leafCert = chain[^1];  // Last certificate in chain
var rootCert = chain[0];   // First certificate in chain
string did = generator.Generate(leafCert, rootCert);

// Self-signed certificate (use same cert for both leaf and root)
// NOTE: Self-signed certificates are for testing/development only.
// Production SCITT ledgers require certificates from trusted CAs.
var selfSignedCert = new X509Certificate2("self-signed.pfx", "password");
string selfSignedDid = generator.Generate(selfSignedCert, selfSignedCert);

// Validate DID:X509 format
bool isValid = DidX509Generator.IsValidDidX509(did);
```

// Using different hash algorithms
string sha384Did = DidX509Utilities.GenerateDidX509IdentifierFromChain(
```

#### Methods:

- **Generate(X509Certificate2 leafCertificate, X509Certificate2 rootCertificate)**
  - Generates DID from specific leaf and root certificates
  - Returns DID:x509 identifier with base64url hash and key:value subject format
  - For self-signed certificates (testing only): use same certificate for both parameters
  - Example output: `did:x509:0:sha256:WE4P5dd...::subject:C:US:O:GitHub:CN:User`

- **GenerateFromChain(IEnumerable<X509Certificate2> certificates)**
  - Generates DID from a certificate chain (leaf first order)
  - Supports single-certificate chains (self-signed, for testing only)
  - Returns DID:x509 identifier with proper encoding

- **IsValidDidX509(string did)** (static)
  - Validates DID:x509 identifier format per specification
  - Checks base64url hash encoding (43 chars for SHA256)
  - Validates subject policy format (key:value pairs)
  - Returns true if valid, false otherwise

### Complete SCITT Example:

```csharp
using CoseSign1;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Headers;
using System.Security.Cryptography;

// Load certificate and create signing key provider
var cert = new X509Certificate2("mycert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);

// Generate DID:x509 identifier
string did = DidX509Utilities.GenerateDidX509Identifier(
    cert,
    cert,  // Or use root cert from chain
    HashAlgorithmName.SHA256
);

// Create custom CWT claims with all standard claims
var cwtClaims = new CWTClaimsHeaderExtender()
    .SetIssuer(did)  // Use generated DID
    .SetSubject("software.release.v1.2.3")
    .SetAudience("production-environment")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1))
    .SetNotBefore(DateTimeOffset.UtcNow)
    .SetIssuedAt(DateTimeOffset.UtcNow)
    .SetCustomClaim(100, "build-metadata");

// Create combined header extender
var headerExtender = new X509CertificateWithCWTClaimsHeaderExtender(
    signingKeyProvider,
    cwtClaims
);

// Build and sign
byte[] payload = File.ReadAllBytes("payload.txt");
var builder = new CoseSign1MessageBuilder()
    .SetPayloadBytes(payload)
    .UseHeaderExtender(headerExtender);

byte[] signature = builder.Sign(signingKeyProvider);
File.WriteAllBytes("signature.cose", signature);
```

For comprehensive SCITT documentation, CLI usage, and additional examples, see **[SCITTCompliance.md](./SCITTCompliance.md)**.

# DIDx509

Build, parse, validate, and resolve DID:x509 identifiers for X.509 certificate chains.

## Overview

This package implements the DID:x509 method in its **fingerprint + policies** form.
You can:

- Build a DID from a leaf certificate and a pinned CA certificate
- Parse an existing DID into a structured representation
- Validate a DID against a supplied certificate chain
- Resolve a DID into a W3C DID Document

## Installation

```bash
dotnet add package DIDx509 --version 2.0.0-preview
```

## Key Features

- ✅ **DID:x509 Parsing** - Parse DID:x509 URIs to certificate chains
- ✅ **DID Creation** - Create DIDs from X.509 certificates
- ✅ **DID Resolution** - Resolve DIDs to certificates with validation
- ✅ **Chain Validation** - Full X.509 chain validation
- ✅ **DID Documents** - Generate DID documents from certificates

## Quick Start

### Create DID from Certificate

```csharp
using DIDx509;
using DIDx509.Builder;
using System.Security.Cryptography.X509Certificates;

using var leaf = new X509Certificate2("leaf.pfx", "password");
using var root = new X509Certificate2("root.cer");

string did = new DidX509Builder()
    .WithLeafCertificate(leaf)
    .WithCaCertificate(root)
    .WithSubjectFromCertificate()
    .WithHashAlgorithm(DidX509Constants.HashAlgorithmSha256)
    .Build();

Console.WriteLine(did);
// Example: did:x509:0:sha256:<base64url>::subject:CN:...::...
```

### Parse DID URI

```csharp
using DIDx509.Parsing;

string did = "did:x509:0:sha256:...::eku:1.3.6.1.4.1.311.10.3.13";
var parsed = DidX509Parser.Parse(did);

Console.WriteLine(parsed.Version);
Console.WriteLine(parsed.HashAlgorithm);
Console.WriteLine(parsed.CaFingerprint);
```

### Validate DID

```csharp
using DIDx509.Validation;

var result = DidX509Validator.Validate(did, certificates, validateChain: true, checkRevocation: false);
if (!result.IsValid)
{
    foreach (var error in result.Errors)
    {
        Console.WriteLine(error);
    }
}
```

## DID:x509 Format

This implementation uses the fingerprint + policies format:

```
did:x509:0:<hashAlgorithm>:<caFingerprint>::<policyName>:<policyValue>::...
```

- `0` is the supported version.
- `hashAlgorithm` is one of `sha256`, `sha384`, `sha512`.
- `caFingerprint` is the base64url-encoded hash of the pinned CA certificate.
- Policies are appended using `::` separators.

## Creating DIDs

### Using Extension Methods

```csharp
using DIDx509;

// Full control
string did1 = leaf.GetDidBuilder()
    .WithCaCertificate(root)
    .WithSubjectFromCertificate()
    .Build();

// Convenience: pin to the chain root (leaf-first chain)
string did2 = leaf.GetDidWithRoot(chain, hashAlgorithm: DidX509Constants.HashAlgorithmSha256);
```

## DID Resolution (DID Document)

Resolution validates the DID against the chain and produces a DID document.

```csharp
using DIDx509.Resolution;

var document = DidX509Resolver.Resolve(did, certificates, validateChain: true, checkRevocation: false);
Console.WriteLine(document.Id);
```

## Validation Result Shape

`DidX509Validator.Validate(...)` returns a `DidX509ValidationResult`:

- `IsValid` - overall success/failure
- `Errors` - list of error strings (empty on success)
- `ParsedDid` - structured DID (on success)
- `ChainModel` - chain model (on success)

## See Also

- [docs/components/didx509.md](../docs/components/didx509.md)
- [docs/guides/scitt-compliance.md](../docs/guides/scitt-compliance.md)
- ✅ Verifiable credentials with X.509
- ✅ DID-based authentication
- ✅ Certificate portability

## Related Packages

- **CoseSign1.Certificates** - X.509 certificate support
- **CoseSign1.Validation** - Validation framework
- **CoseSign1** - Message creation

## Documentation

- 📖 [Full Package Documentation](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/packages/didx509.md)
- 📖 [DID Core Specification](https://www.w3.org/TR/did-core/)
- 📖 [DID:x509 Method Spec](https://github.com/microsoft/did-x509)

## Support

- 🐛 [Report Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 Email: cosesigntool@microsoft.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

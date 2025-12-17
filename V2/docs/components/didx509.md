# DIDx509

**NuGet**: `DIDx509`  
**Purpose**: Build, parse, validate, and resolve DID:x509 identifiers for X.509 certificate chains.

## DID:x509 Format (V2)

V2 uses the fingerprint + policies format:

```
did:x509:0:<hashAlgorithm>:<caFingerprint>::<policyName>:<policyValue>::...
```

- `0` is the supported version.
- `hashAlgorithm` is one of `sha256`, `sha384`, `sha512`.
- `caFingerprint` is base64url-encoded hash of the pinned CA certificate.
- Policies are appended using `::` separators.

Example (EKU policy):

```
did:x509:0:sha256:<base64url>::eku:1.3.6.1.4.1.311.10.3.13
```

## Parsing

```csharp
using DIDx509.Parsing;

string did = "did:x509:0:sha256:...::eku:1.3.6.1.4.1.311.10.3.13";
var parsed = DidX509Parser.Parse(did);

Console.WriteLine(parsed.Version);
Console.WriteLine(parsed.HashAlgorithm);
Console.WriteLine(parsed.CaFingerprint);
```

## Building

```csharp
using DIDx509;
using DIDx509.Builder;
using System.Security.Cryptography.X509Certificates;

using var leaf = new X509Certificate2("leaf.pfx", "password");
using var root = new X509Certificate2("root.cer");

string did = new DidX509Builder()
    .WithLeafCertificate(leaf)
    .WithCaCertificate(root)
    .WithHashAlgorithm(DidX509Constants.HashAlgorithmSha256)
    .WithSubjectFromCertificate()
    .WithEkuPolicy("1.3.6.1.4.1.311.10.3.13")
    .Build();
```

Convenience extension methods exist on `X509Certificate2`:

```csharp
using DIDx509;

string did = leaf.ToDid(policy: "0");
string did2 = leaf.GetDidWithRoot(chain, hashAlgorithm: DidX509Constants.HashAlgorithmSha256);
```

## Validation

```csharp
using DIDx509.Validation;

var result = DidX509Validator.Validate(did, chain, validateChain: true, checkRevocation: false);
if (!result.IsValid)
{
    foreach (var error in result.Errors)
    {
        Console.WriteLine(error);
    }
}
```

## Resolution (DID Document)

Resolution creates a DID document after validating the DID against the chain.

```csharp
using DIDx509.Resolution;

var document = DidX509Resolver.Resolve(did, chain, validateChain: true, checkRevocation: false);
Console.WriteLine(document.Id);
```

## See Also

- [SCITT Compliance Guide](../guides/scitt-compliance.md)

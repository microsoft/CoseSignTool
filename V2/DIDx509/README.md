# DIDx509 Library

Complete and comprehensive implementation of the [DID:X509 specification](https://github.com/microsoft/did-x509/blob/main/specification.md) for .NET.

## Overview

This library provides full support for creating, parsing, validating, and resolving DID:X509 identifiers from X.509 certificate chains. It implements all policy types, hash algorithms, and validation rules defined in the specification.

## Features

- ✅ **Complete DID:X509 Parsing** - Parse any valid DID:X509 identifier with full validation
- ✅ **All Policy Types** - Support for `subject`, `san`, `eku`, and `fulcio-issuer` policies
- ✅ **All Hash Algorithms** - SHA-256, SHA-384, and SHA-512
- ✅ **Certificate Chain Validation** - RFC 5280 chain validation with customizable options
- ✅ **DID Resolution** - Generate W3C DID Documents with verification methods
- ✅ **Memory-Efficient** - All string constants in static readonly fields to minimize allocations
- ✅ **Easy-to-Use Extensions** - Simple certificate extension methods for common scenarios
- ✅ **Fully Documented** - Comprehensive XML documentation and examples

## Quick Start

### Simple DID Verification (New! 🎉)

```csharp
using DIDx509;

// Simplest verification - just check if certificate matches DID
if (leafCert.VerifyByDid(did, certificateChain))
{
    Console.WriteLine("Certificate matches DID!");
}

// Get detailed validation results with errors
var result = leafCert.VerifyByDidDetailed(did, certificateChain);
if (result.IsValid)
{
    Console.WriteLine($"Valid! DID version: {result.ParsedDid.Version}");
}
else
{
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"Error: {error}");
    }
}

// Try pattern with error output
if (leafCert.TryVerifyByDid(did, certificateChain, out var errors))
{
    Console.WriteLine("Success!");
}
else
{
    Console.WriteLine($"Failed: {string.Join(", ", errors)}");
}

// Verify and resolve DID Document in one call
if (leafCert.VerifyByDidAndResolve(did, certificateChain, out var document))
{
    Console.WriteLine($"Valid! Verification methods: {document.VerificationMethods.Count}");
}

// Fast policy-only verification (no chain validation)
if (leafCert.VerifyByDidPoliciesOnly(did, certificateChain))
{
    Console.WriteLine("Policies match!");
}
```

### Simple DID Generation

```csharp
using DIDx509;

// Get a DID using the root certificate (SHA-256 by default)
string did = leafCert.GetDidWithRoot(certificateChain);

// Get a DID using the Policy CA (immediate parent)
string did = leafCert.GetDidWithPca(certificateChain);

// Get a DID with SHA-512
string did = leafCert.GetDidWithRoot(certificateChain, "sha512");
```

### DID with EKU Policy

```csharp
// Get a DID with the first EKU
string did = leafCert.GetDidWithRootAndEku(certificateChain);

// Get a DID with the longest EKU OID
string did = leafCert.GetDidWithRootAndEku(
    certificateChain, 
    EkuPreference.Longest);

// Get a DID with enterprise-specific EKU (1.3.6.1.4.1.*)
string did = leafCert.GetDidWithRootAndEku(
    certificateChain,
    EkuPreference.MostSpecific,
    ekuPrefixFilter: "1.3.6.1.4.1");
```

### DID with SAN Policy

```csharp
// Get a DID with the first available SAN
string? did = leafCert.GetDidWithRootAndSan(certificateChain);

// Get a DID with a specific SAN type
string? did = leafCert.GetDidWithRootAndSan(
    certificateChain, 
    sanType: "email");
```

### Advanced Chain Location Indexing

```csharp
// Use root certificate (last in chain) - negative indexing
string did = leafCert.GetDidWithCertAtLocationInChain(chain, -1);

// Use Policy CA (immediate parent)
string did = leafCert.GetDidWithCertAtLocationInChain(chain, 1);

// Use specific intermediate (0-based indexing)
string did = leafCert.GetDidWithCertAtLocationInChain(chain, 2);

// Use second from end (negative indexing)
string did = leafCert.GetDidWithCertAtLocationInChain(chain, -2);
```

### Full Customization with Builder

```csharp
using DIDx509.Builder;

string did = new DidX509Builder()
    .WithLeafCertificate(leafCert)
    .WithCaCertificate(rootCert)
    .WithHashAlgorithm("sha512")
    .WithSubjectPolicy(new Dictionary<string, string>
    {
        ["C"] = "US",
        ["O"] = "My Organization",
        ["CN"] = "My Service"
    })
    .WithEkuPolicy("1.3.6.1.4.1.311.10.3.13")
    .WithSanPolicy("email", "service@example.com")
    .Build();

// Or use certificate's subject automatically
string did = leafCert.GetDidBuilder()
    .WithCertificateChain(chain)
    .WithHashAlgorithm("sha384")
    .WithSubjectFromCertificate()
    .WithEkuPolicy("1.3.6.1.5.5.7.3.3")
    .Build();
```

## DID Parsing and Validation

### Parse a DID

```csharp
using DIDx509.Parsing;
using DIDx509.Models;

// Parse a DID string
DidX509ParsedIdentifier parsed = DidX509Parser.Parse(did);

Console.WriteLine($"Version: {parsed.Version}");
Console.WriteLine($"Hash Algorithm: {parsed.HashAlgorithm}");
Console.WriteLine($"CA Fingerprint: {parsed.CaFingerprint}");

foreach (var policy in parsed.Policies)
{
    Console.WriteLine($"Policy: {policy.Name} = {policy.RawValue}");
}

// Safe parsing
if (DidX509Parser.TryParse(did, out var parsed))
{
    // Use parsed
}
```

### Validate a DID Against a Certificate Chain

```csharp
using DIDx509.Validation;

// Full validation (includes RFC 5280 chain validation)
var result = DidX509Validator.Validate(did, certificateChain);

if (result.IsValid)
{
    Console.WriteLine("DID is valid!");
    // Access parsed DID and chain model
    var parsedDid = result.ParsedDid;
    var chainModel = result.ChainModel;
}
else
{
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"Error: {error}");
    }
}

// Validate without RFC 5280 chain validation
var result = DidX509Validator.ValidatePoliciesOnly(did, certificateChain);

// Validate with revocation checking
var result = DidX509Validator.Validate(
    did, 
    certificateChain,
    validateChain: true,
    checkRevocation: true);
```

## DID Resolution

### Resolve to DID Document

```csharp
using DIDx509.Resolution;

// Resolve DID to W3C DID Document
DidDocument document = DidX509Resolver.Resolve(did, certificateChain);

Console.WriteLine($"DID: {document.Id}");
Console.WriteLine($"Verification Methods: {document.VerificationMethods.Count}");

// Get as JSON
string json = document.ToJson(indented: true);

// Safe resolution
if (DidX509Resolver.TryResolve(did, certificateChain, out var doc))
{
    // Use doc
}
```

The DID Document includes:
- **Verification Methods** - Public key in JWK format (RSA, EC)
- **Assertion Method** - If certificate has `digitalSignature` key usage
- **Key Agreement** - If certificate has `keyAgreement` key usage

## Certificate Chain Conversion

Convert X.509 certificate chains to the DID:X509 JSON data model:

```csharp
using DIDx509.CertificateChain;
using DIDx509.Models;

CertificateChainModel chainModel = CertificateChainConverter.Convert(certificates);

// Access leaf certificate
var leafInfo = chainModel.LeafCertificate;
Console.WriteLine($"Subject: {leafInfo.Subject.CN}");
Console.WriteLine($"SHA-256 Fingerprint: {leafInfo.Fingerprints.Sha256}");

// Check extensions
if (leafInfo.Extensions.Eku != null)
{
    foreach (var oid in leafInfo.Extensions.Eku)
    {
        Console.WriteLine($"EKU: {oid}");
    }
}

// Access CA certificates
foreach (var ca in chainModel.CaCertificates)
{
    Console.WriteLine($"CA: {ca.Subject.O}");
}
```

## EKU Preference Options

When a certificate has multiple EKUs, you can control which one to use:

- **`EkuPreference.First`** - Use the first EKU OID (default)
- **`EkuPreference.Longest`** - Use the EKU with the longest string representation
- **`EkuPreference.MostSpecific`** - Use the EKU with the most segments (e.g., `1.2.3.4.5` has 5 segments)
- **`EkuPreference.LongestMostSpecific`** - Combine both criteria (most segments, then longest)

Example:
```csharp
// Prefer the most specific EKU from Microsoft-specific OIDs
string did = leafCert.GetDidWithRootAndEku(
    chain,
    EkuPreference.MostSpecific,
    ekuPrefixFilter: "1.3.6.1.4.1.311");
```

## String Constants for Performance

All string literals are stored in static readonly fields in `DidX509Constants` to minimize memory allocations:

```csharp
using DIDx509;

// All constants available
string prefix = DidX509Constants.DidPrefix;              // "did:x509"
string sha256 = DidX509Constants.HashAlgorithmSha256;    // "sha256"
string policySubject = DidX509Constants.PolicySubject;   // "subject"
char separator = DidX509Constants.ColonChar;             // ':'

// Known X.509 attribute labels
var knownLabels = DidX509Constants.KnownLabels;  // HashSet<string>
```

## Supported .NET Versions

- **.NET 10.0** - Full support with latest APIs
- **.NET Standard 2.0** - Compatible with .NET Framework 4.7.2+, .NET Core 2.0+, etc.

## Architecture

The library is organized into logical namespaces:

- **`DIDx509`** - Core constants and simple generator
- **`DIDx509.Models`** - Data models for parsed DIDs, certificates, and validation results
- **`DIDx509.Parsing`** - DID parsing and percent-encoding utilities
- **`DIDx509.Validation`** - Policy validators and complete DID validation
- **`DIDx509.CertificateChain`** - Certificate chain conversion to JSON data model
- **`DIDx509.Resolution`** - DID resolution to W3C DID Documents
- **`DIDx509.Builder`** - Fluent builder for custom DID creation
- **`DIDx509.Extensions`** - Extension methods for X509Certificate2

## Examples

### Example 1: Simple Corporate Certificate

```csharp
// Corporate certificate with standard subject
string did = leafCert.GetDidWithRoot(chain);
// Output: did:x509:0:sha256:WE4P5dd8...::subject:C:US:O:Contoso:CN:api.contoso.com
```

### Example 2: Code Signing with EKU

```csharp
// Code signing certificate with specific EKU
string did = leafCert.GetDidWithRootAndEku(
    chain,
    EkuPreference.MostSpecific);
// Output: did:x509:0:sha256:WE4P5dd8...::subject:C:US:O:Contoso:CN:MyApp::eku:1.3.6.1.5.5.7.3.3
```

### Example 3: Sigstore Fulcio Certificate

```csharp
// Sigstore certificate with Fulcio issuer and SAN
string did = new DidX509Builder()
    .WithCertificateChain(chain)
    .WithSubjectFromCertificate()
    .WithFulcioIssuerPolicy("token.actions.githubusercontent.com")
    .WithSanPolicy("uri", "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main")
    .Build();
// Output: did:x509:0:sha256:WE4P5dd8...::subject:CN:...::fulcio-issuer:token.actions.githubusercontent.com::san:uri:https%3A%2F%2F...
```

### Example 4: Multi-Policy DID

```csharp
// Combine subject, EKU, and SAN policies
string did = new DidX509Builder()
    .WithLeafCertificate(leafCert)
    .WithCaCertificate(rootCert)
    .WithHashAlgorithm("sha512")
    .WithSubjectFromCertificate()
    .WithEkuPolicy("1.3.6.1.4.1.311.10.3.13")
    .WithSanPolicy("email", "service@example.com")
    .Build();
```

## Specification Compliance

This implementation fully complies with the [DID:X509 specification](https://github.com/microsoft/did-x509/blob/main/specification.md):

- ✅ All ABNF syntax rules
- ✅ All policy types (subject, san, eku, fulcio-issuer)
- ✅ All hash algorithms (SHA-256, SHA-384, SHA-512)
- ✅ RFC 3986 percent-encoding
- ✅ RFC 4514 Distinguished Name parsing
- ✅ RFC 5280 certificate chain validation
- ✅ RFC 4648 base64url encoding
- ✅ W3C DID Core 1.0 DID Documents
- ✅ Sigstore Fulcio extension support

## Performance Considerations

- **String Constants**: All string keys are static readonly to avoid repeated allocations
- **Efficient Parsing**: Single-pass parsing with minimal allocations
- **Lazy Evaluation**: Chain validation only performed when requested
- **Span Support**: Uses `Span<T>` where available (NET10.0+)

## License

Copyright (c) Microsoft Corporation. Licensed under the MIT License.

# SCITT Compliance Guide

This guide explains how CoseSignTool V2 supports SCITT (Supply Chain Integrity, Transparency, and Trust) compliance.

## Overview

SCITT is an IETF standard for supply chain security that defines how to create, register, and verify signed statements about software artifacts. CoseSignTool V2 provides SCITT-compatible signing and verification.

## What is SCITT?

SCITT defines:

- **Signed Statements** - COSE-signed claims about artifacts
- **Transparency Services** - Append-only logs for signed statements
- **Receipts** - Cryptographic proof of inclusion in logs
- **Verification** - Standard way to verify statements and receipts

## SCITT Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SCITT Architecture                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │   Issuer    │──▶│  Transparency   │───▶│  Verifier  │  │
│  │  (Signer)   │    │    Service      │    │             │  │
│  └─────────────┘    └─────────────────┘    └─────────────┘  │
│         │                   │                     │         │
│         ▼                   ▼                     ▼         │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │   Signed    │    │    Receipt      │    │  Verified   │  │
│  │  Statement  │    │                 │    │  Statement  │  │
│  └─────────────┘    └─────────────────┘    └─────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Creating SCITT-Compatible Signatures

### Required Headers

SCITT requires specific COSE headers:

```csharp
using CoseSign1.Factories;
using var factory = new CoseSign1MessageFactory(signingService);

// Content type for SCITT statements
var contentType = "application/vnd.scitt.claim+cbor";

// Create SCITT-compatible signature
var signature = factory.CreateDirectCoseSign1MessageBytes(payload, contentType);
```

### CWT Claims for SCITT

SCITT uses CWT (CBOR Web Token) claims:

```csharp
using CoseSign1.Headers;

var cwtContributor = new CwtClaimsHeaderContributor()
    .SetIssuer("https://my-issuer.example.com")
    .SetSubject("artifact-digest-sha256:abc123...")
    .SetIssuedAt(DateTimeOffset.UtcNow)
    // Custom claim labels are integer keys.
    // Pick a label according to your SCITT profile (this is just an example).
    .SetCustomClaim(label: 1000, value: "software_artifact");
```

### Feed Header

SCITT uses a "feed" header to group related statements:

```csharp
public class ScittFeedHeaderContributor : IHeaderContributor
{
    private readonly string _feed;
    
    public ScittFeedHeaderContributor(string feed)
    {
        _feed = feed;
    }

    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // SCITT feed header (registered COSE header)
        headers.Add(new CoseHeaderLabel(392), _feed);
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
    }
}
```

## Registering with Transparency Services

### Submit to Transparency Service

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;

// Create signed statement
var statement = factory.CreateCoseSign1Message(payload, contentType);

// Add an MST receipt to the statement
var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
var mstProvider = new MstTransparencyProvider(client);
var statementWithReceipt = await mstProvider.AddTransparencyProofAsync(statement);
```

### Embed Receipt

Receipts can be embedded in the signature's unprotected headers:

```csharp
// Receipts are embedded by the transparency provider.
// (See AddTransparencyProofAsync above.)
```

## Verification

### Verify Signed Statement

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(statement);

var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: CoseHeaderLocation.Protected))
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();

var results = message.Validate(validator);
var signatureResult = results.Signature;
var trustResult = results.Trust;
```

### Verify Receipt

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;

var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
var provider = new MstTransparencyProvider(client);
var receiptResult = await provider.VerifyTransparencyProofAsync(message);

if (!receiptResult.IsValid)
{
    foreach (var error in receiptResult.Errors)
    {
        Console.WriteLine(error);
    }
}
```

### Full SCITT Verification

```csharp
// There isn't a single "SCITT validator" type.
// Compose the checks you need (cert chain, claims, receipts, etc.) using the validation builder.
```

## CLI Usage

### Create SCITT Statement

```bash
CoseSignTool sign-pfx artifact-manifest.json ^
    --pfx issuer.pfx ^
    --content-type "application/vnd.scitt.claim+cbor" ^
    --output statement.cose
```

### Verify with Transparency

```bash
CoseSignTool verify statement.cose ^
    --require-receipt ^
    --mst-endpoint https://dataplane.codetransparency.azure.net
```

## SCITT Content Types

| Content Type | Description |
|--------------|-------------|
| `application/vnd.scitt.claim+cbor` | CBOR-encoded SCITT claim |
| `application/vnd.scitt.claim+json` | JSON-encoded SCITT claim |
| `application/vnd.scitt.receipt+cbor` | SCITT receipt |

## SCITT Statement Structure

A SCITT statement contains:

```
COSE_Sign1 {
    protected: {
        alg: ES256,
        content_type: "application/vnd.scitt.claim+cbor",
        cwt_claims: {
            iss: "https://issuer.example.com",
            sub: "artifact-identifier",
            iat: 1699999999
        },
        feed: "my-product-feed"
    },
    unprotected: {
        receipt: <transparency receipt>
    },
    payload: <claim payload>
}
```

## SCITT Compliance Checklist

- [ ] Use SCITT-compatible content type
- [ ] Include required CWT claims (iss, sub, iat)
- [ ] Include feed header for statement grouping
- [ ] Use approved signature algorithms
- [ ] Register with SCITT-compatible transparency service
- [ ] Embed or provide transparency receipt
- [ ] Verify receipt before trusting statement

## Integration with Microsoft's Signing Transparency

MST is a SCITT-compatible transparency service:

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;

var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
var mstProvider = new MstTransparencyProvider(client);
var statementWithReceipt = await mstProvider.AddTransparencyProofAsync(statement);
```

## See Also

- [SCITT Architecture Specification](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)
- [Transparency Overview](../components/transparent.md)
- [MST Integration](../components/mst.md)
- [CWT Claims](custom-headers.md)

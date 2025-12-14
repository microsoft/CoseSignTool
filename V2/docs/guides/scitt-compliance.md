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
│                     SCITT Architecture                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │   Issuer    │───▶│  Transparency   │───▶│  Verifier   │  │
│  │  (Signer)   │    │    Service      │    │             │  │
│  └─────────────┘    └─────────────────┘    └─────────────┘  │
│         │                   │                     │          │
│         ▼                   ▼                     ▼          │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │   Signed    │    │    Receipt      │    │  Verified   │  │
│  │  Statement  │    │                 │    │  Statement  │  │
│  └─────────────┘    └─────────────────┘    └─────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Creating SCITT-Compatible Signatures

### Required Headers

SCITT requires specific COSE headers:

```csharp
var factory = new DirectSignatureFactory(signingService);

// Content type for SCITT statements
var contentType = "application/vnd.scitt.claim+cbor";

// Create SCITT-compatible signature
var signature = factory.CreateCoseSign1MessageBytes(payload, contentType);
```

### CWT Claims for SCITT

SCITT uses CWT (CBOR Web Token) claims:

```csharp
var cwtContributor = new CwtClaimsHeaderContributor(claims =>
{
    claims.Issuer = "https://my-issuer.example.com";
    claims.Subject = "artifact-digest-sha256:abc123...";
    claims.IssuedAt = DateTimeOffset.UtcNow;
    
    // SCITT-specific claims
    claims.SetClaim("scitt_statement_type", "software_artifact");
});
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
    
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContext context)
    {
        // SCITT feed header (registered COSE header)
        headers.Add(new CoseHeaderLabel(392), _feed);
    }
}
```

## Registering with Transparency Services

### Submit to Transparency Service

```csharp
using CoseSign1.Transparent;

// Create signed statement
var statement = factory.CreateCoseSign1MessageBytes(payload, contentType);

// Register with transparency service
var transparencyProvider = new TransparencyProvider(serviceOptions);
var receipt = await transparencyProvider.RegisterAsync(statement);
```

### Embed Receipt

Receipts can be embedded in the signature's unprotected headers:

```csharp
// Add receipt to unprotected headers
var messageWithReceipt = EmbedReceipt(statement, receipt);
```

## Verification

### Verify Signed Statement

```csharp
var validator = ValidationBuilder.Create()
    .AddSignatureValidator()
    .AddCertificateChainValidator()
    .AddScittComplianceValidator()
    .Build();

var result = await validator.ValidateAsync(statement);
```

### Verify Receipt

```csharp
var receiptValidator = new ReceiptValidator(transparencyServiceOptions);
var isValid = await receiptValidator.ValidateAsync(statement, receipt);
```

### Full SCITT Verification

```csharp
var scittValidator = new ScittValidator(options);
var result = await scittValidator.ValidateAsync(statement);

if (result.IsValid)
{
    Console.WriteLine($"Statement verified");
    Console.WriteLine($"Issuer: {result.Issuer}");
    Console.WriteLine($"Subject: {result.Subject}");
    Console.WriteLine($"Registered at: {result.ReceiptTimestamp}");
}
```

## CLI Usage

### Create SCITT Statement

```bash
CoseSignTool sign-pfx artifact-manifest.json ^
    --pfx-file issuer.pfx ^
    --content-type "application/vnd.scitt.claim+cbor" ^
    --output statement.cose
```

### Verify with Transparency

```bash
CoseSignTool verify statement.cose ^
    --transparency-service https://ts.example.com ^
    --verify-receipt
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
using CoseSign1.Transparent.MST;

var mstOptions = new MstOptions
{
    ServiceUri = new Uri("https://mst.microsoft.com")
};

var mstProvider = new MstTransparencyProvider(mstOptions);
var receipt = await mstProvider.RegisterAsync(statement);
```

## See Also

- [SCITT Architecture Specification](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)
- [Transparency Overview](../components/transparent.md)
- [MST Integration](../components/mst.md)
- [CWT Claims](custom-headers.md)

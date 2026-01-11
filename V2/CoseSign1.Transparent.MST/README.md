# CoseSign1.Transparent.MST

Microsoft's Signing Transparency (MST) receipts for COSE Sign1 messages.

## Overview

Implements Microsoft's Signing Transparency receipts for SCITT compliance, enabling verifiable inclusion proofs for COSE Sign1 messages in transparency logs.

## Installation

```bash
dotnet add package CoseSign1.Transparent.MST --version 2.0.0-preview
```

## Key Features

- ✅ **MST Receipt Generation** - Create transparency receipts
- ✅ **Receipt Verification** - Verify inclusion proofs
- ✅ **SCITT Compatible** - Standards-compliant transparency
- ✅ **Sparse Merkle Trees** - Efficient proof generation
- ✅ **Merkle Inclusion Proofs** - Cryptographic verification
- ✅ **Log Integration** - Integration with transparency services

## Quick Start

### Generate Receipt

```csharp
using CoseSign1.Transparent.MST;

// Create transparency service
var transparencyService = new MstTransparencyService(serviceUrl);

// Submit COSE message for transparency
var message = await CreateCoseSign1MessageAsync(payload);
var receipt = await transparencyService.SubmitAsync(message);

// Receipt contains inclusion proof
Console.WriteLine($"Log Entry ID: {receipt.EntryId}");
Console.WriteLine($"Log Index: {receipt.LogIndex}");
```

### Verify Receipt

```csharp
// Verify receipt authenticity
var isValid = await transparencyService.VerifyReceiptAsync(receipt);

if (isValid)
{
    Console.WriteLine("Receipt verified successfully");
}
else
{
    Console.WriteLine("Receipt verification failed");
}
```

### Add Receipt to Message

```csharp
// Attach receipt to COSE message
message.AddTransparencyReceipt(receipt);

// Encode message with receipt
byte[] encodedWithReceipt = message.Encode();
```

## Transparency Receipt Structure

```csharp
public class TransparencyReceipt
{
    public string EntryId { get; set; }
    public long LogIndex { get; set; }
    public byte[] InclusionProof { get; set; }
    public byte[] TreeHead { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string LogId { get; set; }
}
```

## MST Transparency Service

```csharp
public class MstTransparencyService : ITransparencyService
{
    public MstTransparencyService(string serviceUrl);
    public MstTransparencyService(string serviceUrl, HttpClient httpClient);
    
    public Task<TransparencyReceipt> SubmitAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
    
    public Task<bool> VerifyReceiptAsync(
        TransparencyReceipt receipt,
        CancellationToken cancellationToken = default);
    
    public Task<TransparencyReceipt> GetReceiptAsync(
        string entryId,
        CancellationToken cancellationToken = default);
}
```

## Advanced Usage

### Custom Transparency Configuration

```csharp
var config = new MstConfiguration
{
    ServiceUrl = "https://transparency.contoso.com",
    LogId = "contoso-production",
    TreeDepth = 256,
    HashAlgorithm = HashAlgorithmName.SHA256
};

var service = new MstTransparencyService(config);
```

### Batch Submission

```csharp
var messages = new List<CoseSign1Message>
{
    message1, message2, message3
};

var receipts = new List<TransparencyReceipt>();

foreach (var msg in messages)
{
    var receipt = await transparencyService.SubmitAsync(msg);
    receipts.Add(receipt);
}
```

### Receipt Extraction

```csharp
// Extract receipt from message
TransparencyReceipt? receipt = message.GetTransparencyReceipt();

if (receipt != null)
{
    Console.WriteLine($"Message has receipt: {receipt.EntryId}");
    var isValid = await transparencyService.VerifyReceiptAsync(receipt);
}
```

## SCITT Integration

```csharp
using CoseSign1.Headers;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;

public async Task<CoseSign1Message> CreateScittStatementAsync(
    byte[] payload,
    ISigningService signingService)
{
    // Create SCITT-compliant message
    var claims = new CwtClaims
    {
        Issuer = "https://contoso.com",
        Subject = "package:npm/my-package@1.0.0",
        IssuedAt = DateTimeOffset.UtcNow
    };
    
    var contributor = new CwtClaimsHeaderContributor(claims);

    using var factory = new CoseSign1MessageFactory(signingService);

    var options = new DirectSignatureOptions
    {
        EmbedPayload = true,
        AdditionalHeaderContributors = [contributor],
    };

    var message = await factory.DirectFactory.CreateCoseSign1MessageAsync(
        payload,
        contentType: "application/octet-stream",
        options);
    
    // Submit to transparency log
    var receipt = await _transparencyService.SubmitAsync(message);
    
    // Attach receipt
    message.AddTransparencyReceipt(receipt);
    
    return message;
}
```

## Verification Pipeline

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Certificates.Validation;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;
using CoseSign1.Validation.Trust;
using System.Security.Cryptography.Cose;

var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));

var validator = new CoseSign1ValidationBuilder()
    .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: CoseHeaderLocation.Any))
    .ValidateMst(mst => mst
        .RequireReceiptPresence()
        .VerifyReceipt(client))
    .OverrideDefaultTrustPolicy(MstTrustPolicies.RequireReceiptPresentAndTrusted())
    .Build();

var result = message.Validate(validator);

if (!result.Overall.IsValid)
{
    // Inspect staged results: result.Trust, result.Signature, etc.
}
```

## Inclusion Proof Verification

```csharp
public class InclusionProofVerifier
{
    public static bool VerifyInclusionProof(
        byte[] leafHash,
        byte[] proof,
        byte[] treeHead,
        long index)
    {
        var currentHash = leafHash;
        var currentIndex = index;
        
        // Walk up the tree
        for (int i = 0; i < proof.Length; i += 32)
        {
            var sibling = proof[i..(i + 32)];
            
            if (currentIndex % 2 == 0)
            {
                // Left child
                currentHash = SHA256.HashData(
                    currentHash.Concat(sibling).ToArray());
            }
            else
            {
                // Right child
                currentHash = SHA256.HashData(
                    sibling.Concat(currentHash).ToArray());
            }
            
            currentIndex /= 2;
        }
        
        return currentHash.SequenceEqual(treeHead);
    }
}
```

## ASP.NET Core Integration

Register MST components via DI:

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Transparent.MST;

services.AddSingleton(sp =>
    new CodeTransparencyClient(new Uri(configuration["Mst:Endpoint"]!)));

services.AddSingleton<ITransparencyProvider>(sp =>
    new MstTransparencyProvider(sp.GetRequiredService<CodeTransparencyClient>()));
```

## Extension Methods

```csharp
// Add receipt to message
message.AddTransparencyReceipt(receipt);

// Get receipt from message
TransparencyReceipt? receipt = message.GetTransparencyReceipt();

// Check if message has receipt
bool hasReceipt = message.HasTransparencyReceipt();

// Remove receipt from message
message.RemoveTransparencyReceipt();
```

## When to Use

- ✅ SCITT compliance and transparency
- ✅ Verifiable transparency logs
- ✅ Supply chain auditability
- ✅ Immutable record keeping
- ✅ Provenance tracking
- ✅ Compliance requirements

## Related Packages

- **CoseSign1.Factories** - Message creation
- **CoseSign1.Headers** - CWT claims for SCITT
- **CoseSign1.Validation** - Validation framework
- **CoseSign1.Certificates** - Certificate-based signing

## Documentation

- 📖 [Full Package Documentation](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/packages/transparency-mst.md)
- 📖 [SCITT Guide](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/scitt-compliance.md)
- 📖 [Transparency Guide](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/transparency.md)

## Support

- 🐛 [Report Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 Email: cosesigntool@microsoft.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

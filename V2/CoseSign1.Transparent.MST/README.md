# Microsoft Signing Transparency (MST) Provider for V2

This package provides a V2 transparency provider implementation for Microsoft's Signing Transparency (MST) service, enabling transparent COSE Sign1 messages with MST receipts.

## Overview

The `MstTransparencyProvider` implements the `ITransparencyProvider` interface, allowing seamless integration with the V2 factory pattern. Configure transparency providers once at the factory level, and all signed messages automatically include MST receipts.

## Features

- ✅ **Factory-Level Configuration**: Set up MST once when creating factories
- ✅ **Automatic Receipt Embedding**: Receipts added automatically after signing
- ✅ **Verification Support**: Built-in verification with configurable policies
- ✅ **Provider Chaining**: Combine MST with other transparency services
- ✅ **Logging Integration**: Optional callbacks for verbose and error logging

## Installation

```bash
dotnet add package CoseSign1.Transparent.MST
```

## Quick Start

### Basic Usage

```csharp
using Azure.Identity;
using Azure.Security.CodeTransparency;
using CoseSign1.Direct;
using CoseSign1.Transparent.MST;

// Create MST client
var credential = new DefaultAzureCredential();
var mstClient = new CodeTransparencyClient(
    new Uri("https://your-mst-instance.azure.net"),
    credential);

// Create MST transparency provider
var mstProvider = new MstTransparencyProvider(mstClient);

// Create factory with MST transparency
var factory = new DirectSignatureFactory(
    signingService,
    transparencyProviders: new[] { mstProvider });

// Sign and make transparent in one call!
var message = await factory.CreateCoseSign1MessageAsync(
    payload,
    "application/json");

// Message now has MST receipt embedded
```

### With Verification Options

```csharp
using Azure.Security.CodeTransparency;

// Configure verification behavior
var verificationOptions = new CodeTransparencyVerificationOptions
{
    AuthorizedDomains = new List<string> { "contoso.com", "fabrikam.com" },
    AuthorizedReceiptBehavior = ReceiptValidationBehavior.Require,
    UnauthorizedReceiptBehavior = ReceiptValidationBehavior.Allow
};

var mstProvider = new MstTransparencyProvider(
    mstClient,
    verificationOptions,
    clientOptions: null);

var factory = new DirectSignatureFactory(
    signingService,
    new[] { mstProvider });
```

### With Logging

```csharp
var mstProvider = new MstTransparencyProvider(
    mstClient,
    verificationOptions: null,
    clientOptions: null,
    logVerbose: msg => Console.WriteLine($"[VERBOSE] {msg}"),
    logError: msg => Console.Error.WriteLine($"[ERROR] {msg}"));
```

### Chaining Multiple Transparency Providers

```csharp
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.CTS; // Example of another provider

var providers = new ITransparencyProvider[]
{
    new MstTransparencyProvider(mstClient),
    new CtsTransparencyProvider(ctsClient) // Add multiple providers
};

var factory = new DirectSignatureFactory(
    signingService,
    transparencyProviders: providers);

// One call adds BOTH MST and CTS receipts!
var message = await factory.CreateCoseSign1MessageAsync(payload, contentType);
```

## Verification

### Verify MST Receipt

```csharp
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Transparent.MST.Extensions;

// Check if message has MST receipt
if (message.HasMstReceipt())
{
    Console.WriteLine("Message has MST receipt");
    
    // Verify the receipt
    var result = await message.VerifyTransparencyAsync(mstProvider);
    
    if (result.IsValid)
    {
        Console.WriteLine($"Valid MST proof from {result.ProviderName}");
    }
    else
    {
        foreach (var error in result.Errors)
        {
            Console.WriteLine($"Error: {error}");
        }
    }
}
```

### Extract MST Receipt

```csharp
using CoseSign1.Transparent.MST.Extensions;

if (message.HasMstReceipt())
{
    // Get parsed receipts as CoseSign1Message objects
    var receipts = message.GetMstReceipts();
    Console.WriteLine($"Found {receipts.Count} receipt(s)");
    
    foreach (var receipt in receipts)
    {
        // Inspect receipt headers and signature
        Console.WriteLine($"Receipt algorithm: {receipt.ProtectedHeaders[CoseHeaderLabel.Algorithm]}");
    }
    
    // Or get raw receipt bytes if needed
    var receiptBytes = message.GetMstReceiptBytes();
    Console.WriteLine($"First receipt size: {receiptBytes[0].Length} bytes");
}
```

## Extension Methods

The package provides convenient extension methods in `CoseSign1.Transparent.MST.Extensions`:

### For CoseSign1Message

- `HasMstReceipt()` - Checks if the message contains MST receipt(s)
- `GetMstReceipts()` - Returns a list of receipt COSE_Sign1 messages
- `GetMstReceiptBytes()` - Returns a list of raw receipt byte arrays

### For BinaryData

- `TryGetMstEntryId(out string entryId)` - Extracts entry ID from MST response

## Architecture

### How It Works

```
┌─────────────────────────────────────────────────────┐
│              MST Transparency Flow                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Factory signs payload → CoseSign1Message        │
│  2. MstTransparencyProvider.AddTransparencyProofAsync():
│     a. Encode message to bytes                     │
│     b. Submit to MST service (CreateEntryAsync)    │
│     c. Receive entry ID                            │
│     d. Retrieve transparent statement with receipt │
│     e. Return message with receipt embedded        │
│  3. Return final transparent message                │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Receipt Storage

MST receipts are stored in the unprotected headers of the COSE Sign1 message using header label 394 (as defined in RFC 8392). This allows receipts to be added after signing without invalidating the signature.

## Error Handling

The provider throws `InvalidOperationException` with detailed messages when:
- MST service submission fails
- Entry ID extraction fails
- Transparent statement retrieval fails

Configure error handling behavior using `SigningOptions.FailOnTransparencyError`:

```csharp
var options = new SigningOptions
{
    FailOnTransparencyError = false // Best-effort mode
};

// If MST fails, still get the signed message without receipt
var message = await factory.CreateCoseSign1MessageAsync(
    payload,
    contentType,
    options);
```

## Per-Operation Opt-Out

Disable transparency for specific operations:

```csharp
// Factory has MST configured
var factory = new DirectSignatureFactory(
    signingService,
    new[] { mstProvider });

// But this specific message won't have MST receipt
var options = new SigningOptions { DisableTransparency = true };
var message = await factory.CreateCoseSign1MessageAsync(
    payload,
    contentType,
    options);
```

## Testing

Mock the MST provider for unit tests:

```csharp
using Moq;
using CoseSign1.Abstractions.Transparency;

var mockProvider = new Mock<ITransparencyProvider>();
mockProvider.Setup(p => p.ProviderName).Returns("MockMST");
mockProvider
    .Setup(p => p.AddTransparencyProofAsync(It.IsAny<CoseSign1Message>(), default))
    .ReturnsAsync((CoseSign1Message msg, CancellationToken _) => msg);

var factory = new DirectSignatureFactory(
    signingService,
    new[] { mockProvider.Object });
```

## Performance Considerations

- MST submission involves network round-trips (~100-500ms typical)
- Chaining multiple providers multiplies latency
- Consider `FailOnTransparencyError = false` for non-critical scenarios
- Receipt sizes vary based on ledger state (~1-5KB typical)

## Migration from V1

### V1 Pattern
```csharp
// V1: Two-step process
var signedMessage = await factory.CreateAsync(payload, contentType);
var transparentMessage = await mstService.MakeTransparentAsync(signedMessage);
```

### V2 Pattern
```csharp
// V2: One-step process
var factory = new DirectSignatureFactory(
    signingService,
    new[] { new MstTransparencyProvider(mstClient) });

var message = await factory.CreateAsync(payload, contentType);
// Already transparent!
```

## Security Considerations

- MST receipts are in **unprotected headers** (not covered by signature)
- Always verify receipts independently when required
- Use `CodeTransparencyVerificationOptions` to enforce authorized domains
- Receipts prove ledger inclusion but don't authenticate the signer

## Related Packages

- `CoseSign1.Abstractions` - Core abstractions and interfaces
- `CoseSign1` - Factory implementations
- `Azure.Security.CodeTransparency` - MST client SDK

## License

Copyright (c) Microsoft Corporation. Licensed under the MIT License.

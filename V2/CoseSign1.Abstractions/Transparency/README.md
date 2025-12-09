# Transparency in V2 Architecture

## Overview

The V2 architecture integrates transparency **elegantly and natively** into the signing workflow, eliminating the need for separate transparency submission steps. Transparency is now a first-class citizen in the factory pattern.

## Key Design Principles

1. **Single Call Experience** - Create signed + transparent messages in one operation
2. **Provider Abstraction** - Support multiple transparency services via plugins
3. **Zero Breaking Changes** - Works without transparency, fully backward compatible
4. **Fail-Safe Options** - Choose whether to fail-fast or degrade gracefully
5. **Clean Separation** - Core abstractions, specific providers in separate packages

## Architecture

### Core Abstractions (`CoseSign1.Abstractions`)

```
CoseSign1.Abstractions/
├── Transparency/
│   ├── ITransparencyProvider.cs          # Provider interface
│   ├── TransparencyValidationResult.cs   # Verification result
│   └── TransparencyExtensions.cs         # Helper extensions
└── SigningOptions.cs                      # Extended with transparency support
```

### Provider Implementations (Separate Packages)

```
CoseSign1.Transparent.CTS/               # Azure CTS implementation
CoseSign1.Transparent.SCT/               # Certificate Transparency (future)
CoseSign1.Transparent.Custom/            # Custom implementations
```

## How It Works

### 1. Factory Integration

The factory automatically calls the transparency provider **after signing** when configured:

```
┌─────────────────────────────────────────────────────┐
│                    Factory Flow                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Apply header contributors                      │
│  2. Sign payload → CoseSign1Message                │
│  3. IF TransparencyProvider configured:            │
│     └─> AddTransparencyProofAsync()                │
│         ├─> Submit to transparency service         │
│         ├─> Receive receipt/proof                  │
│         └─> Embed proof in unprotected headers     │
│  4. Return final message                           │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 2. SigningOptions Extension

```csharp
public class SigningOptions
{
    // ... existing properties ...

    /// <summary>
    /// Transparency provider to augment the signed message.
    /// When set, the factory automatically adds transparency proof after signing.
    /// </summary>
    public ITransparencyProvider? TransparencyProvider { get; set; }

    /// <summary>
    /// Whether to fail the entire operation if transparency fails.
    /// Default: true (fail-fast)
    /// Set to false for best-effort transparency.
    /// </summary>
    public bool FailOnTransparencyError { get; set; } = true;
}
```

## Usage Examples

### Example 1: Azure CTS Transparency (Single Call!)

```csharp
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Transparent.CTS;

// Set up CTS transparency provider
var ctsClient = new CodeTransparencyClient(new Uri("https://..."), credential);
var transparencyProvider = new AzureCtsTransparencyProvider(ctsClient);

// Create signing options with transparency
var options = new SigningOptions
{
    TransparencyProvider = transparencyProvider
};

// Single call creates signed + transparent message! 🎉
var message = await factory.CreateCoseSign1MessageAsync(
    payload, 
    contentType, 
    options);

// Message now has:
// - Cryptographic signature
// - Transparency receipt in unprotected headers
// All in one operation!
```

### Example 2: Best-Effort Transparency

```csharp
var options = new SigningOptions
{
    TransparencyProvider = transparencyProvider,
    FailOnTransparencyError = false  // Don't fail if transparency unavailable
};

// If CTS is down, still get a valid signature (without transparency)
var message = await factory.CreateCoseSign1MessageAsync(payload, contentType, options);
```

### Example 3: Verify Transparency

```csharp
using CoseSign1.Abstractions.Transparency;

// Verify the transparency proof
var result = await message.VerifyTransparencyAsync(transparencyProvider);

if (result.IsValid)
{
    Console.WriteLine($"Valid transparency proof from {result.ProviderName}");
    Console.WriteLine($"Log entry ID: {result.Metadata["entryId"]}");
}
else
{
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"Transparency error: {error}");
    }
}
```

### Example 4: Check for Transparency

```csharp
// Quick heuristic check
if (message.HasTransparencyProof())
{
    Console.WriteLine("Message appears to have transparency proof");
}
```

## Implementing a Custom Provider

```csharp
using CoseSign1.Abstractions.Transparency;

public class MyCustomTransparencyProvider : ITransparencyProvider
{
    public string ProviderName => "MyCustomTransparency";

    public async Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        // 1. Submit message to your transparency service
        var proof = await _myService.SubmitAsync(message.Encode(), cancellationToken);

        // 2. Create new message with proof in unprotected headers
        var headers = new CoseHeaderMap(message.UnprotectedHeaders);
        headers.Add(new CoseHeaderLabel(_myProofLabel), CoseHeaderValue.FromBytes(proof));

        // 3. Return augmented message
        return new CoseSign1Message(
            message.ProtectedHeaders,
            headers,
            message.Content,
            message.Signature);
    }

    public async Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        // Extract proof and verify with your service
        var proof = ExtractProof(message);
        var isValid = await _myService.VerifyAsync(message.Encode(), proof, cancellationToken);

        return isValid
            ? TransparencyValidationResult.Success(ProviderName)
            : TransparencyValidationResult.Failure(ProviderName, "Invalid proof");
    }
}
```

## Migration from V1

### V1 Pattern (Two Steps ❌)

```csharp
// Step 1: Create signed message
var signedMessage = await factory.CreateCoseSign1MessageAsync(payload, contentType);

// Step 2: Make it transparent (separate call)
var transparentMessage = await transparencyService.MakeTransparentAsync(signedMessage);
```

### V2 Pattern (One Step ✅)

```csharp
// Single call with transparency provider in options
var options = new SigningOptions { TransparencyProvider = provider };
var message = await factory.CreateCoseSign1MessageAsync(payload, contentType, options);
// Done! Message is both signed and transparent
```

## Benefits

### ✅ For Callers
- **Simpler API** - One call instead of two
- **Less error-prone** - Can't forget transparency step
- **Cleaner code** - No intermediate variables
- **Flexible** - Opt-in per operation or globally

### ✅ For Providers
- **Clean interface** - Simple contract to implement
- **Composable** - Works with any signing implementation
- **Testable** - Easy to mock and test
- **Discoverable** - NuGet packages with clear purpose

### ✅ For Architecture
- **Non-breaking** - Fully backward compatible
- **Extensible** - New transparency services are plugins
- **Maintainable** - Clean separation of concerns
- **Future-proof** - Ready for new transparency standards

## Provider Packages

| Package | Description | Status |
|---------|-------------|--------|
| `CoseSign1.Transparent.CTS` | Azure Code Transparency Service | ✅ V2 Ready |
| `CoseSign1.Transparent.SCT` | Certificate Transparency (SCT) | 🔄 Planned |
| `CoseSign1.Transparent.Merkle` | Generic Merkle tree transparency | 🔄 Planned |

## Testing

Mock transparency providers for unit tests:

```csharp
public class MockTransparencyProvider : ITransparencyProvider
{
    public string ProviderName => "Mock";
    
    public Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message, 
        CancellationToken cancellationToken = default)
    {
        // Return message with mock proof
        return Task.FromResult(message);
    }
    
    public Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
        CoseSign1Message message, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(TransparencyValidationResult.Success(ProviderName));
    }
}
```

## Performance Considerations

- Transparency calls are **async** and can be slow (network round-trip)
- Consider using `FailOnTransparencyError = false` for non-critical scenarios
- Providers should implement proper timeouts and retries
- Consider batch operations for high-volume scenarios (future enhancement)

## Security Considerations

- Transparency proofs are in **unprotected headers** (not covered by signature)
- This is by design - proofs are added after signing
- Always verify transparency proofs independently if required
- Don't trust proof presence alone - verify with the service

## Future Enhancements

- [ ] Batch transparency operations
- [ ] Transparency proof caching
- [ ] Offline transparency (pre-signed receipts)
- [ ] Multi-provider support (multiple transparency services)
- [ ] Transparency policy enforcement

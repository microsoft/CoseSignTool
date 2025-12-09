# V2 Transparency Architecture - Design Summary

## Problem Statement (V1)

In V1, transparency required a **two-step process**:
1. Create signed message with factory
2. Call transparency service separately to augment message

This was:
- ❌ **Cumbersome** - Two method calls required
- ❌ **Error-prone** - Easy to forget transparency step
- ❌ **Unclear** - Relationship between signing and transparency not obvious
- ❌ **Inefficient** - Extra serialization/deserialization

## Solution (V2)

### Core Innovation: **Transparency as an Integrated Option**

Transparency is now a property of `SigningOptions`, allowing the factory to handle everything in **one call**.

### Key Components

#### 1. `ITransparencyProvider` Interface
```csharp
public interface ITransparencyProvider
{
    string ProviderName { get; }
    
    // Called automatically by factory after signing
    Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
    
    // Verify transparency proof
    Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}
```

#### 2. Extended `SigningOptions`
```csharp
public class SigningOptions
{
    // ... existing properties ...
    
    // NEW: Transparency integration
    public ITransparencyProvider? TransparencyProvider { get; set; }
    
    // NEW: Failure behavior control
    public bool FailOnTransparencyError { get; set; } = true;
}
```

#### 3. `TransparencyValidationResult`
```csharp
public sealed class TransparencyValidationResult
{
    public bool IsValid { get; }
    public IReadOnlyList<string> Errors { get; }
    public string? ProviderName { get; }
    public IReadOnlyDictionary<string, object>? Metadata { get; }
}
```

## Usage Comparison

### V1 (Old Way)
```csharp
// Step 1: Sign
var signedMessage = await factory.CreateCoseSign1MessageAsync(payload, contentType);

// Step 2: Add transparency (separate call)
var transparentMessage = await transparencyService.MakeTransparentAsync(signedMessage);
```

### V2 (New Way)
```csharp
var options = new SigningOptions
{
    TransparencyProvider = new AzureCtsTransparencyProvider(ctsClient)
};

// Single call! ✨
var message = await factory.CreateCoseSign1MessageAsync(payload, contentType, options);
// Done - message is signed AND transparent
```

## Factory Implementation Pattern

Factories should implement this pattern:

```csharp
public async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
    byte[] payload,
    string contentType,
    TOptions? options = default,
    CancellationToken cancellationToken = default)
{
    // 1. Apply header contributors
    // 2. Sign the message
    var signedMessage = ... // signing logic
    
    // 3. Apply transparency if configured
    if (options?.TransparencyProvider != null)
    {
        try
        {
            return await options.TransparencyProvider.AddTransparencyProofAsync(
                signedMessage, 
                cancellationToken);
        }
        catch (Exception ex) when (!options.FailOnTransparencyError)
        {
            // Log warning and return signed message without transparency
            Log.Warning($"Transparency failed: {ex.Message}. Returning signed message without transparency.");
            return signedMessage;
        }
        // If FailOnTransparencyError is true, exception propagates
    }
    
    return signedMessage;
}
```

## Provider Implementation Pattern

### Example: Azure CTS Provider

```csharp
public class AzureCtsTransparencyProvider : ITransparencyProvider
{
    private readonly CodeTransparencyClient _client;
    
    public string ProviderName => "AzureCTS";
    
    public async Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        // 1. Submit to CTS
        var entry = await _client.CreateEntryAsync(
            message.Encode(), 
            cancellationToken);
        
        // 2. Get receipt
        var receipt = await _client.GetReceiptAsync(
            entry.EntryId, 
            cancellationToken);
        
        // 3. Embed receipt in unprotected headers
        var headers = new CoseHeaderMap(message.UnprotectedHeaders);
        headers.Add(CtsHeaderLabel, CoseHeaderValue.FromBytes(receipt));
        
        // 4. Return augmented message
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
        var receipt = ExtractReceipt(message);
        var isValid = await _client.VerifyReceiptAsync(receipt, cancellationToken);
        
        return isValid
            ? TransparencyValidationResult.Success(ProviderName)
            : TransparencyValidationResult.Failure(ProviderName, "Invalid receipt");
    }
}
```

## Benefits

### For Callers ✅
- **One call** instead of two
- **Less code** to write
- **Fewer errors** (can't forget transparency)
- **Clearer intent** (transparency is an option, not a separate step)

### For Implementers ✅
- **Clean interface** to implement
- **Works with any factory** (abstraction-based)
- **Easy to test** (mockable)
- **Plugin architecture** (separate NuGet packages)

### For Architecture ✅
- **Zero breaking changes** (fully backward compatible)
- **Extensible** (new providers are easy)
- **Composable** (works with all existing features)
- **Future-proof** (ready for new transparency standards)

## Migration Path

### Existing V1 Code
Keep working - no changes required.

### New V2 Code
Use the new integrated pattern from the start.

### Gradual Migration
1. Add transparency provider to options
2. Remove separate `MakeTransparentAsync` calls
3. Enjoy simpler code!

## Package Structure

```
CoseSign1.Abstractions/
└── Transparency/
    ├── ITransparencyProvider.cs
    ├── TransparencyValidationResult.cs
    ├── TransparencyExtensions.cs
    └── README.md

CoseSign1.Transparent.CTS/           # Azure CTS implementation (separate package)
├── AzureCtsTransparencyProvider.cs
└── Extensions/
    └── ...

CoseSign1.Transparent.SCT/           # Certificate Transparency (future)
CoseSign1.Transparent.Merkle/        # Generic Merkle tree (future)
```

## Design Decisions

### Why in SigningOptions?
- ✅ Natural fit - transparency augments signing
- ✅ Per-operation control - can vary by call
- ✅ Backward compatible - optional property
- ✅ Discoverable - IntelliSense shows it

### Why after signing?
- ✅ Transparency services need the signed message
- ✅ Keeps signature pure (no transparency in protected headers)
- ✅ Allows verification of signature independent of transparency
- ✅ Standard pattern (CTS, SCT, etc. all work this way)

### Why separate provider packages?
- ✅ Dependencies isolated (don't force Azure.CodeTransparency on everyone)
- ✅ Clear responsibility (each package has one job)
- ✅ Easier maintenance (version independently)
- ✅ Better discoverability (NuGet search works)

### Why FailOnTransparencyError flag?
- ✅ Flexibility - some scenarios require transparency, others prefer best-effort
- ✅ Resilience - can continue if transparency service is down
- ✅ Control - caller decides criticality
- ✅ Sensible default - fail-fast is safer

## Testing Strategy

### Unit Tests
- Mock `ITransparencyProvider` for factory tests
- Test both success and failure paths
- Verify `FailOnTransparencyError` behavior

### Integration Tests
- Real transparency service calls
- Verify proof format and validity
- Test end-to-end workflows

### Example Mock
```csharp
var mockProvider = new Mock<ITransparencyProvider>();
mockProvider.Setup(p => p.AddTransparencyProofAsync(It.IsAny<CoseSign1Message>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync((CoseSign1Message msg, CancellationToken ct) => msg); // Pass-through

var options = new SigningOptions { TransparencyProvider = mockProvider.Object };
```

## Next Steps

1. ✅ **Design Complete** - Core abstractions defined
2. 🔄 **Implement in Factories** - Add transparency support to DirectSignatureFactory and IndirectSignatureFactory
3. 🔄 **Migrate CTS Provider** - Convert V1 AzureCtsTransparencyService to V2 AzureCtsTransparencyProvider
4. 🔄 **Add Tests** - Unit and integration tests for transparency
5. 🔄 **Update Documentation** - Examples and migration guides
6. 🔄 **Consider Future Providers** - SCT, Merkle tree, etc.

## Questions to Address

- [ ] Should factories log transparency failures when `FailOnTransparencyError = false`?
- [ ] Should there be a way to add multiple transparency providers?
- [ ] Should transparency metadata be accessible without full verification?
- [ ] Should there be a standard header label for transparency proofs?
- [ ] Should we support offline/detached transparency receipts?

---

**Status**: ✅ Design complete and validated (builds successfully)
**Next**: Implement in factories and migrate CTS provider

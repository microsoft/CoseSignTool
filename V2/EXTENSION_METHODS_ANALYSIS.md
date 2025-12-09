# V1 Extension Methods Analysis & V2 Modernization Plan

## Executive Summary

V1 has extensive extension methods for extracting data from `CoseSign1Message` objects. These need to be modernized and brought into V2 to provide a clean foundation for the validation architecture.

## V1 Extension Methods Inventory

### 1. Certificate Extensions (`CoseSign1.Certificates/Extensions/CoseSign1MessageExtensions.cs`)

#### Certificate Extraction
- **`TryGetSigningCertificate()`** - Extracts signing cert from x5t header + x5chain
  - Uses MemoryCache for performance
  - Thread-safe with ConcurrentDictionary locks
  - Validates thumbprint against chain

- **`TryGetCertificateChain()`** - Extracts x5chain header (wrapper for TryGetCertificateList)
- **`TryGetExtraCertificates()`** - Extracts x5bag header (wrapper for TryGetCertificateList)
- **`TryGetCertificateList()`** - Private helper for extracting cert lists from headers

#### Signature Verification
- **`VerifyEmbeddedWithCertificate()`** - Verifies embedded signature with extracted cert
- **`VerifyDetachedWithCertificate(byte[])`** - Verifies detached with byte array
- **`VerifyDetachedWithCertificate(ReadOnlySpan<byte>)`** - Verifies detached with span
- **`VerifyDetachedWithCertificate(Stream)`** - Verifies detached with stream
- **`GetEmbeddedPublicKey()`** - Private helper to extract public key from cert

### 2. Indirect Signature Extensions

#### `CoseSign1MessageIndirectSignatureExtensions.cs`
- **`TryGetIndirectSignatureAlgorithm()`** - Extracts hash algorithm from content-type header
  - Uses regex to parse "+hash-sha256" style extensions
  - Returns HashAlgorithmName

- **`IsIndirectSignature()`** - Checks if message is indirect signature (any format)
- **`SignatureMatches(Stream)`** - Validates indirect sig against stream
- **`SignatureMatches(ReadOnlyMemory<byte>)`** - Validates indirect sig against bytes
- **`TryGetHashAlgorithm()`** - Creates HashAlgorithm instance from content-type
- **`CreateHashAlgorithmFromName()`** - Factory for HashAlgorithm instances
- **`SignatureMatchesInternal()`** - Private router to format-specific validators
- **`SignatureMatchesInternalDirect()`** - Validates "direct hash" format

#### `CoseSign1MessageCoseHashEnvelopeExtensions.cs`
- **`TryGetIsCoseHashEnvelope()`** - Checks if message is CoseHashEnvelope format
- **`TryGetPayloadHashAlgorithm()`** - Extracts header 258 (payload hash algorithm)
- **`TryGetPreImageContentType(string)`** - Extracts header 259 as string
- **`TryGetPreImageContentType(int)`** - Extracts header 259 as CoAP int
- **`TryGetPreImageContentType(string, int)`** - Extracts header 259 (both formats)
- **`TryGetPayloadLocation()`** - Extracts header 260 (payload location URI)
- **`SignatureMatchesInternalCoseHashEnvelope()`** - Private validator for envelope format

#### `CoseSign1MessageCoseHashVExtensions.cs`
- **`TryGetIsCoseHashVContentType()`** - Checks for "+cose-hash-v" in content-type
- **`GetCoseHashV()`** - Deserializes CoseHashV structure from content
- **`TryGetCoseHashV()`** - Try pattern for GetCoseHashV
- **`SignatureMatchesInternalCoseHashV()`** - Private validator for hash-v format

### 3. CBOR Extensions

#### `CborReaderExtensions.cs`
- **`TryReadCertificateSet()`** - Try pattern for reading cert set
- **`ReadCertificateSet()`** - Reads CBOR array or single cert ByteString
- **`ReadByteStringAsCertificate()`** - Private helper to convert ByteString to X509Certificate2

#### `CborWriterExtensions.cs`
- **`WriteCertificateSet()`** - Writes cert list as CBOR array or single ByteString
- **`WriteCertificateList()`** - Private helper for arrays

### 4. Other Extensions

#### `X509Certificate2CollectionExtensions.cs`
- **`First()`** - Gets first cert from collection

#### `ICertificateChainBuilderExtensions.cs`
- **`TryBuildWithPartialChain()`** - Builds chain allowing partial chains
- **`TryBuildIgnoringFlags()`** - Builds chain ignoring specific status flags

## Key Issues to Address in V2

### 1. **Content Type Abstraction Problem** ⚠️ HIGH PRIORITY
**Current Issue:** Content type can be in multiple places:
- Header 3 (standard content-type) for direct signatures
- Header 259 (preimage-content-type) for CoseHashEnvelope
- Header 3 with "+hash-*" extension for legacy indirect
- Header 3 with "+cose-hash-v" for CoseHashV

**V2 Solution Needed:**
```csharp
// Unified API that handles all formats
public static bool TryGetContentType(
    this CoseSign1Message message, 
    out string? contentType);

// Gets the "logical" content type regardless of format
// - For direct signatures: returns header 3
// - For CoseHashEnvelope: returns header 259 (preimage content type)
// - For CoseHashV: returns header 3 without "+cose-hash-v"
// - For legacy indirect: returns header 3 without "+hash-*"
```

### 2. **Memory Management & Caching**
**V1 Issues:**
- Uses `MemoryCache.Default` (global static)
- Uses `ConcurrentDictionary` for locks
- Memory leaks possible if locks not cleaned up
- No cancellation support

**V2 Improvements:**
- Remove caching (let callers cache if needed)
- Simpler, stateless extensions
- Better suited for DI scenarios

### 3. **Thread Safety**
**V1 Approach:**
- Complex locking with ConcurrentDictionary
- Lock cleanup in finally blocks

**V2 Approach:**
- Stateless, immutable operations
- No shared state = naturally thread-safe

### 4. **Error Handling**
**V1 Approach:**
- Mix of Try patterns and exceptions
- Trace.TraceWarning for diagnostics
- Some methods throw, some return false

**V2 Improvements:**
- Consistent Try pattern for all extractions
- No trace logging (let callers log)
- Result types with detailed error info

### 5. **Async Support**
**V1 Issue:**
- All synchronous
- Stream operations block

**V2 Improvement:**
- Async overloads for stream operations
- CancellationToken support

## V2 Modernization Plan

### Phase 1: Core Header Extraction (Foundation)

Create `V2/CoseSign1.Abstractions/Extensions/CoseSign1MessageExtensions.cs`:

```csharp
namespace CoseSign1.Abstractions.Extensions;

/// <summary>
/// Core extension methods for extracting data from CoseSign1Message.
/// Provides unified API for all signature formats (direct, indirect, CoseHashEnvelope, CoseHashV).
/// </summary>
public static class CoseSign1MessageExtensions
{
    /// <summary>
    /// Gets the logical content type regardless of signature format.
    /// For direct signatures: returns header 3
    /// For CoseHashEnvelope: returns header 259 (preimage content type)  
    /// For CoseHashV: returns header 3 without "+cose-hash-v"
    /// For legacy indirect: returns header 3 without "+hash-*" extension
    /// </summary>
    public static bool TryGetContentType(
        this CoseSign1Message message,
        out string? contentType);
    
    /// <summary>
    /// Determines the signature format type.
    /// </summary>
    public static SignatureFormat GetSignatureFormat(this CoseSign1Message message);
    
    /// <summary>
    /// Tries to get a header value as string from protected or unprotected headers.
    /// </summary>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out string? value,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Tries to get a header value as int from protected or unprotected headers.
    /// </summary>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out int value,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Tries to get a header value as bytes from protected or unprotected headers.
    /// </summary>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out ReadOnlyMemory<byte> value,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Checks if a header exists in protected headers (and optionally unprotected).
    /// </summary>
    public static bool HasHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        bool allowUnprotected = false);
}

/// <summary>
/// Signature format enumeration.
/// </summary>
public enum SignatureFormat
{
    Direct,              // Standard embedded or detached
    IndirectHashLegacy,  // Content-type with "+hash-sha256" 
    IndirectCoseHashV,   // Content-type with "+cose-hash-v"
    IndirectCoseHashEnvelope  // Has header 258 (payload hash alg)
}
```

### Phase 2: Certificate Extensions

Create `V2/CoseSign1.Certificates/Extensions/CoseSign1MessageCertificateExtensions.cs`:

```csharp
namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for extracting certificates from CoseSign1Message.
/// Modernized from V1 with simpler, stateless implementations.
/// </summary>
public static class CoseSign1MessageCertificateExtensions
{
    /// <summary>
    /// Extracts the signing certificate from x5t header + x5chain.
    /// No caching - callers cache if needed.
    /// </summary>
    public static bool TryGetSigningCertificate(
        this CoseSign1Message message,
        out X509Certificate2? certificate,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Extracts certificate chain from x5chain header (33).
    /// </summary>
    public static bool TryGetCertificateChain(
        this CoseSign1Message message,
        out X509Certificate2Collection? chain,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Extracts extra certificates from x5bag header (32).
    /// </summary>
    public static bool TryGetExtraCertificates(
        this CoseSign1Message message,
        out X509Certificate2Collection? certificates,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Extracts thumbprint from x5t header (34).
    /// </summary>
    public static bool TryGetCertificateThumbprint(
        this CoseSign1Message message,
        out CoseX509Thumbprint? thumbprint,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Gets the public key from the signing certificate.
    /// </summary>
    public static bool TryGetPublicKey(
        this CoseSign1Message message,
        out AsymmetricAlgorithm? publicKey,
        bool allowUnprotected = false);
}
```

### Phase 3: Indirect Signature Extensions

Create `V2/CoseSign1.Indirect/Extensions/CoseSign1MessageIndirectExtensions.cs`:

```csharp
namespace CoseSign1.Indirect.Extensions;

/// <summary>
/// Extension methods for working with indirect signatures.
/// Supports all formats: legacy hash, CoseHashV, CoseHashEnvelope.
/// </summary>
public static class CoseSign1MessageIndirectExtensions
{
    /// <summary>
    /// Checks if message is an indirect signature (any format).
    /// </summary>
    public static bool IsIndirectSignature(this CoseSign1Message message);
    
    /// <summary>
    /// Gets the indirect signature format type.
    /// Returns null if not an indirect signature.
    /// </summary>
    public static IndirectSignatureFormat? GetIndirectFormat(
        this CoseSign1Message message);
    
    /// <summary>
    /// Gets hash algorithm used for indirect signature.
    /// Works with all formats.
    /// </summary>
    public static bool TryGetHashAlgorithm(
        this CoseSign1Message message,
        out HashAlgorithmName algorithm);
    
    /// <summary>
    /// For CoseHashEnvelope: gets payload hash algorithm from header 258.
    /// </summary>
    public static bool TryGetPayloadHashAlgorithm(
        this CoseSign1Message message,
        out HashAlgorithmName algorithm);
    
    /// <summary>
    /// For CoseHashEnvelope: gets preimage content type from header 259.
    /// Handles both string and CoAP int formats.
    /// </summary>
    public static bool TryGetPreImageContentType(
        this CoseSign1Message message,
        out string? contentType);
    
    /// <summary>
    /// For CoseHashEnvelope: gets payload location from header 260.
    /// </summary>
    public static bool TryGetPayloadLocation(
        this CoseSign1Message message,
        out Uri? location);
    
    /// <summary>
    /// For CoseHashV: extracts and deserializes CoseHashV structure from content.
    /// </summary>
    public static bool TryGetCoseHashV(
        this CoseSign1Message message,
        out CoseHashV? hashV);
    
    /// <summary>
    /// Validates indirect signature against original payload (sync).
    /// Auto-detects format and uses appropriate validation.
    /// </summary>
    public static bool ValidateIndirectSignature(
        this CoseSign1Message message,
        ReadOnlySpan<byte> originalPayload);
    
    /// <summary>
    /// Validates indirect signature against original payload (async).
    /// Supports large streams efficiently.
    /// </summary>
    public static Task<bool> ValidateIndirectSignatureAsync(
        this CoseSign1Message message,
        Stream originalPayload,
        CancellationToken cancellationToken = default);
}

public enum IndirectSignatureFormat
{
    HashLegacy,      // "+hash-sha256" in content-type
    CoseHashV,       // "+cose-hash-v" in content-type
    CoseHashEnvelope // Header 258 present
}
```

### Phase 4: Signature Verification Extensions

Create `V2/CoseSign1.Certificates/Extensions/CoseSign1MessageVerificationExtensions.cs`:

```csharp
namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for verifying signatures.
/// Simplified from V1, no caching, stateless.
/// </summary>
public static class CoseSign1MessageVerificationExtensions
{
    /// <summary>
    /// Verifies embedded signature using certificate from x5t header.
    /// </summary>
    public static bool VerifyWithEmbeddedCertificate(
        this CoseSign1Message message,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Verifies detached signature using certificate from x5t header.
    /// </summary>
    public static bool VerifyDetachedWithEmbeddedCertificate(
        this CoseSign1Message message,
        ReadOnlySpan<byte> detachedContent,
        bool allowUnprotected = false);
    
    /// <summary>
    /// Verifies detached signature using certificate from x5t header (async).
    /// </summary>
    public static Task<bool> VerifyDetachedWithEmbeddedCertificateAsync(
        this CoseSign1Message message,
        Stream detachedContent,
        bool allowUnprotected = false,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Verifies signature with provided public key.
    /// </summary>
    public static bool VerifyWithPublicKey(
        this CoseSign1Message message,
        AsymmetricAlgorithm publicKey);
    
    /// <summary>
    /// Verifies detached signature with provided public key.
    /// </summary>
    public static bool VerifyDetachedWithPublicKey(
        this CoseSign1Message message,
        ReadOnlySpan<byte> detachedContent,
        AsymmetricAlgorithm publicKey);
}
```

## Implementation Priorities

### High Priority (Foundational)
1. ✅ Core header extraction with unified content-type API
2. ✅ SignatureFormat/IndirectSignatureFormat enums
3. ✅ Certificate extraction (no caching)
4. ✅ Indirect signature format detection

### Medium Priority (Validation Support)
5. ✅ Indirect signature validation
6. ✅ Signature verification helpers
7. ✅ CoseHashV/CoseHashEnvelope helpers

### Lower Priority (Nice to Have)
8. ⏸️ CBOR extensions (if needed)
9. ⏸️ Advanced cert chain helpers

## Breaking Changes from V1

### Removed Features
- ❌ MemoryCache integration (callers cache if needed)
- ❌ Trace logging (use structured logging in callers)
- ❌ Lock management (stateless = no locks)

### API Changes
- ✅ More consistent Try pattern
- ✅ X509Certificate2Collection instead of List<X509Certificate2>
- ✅ Uri instead of string for payload location
- ✅ Async overloads for stream operations
- ✅ CancellationToken support

### Improvements
- ✅ Unified content-type API (handles all formats)
- ✅ SignatureFormat enum for clarity
- ✅ Simpler, more testable implementations
- ✅ Better async/await support
- ✅ DI-friendly (no static state)

## Testing Strategy

### Unit Tests
- ✅ Each extension method independently
- ✅ All signature formats
- ✅ Edge cases (null, empty, malformed)
- ✅ Thread safety (concurrent access)

### Integration Tests
- ✅ Round-trip: create in V2, extract with extensions
- ✅ V1 compatibility: read V1 messages with V2 extensions
- ✅ Format detection accuracy

## Next Steps

1. **Create design review document** ✅ (this document)
2. **Get approval on API design**
3. **Implement Phase 1: Core header extraction**
4. **Implement Phase 2: Certificate extensions**
5. **Implement Phase 3: Indirect signature extensions**
6. **Implement Phase 4: Verification extensions**
7. **Write comprehensive tests**
8. **Update validation architecture to use new extensions**

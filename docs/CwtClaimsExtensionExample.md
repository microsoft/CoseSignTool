# CWT Claims Extension Method Usage

## Overview

The `TryGetCwtClaims()` extension method provides strongly-typed access to CWT Claims in a `CoseSign1Message` without requiring knowledge of CBOR parsing.

## Basic Usage

```csharp
using CoseSign1.Headers.Extensions;
using System.Security.Cryptography.Cose;

// Decode a CoseSign1Message
CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

// Try to get CWT Claims from protected headers (default) - no CBOR knowledge required!
if (message.TryGetCwtClaims(out CwtClaims? claims))
{
    // Access standard claims as strongly-typed properties
    Console.WriteLine($"Issuer: {claims.Issuer}");
    Console.WriteLine($"Subject: {claims.Subject}");
    Console.WriteLine($"Audience: {claims.Audience}");
    
    if (claims.ExpirationTime.HasValue)
    {
        Console.WriteLine($"Expires: {claims.ExpirationTime.Value}");
    }
    
    if (claims.NotBefore.HasValue)
    {
        Console.WriteLine($"Not Before: {claims.NotBefore.Value}");
    }
    
    if (claims.IssuedAt.HasValue)
    {
        Console.WriteLine($"Issued At: {claims.IssuedAt.Value}");
    }
    
    if (claims.CwtId != null)
    {
        Console.WriteLine($"CWT ID: {BitConverter.ToString(claims.CwtId)}");
    }
    
    // Access custom claims
    if (claims.CustomClaims.Count > 0)
    {
        Console.WriteLine("\nCustom Claims:");
        foreach (var kvp in claims.CustomClaims)
        {
            Console.WriteLine($"  Label {kvp.Key}: {kvp.Value}");
        }
    }
    
    // Or just print everything
    Console.WriteLine(claims.ToString());
}
else
{
    Console.WriteLine("No CWT Claims found in message");
}
```

## Advanced Usage: Reading from Unprotected Headers

```csharp
// Read CWT Claims from unprotected headers instead of protected headers
// Note: Not recommended for SCITT compliance, but supported for flexibility
if (message.TryGetCwtClaims(out CwtClaims? claims, useUnprotectedHeaders: true))
{
    Console.WriteLine($"Unprotected Issuer: {claims.Issuer}");
    // ... access other claims
}
```

## Advanced Usage: Custom Header Labels

```csharp
// Read CWT Claims from a custom header label instead of the default label 15
var customLabel = new CoseHeaderLabel(999);
if (message.TryGetCwtClaims(out CwtClaims? claims, headerLabel: customLabel))
{
    Console.WriteLine($"Custom label Issuer: {claims.Issuer}");
    // ... access other claims
}

// Multiple claim sets can coexist at different labels
var defaultResult = message.TryGetCwtClaims(out CwtClaims? defaultClaims);
var customResult = message.TryGetCwtClaims(out CwtClaims? customClaims, headerLabel: customLabel);

if (defaultResult && customResult)
{
    Console.WriteLine($"Default issuer: {defaultClaims!.Issuer}");
    Console.WriteLine($"Custom issuer: {customClaims!.Issuer}");
}
```

## Complete Example with Error Handling

```csharp
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;
using System.Security.Cryptography.Cose;

public void ProcessCoseSignature(byte[] signatureBytes)
{
    try
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
        
        // Try protected headers first (standard location)
        if (message.TryGetCwtClaims(out CwtClaims? claims))
        {
            Console.WriteLine("Found CWT Claims in protected headers");
            PrintClaims(claims);
        }
        // Fallback to unprotected headers
        else if (message.TryGetCwtClaims(out claims, useUnprotectedHeaders: true))
        {
            Console.WriteLine("Found CWT Claims in unprotected headers");
            PrintClaims(claims);
        }
        else
        {
            Console.WriteLine("No CWT Claims found");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error processing signature: {ex.Message}");
    }
}

private void PrintClaims(CwtClaims claims)
{
    // Use the built-in ToString() for formatted output
    Console.WriteLine(claims.ToString());
    
    // Or access individual properties
    if (claims.Issuer != null)
        Console.WriteLine($"Issuer: {claims.Issuer}");
    
    if (claims.Subject != null && claims.Subject != CwtClaims.DefaultSubject)
        Console.WriteLine($"Subject: {claims.Subject}");
}
```

## Benefits

**Before** (manual CBOR parsing - ~90 lines of code):
```csharp
// Find the CWT Claims header
if (message.ProtectedHeaders.TryGetValue(CWTClaimsHeaderLabels.CWTClaims, out CoseHeaderValue headerValue))
{
    byte[] cborBytes = headerValue.EncodedValue.ToArray();
    CborReader reader = new CborReader(cborBytes);
    
    // Read map start
    int? mapSize = reader.ReadStartMap();
    
    // Parse each claim...
    string? issuer = null;
    string? subject = null;
    // ... many more lines of CBOR parsing code ...
}
```

**After** (strongly-typed access - 1 line):
```csharp
if (message.TryGetCwtClaims(out CwtClaims? claims))
{
    Console.WriteLine($"Issuer: {claims.Issuer}");
}
```

## API Reference

### Extension Method

```csharp
public static bool TryGetCwtClaims(
    this CoseSign1Message message, 
    out CwtClaims? claims,
    bool useUnprotectedHeaders = false,
    CoseHeaderLabel? headerLabel = null)
```

**Parameters:**
- `message`: The CoseSign1Message to extract claims from
- `claims`: When this method returns, contains the extracted CWT claims if successful; otherwise, null
- `useUnprotectedHeaders`: If true, reads from unprotected headers; otherwise, from protected headers (default: false)
- `headerLabel`: Optional custom header label to use instead of the default CWT Claims label (15)

**Returns:** `true` if CWT Claims are present and successfully parsed, `false` otherwise.

### CwtClaims Class

```csharp
public sealed class CwtClaims
{
    // Standard claims (read-only properties)
    public string? Issuer { get; }                    // Label 1
    public string? Subject { get; }                   // Label 2 (default: "unknown.intent")
    public string? Audience { get; }                  // Label 3
    public DateTimeOffset? ExpirationTime { get; }    // Label 4 (note: DateTimeOffset, not long)
    public DateTimeOffset? NotBefore { get; }         // Label 5 (note: DateTimeOffset, not long)
    public DateTimeOffset? IssuedAt { get; }          // Label 6 (note: DateTimeOffset, not long)
    public byte[]? CwtId { get; }                     // Label 7
    
    // Custom claims (read-only dictionary)
    public Dictionary<int, object> CustomClaims { get; }
    
    // Static default value
    public static readonly string DefaultSubject = "unknown.intent";
    
    // Methods
    public override string ToString();
    public bool IsDefault();
    public CwtClaims Merge(CwtClaims? other, bool logOverrides = true);
    public byte[] ToCborBytes();
    
    // Static factory method
    public static CwtClaims FromCborBytes(byte[] cborBytes);
}
```

**Key Points:**
- `CwtClaims` is a sealed class (cannot be inherited)
- Timestamp properties are `DateTimeOffset?` (changed from `long?` in earlier versions)
- `CustomClaims` is a mutable `Dictionary<int, object>` (changed from `IReadOnlyDictionary`)
- Default subject is `"unknown.intent"` when not explicitly set
- `IsDefault()` returns true if only the default subject is set (no other claims)
- `Merge()` combines two claim sets, with the parameter overriding values
- `ToCborBytes()` serializes claims back to CBOR format

### CoseHeaderMap Extension Methods

```csharp
// Set CWT claims in a header map
public static CoseHeaderMap SetCwtClaims(
    this CoseHeaderMap headerMap, 
    CwtClaims claims,
    CoseHeaderLabel? headerLabel = null);

// Try to get CWT claims from a header map
public static bool TryGetCwtClaims(
    this CoseHeaderMap headerMap, 
    out CwtClaims? claims,
    CoseHeaderLabel? headerLabel = null);

// Merge CWT claims into a header map
public static CoseHeaderMap MergeCwtClaims(
    this CoseHeaderMap headerMap, 
    CwtClaims newClaims,
    bool logOverrides = true,
    CoseHeaderLabel? headerLabel = null);
```
```

## See Also

- [CoseSign1.Headers.md](CoseSign1.Headers.md) - Header extension documentation
- [SCITTCompliance.md](SCITTCompliance.md) - SCITT compliance details

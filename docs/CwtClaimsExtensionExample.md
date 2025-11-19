# CWT Claims Extension Method Usage

## Overview

The `TryGetCwtClaims()` extension method provides strongly-typed access to CWT Claims in a `CoseSign1Message` without requiring knowledge of CBOR parsing.

## Usage Example

```csharp
using CoseSign1.Headers.Extensions;
using System.Security.Cryptography.Cose;

// Decode a CoseSign1Message
CoseSign1Message message = CoseSign1Message.DecodeSign1(signatureBytes);

// Try to get CWT Claims - no CBOR knowledge required!
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
    
    if (claims.CWTID != null)
    {
        Console.WriteLine($"CWT ID: {BitConverter.ToString(claims.CWTID)}");
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
public static bool TryGetCwtClaims(this CoseSign1Message message, out CwtClaims? claims)
```

Returns `true` if CWT Claims are present, `false` otherwise.

### CwtClaims Class

```csharp
public class CwtClaims
{
    public string? Issuer { get; }                    // Label 1
    public string? Subject { get; }                   // Label 2
    public string? Audience { get; }                  // Label 3
    public DateTimeOffset? ExpirationTime { get; }    // Label 4
    public DateTimeOffset? NotBefore { get; }         // Label 5
    public DateTimeOffset? IssuedAt { get; }          // Label 6
    public byte[]? CWTID { get; }                     // Label 7
    public IReadOnlyDictionary<int, object> CustomClaims { get; }
    
    public override string ToString();
}
```

## See Also

- [CoseSign1.Headers.md](CoseSign1.Headers.md) - Header extension documentation
- [SCITTCompliance.md](SCITTCompliance.md) - SCITT compliance details

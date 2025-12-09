# SCITT Compliance - User Flow Documentation

This document traces how SCITT (Supply Chain Integrity, Transparency, and Trust) options flow from the end user through the signing pipeline.

## Complete Flow Diagram

```
User Code
    ↓
1. Create CertificateSigningOptions with SCITT settings
    ↓
2. Pass to DirectSignatureFactory.CreateCoseSign1MessageBytes()
    ↓
3. Factory creates SigningContext (from DirectSignatureOptions.AdditionalContext)
    ↓
4. Factory calls ISigningService.GetCoseSigner(context)
    ↓
5. CertificateSigningService.GetCoseSigner() extracts options via extension method
    ↓
6. If EnableScittCompliance==true, generate CWT claims with DID:x509
    ↓
7. Add CwtClaimsHeaderContributor to protected headers
    ↓
8. Return CoseSigner with SCITT-compliant headers
```

## Code Flow with Examples

### Option 1: Using CreateSigningOptions() (Recommended - Service-Agnostic)

```csharp
using CoseSign1.Direct;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Headers;

// Step 1: Get service-specific options from the service itself
var certificateSigningService = new LocalCertificateSigningService(...);
var certOptions = certificateSigningService.CreateOptions<CertificateSigningOptions>();

// Step 2: Configure SCITT compliance
certOptions.EnableScittCompliance = true;
certOptions.CustomCwtClaims = new CwtClaims
{
    Issuer = "https://example.com/issuer",
    Subject = "pkg:npm/my-package@1.0.0",
    Audience = "https://transparency.example.com"
};

// Step 3: Attach to signing options and use with factory
var factory = new DirectSignatureFactory(certificateSigningService);
var options = new DirectSignatureOptions()
    .WithCertificateOptions(certOptions);

byte[] signature = factory.CreateCoseSign1MessageBytes(
    payload: myPayload,
    contentType: "application/json",
    options: options);
```

**Benefits:**
- No need to know the concrete service type
- Service determines the correct options type
- Type-safe via generic `CreateOptions<T>()`
- Decouples caller from service implementation

### Option 2: Using Extension Method (When You Know the Service Type)

```csharp
using CoseSign1.Direct;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Headers;

// Step 1: User creates certificate signing options directly
var certificateOptions = new CertificateSigningOptions
{
    EnableScittCompliance = true,
    CustomCwtClaims = new CwtClaims
    {
        Issuer = "https://example.com/issuer",
        Subject = "pkg:npm/my-package@1.0.0",
        Audience = "https://transparency.example.com"
    }
};

// Step 2: User creates signing options and attaches certificate options
var options = new DirectSignatureOptions()
    .WithCertificateOptions(certificateOptions);  // Extension method from CertificateSigningOptionsExtensions

// Step 3: User calls factory to create signature
var factory = new DirectSignatureFactory(certificateSigningService);
byte[] signature = factory.CreateCoseSign1MessageBytes(
    payload: myPayload,
    contentType: "application/json",
    options: options);
```

**What happens internally:**

1. `WithCertificateOptions()` extension method adds `CertificateSigningOptions` to `options.AdditionalContext["CertificateSigningOptions"]`
2. `DirectSignatureFactory` creates `SigningContext` with the `AdditionalContext` dictionary
3. `CertificateSigningService.GetCoseSigner()` calls `context.TryGetCertificateOptions()` extension method
4. Extension method retrieves options from context and checks `EnableScittCompliance`
5. If enabled, `CreateScittCwtClaimsContributor()` generates DID:x509 issuer and creates contributor
6. Contributor adds CWT claims to protected headers

### Option 2: Manual Dictionary Approach

```csharp
using CoseSign1.Direct;
using CoseSign1.Certificates;
using CoseSign1.Headers;

// Step 1: User creates certificate signing options
var certificateOptions = new CertificateSigningOptions
{
    EnableScittCompliance = true
    // Uses default DID:x509 issuer and "unknown.intent" subject
};

// Step 2: User manually adds to AdditionalContext
var options = new DirectSignatureOptions
{
    AdditionalContext = new Dictionary<string, object>
    {
        ["CertificateSigningOptions"] = certificateOptions
    }
};

// Step 3: User calls factory
var factory = new DirectSignatureFactory(certificateSigningService);
var signature = factory.CreateCoseSign1MessageBytes(myPayload, "application/json", options);
```

## New Interface Method: CreateSigningOptions()

The `ISigningService` interface now includes:

```csharp
public interface ISigningService : IDisposable
{
    CoseSigner GetCoseSigner(SigningContext context);
    SigningOptions CreateSigningOptions();  // New method
    bool IsRemote { get; }
    SigningServiceMetadata ServiceMetadata { get; }
}
```

This allows services to expose their specific options type without callers needing to know concrete types:

```csharp
// CertificateSigningService implementation
public virtual SigningOptions CreateSigningOptions()
{
    return new CertificateSigningOptions();
}

// Usage with generic helper extension
var options = signingService.CreateOptions<CertificateSigningOptions>();
options.EnableScittCompliance = true;
```

## Key Classes and Their Roles

### User-Facing Classes

1. **CertificateSigningOptions** (User creates)
   - `EnableScittCompliance`: Flag to enable SCITT
   - `CustomCwtClaims`: Optional custom claims (otherwise defaults are generated)

2. **DirectSignatureOptions** (User creates, inherits from SigningOptions)
   - `AdditionalContext`: Dictionary where certificate options are stored
   - User either manually adds to dictionary or uses `WithCertificateOptions()` extension

### Internal Pipeline Classes

3. **DirectSignatureFactory** (User calls)
   - Takes `DirectSignatureOptions`
   - Creates `SigningContext` passing through `options.AdditionalContext`
   - Calls `_signingService.GetCoseSigner(context)`

4. **SigningContext** (Created by factory)
   - Immutable context passed through pipeline
   - Contains `AdditionalContext` dictionary

5. **CertificateSigningService** (Receives context)
   - Calls `context.TryGetCertificateOptions()` to extract certificate options
   - Checks `EnableScittCompliance` flag
   - Generates DID:x509 issuer from certificate chain
   - Creates `CwtClaimsHeaderContributor` with claims

6. **CwtClaimsHeaderContributor** (Created internally)
   - Takes `CwtClaims` object in constructor
   - Adds claims to protected headers as CBOR map at label 15

## Data Flow Through AdditionalContext

```
User creates:
    CertificateSigningOptions { EnableScittCompliance = true }
        ↓
User calls:
    options.WithCertificateOptions(certificateOptions)
        ↓
Extension method stores:
    options.AdditionalContext["CertificateSigningOptions"] = certificateOptions
        ↓
Factory creates:
    new SigningContext(..., options.AdditionalContext)
        ↓
Service retrieves:
    context.TryGetCertificateOptions(out var certOptions)
        → Reads context.AdditionalContext["CertificateSigningOptions"]
        → Returns true if found and EnableScittCompliance == true
        ↓
Service generates:
    - DID:x509 issuer from certificate chain
    - CwtClaims with issuer, subject, timestamps
    - CwtClaimsHeaderContributor
        ↓
Headers added to signature
```

## Why This Design?

1. **Loose Coupling**: `DirectSignatureFactory` doesn't need to know about certificate-specific options
2. **Extensibility**: New option types can be added without changing factory signatures
3. **Type Safety**: Extension methods provide compile-time type checking
4. **Backward Compatibility**: Existing code without SCITT options continues to work
5. **Clean API**: Users have a fluent interface (`WithCertificateOptions()`) or can use dictionaries directly

## Key Methods

- **CertificateSigningOptionsExtensions.WithCertificateOptions()**: User-facing extension to attach options
- **CertificateSigningOptionsExtensions.TryGetCertificateOptions()**: Internal extension to extract options
- **CertificateSigningService.CreateScittCwtClaimsContributor()**: Generates CWT claims with DID:x509
- **DidX509Generator.GenerateFromChain()**: Creates DID:x509 identifier from certificate chain

## Default SCITT Behavior

When `EnableScittCompliance = true` and `CustomCwtClaims = null`:

```csharp
var claims = new CwtClaims
{
    Issuer = "did:x509:0:sha256:{base64url-hash}::subject:CN:{name}:...",  // Generated from cert chain
    Subject = "unknown.intent",                                              // Default value
    IssuedAt = DateTimeOffset.UtcNow,                                       // Current timestamp
    NotBefore = DateTimeOffset.UtcNow                                       // Current timestamp
};
```

The DID:x509 issuer format:
- Hash of root certificate (SHA256, base64url encoded)
- Leaf certificate subject DN (RFC 4514 format, percent-encoded)
- Example: `did:x509:0:sha256:AbC123...XyZ::subject:CN:MyCompany:O:Contoso:C:US`

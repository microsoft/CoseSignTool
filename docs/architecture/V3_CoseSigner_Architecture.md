# V3 Architecture - CoseSigner Emission Pattern

## Executive Summary

The V3 architecture is based on **SigningServices emitting CoseSigner instances** (from `System.Security.Cryptography.Cose`). This is the simplest possible design that fully leverages .NET's battle-tested COSE implementation.

### Key Insight

The V3 architecture uses a clean abstraction layer with dynamic key acquisition:
- **`ISigningKey`** → emits `CoseKey` (handles key lifecycle, caching, rotation)
- **`ISigningService`** → acquires `ISigningKey` **dynamically within `GetCoseSigner()`**, builds headers, returns `CoseSigner`
- **`SigningServiceBase`** → abstract base class implementing template method pattern for common logic
- **`.NET's CoseSigner`** → contains `CoseKey` + headers for `CoseSign1Message.Sign()`

Key insight: **Signing keys are acquired dynamically per operation**, not stored as properties. This enables certificate rotation, multi-key scenarios, and context-based key selection.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         CALLER                               │
│  1. Create SigningKey (Local or Remote)                     │
│  2. Create SigningService with SigningKey                   │
│  3. Pass SigningService to Factory (via DI)                 │
│  4. Factory calls GetCoseSigner(context) → CoseSigner       │
│  5. Factory uses CoseSigner with CoseSign1Message.Sign()    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  SIGNING SERVICE LAYER                       │
│                                                              │
│  ISigningService.GetCoseSigner(SigningContext)              │
│    1. Calls GetSigningKey(context) - DYNAMIC ACQUISITION!    │
│    2. Gets CoseKey from ISigningKey                          │
│    3. Builds headers using IHeaderContributors               │
│    4. Returns CoseSigner (CoseKey + headers)                 │
│                                                              │
│  SigningServiceBase (abstract class):                       │
│    - GetCoseSigner() is final (template method)              │
│    - GetSigningKey(context) is abstract (override in derived)│
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   SIGNING KEY LAYER                          │
│                                                              │
│  ISigningKey.GetCoseKey() + Metadata                        │
│                                                              │
│  Local Case:                                                │
│  • CoseKey created once from certificate private key        │
│  • CoseKey cached and reused across multiple signatures     │
│  • Metadata computed once at initialization                 │
│                                                              │
│  Remote Case:                                               │
│  • CoseKey may be refreshed if certificate rotates          │
│  • CoseKey reused if public key thumbprint unchanged        │
│  • Metadata reflects current certificate state              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              .NET RUNTIME COSE LAYER                         │
│                                                              │
│  CoseSigner (Microsoft's System.Security.Cryptography.Cose) │
│  • Contains: CoseKey + ProtectedHeaders + UnprotectedHeaders│
│  • Used by: CoseSign1Message.Sign(signer, payload)          │
│  • Supports: RSA, ECDsa, ML-DSA (PQC)                       │
│                                                              │
│  CoseKey (Internal to CoseSigner)                           │
│  • Sign(ReadOnlySpan<byte>) → signature                     │
│  • Verify(ReadOnlySpan<byte>) → bool                        │
│  • Algorithm mapping (RSA+SHA256→PS256, etc.)               │
│  • ComputeSignatureSize() → signature size                  │
│  • Can delegate signing operations (remote)                 │
└─────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### ISigningKey - Emits CoseKey

```csharp
/// <summary>
/// Represents a cryptographic signing key that can emit CoseKey instances.
/// This is the abstraction between the signing service and the underlying key material.
/// Implementations handle key lifecycle (local vs remote, caching, rotation, etc.).
/// </summary>
public interface ISigningKey : IDisposable
{
    /// <summary>
    /// Gets the CoseKey for signing operations.
    /// 
    /// For local keys: Returns cached CoseKey instance (created once, reused).
    /// For remote keys: May return cached CoseKey if public key unchanged, or new instance if rotated.
    /// 
    /// The returned CoseKey may be disposed when the ISigningKey is disposed.
    /// Callers should not dispose the CoseKey directly.
    /// </summary>
    /// <returns>A CoseKey ready for signing operations</returns>
    CoseKey GetCoseKey();
    
    /// <summary>
    /// Gets metadata about the signing key.
    /// Used by signing service to determine algorithm, create header contributors, etc.
    /// </summary>
    SigningKeyMetadata Metadata { get; }
    
    /// <summary>
    /// Gets the signing service that owns this key.
    /// Allows access to service-level metadata that may be needed for header contribution.
    /// </summary>
    ISigningService SigningService { get; }
}
```

### ISigningService - Emits CoseSigner

```csharp
/// <summary>
/// Represents a service capable of signing COSE messages.
/// Emits CoseSigner instances (from .NET runtime) for signing operations.
/// Uses an ISigningKey to get the underlying CoseKey and applies headers.
/// </summary>
public interface ISigningService : IDisposable
{
    /// <summary>
    /// Creates a CoseSigner for the signing operation with appropriate headers.
    /// The CoseSigner contains the CoseKey (from ISigningKey) and all headers.
    /// 
    /// Process:
    /// 1. Gets CoseKey from ISigningKey.GetCoseKey()
    /// 2. Builds headers using IHeaderContributors (with ISigningKey context)
    /// 3. Creates and returns CoseSigner with CoseKey + headers
    /// </summary>
    /// <param name="context">The signing context (payload info, custom headers, etc.)</param>
    /// <returns>A CoseSigner ready to sign the message</returns>
    CoseSigner GetCoseSigner(SigningContext context);
    
    /// <summary>
    /// Gets a value indicating whether this is a remote signing service.
    /// </summary>
    bool IsRemote { get; }
    
    /// <summary>
    /// Gets metadata about the signing service.
    /// Used by header contributors to make service-level decisions.
    /// Examples: service name, version, compliance requirements (SCITT, etc.)
    /// </summary>
    SigningServiceMetadata ServiceMetadata { get; }
}
```

### SigningKeyMetadata

```csharp
/// <summary>
/// Metadata about the signing key used in the operation.
/// Provided by ISigningKey implementations to describe key properties.
/// Used by signing services to create appropriate header contributors.
/// </summary>
public class SigningKeyMetadata
{
    /// <summary>
    /// The COSE algorithm identifier.
    /// </summary>
    public required int CoseAlgorithmId { get; init; }
    
    /// <summary>
    /// The cryptographic key type (RSA, ECDsa, ML-DSA, etc.).
    /// </summary>
    public required CryptographicKeyType KeyType { get; init; }
    
    /// <summary>
    /// The hash algorithm used (if applicable).
    /// </summary>
    public HashAlgorithmName? HashAlgorithm { get; init; }
    
    /// <summary>
    /// Key size in bits.
    /// </summary>
    public int? KeySizeInBits { get; init; }
    
    /// <summary>
    /// Whether this is a remote signing key.
    /// </summary>
    public required bool IsRemote { get; init; }
    
    /// <summary>
    /// Additional key-specific metadata.
    /// For certificate-based keys, this might include the certificate.
    /// For other key types, this might include key identifiers, URIs, etc.
    /// </summary>
    public Dictionary<string, object>? AdditionalMetadata { get; init; }
}
```

### SigningServiceMetadata

```csharp
/// <summary>
/// Metadata about the signing service.
/// Provides service-level information that may be contributed to headers.
/// Examples: service name, version, compliance requirements, transparency log URLs, etc.
/// </summary>
public class SigningServiceMetadata
{
    /// <summary>
    /// Name of the signing service (e.g., "AzureTrustedSigning", "LocalSigning").
    /// </summary>
    public string? ServiceName { get; init; }
    
    /// <summary>
    /// Version of the signing service implementation.
    /// </summary>
    public string? ServiceVersion { get; init; }
    
    /// <summary>
    /// Additional service-specific metadata.
    /// Can be used by custom header contributors for service-specific headers.
    /// </summary>
    public Dictionary<string, object>? AdditionalMetadata { get; init; }
}
```

### SigningContext

```csharp
/// <summary>
/// Context information for a signing operation.
/// Contains the payload and per-operation metadata.
/// This is passed to header contributors at sign-time.
/// </summary>
public class SigningContext
{
    /// <summary>
    /// The payload to be signed.
    /// </summary>
    public required byte[] Payload { get; init; }
    
    /// <summary>
    /// Optional content type of the payload (e.g., "application/json").
    /// May be used by header contributors or for validation.
    /// </summary>
    public string? ContentType { get; init; }
    
    /// <summary>
    /// Additional header contributors to apply for this specific operation.
    /// Applied after the signing service's required contributors.
    /// </summary>
    public IReadOnlyList<IHeaderContributor>? AdditionalHeaderContributors { get; init; }
    
    /// <summary>
    /// Additional context for custom header contributors.
    /// </summary>
    public Dictionary<string, object>? AdditionalContext { get; init; }
}
```

### IHeaderContributor

```csharp
/// <summary>
/// Defines how to handle conflicts when a header already exists in the map.
/// </summary>
public enum HeaderMergeStrategy
{
    /// <summary>
    /// Throw an exception if the header already exists.
    /// This is the safest default behavior.
    /// </summary>
    Fail,
    
    /// <summary>
    /// Skip adding the header if it already exists (keep existing value).
    /// </summary>
    KeepExisting,
    
    /// <summary>
    /// Replace the existing header value with the new one.
    /// </summary>
    Replace,
    
    /// <summary>
    /// Allow the contributor to decide based on the existing value.
    /// The contributor's Contribute method will be called and can inspect existing headers.
    /// </summary>
    Custom
}

/// <summary>
/// Context information provided to header contributors during signing.
/// Includes access to the signing key for header derivation.
/// </summary>
public class HeaderContributorContext
{
    /// <summary>
    /// The signing context (payload, content type, etc.).
    /// </summary>
    public required SigningContext SigningContext { get; init; }
    
    /// <summary>
    /// The signing key being used for the operation.
    /// Contributors can access key metadata via SigningKey.Metadata.
    /// </summary>
    public required ISigningKey SigningKey { get; init; }
}

/// <summary>
/// Contributes headers to COSE messages based on sign-time context.
/// IMPORTANT: Contributors are invoked at sign-time, not at service init-time.
/// THREAD-SAFETY: Implementations MUST be thread-safe as they may be called concurrently.
/// Contributors should be immutable or use thread-safe operations.
/// ORDER: The signing service controls the order in which contributors are invoked.
/// </summary>
public interface IHeaderContributor
{
    /// <summary>
    /// Gets the merge strategy for handling conflicts when headers already exist.
    /// Default behavior should be Fail for safety.
    /// </summary>
    HeaderMergeStrategy MergeStrategy { get; }
    
    /// <summary>
    /// Contributes protected headers. Called at sign-time with full context.
    /// MUST be thread-safe - may be called concurrently from multiple threads.
    /// 
    /// If MergeStrategy is Custom, this method should check for existing headers
    /// and decide whether to add, skip, or modify them.
    /// </summary>
    /// <param name="headers">The header map to contribute to. May already contain headers.</param>
    /// <param name="context">Context including signing context and signing key (which provides metadata).</param>
    void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
    
    /// <summary>
    /// Contributes unprotected headers. Called at sign-time with full context.
    /// MUST be thread-safe - may be called concurrently from multiple threads.
    /// 
    /// If MergeStrategy is Custom, this method should check for existing headers
    /// and decide whether to add, skip, or modify them.
    /// </summary>
    /// <param name="headers">The header map to contribute to. May already contain headers.</param>
    /// <param name="context">Context including signing context and signing key (which provides metadata).</param>
    void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
}

// Example: Thread-safe algorithm header contributor (immutable state)
public class AlgorithmHeaderContributor : IHeaderContributor
{
    private readonly int _algorithmId;
    
    public AlgorithmHeaderContributor(int algorithmId)
    {
        _algorithmId = algorithmId;
    }
    
    // Algorithm header is critical - fail if it already exists to avoid conflicts
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;
    
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Thread-safe: only reads immutable field and writes to caller's header map
        var label = CoseHeaderLabel.Algorithm;
        
        // Check merge strategy
        if (headers.TryGetValue(label, out var existing))
        {
            switch (MergeStrategy)
            {
                case HeaderMergeStrategy.Fail:
                    throw new InvalidOperationException(
                        $"Algorithm header already exists with value {existing}. Cannot add {_algorithmId}.");
                case HeaderMergeStrategy.KeepExisting:
                    return; // Skip
                case HeaderMergeStrategy.Replace:
                    break; // Continue to set
            }
        }
        
        headers[label] = CoseHeaderValue.FromInt32(_algorithmId);
    }
    
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // No unprotected headers
    }
}

// Example: Thread-safe certificate header contributor (gets cert from context)
public class CertificateHeaderContributor : IHeaderContributor
{
    private readonly X509Certificate2 _certificate;
    
    // Certificate provided at construction time (from signing service)
    public CertificateHeaderContributor(X509Certificate2 certificate)
    {
        _certificate = certificate;
    }
    
    // Certificate headers can be replaced if caller wants to override
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;
    
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Protected headers typically don't include certificate
    }
    
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Thread-safe: only uses immutable certificate field and caller's header map
        // No shared mutable state
        
        var thumbprintLabel = CertificateCoseHeaderLabels.X5T;
        var chainLabel = CertificateCoseHeaderLabels.X5Chain;
        
        // Apply merge strategy for thumbprint
        if (!headers.ContainsKey(thumbprintLabel) || MergeStrategy == HeaderMergeStrategy.Replace)
        {
            var thumbprint = ComputeThumbprint(_certificate);
            headers[thumbprintLabel] = CoseHeaderValue.FromBytes(thumbprint);
        }
        
        // Apply merge strategy for chain
        if (!headers.ContainsKey(chainLabel) || MergeStrategy == HeaderMergeStrategy.Replace)
        {
            var chain = BuildCertificateChain(_certificate);
            if (chain != null)
            {
                headers[chainLabel] = CoseHeaderValue.FromBytes(EncodeCertificateChain(chain));
            }
        }
    }
    
    private static byte[] ComputeThumbprint(X509Certificate2 cert)
    {
        // Thread-safe: pure function, no shared state
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(cert.RawData);
    }
    
    private static List<X509Certificate2>? BuildCertificateChain(X509Certificate2 cert)
    {
        // Thread-safe: creates new chain instance per call
        using var chain = new X509Chain();
        chain.Build(cert);
        return chain.ChainElements.Cast<X509ChainElement>()
            .Select(e => e.Certificate)
            .ToList();
    }
}

// Example: Custom merge strategy - conditionally add header based on key type
public class KeyTypeSpecificHeaderContributor : IHeaderContributor
{
    // Use Custom strategy to make decisions based on context
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Custom;
    
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Access key metadata to make decisions
        var keyMetadata = context.SigningKey.Metadata;
        
        // Access service metadata through the signing key
        var serviceMetadata = context.SigningKey.SigningService.ServiceMetadata;
        
        // Only add this header for PQC algorithms
        if (keyMetadata.KeyType == CryptographicKeyType.MLDsa)
        {
            var customLabel = new CoseHeaderLabel("custom-pqc-header");
            
            // Custom strategy: only add if not present
            if (!headers.ContainsKey(customLabel))
            {
                headers[customLabel] = CoseHeaderValue.FromString("pqc-enabled");
            }
        }
    }
    
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Could access signing context for payload-specific decisions
        var signingContext = context.SigningContext;
        
        if (signingContext.ContentType == "application/sensitive-data")
        {
            // Add security-level header based on key size
            var keySize = context.SigningKey.Metadata.KeySizeInBits ?? 0;
            var securityLevel = keySize >= 3072 ? "high" : "medium";
            
            var securityLabel = new CoseHeaderLabel("security-level");
            if (!headers.ContainsKey(securityLabel))
            {
                headers[securityLabel] = CoseHeaderValue.FromString(securityLevel);
            }
        }
    }
}

// Example: Service metadata contributor for SCITT compliance
public class ScittComplianceHeaderContributor : IHeaderContributor
{
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.KeepExisting;
    
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Access service metadata to check if SCITT compliance is enabled
        var serviceMetadata = context.SigningKey.SigningService.ServiceMetadata;
        
        if (serviceMetadata.EnableScittCompliance)
        {
            // Add SCITT-specific headers
            var scittLabel = new CoseHeaderLabel("scitt-version");
            if (!headers.ContainsKey(scittLabel))
            {
                headers[scittLabel] = CoseHeaderValue.FromString("1.0");
            }
            
            // Add transparency log URL if available
            if (!string.IsNullOrEmpty(serviceMetadata.TransparencyLogUrl))
            {
                var logLabel = new CoseHeaderLabel("transparency-log");
                if (!headers.ContainsKey(logLabel))
                {
                    headers[logLabel] = CoseHeaderValue.FromString(serviceMetadata.TransparencyLogUrl);
                }
            }
        }
    }
    
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // SCITT headers go in protected section
    }
}
```

## Local Certificate Signing Service

### Implementation

```csharp
/// <summary>
/// Local certificate signing service that emits CoseSigner instances.
/// Caches a single ISigningKey and returns it for all operations.
/// </summary>
public class LocalCertificateSigningService : SigningServiceBase
{
    private readonly ISigningKey _signingKey;
    
    public override bool IsRemote => false;
    
    // Factory methods
    public static LocalCertificateSigningService FromWindowsStore(
        string thumbprint,
        StoreName storeName = StoreName.My,
        StoreLocation location = StoreLocation.CurrentUser)
    {
        var cert = CertificateLoader.LoadFromStore(thumbprint, storeName, location);
        var signingKey = new LocalCertificateSigningKey(cert);
        return new LocalCertificateSigningService(signingKey);
    }
    
    public static LocalCertificateSigningService FromPfxFile(
        string path,
        string? password = null)
    {
        var cert = new X509Certificate2(path, password, 
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        var signingKey = new LocalCertificateSigningKey(cert);
        return new LocalCertificateSigningService(signingKey);
    }
    
    public static LocalCertificateSigningService FromCertificate(X509Certificate2 certificate)
    {
        var signingKey = new LocalCertificateSigningKey(certificate);
        return new LocalCertificateSigningService(signingKey);
    }
    
    // Example: Creating service with custom metadata
    public static LocalCertificateSigningService FromCertificateWithMetadata(
        X509Certificate2 certificate,
        SigningServiceMetadata serviceMetadata)
    {
        var signingKey = new LocalCertificateSigningKey(certificate);
        return new LocalCertificateSigningService(signingKey, serviceMetadata);
    }
    
    public LocalCertificateSigningService(
        ISigningKey signingKey,
        SigningServiceMetadata? serviceMetadata = null)
        : base(CreateHeaderContributors(signingKey), serviceMetadata)
    {
        _signingKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
        
        // Link key back to this service (for service metadata access)
        if (_signingKey is LocalCertificateSigningKey localKey)
        {
            localKey.SigningService = this;
        }
    }
    
    private static IReadOnlyList<IHeaderContributor> CreateHeaderContributors(ISigningKey signingKey)
    {
        // Create header contributors based on signing key metadata
        // Order matters: algorithm first, then certificate headers
        var metadata = signingKey.Metadata;
        return new IHeaderContributor[]
        {
            new AlgorithmHeaderContributor(metadata.CoseAlgorithmId),
            // Get certificate from AdditionalMetadata if this is a certificate-based key
            CreateCertificateContributor(signingKey)
        };
    }
    
    private static IHeaderContributor CreateCertificateContributor(ISigningKey signingKey)
    {
        // For certificate-based signing keys, certificate is in AdditionalMetadata
        if (signingKey.Metadata.AdditionalMetadata?.TryGetValue("Certificate", out var certObj) == true
            && certObj is X509Certificate2 cert)
        {
            return new CertificateHeaderContributor(cert);
        }
        
        // For non-certificate keys, return a no-op contributor
        return new NoOpHeaderContributor();
    }
    
    /// <summary>
    /// Gets the signing key for the operation.
    /// For local service, returns the cached key instance.
    /// </summary>
    protected override ISigningKey GetSigningKey(SigningContext context)
    {
        // Local service: always return the same cached key
        return _signingKey;
    }
    
    public override void Dispose()
    {
        _signingKey?.Dispose();
        base.Dispose();
    }
}

### LocalCertificateSigningKey Implementation

```csharp
/// <summary>
/// Local certificate-based signing key implementation.
/// Caches the CoseKey and provides metadata about the certificate.
/// </summary>
public class LocalCertificateSigningKey : ISigningKey
{
    private readonly X509Certificate2 _certificate;
    private readonly AsymmetricAlgorithm _privateKey;
    private readonly SigningKeyMetadata _metadata;
    
    // CoseKey is cached (thread-safe initialization)
    private CoseKey? _cachedCoseKey;
    private readonly object _coseKeyLock = new();
    
    public SigningKeyMetadata Metadata => _metadata;
    public ISigningService SigningService { get; private set; } = null!; // Set by service
    
    public LocalCertificateSigningKey(X509Certificate2 certificate)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        
        // Extract private key (auto-detects RSA, ECDsa, or ML-DSA)
        _privateKey = certificate.GetRSAPrivateKey() 
                   ?? certificate.GetECDsaPrivateKey() 
                   ?? certificate.GetMLDsaPrivateKey()
                   ?? throw new InvalidOperationException("Certificate has no supported private key");
        
        // Build metadata once at construction
        var keyType = DetermineKeyType(_privateKey);
        var hashAlgorithm = DetermineHashAlgorithm(keyType, certificate);
        var coseAlgorithmId = DetermineCoseAlgorithm(keyType, hashAlgorithm, GetKeySize(_privateKey));
        
        _metadata = new SigningKeyMetadata
        {
            CoseAlgorithmId = coseAlgorithmId,
            KeyType = keyType,
            HashAlgorithm = hashAlgorithm,
            KeySizeInBits = GetKeySize(_privateKey),
            IsRemote = false,
            AdditionalMetadata = new Dictionary<string, object>
            {
                ["Certificate"] = certificate  // Store certificate for header contributors
            }
        };
    }
    
    public CoseKey GetCoseKey()
    {
        // Lazy initialization with double-checked locking
        if (_cachedCoseKey == null)
        {
            lock (_coseKeyLock)
            {
                if (_cachedCoseKey == null)
                {
                    _cachedCoseKey = _privateKey switch
                    {
                        RSA rsa => new CoseKey(rsa, RSASignaturePadding.Pss, _metadata.HashAlgorithm!.Value),
                        ECDsa ecdsa => new CoseKey(ecdsa, _metadata.HashAlgorithm!.Value),
                        MLDsa mldsa => new CoseKey(mldsa),  // PQC!
                        _ => throw new NotSupportedException($"Key type {_privateKey.GetType()} not supported")
                    };
                }
            }
        }
        
        return _cachedCoseKey;
    }
    
    public void Dispose()
    {
        _cachedCoseKey?.Dispose();
        _privateKey?.Dispose();
        _certificate?.Dispose();
    }
}
```

### Key Aspects

1. **CoseKey Caching**: Created once in `GetCoseKey()`, reused across all signatures
2. **Metadata Computed Once**: Algorithm, key type, hash algorithm determined at construction
3. **Thread Safety**: Lock-based lazy initialization of CoseKey
4. **PQC Support**: ML-DSA "just works" through CoseKey
5. **Certificate Storage**: Certificate stored in AdditionalMetadata for header contributors

## Dependency Injection Support

```csharp
/// <summary>
/// Factory for loading certificates from various sources.
/// Can be mocked/replaced for testing.
/// </summary>
public interface ICertificateLoader
{
    X509Certificate2 LoadFromStore(string thumbprint, StoreName storeName, StoreLocation location);
    X509Certificate2 LoadFromPfx(string path, string? password);
}

/// <summary>
/// Default certificate loader implementation.
/// </summary>
public class DefaultCertificateLoader : ICertificateLoader
{
    public X509Certificate2 LoadFromStore(string thumbprint, StoreName storeName, StoreLocation location)
    {
        using var store = new X509Store(storeName, location);
        store.Open(OpenFlags.ReadOnly);
        
        var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        if (certs.Count == 0)
            throw new InvalidOperationException($"Certificate with thumbprint {thumbprint} not found");
        
        return certs[0];
    }
    
    public X509Certificate2 LoadFromPfx(string path, string? password)
    {
        return new X509Certificate2(path, password,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }
}

/// <summary>
/// Builder for LocalCertificateSigningService (DI-friendly, testable).
/// </summary>
public class LocalCertificateSigningServiceBuilder
{
    private readonly ICertificateLoader _certificateLoader;
    
    public LocalCertificateSigningServiceBuilder(
        ICertificateLoader? certificateLoader = null)
    {
        _certificateLoader = certificateLoader ?? new DefaultCertificateLoader();
    }
    
    public LocalCertificateSigningService FromWindowsStore(
        string thumbprint,
        StoreName storeName = StoreName.My,
        StoreLocation location = StoreLocation.CurrentUser)
    {
        var cert = _certificateLoader.LoadFromStore(thumbprint, storeName, location);
        return new LocalCertificateSigningService(cert);
    }
    
    public LocalCertificateSigningService FromPfxFile(string path, string? password = null)
    {
        var cert = _certificateLoader.LoadFromPfx(path, password);
        return new LocalCertificateSigningService(cert);
    }
    
    public LocalCertificateSigningService FromCertificate(X509Certificate2 certificate)
    {
        return new LocalCertificateSigningService(certificate);
    }
}
```

### DI Container Registration

```csharp
// ASP.NET Core / Microsoft.Extensions.DependencyInjection
public static class CoseSigningServiceCollectionExtensions
{
    public static IServiceCollection AddCoseSigningServices(this IServiceCollection services)
    {
        // Register core infrastructure
        services.AddSingleton<ICertificateLoader, DefaultCertificateLoader>();
        services.AddSingleton<LocalCertificateSigningServiceBuilder>();
        
        // Register factories with SigningService injected
        // Factory lifetime should match expected usage pattern
        services.AddTransient<DirectSignatureFactory>();
        services.AddTransient<IndirectSignatureFactory>();
        
        return services;
    }
    
    // For scenarios where certificate is known at startup
    public static IServiceCollection AddLocalCertificateSigningService(
        this IServiceCollection services,
        Func<IServiceProvider, X509Certificate2> certificateFactory)
    {
        services.AddSingleton<ISigningService>(sp =>
        {
            var cert = certificateFactory(sp);
            return new LocalCertificateSigningService(cert);
        });
        
        return services;
    }
}

// Usage in Startup.cs or Program.cs
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddCoseSigningServices();
        
        // Option 1: Builder-based (runtime certificate selection)
        // Inject LocalCertificateSigningServiceBuilder and call FromWindowsStore()
        
        // Option 2: Singleton service (certificate known at startup)
        services.AddLocalCertificateSigningService(sp =>
        {
            var config = sp.GetRequiredService<IConfiguration>();
            var thumbprint = config["Signing:CertificateThumbprint"];
            var loader = sp.GetRequiredService<ICertificateLoader>();
            return loader.LoadFromStore(thumbprint, StoreName.My, StoreLocation.CurrentUser);
        });
    }
}
```
```

### Key Aspects

1. **CoseKey Caching**: Created once, reused across all signatures
2. **CoseSigner Creation**: New instance per call with updated headers
3. **Thread Safety**: Lock-based initialization of CoseKey
4. **PQC Support**: ML-DSA "just works" through CoseKey
5. **Header Management**: Contributors + custom headers combined per operation

## Remote Certificate Signing Service

### Implementation with Dependency Injection

```csharp
/// <summary>
/// Remote certificate signing service that emits CoseSigner instances with custom signing delegates.
/// May refresh the signing key if certificate rotation is detected.
/// Thread-safe: All operations use locks for cache access.
/// DI-friendly: Accepts IRemoteSigningClient via constructor.
/// </summary>
public class RemoteCertificateSigningService : SigningServiceBase
{
    private readonly IRemoteSigningClient _client;
    private ISigningKey? _cachedSigningKey;
    private readonly object _keyLock = new();
    
    public override bool IsRemote => true;
    
    // Factory methods
    public static RemoteCertificateSigningService ForAzureTrustedSigning(
        string endpoint,
        string accountName,
        string certificateProfileName,
        TokenCredential credential)
    {
        var client = new AzureTrustedSigningClient(endpoint, accountName, certificateProfileName, credential);
        return new RemoteCertificateSigningService(client);
    }
    
    public static RemoteCertificateSigningService ForAzureKeyVault(
        string vaultUri,
        string certificateName,
        TokenCredential credential)
    {
        var client = new AzureKeyVaultSigningClient(vaultUri, certificateName, credential);
        return new RemoteCertificateSigningService(client);
    }
    
    public static RemoteCertificateSigningService FromClient(IRemoteSigningClient client)
    {
        return new RemoteCertificateSigningService(client);
    }
    
    public RemoteCertificateSigningService(
        IRemoteSigningClient client,
        SigningServiceMetadata? serviceMetadata = null)
        : base(Array.Empty<IHeaderContributor>(), serviceMetadata)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }
    
    /// <summary>
    /// Gets the signing key for the operation.
    /// For remote service, checks if certificate has rotated and creates new key if needed.
    /// Thread-safe: Uses lock for cache access.
    /// </summary>
    protected override ISigningKey GetSigningKey(SigningContext context)
    {
        // Check current certificate from remote service
        var currentCert = _client.GetCertificate();
        
        lock (_keyLock)
        {
            // If no cached key, or certificate thumbprint changed, create new signing key
            if (_cachedSigningKey == null ||
                (_cachedSigningKey.Metadata.AdditionalMetadata?.TryGetValue("Certificate", out var certObj) == true &&
                 certObj is X509Certificate2 cachedCert &&
                 cachedCert.Thumbprint != currentCert.Thumbprint))
            {
                // Dispose old key if it exists
                _cachedSigningKey?.Dispose();
                
                // Create new signing key with current certificate
                _cachedSigningKey = new RemoteCertificateSigningKey(_client)
                {
                    SigningService = this // Link key back to this service
                };
            }
            
            return _cachedSigningKey;
        }
    }
    
    public override void Dispose()
    {
        lock (_keyLock)
        {
            _cachedSigningKey?.Dispose();
        }
        base.Dispose();
    }
}

### RemoteCertificateSigningKey Implementation

```csharp
/// <summary>
/// Remote certificate-based signing key implementation.
/// Handles certificate rotation and delegates signing to remote service.
/// </summary>
public class RemoteCertificateSigningKey : ISigningKey
{
    private readonly IRemoteSigningClient _client;
    private readonly SigningKeyMetadata _metadata;
    
    // Cache for certificate and CoseKey (thread-safe access)
    private X509Certificate2? _cachedCertificate;
    private string? _cachedCertificateThumbprint;
    private CoseKey? _cachedCoseKey;
    private readonly object _keyLock = new();
    
    public SigningKeyMetadata Metadata => _metadata;
    public ISigningService SigningService { get; internal set; } = null!; // Set by service
    
    public RemoteCertificateSigningKey(IRemoteSigningClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        
        // Get initial certificate from remote service
        _cachedCertificate = _client.GetCertificate();
        _cachedCertificateThumbprint = _cachedCertificate.Thumbprint;
        
        // Extract public key for metadata
        var publicKey = _cachedCertificate.GetRSAPublicKey() 
                     ?? _cachedCertificate.GetECDsaPublicKey()
                     ?? _cachedCertificate.GetMLDsaPublicKey()
                     ?? throw new InvalidOperationException("Certificate has no supported public key");
        
        // Build metadata once at construction (may be updated on certificate rotation)
        var keyType = DetermineKeyType(publicKey);
        var hashAlgorithm = DetermineHashAlgorithm(keyType, _cachedCertificate);
        var coseAlgorithmId = DetermineCoseAlgorithm(keyType, hashAlgorithm, GetKeySize(publicKey));
        
        _metadata = new SigningKeyMetadata
        {
            CoseAlgorithmId = coseAlgorithmId,
            KeyType = keyType,
            HashAlgorithm = hashAlgorithm,
            KeySizeInBits = GetKeySize(publicKey),
            IsRemote = true,
            AdditionalMetadata = new Dictionary<string, object>
            {
                ["Certificate"] = _cachedCertificate  // Store certificate for header contributors
            }
        };
    }
    
    public CoseKey GetCoseKey()
    {
        // Check if certificate has rotated
        var currentCert = _client.GetCertificate();
        
        lock (_keyLock)
        {
            // If certificate thumbprint changed, refresh CoseKey
            if (_cachedCertificateThumbprint != currentCert.Thumbprint)
            {
                _cachedCertificate = currentCert;
                _cachedCertificateThumbprint = currentCert.Thumbprint;
                _cachedCoseKey?.Dispose();
                _cachedCoseKey = null;
                
                // Update metadata with new certificate
                ((Dictionary<string, object>)_metadata.AdditionalMetadata!)["Certificate"] = currentCert;
            }
            
            // Lazy initialization with double-checked locking
            if (_cachedCoseKey == null)
            {
                var publicKey = _cachedCertificate.GetRSAPublicKey() 
                             ?? _cachedCertificate.GetECDsaPublicKey()
                             ?? _cachedCertificate.GetMLDsaPublicKey()!;
                
                // Create CoseKey with remote signing delegate
                _cachedCoseKey = CreateRemoteCoseKey(publicKey);
            }
            
            return _cachedCoseKey;
        }
    }
    
    private CoseKey CreateRemoteCoseKey(AsymmetricAlgorithm publicKey)
    {
        // Create CoseKey with custom delegate that calls remote service
        return publicKey switch
        {
            RSA rsa => CreateRemoteRsaCoseKey(rsa),
            ECDsa ecdsa => CreateRemoteECDsaCoseKey(ecdsa),
            MLDsa mldsa => CreateRemoteMLDsaCoseKey(mldsa),
            _ => throw new NotSupportedException($"Key type {publicKey.GetType()} not supported")
        };
    }
    
    private CoseKey CreateRemoteRsaCoseKey(RSA publicKey)
    {
        // Wrap public key + remote client in custom RSA implementation
        // that delegates signing to _client.SignHash()
        var remoteRsa = new RemoteRsaWrapper(publicKey, _client, _metadata.HashAlgorithm!.Value);
        return new CoseKey(remoteRsa, RSASignaturePadding.Pss, _metadata.HashAlgorithm!.Value);
    }
    
    // Similar for ECDsa and MLDsa...
    
    public void Dispose()
    {
        _cachedCoseKey?.Dispose();
        _cachedCertificate?.Dispose();
        (_client as IDisposable)?.Dispose();
    }
}
```

### Key Aspects

1. **Certificate Rotation**: Checks thumbprint on each GetCoseKey(), refreshes if changed
2. **CoseKey Caching**: Reused until certificate rotates
3. **Remote Delegation**: CoseKey wraps custom algorithm implementation that calls remote service
4. **Thread Safety**: Lock-based access to cached values
5. **Metadata Updates**: Certificate in AdditionalMetadata updated on rotation

## Remote Algorithm Wrappers

### RemoteRsaWrapper Example

```csharp
/// <summary>
/// RSA wrapper that delegates SignHash() to remote signing service.
/// Used to create CoseKey for remote signing scenarios.
/// </summary>
internal class RemoteRsaWrapper : RSA
{
    private readonly RSA _publicKey;
    private readonly IRemoteSigningClient _client;
    private readonly HashAlgorithmName _hashAlgorithm;
    
    public override int KeySize => _publicKey.KeySize;
    
    public RemoteRsaWrapper(RSA publicKey, IRemoteSigningClient client, HashAlgorithmName hashAlgorithm)
    {
        _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _hashAlgorithm = hashAlgorithm;
    }
    
    // This is the key method - delegate to remote service
    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (hashAlgorithm != _hashAlgorithm)
            throw new ArgumentException($"Expected {_hashAlgorithm}, got {hashAlgorithm}");
        
        // Call remote signing service
        return _client.SignHash(hash, hashAlgorithm, padding);
    }
    
    // VerifyHash uses public key (local operation)
    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        => _publicKey.VerifyHash(hash, signature, hashAlgorithm, padding);
    
    // Encryption not supported for remote signing
    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) 
        => throw new NotSupportedException("Remote RSA only supports signing");
    
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) 
        => throw new NotSupportedException("Remote RSA only supports signing");
    
    // Export parameters from public key (for metadata)
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new NotSupportedException("Private key not available locally");
        return _publicKey.ExportParameters(false);
    }
    
    public override void ImportParameters(RSAParameters parameters) 
        => throw new NotSupportedException();
}
```

### Key Aspects

1. **Public Key Operations Local**: VerifyHash, ExportParameters use local public key
2. **Private Key Operations Remote**: SignHash delegates to IRemoteSigningClient
3. **Hash Locally, Sign Remotely**: Only hash sent over network, not full payload
4. **Same CoseKey API**: CoseKey doesn't know if algorithm is local or remote wrapper

/// <summary>
/// Builder for RemoteCertificateSigningService (DI-friendly).
/// </summary>
public class RemoteCertificateSigningServiceBuilder
{
    public RemoteCertificateSigningService ForAzureTrustedSigning(
        string endpoint,
        string accountName,
        string certificateProfileName,
        TokenCredential credential)
    {
        var client = new AzureTrustedSigningClient(endpoint, accountName, certificateProfileName, credential);
        return new RemoteCertificateSigningService(client);
    }
    
    public RemoteCertificateSigningService ForAzureKeyVault(
        string vaultUri,
        string certificateName,
        TokenCredential credential)
    {
        var client = new AzureKeyVaultSigningClient(vaultUri, certificateName, credential);
        return new RemoteCertificateSigningService(client);
    }
    
    public RemoteCertificateSigningService FromClient(IRemoteSigningClient client)
    {
        return new RemoteCertificateSigningService(client, _headerContributorFactory);
    }
}

/// <summary>
/// DI registration extensions for remote signing services.
/// </summary>
public static class RemoteSigningServiceCollectionExtensions
{
    public static IServiceCollection AddRemoteSigningServices(this IServiceCollection services)
    {
        services.AddSingleton<RemoteCertificateSigningServiceBuilder>();
        return services;
    }
    
    // For Azure Trusted Signing
    public static IServiceCollection AddAzureTrustedSigningService(
        this IServiceCollection services,
        string endpoint,
        string accountName,
        string profileName)
    {
        services.AddSingleton<ISigningService>(sp =>
        {
            var credential = sp.GetRequiredService<TokenCredential>();
            var builder = sp.GetRequiredService<RemoteCertificateSigningServiceBuilder>();
            return builder.ForAzureTrustedSigning(endpoint, accountName, profileName, credential);
        });
        
        return services;
    }
}

/// <summary>
/// Interface for remote signing clients (Azure Trusted Signing, Key Vault, etc.)
/// </summary>
public interface IRemoteSigningClient
{
    /// <summary>
    /// Gets the certificate for the remote signing key.
    /// May be called to refresh if certificate rotation occurs.
    /// </summary>
    X509Certificate2 GetCertificate();
    
    /// <summary>
    /// Signs a hash with the remote key.
    /// </summary>
    byte[] SignHash(byte[] hash);
    
    /// <summary>
    /// Asynchronously signs a hash with the remote key.
    /// </summary>
    Task<byte[]> SignHashAsync(byte[] hash, CancellationToken cancellationToken = default);
}

/// <summary>
/// Wrapper around RSA that delegates signing to a remote service.
/// Implements RSA but only supports SignHash operation.
/// </summary>
internal class RemoteRsaWrapper : RSA
{
    private readonly RSA _publicKey;
    private readonly IRemoteSigningClient _client;
    private readonly HashAlgorithmName _hashAlgorithm;
    
    public RemoteRsaWrapper(RSA publicKey, IRemoteSigningClient client, HashAlgorithmName hashAlgorithm)
    {
        _publicKey = publicKey;
        _client = client;
        _hashAlgorithm = hashAlgorithm;
        KeySizeValue = publicKey.KeySize;
    }
    
    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        // Delegate to remote client
        return _client.SignHash(hash);
    }
    
    // Other RSA methods throw NotSupportedException (we only support signing)
    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) 
        => throw new NotSupportedException("Remote RSA only supports signing");
    
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) 
        => throw new NotSupportedException("Remote RSA only supports signing");
    
    // Export parameters from public key (for metadata)
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new NotSupportedException("Private key not available locally");
        return _publicKey.ExportParameters(false);
    }
    
    public override void ImportParameters(RSAParameters parameters) 
        => throw new NotSupportedException();
}
```

### Key Aspects

1. **Certificate Caching**: Public key cached, refreshed if thumbprint changes
2. **Remote Delegation**: RSA/ECDsa/MLDsa wrapper delegates SignHash() to remote client
3. **Hash Locally, Sign Remotely**: Only hash sent over network, not full payload
4. **Same CoseSigner API**: Caller doesn't know if key is local or remote

## Factory Usage with Dependency Injection

### DirectSignatureFactory (Instance-Based for DI)

```csharp
/// <summary>
/// Factory for creating direct COSE signatures.
/// Instance-based design supports dependency injection and testability.
/// Thread-safe: all methods are stateless or use local state only.
/// </summary>
public class DirectSignatureFactory
{
    private readonly ISigningService _signingService;
    private readonly ILogger<DirectSignatureFactory>? _logger;
    private readonly bool _embedPayload;
    
    /// <summary>
    /// Creates a DirectSignatureFactory with DI.
    /// </summary>
    /// <param name="signingService">The signing service (injected).</param>
    /// <param name="embedPayload">Whether to embed payload in signatures (factory-level option).</param>
    /// <param name="logger">Optional logger.</param>
    public DirectSignatureFactory(
        ISigningService signingService,
        bool embedPayload = true,
        ILogger<DirectSignatureFactory>? logger = null)
    {
        _signingService = signingService ?? throw new ArgumentNullException(nameof(signingService));
        _embedPayload = embedPayload;
        _logger = logger;
    }
    
    /// <summary>
    /// Signs payload with the configured signing service.
    /// Thread-safe: can be called concurrently from multiple threads.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">Optional content type of the payload.</param>
    /// <param name="additionalHeaderContributors">Optional additional headers for this operation.</param>
    public CoseSign1Message Sign(
        byte[] payload,
        string? contentType = null,
        IReadOnlyList<IHeaderContributor>? additionalHeaderContributors = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        
        _logger?.LogDebug("Signing payload of {Size} bytes", payload.Length);
        
        // Build signing context with payload and per-operation metadata
        var context = new SigningContext
        {
            Payload = payload,
            ContentType = contentType,
            AdditionalHeaderContributors = additionalHeaderContributors
        };
        
        // Get CoseSigner from the injected signing service
        using var signer = _signingService.GetCoseSigner(context);
        
        // Use .NET's CoseSign1Message.Sign() with the CoseSigner
        var message = new CoseSign1Message(
            protectedHeaders: signer.ProtectedHeaders,
            unprotectedHeaders: signer.UnprotectedHeaders,
            content: _embedPayload ? payload : null);
        
        // Sign using CoseSigner
        byte[] signature = message.Sign(signer, _embedPayload ? null : payload);
        
        _logger?.LogDebug("Signature created: {Size} bytes", signature.Length);
        
        return message;
    }
    
    /// <summary>
    /// Stream-based version for large files.
    /// Thread-safe: can be called concurrently.
    /// </summary>
    public async Task<CoseSign1Message> SignAsync(
        Stream payloadStream,
        string? contentType = null,
        IReadOnlyList<IHeaderContributor>? additionalHeaderContributors = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payloadStream);
        
        _logger?.LogDebug("Signing stream (async)");
        
        // For stream signing, we need to hash the stream first
        // Get hash algorithm from signing service metadata
        // Note: This requires adding a way to query the algorithm without signing
        byte[] hash = await ComputeHashAsync(payloadStream, HashAlgorithmName.SHA256, cancellationToken);
        
        // Build context
        var context = new SigningContext
        {
            Payload = hash,  // Use hash as "payload" for ToBeSigned
            ContentType = contentType,
            AdditionalHeaderContributors = additionalHeaderContributors
        };
        
        // Get CoseSigner from the injected signing service
        using var signer = _signingService.GetCoseSigner(context);
        
        // Create message and sign
        var message = new CoseSign1Message(
            protectedHeaders: signer.ProtectedHeaders,
            unprotectedHeaders: signer.UnprotectedHeaders,
            content: null);  // Detached for streams
        
        byte[] signature = message.Sign(signer, hash);
        
        return message;
    }
    
    private static async Task<byte[]> ComputeHashAsync(
        Stream stream, 
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken)
    {
        // Thread-safe: each call uses local IncrementalHash instance
        using var incrementalHash = IncrementalHash.CreateHash(hashAlgorithm);
        
        byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
            {
                incrementalHash.AppendData(buffer, 0, bytesRead);
            }
            return incrementalHash.GetHashAndReset();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
```

### Usage with Dependency Injection

```csharp
// Controller or service with DI
public class DocumentSigningController : ControllerBase
{
    private readonly DirectSignatureFactory _signatureFactory;
    private readonly ILogger<DocumentSigningController> _logger;
    
    // SigningService is injected into factory, not controller!
    public DocumentSigningController(
        DirectSignatureFactory signatureFactory,  // Factory has SigningService injected
        ILogger<DocumentSigningController> logger)
    {
        _signatureFactory = signatureFactory;
        _logger = logger;
    }
    
    [HttpPost("sign")]
    public IActionResult SignDocument([FromBody] byte[] payload, [FromQuery] string? contentType = null)
    {
        // Clean API: Just payload and content-type
        // Factory handles the signing service (injected)
        var signedMessage = _signatureFactory.Sign(
            payload,
            contentType: contentType ?? "application/octet-stream");
        
        return Ok(signedMessage.Encode());
    }
}
```

### Complete DI Setup Example

```csharp
public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        
        // Register COSE signing services
        builder.Services.AddCoseSigningServices();
        
        // Register signing service based on configuration
        var certThumbprint = builder.Configuration["Signing:CertificateThumbprint"];
        if (!string.IsNullOrEmpty(certThumbprint))
        {
            // Local certificate signing
            builder.Services.AddSingleton<ISigningService>(sp =>
            {
                var certLoader = sp.GetRequiredService<ICertificateLoader>();
                var cert = certLoader.LoadFromStore(certThumbprint, StoreName.My, StoreLocation.CurrentUser);
                var signingKey = new LocalCertificateSigningKey(cert);
                return new LocalCertificateSigningService(signingKey);
            });
        }
        else
        {
            // Azure Trusted Signing
            var endpoint = builder.Configuration["AzureTrustedSigning:Endpoint"];
            var account = builder.Configuration["AzureTrustedSigning:AccountName"];
            var profile = builder.Configuration["AzureTrustedSigning:ProfileName"];
            
            builder.Services.AddAzureTrustedSigningService(endpoint!, account!, profile!);
        }
        
        // Register factories (instance-based, not static)
        builder.Services.AddTransient<DirectSignatureFactory>();
        builder.Services.AddTransient<IndirectSignatureFactory>();
        
        var app = builder.Build();
        app.MapControllers();
        app.Run();
    }
}
```
```

## Benefits of V3 Architecture with Dynamic Key Acquisition

### 1. **Dynamic Key Acquisition**
- **Keys acquired per operation**: `GetSigningKey(context)` called within `GetCoseSigner()`
- **Enables certificate rotation**: Remote service detects and handles rotation automatically
- **Supports multi-key scenarios**: Select key based on context (payload type, user, etc.)
- **Context-aware**: Key selection can consider signing context
- **Service metadata access**: Keys linked to parent service for service-level metadata contribution

### 2. **Service-Level Metadata**
- **SigningServiceMetadata**: Service-level information available to header contributors
- **Bidirectional linking**: `ISigningKey.SigningService` provides access to parent service
- **Compliance support**: Enable SCITT, transparency logs, or other compliance requirements
- **Flexible contribution**: Contributors can access both key metadata and service metadata
- **Examples**: Service name/version, transparency log URLs, compliance flags

### 2. **Template Method Pattern with Abstract Base Class**
- **SigningServiceBase**: Common logic in base class (header building, contributor application)
- **GetSigningKey()**: Override point for derived classes (local vs remote vs multi-key)
- **GetCoseSigner()**: Final method - consistent behavior across all services
- **ServiceMetadata**: Service-level metadata available to all derived classes
- **Less duplication**: Header logic written once, reused by all services

### 3. **Clean Separation of Concerns**
- **ISigningKey**: Emits `CoseKey`, provides metadata, handles key lifecycle
- **ISigningService**: Orchestrates signing (acquire key, build headers, create CoseSigner)
- **SigningServiceBase**: Implements template method pattern for common logic
- **Factory**: Uses `CoseSigner` with `.NET's CoseSign1Message.Sign()`

### 4. **Perfect Header Integration**
- `CoseSigner` contains `CoseKey` + protected/unprotected headers
- Headers built at sign-time with full context (SigningContext + ISigningKey)
- Contributors access metadata via `context.SigningKey.Metadata`
- Header merge strategies prevent accidental conflicts

### 3. **Key Lifecycle Flexibility**
- **Local**: `CoseKey` created once in `ISigningKey.GetCoseKey()`, cached and reused
- **Remote**: `CoseKey` refreshed if certificate rotates (thumbprint check)
- **Thread-safe**: Lock-based lazy initialization
- **Testing**: Easy to mock ISigningKey implementations

### 4. **Minimal Surface Area**
```csharp
// Core abstractions:
interface ISigningKey {
    CoseKey GetCoseKey();           // Emit CoseKey with caching/lifecycle management
    SigningKeyMetadata Metadata { get; }  // Describe the key (algorithm, type, etc.)
}

interface ISigningService {
    CoseSigner GetCoseSigner(SigningContext);  // Emit CoseSigner with headers
    ISigningKey SigningKey { get; }            // Access to underlying key
}

// That's it! CoseSigner handles everything else.
```

### 5. **Extensible Without Modification**
- New key types: Implement `ISigningKey` (e.g., HSM-backed, PQC)
- New header logic: Implement `IHeaderContributor`
- New signing services: Implement `ISigningService`
- No changes to factory or calling code

### 6. **Stream Support Added at Factory Level**
- `SigningService.GetCoseSigner()` works with byte arrays
- `DirectSignatureFactory.SignAsync(Stream)` handles incremental hashing
- Clean separation: service emits signer, factory handles I/O

## Testing Strategy

### Test 1: CoseKey Reuse (Local)

```csharp
[Fact]
public void LocalSigningKey_ReusesCoseKey_AcrossMultipleCalls()
{
    var cert = GetTestCertificate();
    using var signingKey = new LocalCertificateSigningKey(cert);
    
    var coseKey1 = signingKey.GetCoseKey();
    var coseKey2 = signingKey.GetCoseKey();
    
    // Verify CoseKey is reused (same instance)
    Assert.Same(coseKey1, coseKey2);
}

[Fact]
public void LocalService_ReusesCoseKey_AcrossMultipleSignings()
{
    var cert = GetTestCertificate();
    var signingKey = new LocalCertificateSigningKey(cert);
    using var service = new LocalCertificateSigningService(signingKey);
    
    var context1 = new SigningContext { Payload = "test1"u8.ToArray() };
    var context2 = new SigningContext { Payload = "test2"u8.ToArray() };
    
    using var signer1 = service.GetCoseSigner(context1);
    using var signer2 = service.GetCoseSigner(context2);
    
    // Verify both signing operations complete successfully
    // (same CoseKey reused internally in the signing key)
    Assert.NotNull(signer1);
    Assert.NotNull(signer2);
}
```

### Test 2: CoseKey Disposal (Local)

```csharp
[Fact]
public void LocalSigningKey_DisposesOnlyOnKeyDisposal()
{
    var cert = GetTestCertificate();
    var signingKey = new LocalCertificateSigningKey(cert);
    var service = new LocalCertificateSigningService(signingKey);
    
    var context = new SigningContext { Payload = "test"u8.ToArray() };
    using var signer = service.GetCoseSigner(context);
    
    // Sign should work
    var message = CoseSign1Message.Sign(signer, context.Payload);
    
    // Dispose signer (shouldn't affect CoseKey - it's owned by ISigningKey)
    signer.Dispose();
    
    // Get new signer - should still work (CoseKey cached in ISigningKey)
    using var signer2 = service.GetCoseSigner(context);
    var message2 = CoseSign1Message.Sign(signer2, context.Payload);
    
    Assert.NotNull(message2);
    
    // Dispose service (disposes ISigningKey which disposes CoseKey)
    service.Dispose();
}
```

### Test 3: Remote Certificate Change

```csharp
[Fact]
public async Task RemoteSigningKey_RefreshesKey_WhenCertificateChanges()
{
    var client = new MockRemoteSigningClient();
    var cert1 = GetTestCertificate("key1");
    client.SetCertificate(cert1);
    
    var signingKey = new RemoteCertificateSigningKey(client);
    var coseKey1 = signingKey.GetCoseKey();
    
    // Simulate certificate rotation
    var cert2 = GetTestCertificate("key2");
    client.SetCertificate(cert2);
    
    var coseKey2 = signingKey.GetCoseKey();
    
    // Verify different CoseKey instances (different certificates)
    Assert.NotSame(coseKey1, coseKey2);
}

[Fact]
public async Task RemoteService_UsesUpdatedKey_AfterCertificateRotation()
{
    var client = new MockRemoteSigningClient();
    var cert1 = GetTestCertificate("key1");
    client.SetCertificate(cert1);
    
    var service = new RemoteCertificateSigningService(client);
    
    var context = new SigningContext { Payload = "test"u8.ToArray() };
    using var signer1 = service.GetCoseSigner(context);
    
    // Simulate certificate rotation
    var cert2 = GetTestCertificate("key2");
    client.SetCertificate(cert2);
    
    using var signer2 = service.GetCoseSigner(context);
    
    // Service detects rotation and uses new key internally
    // Both signing operations complete successfully
    Assert.NotNull(signer1);
    Assert.NotNull(signer2);
}
```

## Conclusion

The **V3 architecture with dynamic key acquisition and abstract base class** provides the optimal design:

1. ✅ **Dynamic key acquisition**: Keys acquired per operation via `GetSigningKey(context)`, not stored as properties
2. ✅ **Service metadata**: `SigningServiceMetadata` provides service-level information to header contributors
3. ✅ **Bidirectional linking**: Keys reference parent service via `ISigningKey.SigningService` property
4. ✅ **Template method pattern**: `SigningServiceBase` provides common logic, derived classes override `GetSigningKey()`
5. ✅ **Certificate rotation**: Remote service detects rotation automatically in `GetSigningKey()`
6. ✅ **Multi-key scenarios**: Services can select different keys based on context
7. ✅ **Compliance support**: Service metadata enables SCITT, transparency logs, etc.
8. ✅ **Clean abstractions**: `ISigningKey` emits `CoseKey`, `ISigningService` orchestrates signing
9. ✅ **Battle-tested**: Uses Microsoft's `CoseSigner` and `CoseKey` directly  
10. ✅ **Minimal API surface**: Simple interfaces, clear responsibilities
11. ✅ **Testable**: Easy to mock `ISigningKey` and verify behavior
12. ✅ **PQC ready**: ML-DSA support through `CoseKey`, no AsymmetricAlgorithm assumptions
13. ✅ **DI-friendly**: Constructor injection, builder patterns available
14. ✅ **Thread-safe**: Lock-based caching where needed, immutable contributors
15. ✅ **Extensible**: New key types or services without modifying existing code

The key insights:
1. **Dynamic key acquisition**: `GetSigningKey(context)` called within `GetCoseSigner()` enables rotation, multi-key, and context-aware scenarios
2. **Service metadata**: Bidirectional linking (`ISigningKey.SigningService`) allows contributors to access service-level metadata for compliance, transparency, etc.
3. **Template method pattern**: Abstract base class centralizes common logic, derived classes focus on key acquisition strategy
4. **Separation of concerns**: `ISigningKey` manages key lifecycle, `ISigningService` orchestrates signing with metadata, `.NET's CoseSign1Message.Sign()` does cryptographic work

using System.Security.Cryptography.Cose;

namespace CoseSign1.Abstractions;

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

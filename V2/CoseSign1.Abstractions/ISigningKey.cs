// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions;

/// <summary>
/// Represents a cryptographic signing key that can emit CoseKey instances.
/// This is the minimal abstraction for key material - implementations handle
/// key lifecycle (local vs remote, caching, rotation, etc.).
/// </summary>
/// <remarks>
/// <para>
/// This interface represents only the key material itself. For scenarios requiring
/// metadata or service context, use <see cref="ISigningServiceKey"/>.
/// </para>
/// <para>
/// Design rationale: Separating key material from metadata/service coupling allows:
/// <list type="bullet">
/// <item><description>Simpler abstractions where only key material is needed (e.g., signature verification)</description></item>
/// <item><description>Clear compile-time separation between key-only and service-coupled scenarios</description></item>
/// <item><description>Better testability with minimal mock requirements</description></item>
/// </list>
/// </para>
/// </remarks>
public interface ISigningKey : IDisposable
{
    /// <summary>
    /// Gets the CoseKey for signing operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For local keys: Returns cached CoseKey instance (created once, reused).
    /// For remote keys: May return cached CoseKey if public key unchanged, or new instance if rotated.
    /// </para>
    /// <para>
    /// The returned CoseKey may be disposed when the ISigningKey is disposed.
    /// Callers should not dispose the CoseKey directly.
    /// </para>
    /// </remarks>
    /// <returns>A CoseKey ready for signing operations.</returns>
    CoseKey GetCoseKey();
}

/// <summary>
/// Represents a signing key coupled to its signing service context and metadata.
/// Use this interface when you need access to key metadata or the owning signing service.
/// </summary>
/// <remarks>
/// <para>
/// This interface extends <see cref="ISigningKey"/> to add service context. Use it when:
/// <list type="bullet">
/// <item><description>You need algorithm metadata for header contribution</description></item>
/// <item><description>You need access to the owning signing service</description></item>
/// <item><description>You're building COSE headers that depend on key properties</description></item>
/// </list>
/// </para>
/// <para>
/// When only key material is needed (e.g., signature verification), prefer <see cref="ISigningKey"/>.
/// </para>
/// </remarks>
public interface ISigningServiceKey : ISigningKey
{
    /// <summary>
    /// Gets metadata about the signing key.
    /// Used by signing service to determine algorithm, create header contributors, etc.
    /// </summary>
    SigningKeyMetadata Metadata { get; }

    /// <summary>
    /// Gets the signing service that owns this key.
    /// Allows access to service-level metadata that may be needed for header contribution.
    /// </summary>
    ISigningService<SigningOptions> SigningService { get; }
}
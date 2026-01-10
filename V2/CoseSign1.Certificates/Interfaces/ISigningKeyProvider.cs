// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Interfaces;

/// <summary>
/// Provides the actual signing operation abstraction.
/// Extends <see cref="ISigningKey"/> to add metadata about whether the key is remote.
/// Separates certificate management from how signing is performed.
/// </summary>
/// <remarks>
/// Implementations:
/// <list type="bullet">
/// <item><description><see cref="Local.DirectSigningKeyProvider"/>: Uses X509Certificate2 private keys directly (local)</description></item>
/// <item><description>Remote implementations delegate to remote signing services</description></item>
/// </list>
/// </remarks>
public interface ISigningKeyProvider : ISigningKey
{
    /// <summary>
    /// Gets whether this is a remote signing provider.
    /// </summary>
    /// <remarks>
    /// When <c>true</c>, the actual signing operation is performed by a remote service.
    /// When <c>false</c>, signing uses local private key material.
    /// </remarks>
    bool IsRemote { get; }
}
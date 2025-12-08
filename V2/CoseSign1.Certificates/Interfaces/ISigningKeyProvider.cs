// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;

namespace CoseSign1.Certificates.Interfaces;

/// <summary>
/// Provides the actual signing operation abstraction.
/// Separates certificate management from how signing is performed.
/// Implementations:
/// - DirectSigningKeyProvider: Uses X509Certificate2 private keys directly (local)
/// - RemoteSigningKeyProvider: Delegates to remote signing service
/// </summary>
public interface ISigningKeyProvider : IDisposable
{
    /// <summary>
    /// Gets the CoseKey for signing operations.
    /// For local: Created from X509Certificate2 private key (RSA/ECDsa/ML-DSA)
    /// For remote: Wraps remote signing client
    /// </summary>
    /// <returns>CoseKey for signing</returns>
    CoseKey GetCoseKey();

    /// <summary>
    /// Gets whether this is a remote signing provider.
    /// </summary>
    bool IsRemote { get; }
}

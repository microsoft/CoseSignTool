// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Interfaces;

using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Provides nonblocking RSA signing for remote keys.
/// </summary>
public interface IAsyncRsaSigningKeyProvider : ICoseSigningKeyProvider
{
    /// <summary>
    /// Asynchronously prepares the certificate metadata used by the header getters and returns the public key.
    /// The caller must dispose the returned key.
    /// </summary>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>The RSA public key corresponding to the prepared signing certificate.</returns>
    Task<RSA> GetPublicKeyAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Asynchronously signs a digest of the COSE Sig_structure with the prepared signing certificate.
    /// </summary>
    /// <param name="digest">The digest to sign, not the payload digest.</param>
    /// <param name="hashAlgorithm">The algorithm used to compute the digest.</param>
    /// <param name="padding">The RSA signature padding.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>The RSA signature bytes.</returns>
    Task<byte[]> SignHashAsync(
        byte[] digest,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding,
        CancellationToken cancellationToken);
}

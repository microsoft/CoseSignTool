// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests.Common;

using CoseSign1.Certificates.Local;

/// <summary>
/// Signs with an ML-DSA private key held separately from its public-key-only certificate,
/// the way remote signing providers supply ML-DSA keys.
/// </summary>
public sealed class MLDsaTestSigningKeyProvider : X509Certificate2CoseSigningKeyProvider
{
    private readonly MLDsa PrivateKey;

    /// <summary>
    /// Creates a new <see cref="MLDsaTestSigningKeyProvider"/>.
    /// </summary>
    /// <param name="certificate">The ML-DSA certificate, without a private key.</param>
    /// <param name="privateKey">The ML-DSA private key for <paramref name="certificate"/>.</param>
    public MLDsaTestSigningKeyProvider(X509Certificate2 certificate, MLDsa privateKey)
        : base(certificate)
    {
        PrivateKey = privateKey;
    }

    /// <inheritdoc/>
    protected override MLDsa? ProvideMLDsaKey(bool publicKey = false) => publicKey ? base.ProvideMLDsaKey(publicKey) : PrivateKey;
}

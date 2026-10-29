// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Exposes an ML-DSA (FIPS 204) key for signing key providers that support post-quantum signatures.
/// </summary>
/// <remarks>
/// This is separate from <see cref="ICoseSigningKeyProvider"/> so existing implementations are unaffected.
/// The CoseSign1 message factory signs with this key when the provider returns neither an RSA nor an ECDsa key.
/// COSE ML-DSA signs the full Sig_structure (pure ML-DSA), so <see cref="ICoseSigningKeyProvider.HashAlgorithm"/>
/// does not apply to ML-DSA signatures.
/// </remarks>
public interface ISupportsMLDsaKey
{
    /// <summary>
    /// Gets the ML-DSA key used for signing or verification operations.
    /// </summary>
    /// <param name="publicKey">True to return the public key, false (default) to return the private key.</param>
    /// <returns>The ML-DSA key if present; otherwise null.</returns>
    public MLDsa? GetMLDsaKey(bool publicKey = false);
}

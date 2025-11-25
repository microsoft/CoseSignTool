// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Interface represents a KeyProvider Interface for CoseSigning
/// </summary>
public interface ICoseSigningKeyProvider
{
    /// <summary>
    /// Returns true if the signing key is RSA, false if the signing key is ECDsa.
    /// </summary>
    public bool IsRSA { get; }

    /// <summary>
    /// The hashing algorithm to use
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>
    /// Gets RSA Key used for signing or verification operations.
    /// </summary>
    /// <returns>RSA Key if present, else returns null</returns>
    public RSA? GetRSAKey(bool publicKey = false);

    /// <summary>
    /// Gets ECDsa Key used for signing or verification operations.
    /// </summary>
    /// /// <returns>ECDsa Key if present, else returns null</returns>
    public ECDsa? GetECDsaKey(bool publicKey = false);

    /// <summary>
    /// Gets the key chain representing the parents (in bottom-up order) of the RSA or ECDsa key.
    /// The first element in the list corresponds to the key returned by GetRSAKey or GetECDsaKey,
    /// and subsequent elements represent the parent keys up the chain.
    /// </summary>
    /// <returns>List of AsymmetricAlgorithm representing the key chain, or empty list if no chain is available</returns>
    public IReadOnlyList<AsymmetricAlgorithm> KeyChain { get; }

    /// <summary>
    /// Gets the issuer identifier for this signing key provider.
    /// For certificate-based providers, this typically returns a DID:X509 identifier derived from the certificate chain.
    /// For other providers, this may return null or a provider-specific identifier.
    /// </summary>
    public string? Issuer { get; }

    /// <summary>
    /// Returns the Protected Headers
    /// </summary>
    public CoseHeaderMap GetProtectedHeaders();

    /// <summary>
    /// Returns the UnProtected Headers
    /// </summary>
    public CoseHeaderMap? GetUnProtectedHeaders();
}

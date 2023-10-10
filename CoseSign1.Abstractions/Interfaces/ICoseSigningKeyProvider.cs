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
    /// Returns the Protected Headers
    /// </summary>
    public CoseHeaderMap GetProtectedHeaders();

    /// <summary>
    /// Returns the UnProtected Headers
    /// </summary>
    public CoseHeaderMap? GetUnProtectedHeaders();
}

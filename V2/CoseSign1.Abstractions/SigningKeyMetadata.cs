// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions;

using System.Collections.ObjectModel;

/// <summary>
/// Cryptographic key type enumeration.
/// </summary>
public enum CryptographicKeyType
{
    /// <summary>RSA key</summary>
    RSA,
    /// <summary>Elliptic Curve Digital Signature Algorithm key</summary>
    ECDsa,
    /// <summary>Edwards-curve Digital Signature Algorithm key</summary>
    EdDSA,
    /// <summary>ML-DSA (FIPS 204) Post-Quantum Cryptography key</summary>
    MLDSA,
    /// <summary>Other/Unknown key type</summary>
    Other
}

/// <summary>
/// Metadata about a signing key, including its identifier, algorithm, and key type information.
/// Provided by ISigningKey implementations to describe key properties.
/// Used by signing services to create appropriate header contributors.
/// </summary>
public class SigningKeyMetadata
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ToStringFormat = "SigningKeyMetadata[KeyType={0}, Algorithm={1}, IsRemote={2}]";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SigningKeyMetadata"/> class.
    /// </summary>
    /// <param name="coseAlgorithmId">The COSE algorithm identifier (e.g., -7 for ES256, -260 for ML-DSA-65).</param>
    /// <param name="keyType">The cryptographic key type (RSA, ECDsa, ML-DSA, etc.).</param>
    /// <param name="isRemote">A value indicating whether this is a remote signing key.</param>
    /// <param name="hashAlgorithm">The hash algorithm used (if applicable).</param>
    /// <param name="keySizeInBits">The key size in bits (if applicable).</param>
    /// <param name="additionalMetadata">Optional additional key-specific metadata.</param>
    public SigningKeyMetadata(
        int coseAlgorithmId,
        CryptographicKeyType keyType,
        bool isRemote,
        HashAlgorithmName? hashAlgorithm = null,
        int? keySizeInBits = null,
        IDictionary<string, object>? additionalMetadata = null)
    {
        CoseAlgorithmId = coseAlgorithmId;
        KeyType = keyType;
        IsRemote = isRemote;
        HashAlgorithm = hashAlgorithm;
        KeySizeInBits = keySizeInBits;
        AdditionalMetadata = additionalMetadata != null
            ? new ReadOnlyDictionary<string, object>(new Dictionary<string, object>(additionalMetadata))
            : new ReadOnlyDictionary<string, object>(new Dictionary<string, object>());
    }

    /// <summary>
    /// Gets the COSE algorithm identifier (e.g., -7 for ES256, -260 for ML-DSA-65).
    /// </summary>
    /// <value>The COSE algorithm identifier.</value>
    public int CoseAlgorithmId { get; }

    /// <summary>
    /// Gets the cryptographic key type (RSA, ECDsa, ML-DSA, etc.).
    /// </summary>
    /// <value>The cryptographic key type.</value>
    public CryptographicKeyType KeyType { get; }

    /// <summary>
    /// Gets the hash algorithm used (if applicable).
    /// </summary>
    /// <value>The hash algorithm used, or <see langword="null"/> if not applicable.</value>
    public HashAlgorithmName? HashAlgorithm { get; }

    /// <summary>
    /// Gets the key size in bits.
    /// </summary>
    /// <value>The key size in bits, or <see langword="null"/> if not known or not applicable.</value>
    public int? KeySizeInBits { get; }

    /// <summary>
    /// Gets a value indicating whether this is a remote signing key.
    /// </summary>
    /// <value><see langword="true"/> if this is a remote signing key; otherwise, <see langword="false"/>.</value>
    public bool IsRemote { get; }

    /// <summary>
    /// Gets additional key-specific metadata.
    /// For certificate-based keys, this might include the certificate.
    /// For other key types, this might include key identifiers, URIs, etc.
    /// </summary>
    /// <value>Additional key-specific metadata.</value>
    public IReadOnlyDictionary<string, object> AdditionalMetadata { get; }

    /// <summary>
    /// Returns a string representation of the signing key metadata.
    /// </summary>
    /// <returns>A string representation of the signing key metadata.</returns>
    public override string ToString()
    {
        return string.Format(ClassStrings.ToStringFormat, KeyType, CoseAlgorithmId, IsRemote);
    }
}
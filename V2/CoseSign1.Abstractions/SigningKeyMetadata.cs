using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace CoseSign1.Abstractions;

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
    /// <summary>
    /// Initializes a new instance of the <see cref="SigningKeyMetadata"/> class.
    /// </summary>
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
    public int CoseAlgorithmId { get; }

    /// <summary>
    /// Gets the cryptographic key type (RSA, ECDsa, ML-DSA, etc.).
    /// </summary>
    public CryptographicKeyType KeyType { get; }

    /// <summary>
    /// Gets the hash algorithm used (if applicable).
    /// </summary>
    public HashAlgorithmName? HashAlgorithm { get; }

    /// <summary>
    /// Gets the key size in bits.
    /// </summary>
    public int? KeySizeInBits { get; }

    /// <summary>
    /// Gets a value indicating whether this is a remote signing key.
    /// </summary>
    public bool IsRemote { get; }

    /// <summary>
    /// Gets additional key-specific metadata.
    /// For certificate-based keys, this might include the certificate.
    /// For other key types, this might include key identifiers, URIs, etc.
    /// </summary>
    public IReadOnlyDictionary<string, object> AdditionalMetadata { get; }

    /// <summary>
    /// Returns a string representation of the signing key metadata.
    /// </summary>
    public override string ToString()
    {
        return $"SigningKeyMetadata[KeyType={KeyType}, Algorithm={CoseAlgorithmId}, IsRemote={IsRemote}]";
    }
}

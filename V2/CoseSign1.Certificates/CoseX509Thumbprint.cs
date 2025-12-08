// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Certificates;

/// <summary>
/// Represents a COSE X509 thumbprint, which corresponds to the x5t header in a COSE signature structure.
/// </summary>
public class CoseX509Thumbprint
{
    private static readonly Dictionary<HashAlgorithmName, int> HashAlgorithmToCoseId = new()
    {
        { HashAlgorithmName.SHA256, -16 },
        { HashAlgorithmName.SHA384, -43 },
        { HashAlgorithmName.SHA512, -44 }
    };

    /// <summary>
    /// Gets the COSE hash algorithm ID.
    /// </summary>
    public int HashId { get; }

    /// <summary>
    /// Gets the thumbprint value.
    /// </summary>
    public ReadOnlyMemory<byte> Thumbprint { get; }

    /// <summary>
    /// Construct a thumbprint based on a certificate using SHA256 (default).
    /// </summary>
    /// <param name="cert">The certificate to create a thumbprint for.</param>
    public CoseX509Thumbprint(X509Certificate2 cert)
        : this(cert, HashAlgorithmName.SHA256)
    {
    }

    /// <summary>
    /// Construct a thumbprint based on a certificate and a hash algorithm.
    /// </summary>
    /// <param name="cert">The certificate to create a thumbprint for.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    public CoseX509Thumbprint(X509Certificate2 cert, HashAlgorithmName hashAlgorithm)
    {
        if (cert == null)
        {
            throw new ArgumentNullException(nameof(cert));
        }

        if (!HashAlgorithmToCoseId.TryGetValue(hashAlgorithm, out int coseId))
        {
            throw new ArgumentException($"Hash algorithm {hashAlgorithm} is not supported for COSE X509 thumbprints.", nameof(hashAlgorithm));
        }

        HashId = coseId;
        
        byte[] hash = hashAlgorithm.Name switch
        {
            nameof(SHA256) => SHA256.HashData(cert.RawData),
            nameof(SHA384) => SHA384.HashData(cert.RawData),
            nameof(SHA512) => SHA512.HashData(cert.RawData),
            _ => throw new ArgumentException($"Hash algorithm {hashAlgorithm} is not supported for COSE X509 thumbprints.", nameof(hashAlgorithm))
        };
        
        Thumbprint = hash;
    }

    /// <summary>
    /// Serializes the thumbprint to CBOR format.
    /// </summary>
    /// <param name="writer">The CBOR writer to write to.</param>
    /// <returns>The encoded bytes.</returns>
    public byte[] Serialize(CborWriter writer)
    {
        if (writer == null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        writer.Reset();
        writer.WriteStartArray(2);
        writer.WriteInt32(HashId);
        writer.WriteByteString(Thumbprint.Span);
        writer.WriteEndArray();
        
        return writer.Encode();
    }
}

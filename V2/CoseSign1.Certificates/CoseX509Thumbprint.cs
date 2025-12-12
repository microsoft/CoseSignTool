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

    private static readonly Dictionary<int, HashAlgorithmName> CoseIdToHashAlgorithm = new()
    {
        { -16, HashAlgorithmName.SHA256 },
        { -43, HashAlgorithmName.SHA384 },
        { -44, HashAlgorithmName.SHA512 }
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
#if NET5_0_OR_GREATER
            nameof(SHA256) => SHA256.HashData(cert.RawData),
            nameof(SHA384) => SHA384.HashData(cert.RawData),
            nameof(SHA512) => SHA512.HashData(cert.RawData),
#else
            nameof(SHA256) => ComputeHash(cert.RawData, SHA256.Create()),
            nameof(SHA384) => ComputeHash(cert.RawData, SHA384.Create()),
            nameof(SHA512) => ComputeHash(cert.RawData, SHA512.Create()),
#endif
            _ => throw new ArgumentException($"Hash algorithm {hashAlgorithm} is not supported for COSE X509 thumbprints.", nameof(hashAlgorithm))
        };

        Thumbprint = hash;
    }

    /// <summary>
    /// Private constructor for deserialization.
    /// </summary>
    /// <param name="hashId">The COSE hash algorithm ID.</param>
    /// <param name="thumbprint">The thumbprint bytes.</param>
    private CoseX509Thumbprint(int hashId, byte[] thumbprint)
    {
        HashId = hashId;
        Thumbprint = thumbprint;
    }

#if !NET5_0_OR_GREATER
    private static byte[] ComputeHash(byte[] data, HashAlgorithm algorithm)
    {
        using (algorithm)
        {
            return algorithm.ComputeHash(data);
        }
    }
#endif

    /// <summary>
    /// Checks if a certificate matches this thumbprint.
    /// </summary>
    /// <param name="certificate">Certificate to check.</param>
    /// <returns>True if the certificate matches this thumbprint, false otherwise.</returns>
    public bool Match(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        byte[] certHash = HashId switch
        {
#if NET5_0_OR_GREATER
            -16 => SHA256.HashData(certificate.RawData),
            -43 => SHA384.HashData(certificate.RawData),
            -44 => SHA512.HashData(certificate.RawData),
#else
            -16 => ComputeHash(certificate.RawData, SHA256.Create()),
            -43 => ComputeHash(certificate.RawData, SHA384.Create()),
            -44 => ComputeHash(certificate.RawData, SHA512.Create()),
#endif
            _ => throw new CryptographicException($"Unsupported thumbprint hash algorithm with COSE ID {HashId}")
        };

        return Thumbprint.Span.SequenceEqual(certHash);
    }

    /// <summary>
    /// Deserializes a CBOR encoded x5t header into a CoseX509Thumbprint.
    /// </summary>
    /// <param name="reader">CborReader that contains the data stream to deserialize.</param>
    /// <returns>CoseX509Thumbprint object.</returns>
    /// <exception cref="CoseX509FormatException">Thrown when the data stream does not meet x5t format requirements.</exception>
    public static CoseX509Thumbprint Deserialize(CborReader reader)
    {
        if (reader == null)
        {
            throw new ArgumentNullException(nameof(reader));
        }

        if (reader.PeekState() != CborReaderState.StartArray)
        {
            throw new CoseX509FormatException("x5t first level must be an array");
        }

        int? arrayLength = reader.ReadStartArray();
        if (arrayLength != 2)
        {
            throw new CoseX509FormatException("x5t first level must be a 2-element array");
        }

        // CBOR makes the types clear but .NET is fuzzy here so we have to allow both
        if (reader.PeekState() != CborReaderState.NegativeInteger &&
            reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CoseX509FormatException("x5t first element must be NegativeInteger or UnsignedInteger");
        }

        int hashId = reader.ReadInt32();

        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CoseX509FormatException("x5t second element must be ByteString");
        }

        byte[] thumbprint = reader.ReadByteString();
        reader.ReadEndArray();

        // Validate hash ID is supported
        if (!CoseIdToHashAlgorithm.ContainsKey(hashId))
        {
            throw new CoseX509FormatException($"Unsupported thumbprint hash algorithm with COSE ID {hashId}");
        }

        return new CoseX509Thumbprint(hashId, thumbprint);
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
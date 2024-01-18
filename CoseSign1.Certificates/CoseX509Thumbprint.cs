// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates;

using System.Buffers.Text;

/// <summary>
/// Represents a COSE X509 thumbprint, which corresponds to the x5t header in a COSE signature structure.
/// This is different from an X509 certificate thumbprint, which is the SHA1 hash of the certificate.
/// </summary>
public class CoseX509Thumprint
{
    #region Properties and fields
    /// <summary>
    /// Dictionary of supported HashIds and related managed hash algorithm names used to construct HashAlgorithm objects.
    /// These are taken from https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    /// </summary>
    private static readonly Dictionary<int, HashAlgorithmName> HashAlgorithmToCoseValues = new()
    {
        { -14, HashAlgorithmName.SHA1 },
        { -16, HashAlgorithmName.SHA256 },
        { -43, HashAlgorithmName.SHA384 },
        { -44, HashAlgorithmName.SHA512 }
    };

    /// <summary>
    /// Hash algorithm instance used to compute thumbprints
    /// </summary>
    private HashAlgorithm? Hasher { get; set; }

    /// <summary>
    /// Gets the HashId used in the CBOR/COSE representation of the x5t header
    /// </summary>
    public int HashId { get; private set; }

    /// <summary>
    /// Gets the thumbprint value from the x5t header
    /// </summary>
    public ReadOnlyMemory<byte> Thumbprint { get; private set; }
    #endregion

    // For Deserialize
    private CoseX509Thumprint() { }

    /// <summary>
    /// Construct a thumbprint based on a certificate and the default hash algorithm, which is SHA256.
    /// </summary>
    /// <param name="cert">The certificate to create a thumbprint for.</param>
    public CoseX509Thumprint(X509Certificate2 cert)
    {
        BuildHasher(GetHashID(HashAlgorithmName.SHA256.Name ?? "SHA256"));
        Thumbprint = Hasher?.ComputeHash(cert.RawData);
    }

    /// <summary>
    /// Construct a thumbprint based on a certificate and a hash algorithm.
    /// </summary>
    /// <param name="cert">The certificate to create a thumbprint for.</param>
    public CoseX509Thumprint(X509Certificate2 cert, HashAlgorithmName hashAlgorithm)
    {
        BuildHasher(GetHashID(hashAlgorithm.Name
            ?? throw new CryptographicException(nameof(hashAlgorithm), "The supplied hash algorithm name was not recognized.")));
        Thumbprint = Hasher?.ComputeHash(cert.RawData);
    }

    #region Public Methods
    private string? ToStringCache = null;
    /// <inheritdoc />
    public override string ToString() => ToStringCache ??= Convert.ToBase64String(Thumbprint.ToArray());

    /// <summary>
    /// Checks if a certificate matches this thumbprint
    /// </summary>
    /// <param name="certificate">Certificate to check</param>
    /// <returns></returns>
    public bool Match(X509Certificate2 certificate)
    {
        return Thumbprint.ToArray().SequenceEqual(Hasher?.ComputeHash(certificate.RawData)
            ?? throw new InvalidOperationException($"The current {nameof(CoseX509Thumprint)} object is not yet initialized."));
    }

    /// <summary>
    /// Deserializes a CBOR encoded x5t header into a Cosex509Thumbprint
    /// </summary>
    /// <param name="reader">CborReader that contains the data stream to deserialize</param>
    /// <returns>CoseX509Thumbprint object on success, else null</returns>
    /// <exception cref="CoseX509FormatException">Thrown when the data stream in the CborReader does not meet the requirements of the x5t standard</exception>
    public static CoseX509Thumprint Deserialize(CborReader reader)
    {
        CoseX509Thumprint result = new();

        if (reader.PeekState() != CborReaderState.StartArray)
        {
            throw new CoseX509FormatException("x5t first level must be an array");
        }

        if (reader.ReadStartArray() != 2)
        {
            throw new CoseX509FormatException("x5t first level must be 2 element array");
        }

        // CBOR makes the types clear but .NET is fuzzy here so we have to allow both to properly support
        // round tripping of data
        if (reader.PeekState() != CborReaderState.NegativeInteger &&
            reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CoseX509FormatException("x5t first member must be NegativeInteger or UnsignedInteger");
        }

        int hashId = reader.ReadInt32();
        result.BuildHasher(hashId);

        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CoseX509FormatException("x5t second member must be ByteString");
        }

        result.Thumbprint = reader.ReadByteString();
        reader.ReadEndArray();

        return result;
    }

    /// <summary>
    /// Loads the current CoseX509Thumbprint object into a CborWriter.
    /// </summary>
    /// <param name="writer">A CborWriter to serialize data to.</param>
    /// <returns>The encoded bytes.</returns>
    public byte[] Serialize(CborWriter writer)
    {
        writer.WriteStartArray(2);
        writer.WriteInt32(HashId);
        writer.WriteByteString(Thumbprint.ToArray());
        writer.WriteEndArray();

        return writer.Encode();
    }
    #endregion

    #region Private helper methods
    /// <summary>
    /// Looks up the HashId from the HashAlgorithmToCoseValues dictionary
    /// </summary>
    /// <param name="algorithmName">Name of hash algorithm</param>
    /// <returns>Valid supported HashId or 0</returns>
    private static int GetHashID(string algorithmName)
    {
        KeyValuePair<int, HashAlgorithmName> data = HashAlgorithmToCoseValues.FirstOrDefault(t => t.Value.Name == algorithmName);
        return data.Key;
    }

    // Sets HashID and returns the value for Hasher.
    private void BuildHasher(int coseHashAlgorithmId)
    {
        if (!HashAlgorithmToCoseValues.TryGetValue(coseHashAlgorithmId, out HashAlgorithmName algName))
        {
            throw new CoseX509FormatException($"Unsupported thumbprint hash algorithm value of {coseHashAlgorithmId}");
        }

        HashId = coseHashAlgorithmId;

        // HashAlgorithmName values are not constants, so we can't use an actual switch here.
        Hasher =
            algName == HashAlgorithmName.SHA1 ? SHA1.Create() :
            algName == HashAlgorithmName.SHA256 ? SHA256.Create() :
            algName == HashAlgorithmName.SHA384 ? SHA384.Create() :
            algName == HashAlgorithmName.SHA512 ? SHA512.Create() :
            throw new CoseX509FormatException($"Unsupported thumbprint hash algorithm value of {coseHashAlgorithmId}");
    }

    #endregion
}
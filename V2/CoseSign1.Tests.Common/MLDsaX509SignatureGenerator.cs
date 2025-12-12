// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Tests.Common;

/// <summary>
/// Custom X509SignatureGenerator implementation for ML-DSA Post-Quantum Cryptography.
/// </summary>
/// <remarks>
/// This class enables creation of ML-DSA certificate chains by providing a signature generator
/// that can sign certificate requests using ML-DSA keys. This is needed because .NET 10's
/// CertificateRequest.Create(issuerCertificate, ...) doesn't yet recognize ML-DSA OIDs.
/// </remarks>
internal sealed class MLDsaX509SignatureGenerator : X509SignatureGenerator
{
    private readonly MLDsa _mldsaKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="MLDsaX509SignatureGenerator"/> class.
    /// </summary>
    /// <param name="mldsaKey">The ML-DSA key to use for signing.</param>
    public MLDsaX509SignatureGenerator(MLDsa mldsaKey)
    {
        _mldsaKey = mldsaKey ?? throw new ArgumentNullException(nameof(mldsaKey));
    }

    /// <summary>
    /// Builds the public key for the signature generator.
    /// </summary>
    /// <returns>The public key.</returns>
    protected override PublicKey BuildPublicKey()
    {
        // Export the public key and create a PublicKey object
        byte[] publicKeyBytes = _mldsaKey.ExportSubjectPublicKeyInfo();
        return PublicKey.CreateFromSubjectPublicKeyInfo(publicKeyBytes, out _);
    }

    /// <summary>
    /// Signs the data using the ML-DSA key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm (not used by ML-DSA).</param>
    /// <returns>The signature bytes.</returns>
    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        // ML-DSA has a built-in hash function, so we ignore the hashAlgorithm parameter
        return _mldsaKey.SignData(data);
    }

    /// <summary>
    /// Gets the signature algorithm identifier for the certificate.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm (not used by ML-DSA).</param>
    /// <returns>The encoded signature algorithm identifier.</returns>
    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
    {
        // Determine ML-DSA parameter set from key
        int keySize = _mldsaKey.ExportSubjectPublicKeyInfo().Length;
        string oid = DetermineMLDsaOid(keySize);

        // Create AlgorithmIdentifier structure for ML-DSA
        // AlgorithmIdentifier ::= SEQUENCE {
        //     algorithm OBJECT IDENTIFIER,
        //     parameters ANY DEFINED BY algorithm OPTIONAL
        // }
        // ML-DSA doesn't have parameters, so we just encode the OID

        byte[] oidBytes = EncodeOid(oid);

        // SEQUENCE tag (0x30) followed by length and content
        byte[] result = new byte[2 + oidBytes.Length];
        result[0] = 0x30; // SEQUENCE tag
        result[1] = (byte)oidBytes.Length; // length
        Array.Copy(oidBytes, 0, result, 2, oidBytes.Length);

        return result;
    }

    /// <summary>
    /// Determines the ML-DSA OID based on the key size.
    /// </summary>
    private static string DetermineMLDsaOid(int keySize)
    {
        // Approximate key sizes for ML-DSA variants (public key sizes in DER format)
        // ML-DSA-44: ~1312 bytes
        // ML-DSA-65: ~1952 bytes
        // ML-DSA-87: ~2592 bytes
        return keySize switch
        {
            < 1600 => "2.16.840.1.101.3.4.3.17", // ML-DSA-44
            < 2300 => "2.16.840.1.101.3.4.3.18", // ML-DSA-65
            _ => "2.16.840.1.101.3.4.3.19"       // ML-DSA-87
        };
    }

    /// <summary>
    /// Encodes an OID string to DER format.
    /// </summary>
    private static byte[] EncodeOid(string oid)
    {
        string[] parts = oid.Split('.');
        if (parts.Length < 2)
        {
            throw new ArgumentException("Invalid OID format", nameof(oid));
        }

        List<byte> encoded = new();

        // First two components are encoded as: (first * 40) + second
        int first = int.Parse(parts[0]);
        int second = int.Parse(parts[1]);
        encoded.Add((byte)((first * 40) + second));

        // Remaining components use variable-length encoding
        for (int i = 2; i < parts.Length; i++)
        {
            int value = int.Parse(parts[i]);
            List<byte> valueBytes = new();

            // Encode in base-128 (7 bits per byte, MSB set for all but last byte)
            valueBytes.Add((byte)(value & 0x7F));
            value >>= 7;

            while (value > 0)
            {
                valueBytes.Insert(0, (byte)((value & 0x7F) | 0x80));
                value >>= 7;
            }

            encoded.AddRange(valueBytes);
        }

        // Add OID tag and length
        byte[] result = new byte[encoded.Count + 2];
        result[0] = 0x06; // OID tag
        result[1] = (byte)encoded.Count; // length
        encoded.CopyTo(result, 2);

        return result;
    }
}
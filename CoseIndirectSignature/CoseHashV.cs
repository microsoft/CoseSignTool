﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature;
using System;
using System.Formats.Cbor;
using System.IO;
using System.Threading.Tasks;
using CoseSign1.Abstractions.Exceptions;

/// <summary>
/// Represents the COSE_Hash_V structure as defined in https://tools.ietf.org/html/rfc9054#section-2.1
/// </summary>
public record CoseHashV
{
    /// <summary>
    /// The hash algorithm used to generate the hash value.
    /// </summary>
    public CoseHashAlgorithm Algorithm { get; set; }

    /// <summary>
    /// The actual value from the hashing function
    /// </summary>
    public byte[] HashValue { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Location of object that was hashed
    /// </summary>
    public string? Location { get; set; }

    /// <summary>
    /// Object containing other details and things
    /// </summary>
    public byte[]? Any { get; set; }

    /// <summary>
    /// Default constructor for the CoseHashV class.
    /// </summary>
    public CoseHashV()
    {
    }

    /// <summary>
    /// Private constructor to share and consolidate initialization code.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="location">The optional location of the content represented by this hash.</param>
    /// <param name="any">The optional additional information.</param>
    private CoseHashV(
        CoseHashAlgorithm algorithm,
        string? location = null,
        byte[]? any = null)
    {
        Algorithm = algorithm;
        Location = location;
        Any = any;
    }

    /// <summary>
    /// Creates a CoseHashV object from byte[] of data.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="byteData">The data to be hashed.</param>
    /// <param name="location">The optional location of the content represented by this hash.</param>
    /// <param name="any">The optional additional information.</param>
    public CoseHashV(
        CoseHashAlgorithm algorithm,
        byte[] byteData,
        string? location = null,
        byte[]? any = null)
        : this(algorithm, location, any)
    {
        _= byteData ?? throw new ArgumentNullException(nameof(byteData));
        using HashAlgorithm hashAlgorightm = GetHashAlgorithmFromCoseHashAlgorithm(algorithm);
        HashValue = hashAlgorightm.ComputeHash(byteData);
    }

    /// <summary>
    /// Creates a CoseHashV object from ReadOnlyMemory{byte} of data.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="readonlyData">The data to be hashed.</param>
    /// <param name="location">The optional location of the content represented by this hash.</param>
    /// <param name="any">The optional additional information.</param>
    public CoseHashV(
        CoseHashAlgorithm algorithm,
        ReadOnlyMemory<byte> readonlyData,
        string? location = null,
        ReadOnlyMemory<byte>? any = null)
        : this(algorithm, location, any?.ToArray())
    {
        if(readonlyData.Length == 0)
        {
            throw new ArgumentNullException(nameof(readonlyData));
        }
        using HashAlgorithm hashAlgorightm = GetHashAlgorithmFromCoseHashAlgorithm(algorithm);
        HashValue = hashAlgorightm.ComputeHash(readonlyData.ToArray());
    }

    /// <summary>
    /// Creates a CoseHashV object from a Stream of data.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="streamData">The data to be hashed.</param>
    /// <param name="location">The optional location of the content represented by this hash.</param>
    /// <param name="any">The optional additional information.</param>
    public CoseHashV(
        CoseHashAlgorithm algorithm,
        Stream streamData,
        string? location = null,
        byte[]? any = null)
        : this(algorithm, location, any)
    {
        _= streamData ?? throw new ArgumentNullException(nameof(streamData));

        using HashAlgorithm hashAlgorightm = GetHashAlgorithmFromCoseHashAlgorithm(algorithm);
        HashValue = hashAlgorightm.ComputeHash(streamData);
    }

    /// <summary>
    /// Validates that the given data stored in the stream matches the hash value stored in this instance.
    /// </summary>
    /// <param name="stream">The data bytes to check to match the hash.</param>
    /// <returns>True if the hash of <paramref name="data"/> matches HashBytes, False otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if data passed in is null or has a length of 0.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if the computed hash length and the stored hash length differ.</exception>
    public Task<bool> ContentMatchesAsync(Stream stream)
        => Task.FromResult(HashMatches(data: null, stream: stream));

    /// <summary>
    /// Validates that the given data stored in the stream matches the hash value stored in this instance.
    /// </summary>
    /// <param name="stream">The data bytes to check to match the hash.</param>
    /// <returns>True if the hash of <paramref name="data"/> matches HashBytes, False otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if data passed in is null or has a length of 0.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if the computed hash length and the stored hash length differ.</exception>
    public bool ContentMatches(Stream stream)
        => HashMatches(data: null, stream: stream);

    /// <summary>
    /// Validates that the given data in bytes matches the hash value stored in this instance.
    /// </summary>
    /// <param name="data">The data bytes to check to match the hash.</param>
    /// <returns>True if the hash of <paramref name="data"/> matches HashBytes, False otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if data passed in is null or has a length of 0.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if the computed hash length and the stored hash length differ.</exception>
    public Task<bool> ContentMatchesAsync(byte[] data)
        => Task.FromResult(HashMatches(data: data, stream: null));
    
    /// <summary>
    /// Validates that the given data in bytes matches the hash value stored in this instance.
    /// </summary>
    /// <param name="data">The data bytes to check to match the hash.</param>
    /// <returns>True if the hash of <paramref name="data"/> matches HashBytes, False otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if data passed in is null or has a length of 0.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if the computed hash length and the stored hash length differ.</exception>
    public bool ContentMatches(ReadOnlyMemory<byte> data)
        => HashMatches(data: data.ToArray(), stream: null);

    /// <summary>
    /// Validates that the given data in bytes matches the hash value stored in this instance.
    /// </summary>
    /// <param name="data">The data bytes to check to match the hash.</param>
    /// <returns>True if the hash of <paramref name="data"/> matches HashBytes, False otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if data passed in is null or has a length of 0.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if the computed hash length and the stored hash length differ.</exception>
    public Task<bool> ContentMatchesAsync(ReadOnlyMemory<byte> data)
        => Task.FromResult(HashMatches(data: data.ToArray(), stream: null));

    /// <summary>
    /// Validates that the given data in bytes matches the hash value stored in this instance.
    /// </summary>
    /// <param name="data">The data bytes to check to match the hash.</param>
    /// <returns>True if the hash of <paramref name="data"/> matches HashBytes, False otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if data passed in is null or has a length of 0.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if the computed hash length and the stored hash length differ.</exception>
    public bool ContentMatches(byte[] data)
        => HashMatches(data: data, stream: null);

    /// <summary>
    /// Method for handling byte[] and stream for the same logic.
    /// </summary>
    /// <param name="data">if specified, then will compute a hash of this data and compare to internal hash value.</param>
    /// <param name="stream">if data is null and stream is specified, then will compute a hash of this stream and compare to internal hash value.</param>
    /// <returns>True if the hashes match, False otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if data is null or data length is 0 and stream is null, or if data is null and stream is null.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if the length of the computed hash does not match the internal stored hash length, thus the wrong hash algorithm is being used.</exception>
    private bool HashMatches(byte[]? data, Stream? stream)
    {
        // handle input validation
        if (
            (data == null || data.Length == 0) &&
            (stream == null))
        {
            throw new ArgumentNullException(nameof(data));
        }

        // initialize and compute the hash
        using HashAlgorithm hashAlgorithm = GetHashAlgorithmFromCoseHashAlgorithm(Algorithm);
        byte[] hash = stream != null ? hashAlgorithm.ComputeHash(stream) : hashAlgorithm.ComputeHash(data);

        // handle the case where the algorithm we derived did not match the algorithm that was used to populate the CoseHashV instance.
        return hash.Length != HashValue.Length
            ? throw new CoseSign1Exception($@"The computed hash length of {hash.Length} for hash type {hashAlgorithm.GetType().FullName} created a hash different than the length of {HashValue.Length} which is unexpected.")
            : hash.SequenceEqual(HashValue);
    }

    /// <summary>
    /// Writes the current CoseHashV instance to a cbor byte[].
    /// </summary>
    /// <returns>a byte[] cbor representation of the CoseHashV object.</returns>
    public byte[] Serialize()
    {
        CborWriter writer = new(CborConformanceMode.Strict, allowMultipleRootLevelValues: true);

        // start out presuming all properties are being written.
        int properties = 4;

        // if Location is null, then we need to decrement the properties count in the cbor object.
        if(Location == null)
        {
            properties--;
        }

        // if Any is null, then we need to decrement the properties count in the cbor object.
        if(Any == null)
        {
            properties--;
        }

        writer.Reset();
        writer.WriteInt64((long)Algorithm);
        writer.WriteByteString(HashValue);
        if (Location != null)
        {
            writer.WriteTextString(Location);
        }
        if (Any != null)
        {
            writer.WriteByteString(Any);
        }

        return writer.Encode();
    }

    /// <summary>
    /// Reads a COSE_Hash_V structure from the <see cref="CborReader"/>.
    /// </summary>
    /// <param name="data">A byte[] which represents a CoseHashV object.</param>
    /// <returns>A proper COSE_Hash_V structure if read from the reader.</returns>
    /// <exception cref="CoseSign1Exception">Thrown if an invalid object state or format is detected.</exception>
    public static CoseHashV Deserialize(byte[] data) => Deserialize(new CborReader(data, allowMultipleRootLevelValues: true));

    /// <summary>
    /// Reads a COSE_Hash_V structure from the <see cref="CborReader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader to be read from, it must have allowMultipleRootLevelValues set to true.</param>
    /// <returns>A proper COSE_Hash_V structure if read from the reader.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="reader"/> is null.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if an invalid object state or format is detected.</exception>
    public static CoseHashV Deserialize(CborReader reader)
    {
        if (reader == null)
        {
            throw new ArgumentNullException(nameof(reader));
        }
        CoseHashV returnValue = new CoseHashV();

        // CBor encodes positive or negative, so we need to check for both.
        if (reader.PeekState() != CborReaderState.UnsignedInteger &&
            reader.PeekState() != CborReaderState.NegativeInteger)
        {
            throw new CoseSign1Exception($"Invalid COSE_Hash_V structure, peek state {reader.PeekState()} was not {nameof(CborReaderState.NegativeInteger)} or  {nameof(CborReaderState.UnsignedInteger)}");
        }

        // read the hash algorithm.
        returnValue.Algorithm = (CoseHashAlgorithm)reader.ReadInt64();

        // read the hash value
        if(reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CoseSign1Exception($"Invalid COSE_Hash_V structure, expected {nameof(CborReaderState.ByteString)} but got {reader.PeekState()} instead.");
        }
        returnValue.HashValue = reader.ReadByteString();

        // read the location if it exists
        if (reader.PeekState() == CborReaderState.TextString)
        {
            returnValue.Location = reader.ReadTextString();
        }

        // read the any field if it exists
        if (reader.PeekState() == CborReaderState.ByteString)
        {
            returnValue.Any = reader.ReadByteString();
        }

        return returnValue;
    }

    /// <summary>
    /// Get the hash algorithm from the specified CoseHashAlgorithm.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to get a hashing type from.</param>
    /// <returns>The type of the hash object to use.</returns>
    /// <exception cref="NotSupportedException">The CoseHashAlgorithm specified is not yet supported.</exception>
    private static HashAlgorithm GetHashAlgorithmFromCoseHashAlgorithm(CoseHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            CoseHashAlgorithm.SHA256 => new SHA256Managed(),
            CoseHashAlgorithm.SHA512 => new SHA512Managed(),
            CoseHashAlgorithm.SHA384 => new SHA384Managed(),
            _ => throw new NotSupportedException($"The algorithm {algorithm} is not supported by {nameof(CoseHashV)}.")
        };
    }
}

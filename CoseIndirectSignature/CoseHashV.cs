// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose Deserialize

namespace CoseIndirectSignature;

/// <summary>
/// Represents the COSE_Hash_V structure as suggested in https://tools.ietf.org/html/rfc9054#section-2.1
/// </summary>
public record CoseHashV
{
    /// <summary>
    /// The hash algorithm used to generate the hash value.
    /// </summary>
    public CoseHashAlgorithm Algorithm { get; set; }

    private byte[]? InternalHashValue;
    /// <summary>
    /// The actual value from the hashing function
    /// </summary>
    public byte[] HashValue
    {
        get => InternalHashValue ?? [];
        set
        {
            // validate the input
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (value.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "The hash value cannot be empty.");
            }
            if (Algorithm == CoseHashAlgorithm.Reserved)
            {
                throw new ArgumentException("The algorithm must be set before the hash can be stored.", nameof(value));
            }

            // sanity check the length of the hash against the specified algorithm to be sure we're not allowing a mismatch.
            HashAlgorithm algo = GetHashAlgorithmFromCoseHashAlgorithm(Algorithm);
            if (value.Length != (algo.HashSize / 8))
            {
                throw new ArgumentOutOfRangeException(nameof(value), @$"The hash value length of {value.Length} did not match the CoseHashAlgorithm {Algorithm} required length of {algo.HashSize / 8}");
            }
            InternalHashValue = value;
        }
    }

    /// <summary>
    /// Optional location of object that was hashed
    /// </summary>
    public string? Location { get; set; }

    /// <summary>
    /// Optional array containing other details meaningful to the application.
    /// </summary>
    public byte[]? AdditionalData { get; set; }

    /// <summary>
    /// Default constructor for the CoseHashV class.
    /// </summary>
    public CoseHashV()
    {
    }

    /// <summary>
    /// Copy constructor for the CoseHashV class.
    /// </summary>
    /// <param name="other">The other <see cref="CoseHashV"/> to copy.</param>
    public CoseHashV(CoseHashV other)
    {
        Algorithm = other.Algorithm;
        // deep copy the hash value over
        InternalHashValue = new byte[other.HashValue.Length];
        other.HashValue.CopyTo(InternalHashValue, 0);

        // copy the location string
        Location = other.Location;

        // deep copy the additional data over if present.
        if (other.AdditionalData != null)
        {
            AdditionalData = new byte[other.AdditionalData.Length];
            other.AdditionalData.CopyTo(AdditionalData, 0);
        }
    }

    /// <summary>
    /// Constructor for the CoseHashV class which takes a hash algorithm and a hash value.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="hashValue">The hash value to be present.</param>
    /// <param name="disableValidation">True to disable the checks which ensure the decoded algorithm expected hash length and the length of the decoded hash match, False (default) to leave them enabled.</param>
    public CoseHashV(
        CoseHashAlgorithm algorithm,
        byte[] hashValue,
        bool disableValidation = false)
        : this(algorithm, null, null)
    {
        _ = hashValue ?? throw new ArgumentNullException(nameof(hashValue));
        if(hashValue.Length == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(hashValue), "Hash value provided must contain > 0 elements.");
        }

        if (disableValidation)
        {
            // bypass the property setter to avoid validation against the algorithm.
            InternalHashValue = hashValue;
        }
        else
        {
            // use the property setter to validate the hash value against the algorithm verses directly assigning InternalHashValue.
            HashValue = hashValue;
        }
    }

    /// <summary>
    /// Creates a CoseHashV object from byte[] of data.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="byteData">The data to be hashed.</param>
    /// <param name="location">The optional location of the content represented by this hash.</param>
    /// <param name="additionalData">The optional additional information.</param>
    public CoseHashV(
        CoseHashAlgorithm algorithm,
        byte[] byteData,
        string? location = null,
        byte[]? additionalData = null)
        : this(algorithm, location, additionalData)
    {
        _= byteData ?? throw new ArgumentNullException(nameof(byteData));
        if(byteData.Length == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteData), "The data to be hashed cannot be empty.");
        }
        using HashAlgorithm hashAlgorightm = GetHashAlgorithmFromCoseHashAlgorithm(algorithm);
        // bypass the property setter since we are computing the hash value based on the algorithm directly.
        InternalHashValue = hashAlgorightm.ComputeHash(byteData);
    }

    /// <summary>
    /// Creates a CoseHashV object from ReadOnlyMemory{byte} of data.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="readonlyData">The data to be hashed.</param>
    /// <param name="location">The optional location of the content represented by this hash.</param>
    /// <param name="additionalData">The optional additional information.</param>
    public CoseHashV(
        CoseHashAlgorithm algorithm,
        ReadOnlyMemory<byte> readonlyData,
        string? location = null,
        ReadOnlyMemory<byte>? additionalData = null)
        : this(algorithm, byteData: readonlyData.ToArray(), location, additionalData?.ToArray())
    {
    }

    /// <summary>
    /// Creates a CoseHashV object from a Stream of data.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="streamData">The data to be hashed.</param>
    /// <param name="location">The optional location of the content represented by this hash.</param>
    /// <param name="additionalData">The optional additional information.</param>
    public CoseHashV(
        CoseHashAlgorithm algorithm,
        Stream streamData,
        string? location = null,
        byte[]? additionalData = null)
        : this(algorithm, location, additionalData)
    {
        _= streamData ?? throw new ArgumentNullException(nameof(streamData));

        using HashAlgorithm hashAlgorightm = GetHashAlgorithmFromCoseHashAlgorithm(algorithm);
        // bypass the property setter since we are computing the hash value based on the algorithm directly.
        InternalHashValue = hashAlgorightm.ComputeHash(streamData);
    }

    /// <summary>
    /// Private constructor to share and consolidate initialization code.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to be used for CoseHashV.</param>
    /// <param name="location">The optional location of the content represented by this hash.</param>
    /// <param name="additionalData">The optional additional information.</param>
    private CoseHashV(
        CoseHashAlgorithm algorithm,
        string? location = null,
        byte[]? additionalData = null)
    {
        Algorithm = algorithm;
        Location = location;
        AdditionalData = additionalData;
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
        CborWriter writer = new(CborConformanceMode.Strict);

        int propertyCount = 2;

        if (Location != null)
        {
            propertyCount++;
        }

        if (AdditionalData != null)
        {
            propertyCount++;
        }

        writer.WriteStartArray(propertyCount);
        writer.WriteInt64((long)Algorithm);
        writer.WriteByteString(HashValue);
        if (Location != null)
        {
            writer.WriteTextString(Location);
        }
        if (AdditionalData != null)
        {
            writer.WriteByteString(AdditionalData);
        }
        writer.WriteEndArray();

        return writer.Encode();
    }

    /// <summary>
    /// Reads a COSE_Hash_V structure from the <see cref="CborReader"/>.
    /// </summary>
    /// <param name="data">A ReadOnlyMemory{byte} which represents a CoseHashV object.</param>
    /// <param name="disableValidation">True to disable the checks which ensure the decoded algorithm expected hash length and the length of the decoded hash match, False (default) to leave them enabled.</param>
    /// <returns>A proper COSE_Hash_V structure if read from the reader.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is null.</exception>
    /// <exception cref="InvalidCoseDataException">Thrown if an invalid object state or format is detected.</exception>
    public static CoseHashV Deserialize(ReadOnlyMemory<byte> data, bool disableValidation = false)
        => Deserialize(new CborReader(data), disableValidation);

    /// <summary>
    /// Reads a COSE_Hash_V structure from the <see cref="CborReader"/>.
    /// </summary>
    /// <param name="data">A ReadOnlySpan{byte} which represents a CoseHashV object.</param>
    /// <param name="disableValidation">True to disable the checks which ensure the decoded algorithm expected hash length and the length of the decoded hash match, False (default) to leave them enabled.</param>
    /// <returns>A proper COSE_Hash_V structure if read from the reader.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is null.</exception>
    /// <exception cref="InvalidCoseDataException">Thrown if an invalid object state or format is detected.</exception>
    public static CoseHashV Deserialize(ReadOnlySpan<byte> data, bool disableValidation = false)
        => Deserialize(new CborReader(data.ToArray().AsMemory()), disableValidation);

    /// <summary>
    /// Reads a COSE_Hash_V structure from the <see cref="CborReader"/>.
    /// </summary>
    /// <param name="data">A byte[] which represents a CoseHashV object.</param>
    /// <param name="disableValidation">True to disable the checks which ensure the decoded algorithm expected hash length and the length of the decoded hash match, False (default) to leave them enabled.</param>
    /// <returns>A proper COSE_Hash_V structure if read from the reader.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is null.</exception>
    /// <exception cref="InvalidCoseDataException">Thrown if an invalid object state or format is detected.</exception>
    public static CoseHashV Deserialize(byte[] data, bool disableValidation = false)
        => Deserialize(new CborReader(data ?? throw new ArgumentNullException(nameof(data), "Cannot deserialize null bytes into a CoseHashV")), disableValidation);

    /// <summary>
    /// Reads a COSE_Hash_V structure from the <see cref="CborReader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader to be read from, it must have allowMultipleRootLevelValues set to true.</param>
    /// <param name="disableValidation">True to disable the checks which ensure the decoded algorithm expected hash length and the length of the decoded hash match, False (default) to leave them enabled.</param>
    /// <returns>A proper COSE_Hash_V structure if read from the reader.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="reader"/> is null.</exception>
    /// <exception cref="InvalidCoseDataException">Thrown if an invalid object state or format is detected.</exception>
    public static CoseHashV Deserialize(CborReader reader, bool disableValidation = false)
    {
        if (reader == null)
        {
            throw new ArgumentNullException(nameof(reader));
        }
        CoseHashV returnValue = new();

        // tracking state for error purposes.
        uint propertiesRead = 0;

        try
        {
            if (PeekStateWithExceptionHandling(reader) != CborReaderState.StartArray)
            {
                throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, expected {nameof(CborReaderState.StartArray)} but got {reader.PeekState()} instead.");
            }

            int? propertiesToRead;
            try
            {
                propertiesToRead = reader.ReadStartArray();
            }
            catch (Exception ex) when (ex is CborContentException)
            {
                throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, reading the state of the reader threw an exception: {ex.Message}", ex);
            }
            if (propertiesToRead < 2 || propertiesToRead > 4)
            {
                throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, expected 2 to 4 properties but got {propertiesToRead} instead.");
            }

            // read the hash algorithm
            CborReaderState state = PeekStateWithExceptionHandling(reader);

            if (state != CborReaderState.UnsignedInteger &&
                state != CborReaderState.NegativeInteger &&
                state != CborReaderState.TextString)
            {
                throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, expected {nameof(CborReaderState.UnsignedInteger)} or {nameof(CborReaderState.NegativeInteger)} or {nameof(CborReaderState.TextString)} but got {state} instead for \"hashAlg\" property.");
            }
            if (state == CborReaderState.TextString)
            {
                string? algorithmString;
                try
                {
                    algorithmString = reader.ReadTextString();
                }
                catch (Exception ex) when (ex is InvalidOperationException || ex is CborContentException)
                {
                    throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, the hash algorithm provided threw an exception: {ex.Message}", ex);
                }

                try
                {
                    returnValue.Algorithm = Enum.TryParse(algorithmString, ignoreCase: true, out CoseHashAlgorithm algorithm)
                        ? algorithm
                        : throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, the hash algorithm provided \"{algorithmString}\" could not be parsed into a valid {nameof(CoseHashAlgorithm)}.");
                }
                catch (ArgumentException ex)
                {
                    throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, the hash algorithm provided \"{algorithmString}\" threw an exception: {ex.Message}", ex);
                }
            }
            else
            {
                try
                {
                    returnValue.Algorithm = (CoseHashAlgorithm)reader.ReadInt64();
                }
                catch (Exception ex) when (ex is InvalidOperationException || ex is OverflowException || ex is CborContentException)
                {
                    throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, the hash algorithm provided threw an exception: {ex.Message}", ex);
                }
            }
            ++propertiesRead;

            state = PeekStateWithExceptionHandling(reader);
            if (state != CborReaderState.ByteString)
            {
                throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, expected {nameof(CborReaderState.ByteString)} but got {state} instead for \"hashValue\" property.");
            }
            try
            {
                byte[]? value;
                try
                {
                    value = reader.ReadByteString();
                }
                catch(Exception ex) when (ex is InvalidOperationException || ex is CborContentException)
                {
                    throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, reading the hash value provided threw an exception: {ex.Message}", ex);
                }
                if (disableValidation)
                {
                    // directly assign to the internal hash value to bypass the property setter.
                    returnValue.InternalHashValue = value;
                }
                else
                {
                    // use the property setter to validate the hash value against the algorithm.
                    returnValue.HashValue = value;
                }
            }
            catch (Exception ex) when (ex is ArgumentException ||
                                      ex is NotSupportedException)
            {
                throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, the hash value provided threw an exception: {ex.Message}", ex);
            }
            ++propertiesRead;

            // check for and read location as a text string.
            state = PeekStateWithExceptionHandling(reader);
            if (state == CborReaderState.TextString)
            {
                try
                {
                    returnValue.Location = reader.ReadTextString();
                }
                catch(Exception ex) when (ex is InvalidOperationException || ex is CborContentException)
                {
                    throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, reading the location provided threw an exception: {ex.Message}", ex);
                }
                ++propertiesRead;
            }

            // check for and read additional data as a byte string
            state = PeekStateWithExceptionHandling(reader);
            if (state == CborReaderState.ByteString)
            {
                try
                {
                    returnValue.AdditionalData = reader.ReadByteString();
                }
                catch(Exception ex) when (ex is InvalidOperationException || ex is CborContentException)
                {
                    throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, reading the additional data provided threw an exception: {ex.Message}", ex);
                }
                ++propertiesRead;
            }

            // validate the end of the structure is present.
            state = PeekStateWithExceptionHandling(reader);
            if (state != CborReaderState.EndArray)
            {
                throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, expected {nameof(CborReaderState.EndArray)} but got {state} instead after reading {propertiesRead} elements of {propertiesToRead} detected elements.");
            }
            try
            {
                reader.ReadEndArray();
            }
            catch(Exception ex) when (ex is InvalidOperationException || ex is CborContentException)
            {
                throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, reading the end of the array threw an exception: {ex.Message}", ex);
            }
        }
        catch(CborContentException ex)
        {
            throw new InvalidCoseDataException($"While processing content, a CborContentException was encountered: \"{ex.Message}\"", ex);
        }
        return returnValue;
    }

    private static CborReaderState PeekStateWithExceptionHandling(CborReader reader)
    {
        try
        {
            return reader.PeekState();
        }
        catch(Exception ex) when (ex is CborContentException)
        {
            throw new InvalidCoseDataException($"Invalid COSE_Hash_V structure, reading the state of the reader threw an exception: {ex.Message}", ex);
        }
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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: cose

namespace CoseIndirectSignature;

/// <summary>
/// Class used to construct <see cref="CoseSign1Message"/> objects which contain a indirect signature of a given payload.
/// </summary>
/// <remarks>
/// This class will append a "+hash-{hash-algorithm-name}" to the content type when storing it within the Content Type protected header of the <see cref="CoseSign1Message"/> using a <see cref="ICoseSign1MessageFactory"/> (Defaulting to a <see cref="CoseSign1MessageFactory"/>).
/// The <see cref="CoseMessage.Content"/> field will contain the hash value of the specified payload.
/// The default hash algorithm used is <see cref="HashAlgorithmName.SHA256"/>.
/// </remarks>
public sealed partial class IndirectSignatureFactory : IDisposable
{
    /// <summary>
    /// The version of the indirect signature to be used.
    /// </summary>
    public enum IndirectSignatureVersion
    {
        /// <summary>
        /// The older format, which is not recommended for new applications and is included for backwards compatibility.
        /// </summary>
        [Obsolete("Use CoseHashEnvelope instead")]
        Direct,
        /// <summary>
        /// The CoseHashV format, which is not recommended for new applications and is included for backwards compatibility.
        /// </summary>
        [Obsolete("Use CoseHashEnvelope instead")]
        CoseHashV,
        /// <summary>
        /// The CoseHashEnvelope format, which is the recommended format for new applications.
        /// </summary>
        CoseHashEnvelope
    }

    private readonly HashAlgorithm InternalHashAlgorithm;
    private readonly uint HashLength;
    private readonly CoseHashAlgorithm InternalCoseHashAlgorithm;
    private readonly HashAlgorithmName InternalHashAlgorithmName;
    private readonly ICoseSign1MessageFactory InternalMessageFactory;

    /// <summary>
    /// The HashAlgorithm this factory is using.
    /// </summary>
    public HashAlgorithm HashAlgorithm => InternalHashAlgorithm;

    /// <summary>
    /// The HashAlgorightmName this factory is using.
    /// </summary>
    public HashAlgorithmName HashAlgorithmName => InternalHashAlgorithmName;

    /// <summary>
    /// The CoseSign1 Message Factory this factory is using.
    /// </summary>
    public ICoseSign1MessageFactory MessageFactory => InternalMessageFactory;


    /// <summary>
    /// Creates a new instance of the <see cref="IndirectSignatureFactory"/> class using the <see cref="HashAlgorithmName.SHA256"/> hash algorithm and a <see cref="CoseSign1MessageFactory"/>.
    /// </summary>
    public IndirectSignatureFactory() : this(HashAlgorithmName.SHA256)
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="IndirectSignatureFactory"/> class using the specified hash algorithm and a <see cref="CoseSign1MessageFactory"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hashing algorithm name to be used when performing hashing operations.</param>
    public IndirectSignatureFactory(HashAlgorithmName hashAlgorithmName) : this(hashAlgorithmName, new CoseSign1MessageFactory())
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="IndirectSignatureFactory"/> class using the specified hash algorithm and the specified <see cref="ICoseSign1MessageFactory"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hashing algorithm name to be used when performing hashing operations.</param>
    /// <param name="coseSign1MessageFactory">The CoseSign1MessageFactory to be used when creating CoseSign1Messages.</param>
    public IndirectSignatureFactory(HashAlgorithmName hashAlgorithmName, ICoseSign1MessageFactory coseSign1MessageFactory)
    {
        InternalHashAlgorithmName = hashAlgorithmName;
        InternalHashAlgorithm = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(hashAlgorithmName) ?? throw new ArgumentOutOfRangeException(nameof(hashAlgorithmName), $"hashAlgorithmName[{hashAlgorithmName}] could not be instantiated into a valid HashAlgorithm");
        InternalMessageFactory = coseSign1MessageFactory;
        HashLength = (uint)InternalHashAlgorithm.HashSize / 8;
        InternalCoseHashAlgorithm = GetCoseHashAlgorithmFromHashAlgorithm(InternalHashAlgorithm);
    }

    private CoseHashAlgorithm GetCoseHashAlgorithmFromHashAlgorithm(HashAlgorithm algorithm)
    {
        return algorithm switch
        {
            SHA256 => CoseHashAlgorithm.SHA256,
            SHA384 => CoseHashAlgorithm.SHA384,
            SHA512 => CoseHashAlgorithm.SHA512,
            _ => throw new ArgumentException($@"No mapping for hash algorithm {algorithm.GetType().FullName} to any {nameof(CoseHashAlgorithm)}")
        };
    }

    /// <summary>
    /// Does the heavy lifting for this class in computing the hash and creating the correct representation of the CoseSign1Message base on input.
    /// </summary>
    /// <param name="returnBytes">True if ReadOnlyMemory<byte> form of CoseSign1Message is to be returned, False for a proper CoseSign1Message</param>
    /// <param name="signingKeyProvider">The signing key provider used for COSE signing operations.</param>
    /// <param name="contentType">The user specified content type.</param>
    /// <param name="streamPayload">If not null, then Stream API's on the CoseSign1MessageFactory are used.</param>
    /// <param name="bytePayload">If streamPayload is null then this must be specified and must not be null and will use the Byte API's on the CoseSign1MesssageFactory</param>
    /// <param name="payloadHashed">True if the payload represents the raw hash</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>Either a CoseSign1Message or a ReadOnlyMemory{byte} representing the CoseSign1Message object.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentNullException">Either streamPayload or bytePayload must be specified, but not both at the same time, or both cannot be null</exception>
    /// <exception cref="ArgumentException">payloadHashed is set, but hash size does not correspond to any known hash algorithms</exception>
    private object CreateIndirectSignatureWithChecksInternal(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        if (streamPayload is null && !bytePayload.HasValue || // both are empty
            streamPayload is not null && bytePayload.HasValue)    // both are specified
        {
            throw new ArgumentNullException("payload", "Either streamPayload or bytePayload must be specified, but not both at the same time, or both cannot be null");
        }

        switch(signatureVersion)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            case IndirectSignatureVersion.Direct:
#pragma warning restore CS0618 // Type or member is obsolete
                return CreateIndirectSignatureWithChecksInternalDirectFormat(
                            returnBytes,
                            signingKeyProvider,
                            contentType,
                            streamPayload,
                            bytePayload,
                            payloadHashed);
#pragma warning disable CS0618 // Type or member is obsolete
            case IndirectSignatureVersion.CoseHashV:
#pragma warning restore CS0618 // Type or member is obsolete
                return CreateIndirectSignatureWithChecksInternalCoseHashVFormat(
                            returnBytes,
                            signingKeyProvider,
                            contentType,
                            streamPayload,
                            bytePayload,
                            payloadHashed);
            case IndirectSignatureVersion.CoseHashEnvelope:
                return CreateIndirectSignatureWithChecksInternalCoseHashEnvelopeFormat(
                            returnBytes,
                            signingKeyProvider,
                            contentType,
                            streamPayload,
                            bytePayload,
                            payloadHashed);
            default:
                throw new ArgumentOutOfRangeException(nameof(signatureVersion), "Unknown signature version");
        }
    }

    /// <summary>
    /// Get the hash algorithm from the specified CoseHashAlgorithm.
    /// </summary>
    /// <param name="algorithm">The CoseHashAlgorithm to get a hashing type from.</param>
    /// <returns>The type of the hash object to use.</returns>
    /// <exception cref="NotSupportedException">The CoseHashAlgorithm specified is not yet supported.</exception>
    public static HashAlgorithm GetHashAlgorithmFromCoseHashAlgorithm(CoseHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            CoseHashAlgorithm.SHA256 => new SHA256Managed(),
            CoseHashAlgorithm.SHA512 => new SHA512Managed(),
            CoseHashAlgorithm.SHA384 => new SHA384Managed(),
            _ => throw new NotSupportedException($"The algorithm {algorithm} is not supported by {nameof(CoseHashV)}.")
        };
    }

    /// <summary>
    /// Method for handling byte[] and stream for the same logic.
    /// </summary>
    /// <param name="data">if specified, then will compute a hash of this data and compare to internal hash value.</param>
    /// <param name="stream">if data is null and stream is specified, then will compute a hash of this stream and compare to internal hash value.</param>
    /// <returns>True if the hashes match, False otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if data is null or data length is 0 and stream is null, or if data is null and stream is null.</exception>
    /// <exception cref="CoseSign1Exception">Thrown if the length of the computed hash does not match the internal stored hash length, thus the wrong hash algorithm is being used.</exception>
    internal static bool HashMatches(CoseHashAlgorithm hashAlgorithm, ReadOnlyMemory<byte> hashValue, ReadOnlyMemory<byte>? data, Stream? stream)
    {
        // handle input validation
        if (
            (data == null || data.Value.Length == 0) &&
            (stream == null))
        {
            throw new ArgumentNullException(nameof(data));
        }

        // initialize and compute the hash
        using HashAlgorithm hashAlgorithmImpl = GetHashAlgorithmFromCoseHashAlgorithm(hashAlgorithm);
        byte[] hash = stream != null ? hashAlgorithmImpl.ComputeHash(stream) : hashAlgorithmImpl.ComputeHash(data!.Value.ToArray());

        // handle the case where the algorithm we derived did not match the algorithm that was used to populate the CoseHashV instance.
        return hash.Length != hashValue.Length
            ? throw new CoseSign1Exception($@"The computed hash length of {hash.Length} for hash type {hashAlgorithm.GetType().FullName} created a hash different than the length of {hashValue.Length} which is unexpected.")
            : hash.SequenceEqual(hashValue.ToArray());
    }

    /// <summary>
    /// quick lookup of algorithm name based on size of raw hash in bytes
    /// References: https://csrc.nist.gov/projects/hash-functions, https://en.wikipedia.org/wiki/Secure_Hash_Algorithms
    /// </summary>
    private static readonly ConcurrentDictionary<int, HashAlgorithmName> SizeInBytesToAlgorithm = new(
        new Dictionary<int, HashAlgorithmName>()
        {
            { 32, HashAlgorithmName.SHA256 },
            { 48, HashAlgorithmName.SHA384 },
            { 64, HashAlgorithmName.SHA512 }
        });

    private bool DisposedValue;
    /// <summary>
    /// Dispose pattern implementation
    /// </summary>
    /// <param name="disposing">True if called from Dispose()</param>
    private void Dispose(bool disposing)
    {
        if (!DisposedValue)
        {
            if (disposing)
            {
                HashAlgorithm.Dispose();
            }
            DisposedValue = true;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}

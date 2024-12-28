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
public sealed class IndirectSignatureFactory : IDisposable
{
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
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateIndirectSignature(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: false,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            bytePayload: payload,
                                            useOldFormat: useOldFormat);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public CoseSign1Message CreateIndirectSignatureFromHash(
        ReadOnlyMemory<byte> rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: false,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            bytePayload: rawHash,
                                            payloadHashed: true,
                                            useOldFormat: useOldFormat);

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureAsync(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => Task.FromResult(
                                        (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: false,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            bytePayload: payload,
                                            useOldFormat: useOldFormat));

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureFromHashAsync(
        ReadOnlyMemory<byte> rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => Task.FromResult(
                                        (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: false,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            bytePayload: rawHash,
                                            payloadHashed: true,
                                            useOldFormat: useOldFormat));

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateIndirectSignature(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: false,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            streamPayload: payload,
                                            useOldFormat: useOldFormat);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public CoseSign1Message CreateIndirectSignatureFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: false,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            streamPayload: rawHash,
                                            payloadHashed: true,
                                            useOldFormat: useOldFormat);

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => Task.FromResult(
                                    (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                                        returnBytes: false,
                                        signingKeyProvider: signingKeyProvider,
                                        contentType: contentType,
                                        streamPayload: payload,
                                        useOldFormat: useOldFormat));

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => Task.FromResult(
                                    (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                                        returnBytes: false,
                                        signingKeyProvider: signingKeyProvider,
                                        contentType: contentType,
                                        streamPayload: rawHash,
                                        payloadHashed: true,
                                        useOldFormat: useOldFormat));

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytes(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: true,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            bytePayload: payload,
                                            useOldFormat: useOldFormat);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytesFromHash(
        ReadOnlyMemory<byte> rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: true,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            bytePayload: rawHash,
                                            payloadHashed: true,
                                            useOldFormat: useOldFormat);

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesAsync(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => Task.FromResult(
                                            (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                                                returnBytes: true,
                                                signingKeyProvider: signingKeyProvider,
                                                contentType: contentType,
                                                bytePayload: payload,
                                                useOldFormat: useOldFormat));

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesFromHashAsync(
        ReadOnlyMemory<byte> rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => Task.FromResult(
                                            (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                                                returnBytes: true,
                                                signingKeyProvider: signingKeyProvider,
                                                contentType: contentType,
                                                bytePayload: rawHash,
                                                payloadHashed: true,
                                                useOldFormat: useOldFormat));

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: true,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            streamPayload: payload,
                                            useOldFormat: useOldFormat);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytesFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                                            returnBytes: true,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            streamPayload: rawHash,
                                            payloadHashed: true,
                                            useOldFormat: useOldFormat);

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => Task.FromResult(
                                    (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                                        returnBytes: true,
                                        signingKeyProvider: signingKeyProvider,
                                        contentType: contentType,
                                        streamPayload: payload,
                                        useOldFormat: useOldFormat));

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) => Task.FromResult(
                                    (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                                        returnBytes: true,
                                        signingKeyProvider: signingKeyProvider,
                                        contentType: contentType,
                                        streamPayload: rawHash,
                                        payloadHashed: true,
                                        useOldFormat: useOldFormat));
    /// <summary>
    /// Does the heavy lifting for this class in computing the hash and creating the correct representation of the CoseSign1Message base on input.
    /// </summary>
    /// <param name="returnBytes">True if ReadOnlyMemory<byte> form of CoseSign1Message is to be returned, False for a proper CoseSign1Message</param>
    /// <param name="signingKeyProvider">The signing key provider used for COSE signing operations.</param>
    /// <param name="contentType">The user specified content type.</param>
    /// <param name="streamPayload">If not null, then Stream API's on the CoseSign1MessageFactory are used.</param>
    /// <param name="bytePayload">If streamPayload is null then this must be specified and must not be null and will use the Byte API's on the CoseSign1MesssageFactory</param>
    /// <param name="payloadHashed">True if the payload represents the raw hash</param>
    /// <param name="useOldFormat">True to use the older format, False to use CoseHashV format (default).</param>
    /// <returns>Either a CoseSign1Message or a ReadOnlyMemory{byte} representing the CoseSign1Message object.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentNullException">Either streamPayload or bytePayload must be specified, but not both at the same time, or both cannot be null</exception>
    /// <exception cref="ArgumentException">payloadHashed is set, but hash size does not correspond to any known hash algorithms</exception>
    private object CreateIndirectSignatureWithChecksInternal(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false,
        bool useOldFormat = false)
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

        return useOldFormat
            ? CreateIndirectSignatureWithChecksInternalOldFormat(
                returnBytes,
                signingKeyProvider,
                contentType,
                streamPayload,
                bytePayload,
                payloadHashed)
            : CreateIndirectSignatureWithChecksInternalNewFormat(
                returnBytes,
                signingKeyProvider,
                contentType,
                streamPayload,
                bytePayload,
                payloadHashed);
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
    /// <returns>Either a CoseSign1Message or a ReadOnlyMemory{byte} representing the CoseSign1Message object.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentNullException">Either streamPayload or bytePayload must be specified, but not both at the same time, or both cannot be null</exception>
    /// <exception cref="ArgumentException">payloadHashed is set, but hash size does not correspond to any known hash algorithms</exception>
    private object CreateIndirectSignatureWithChecksInternalNewFormat(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false)
    {
        CoseHashV hash;
        string extendedContentType = ExtendContentType(contentType);
        if (!payloadHashed)
        {
            hash = streamPayload != null
                                 ? new CoseHashV(InternalCoseHashAlgorithm, streamPayload)
                                 : new CoseHashV(InternalCoseHashAlgorithm, bytePayload!.Value);
        }
        else
        {
            byte[] rawHash = streamPayload != null
                                           ? streamPayload.GetBytes()
                                           : bytePayload!.Value.ToArray();

            if (rawHash.Length != HashLength)
            {
                throw new ArgumentException($"{nameof(payloadHashed)} is set, but payload length {rawHash.Length} does not correspond to the hash size for {InternalHashAlgorithmName} of {HashLength}.");
            }

            hash = new CoseHashV
            {
                Algorithm = InternalCoseHashAlgorithm,
                HashValue = rawHash
            };
        }


        return returnBytes
               // return the raw bytes if asked
               ? InternalMessageFactory.CreateCoseSign1MessageBytes(
                    hash.Serialize(),
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType)
               // return the CoseSign1Message object
               : InternalMessageFactory.CreateCoseSign1Message(
                    hash.Serialize(),
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType);
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
    /// <returns>Either a CoseSign1Message or a ReadOnlyMemory{byte} representing the CoseSign1Message object.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentNullException">Either streamPayload or bytePayload must be specified, but not both at the same time, or both cannot be null</exception>
    /// <exception cref="ArgumentException">payloadHashed is set, but hash size does not correspond to any known hash algorithms</exception>
    private object CreateIndirectSignatureWithChecksInternalOldFormat(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false)
    {
        ReadOnlyMemory<byte> hash;
        string extendedContentType;
        if (!payloadHashed)
        {
            hash = streamPayload != null
                                 ? InternalHashAlgorithm.ComputeHash(streamPayload)
                                 : InternalHashAlgorithm.ComputeHash(bytePayload!.Value.ToArray());
            extendedContentType = ExtendContentTypeOld(contentType);
        }
        else
        {
            hash = streamPayload != null
                                 ? streamPayload.GetBytes()
                                 : bytePayload!.Value.ToArray();
            try
            {
                HashAlgorithmName algoName = SizeInBytesToAlgorithm[hash.Length];
                extendedContentType = ExtendContentTypeOld(contentType, algoName);
            }
            catch (KeyNotFoundException e)
            {
                throw new ArgumentException($"{nameof(payloadHashed)} is set, but payload size does not correspond to any known hash sizes in {nameof(HashAlgorithmName)}", e);
            }
        }


        return returnBytes
               ? InternalMessageFactory.CreateCoseSign1MessageBytes(
                    hash,
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType)
               : InternalMessageFactory.CreateCoseSign1Message(
                    hash,
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType);
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

    /// <summary>
    /// quick lookup map between algorithm name and mime extension
    /// </summary>
    private static readonly ConcurrentDictionary<string, string> MimeExtensionMap = new(
        new Dictionary<string, string>()
        {
            { HashAlgorithmName.SHA256.Name, "+hash-sha256" },
            { HashAlgorithmName.SHA384.Name, "+hash-sha384" },
            { HashAlgorithmName.SHA512.Name, "+hash-sha512" }
        });

    /// <summary>
    /// Method which produces a mime type extension based on the given content type and hash algorithm name.
    /// </summary>
    /// <param name="contentType">The content type to append the hash value to if not already appended.</param>
    /// <returns>A string representing the content type with an appended hash algorithm</returns>
    private string ExtendContentTypeOld(string contentType) => ExtendContentTypeOld(contentType, InternalHashAlgorithmName);

    /// <summary>
    /// Method which produces a mime type extension based on the given content type and hash algorithm name.
    /// </summary>
    /// <param name="contentType">The content type to append the hash value to if not already appended.</param>
    /// <param name="algorithmName">The "HashAlgorithmName" to append if not already appended.</param>
    /// <returns>A string representing the content type with an appended hash algorithm</returns>
    private static string ExtendContentTypeOld(string contentType, HashAlgorithmName algorithmName)
    {
        // extract from the string cache to keep string allocations down.
        string extensionMapping = MimeExtensionMap.GetOrAdd(algorithmName.Name, (name) => $"+hash-{name.ToLowerInvariant()}");

        // only add the extension mapping, if it's not already present within the contentType
        bool alreadyPresent = contentType.IndexOf("+hash-", StringComparison.InvariantCultureIgnoreCase) != -1;

        return alreadyPresent
            ? contentType
            : $"{contentType}{extensionMapping}";
    }

    /// <summary>
    /// Method which produces a mime type extension for cose_hash_v
    /// </summary>
    /// <param name="contentType">The content type to append the cose_hash_v extension to if not already appended.</param>
    /// <returns>A string representing the content type with an appended cose_hash_v extension</returns>
    private static string ExtendContentType(string contentType)
    {
        // only add the extension mapping, if it's not already present within the contentType
        bool alreadyPresent = contentType.IndexOf("+cose-hash-v", StringComparison.InvariantCultureIgnoreCase) != -1;

        return alreadyPresent
            ? contentType
            : $"{contentType}+cose-hash-v";
    }

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

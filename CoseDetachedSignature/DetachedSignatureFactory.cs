// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseDetachedSignature;

/// <summary>
/// Class used to construct <see cref="CoseSign1Message"/> objects which contain a detached signature of a given payload.
/// </summary>
/// <remarks>
/// This class will append a "+hash-{hash-algorithm-name}" to the content type when storing it within the Content Type protected header of the <see cref="CoseSign1Message"/> using a <see cref="ICoseSign1MessageFactory"/> (Defaulting to a <see cref="CoseSign1MessageFactory"/>).
/// The <see cref="CoseMessage.Content"/> field will contain the hash value of the specified payload.
/// The default hash algorithm used is <see cref="HashAlgorithmName.SHA256"/>.
/// </remarks>
public sealed class DetachedSignatureFactory : IDisposable
{
    private readonly HashAlgorithm InternalHashAlgorithm;
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
    /// Creates a new instance of the <see cref="DetachedSignatureFactory"/> class using the <see cref="HashAlgorithmName.SHA256"/> hash algorithm and a <see cref="CoseSign1MessageFactory"/>.
    /// </summary>
    public DetachedSignatureFactory() : this(HashAlgorithmName.SHA256)
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="DetachedSignatureFactory"/> class using the specified hash algorithm and a <see cref="CoseSign1MessageFactory"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hashing algorithm name to be used when performing hashing operations.</param>
    public DetachedSignatureFactory(HashAlgorithmName hashAlgorithmName) : this(hashAlgorithmName, new CoseSign1MessageFactory())
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="DetachedSignatureFactory"/> class using the specified hash algorithm and the specified <see cref="ICoseSign1MessageFactory"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hashing algorithm name to be used when performing hashing operations.</param>
    /// <param name="coseSign1MessageFactory">The CoseSign1MessageFactory to be used when creating CoseSign1Messages.</param>
    public DetachedSignatureFactory(HashAlgorithmName hashAlgorithmName, ICoseSign1MessageFactory coseSign1MessageFactory)
    {
        InternalHashAlgorithmName = hashAlgorithmName;
        InternalHashAlgorithm = CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName(hashAlgorithmName) ?? throw new ArgumentOutOfRangeException(nameof(hashAlgorithmName), $"hashAlgorithmName[{hashAlgorithmName}] could not be instantiated into a valid HashAlgorithm");
        InternalMessageFactory = coseSign1MessageFactory;
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A CoseSign1Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateDetachedSignature(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool payloadHashed = false) => (CoseSign1Message)CreateDetachedSignatureWithChecksInternal(
                                            returnBytes: false,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            bytePayload: payload,
                                            payloadHashed: payloadHashed);

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateDetachedSignatureAsync(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool payloadHashed = false) => Task.FromResult(
                                            (CoseSign1Message)CreateDetachedSignatureWithChecksInternal(
                                                returnBytes: false,
                                                signingKeyProvider: signingKeyProvider,
                                                contentType: contentType,
                                                bytePayload: payload,
                                                payloadHashed: payloadHashed));

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateDetachedSignature(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool payloadHashed = false) => (CoseSign1Message)CreateDetachedSignatureWithChecksInternal(
                                            returnBytes: false,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            streamPayload: payload,
                                            payloadHashed: payloadHashed);

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateDetachedSignatureAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool payloadHashed = false) => Task.FromResult(
                                            (CoseSign1Message)CreateDetachedSignatureWithChecksInternal(
                                                returnBytes: false,
                                                signingKeyProvider: signingKeyProvider,
                                                contentType: contentType,
                                                streamPayload: payload,
                                                payloadHashed: payloadHashed));

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateDetachedSignatureBytes(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool payloadHashed = false) => (ReadOnlyMemory<byte>)CreateDetachedSignatureWithChecksInternal(
                                            returnBytes: true,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            bytePayload: payload,
                                            payloadHashed: payloadHashed);

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateDetachedSignatureBytesAsync(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool payloadHashed = false) => Task.FromResult(
                                            (ReadOnlyMemory<byte>)CreateDetachedSignatureWithChecksInternal(
                                                returnBytes: true,
                                                signingKeyProvider: signingKeyProvider,
                                                contentType: contentType,
                                                bytePayload: payload,
                                                payloadHashed: payloadHashed));

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateDetachedSignatureBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool payloadHashed = false) => (ReadOnlyMemory<byte>)CreateDetachedSignatureWithChecksInternal(
                                            returnBytes: true,
                                            signingKeyProvider: signingKeyProvider,
                                            contentType: contentType,
                                            streamPayload: payload,
                                            payloadHashed: payloadHashed);

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateDetachedSignatureBytesAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool payloadHashed = false) => Task.FromResult(
                                            (ReadOnlyMemory<byte>)CreateDetachedSignatureWithChecksInternal(
                                                returnBytes: true,
                                                signingKeyProvider: signingKeyProvider,
                                                contentType: contentType,
                                                streamPayload: payload,
                                                payloadHashed: payloadHashed));

    /// <summary>
    /// Does the heavy lifting for this class in computing the hash and creating the correct representation of the CoseSign1Message base on input.
    /// </summary>
    /// <param name="returnBytes">True if ReadOnlyMemory<byte> form of CoseSign1Message is to be returned, False for a proper CoseSign1Message</param>
    /// <param name="signingKeyProvider">The signing key provider used for COSE signing operations.</param>
    /// <param name="contentType">The user specified content type.</param>
    /// <param name="streamPayload">If not null, then Stream API's on the CoseSign1MessageFactory are used.</param>
    /// <param name="bytePayload">If streamPayload is null then this must be specified and must not be null and will use the Byte API's on the CoseSign1MesssageFactory</param>
    /// <returns>Either a CoseSign1Message or a ReadOnlyMemory{byte} representing the CoseSign1Message object.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    private object CreateDetachedSignatureWithChecksInternal(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        if (streamPayload == null && !bytePayload.HasValue || // both are empty
           streamPayload != null && bytePayload.HasValue)    // both are specified
        {
            throw new ArgumentNullException("payload", "Either streamPayload or bytePayload must be specified, but not both at the same time, or both cannot be null");
        }

        ReadOnlyMemory<byte> hash;
        string extendedContentType;
        if (!payloadHashed)
        {
            hash = streamPayload != null
                                 ? InternalHashAlgorithm.ComputeHash(streamPayload)
                                 : InternalHashAlgorithm.ComputeHash(bytePayload!.Value.ToArray());
            extendedContentType = ExtendContentType(contentType);
        }
        else
        {
            hash = streamPayload != null
                                 ? streamPayload.GetBytes()
                                 : bytePayload!.Value.ToArray();
            try
            {
                HashAlgorithmName algoName = SizeToAlgorithm[hash.Length];
                extendedContentType = ExtendContentType(contentType, algoName);
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
    /// quick lookup of algorithm name based on hash size
    /// </summary>
    private static readonly ConcurrentDictionary<int, HashAlgorithmName> SizeToAlgorithm = new(
        new Dictionary<int, HashAlgorithmName>()
        {
            { 16, HashAlgorithmName.MD5 },
            { 20, HashAlgorithmName.SHA1 },
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
    private bool DisposedValue;

    /// <summary>
    /// Method which produces a mime type extension based on the given content type and hash algorithm name.
    /// </summary>
    /// <param name="contentType">The content type to append the hash value to if not already appended.</param>
    /// <returns></returns>
    private string ExtendContentType(string contentType) => ExtendContentType(contentType, InternalHashAlgorithmName);

    /// <summary>
    /// Method which produces a mime type extension based on the given content type and hash algorithm name.
    /// </summary>
    /// <param name="contentType">The content type to append the hash value to if not already appended.</param>
    /// <returns></returns>
    private string ExtendContentType(string contentType, HashAlgorithmName algorithmName)
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

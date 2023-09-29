// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1;

/// <summary>
/// Class used to construct <see cref="CoseSign1Message"/> objects which contain a detached signature of a given payload.
/// </summary>
/// <remarks>
/// This class will append a "+hash-{hash-algorithm-name}" to the content type when storing it within the Content Type protected header of the <see cref="CoseSign1Message"/> using a <see cref="ICoseSign1MessageFactory"/> (Defaulting to a <see cref="CoseSign1MessageFactory"/>).
/// The <see cref="CoseMessage.Content"/> field will contain the hash value of the specified payload.
/// The default hash algorithm used is <see cref="HashAlgorithmName.SHA256"/>.
/// </remarks>
public class DetachedSignatureFactory
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
    /// <param name="coseSign1MessageFactory">The CoseSign1MessageFactory to be used when creating COSE Sign1 messages.</param>
    public DetachedSignatureFactory(HashAlgorithmName hashAlgorithmName, ICoseSign1MessageFactory coseSign1MessageFactory)
    {
        InternalHashAlgorithmName = hashAlgorithmName;
        InternalHashAlgorithm = HashAlgorithm.Create(hashAlgorithmName.Name);
        InternalMessageFactory = coseSign1MessageFactory;
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A COSE Sign1 Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateDetachedSignature(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        ReadOnlyMemory<byte> hash = InternalHashAlgorithm.ComputeHash(payload.ToArray());
        return InternalMessageFactory.CreateCoseSign1Message(
            hash,
            signingKeyProvider,
            embedPayload: true,
            contentType: ExtendContentType(contentType));
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which can be awaited which will return a COSE Sign1 Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateDetachedSignatureAsync(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        ReadOnlyMemory<byte> hash = InternalHashAlgorithm.ComputeHash(payload.ToArray());
        return Task.FromResult(InternalMessageFactory.CreateCoseSign1Message(
            hash,
            signingKeyProvider,
            embedPayload: true,
            contentType: ExtendContentType(contentType)));
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which can be awaited which will return a COSE Sign1 Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateDetachedSignature(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        ReadOnlyMemory<byte> hash = InternalHashAlgorithm.ComputeHash(payload);

        return InternalMessageFactory.CreateCoseSign1Message(
            new MemoryStream(hash.ToArray()),
            signingKeyProvider,
            embedPayload: true,
            contentType: ExtendContentType(contentType));
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which can be awaited which will return a COSE Sign1 Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateDetachedSignatureAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        ReadOnlyMemory<byte> hash = InternalHashAlgorithm.ComputeHash(payload);

        return Task.FromResult(InternalMessageFactory.CreateCoseSign1Message(
            new MemoryStream(hash.ToArray()),
            signingKeyProvider,
            embedPayload: true,
            contentType: ExtendContentType(contentType)));
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A byte[] representation of a COSE Sign1 Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateDetachedSignatureBytes(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        ReadOnlyMemory<byte> hash = InternalHashAlgorithm.ComputeHash(payload.ToArray());
        return InternalMessageFactory.CreateCoseSign1MessageBytes(
            hash,
            signingKeyProvider,
            embedPayload: true,
            contentType: ExtendContentType(contentType));
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a COSE Sign1 Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateDetachedSignatureBytesAsync(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        ReadOnlyMemory<byte> hash = InternalHashAlgorithm.ComputeHash(payload.ToArray());
        return Task.FromResult(InternalMessageFactory.CreateCoseSign1MessageBytes(
            new MemoryStream(hash.ToArray()),
            signingKeyProvider,
            embedPayload: true,
            contentType: ExtendContentType(contentType)));
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A byte[] representation of a COSE Sign1 Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateDetachedSignatureBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        ReadOnlyMemory<byte> hash = InternalHashAlgorithm.ComputeHash(payload);
        return InternalMessageFactory.CreateCoseSign1MessageBytes(
            new MemoryStream(hash.ToArray()),
            signingKeyProvider,
            embedPayload: true,
            contentType: ExtendContentType(contentType));
    }

    /// <summary>
    /// Creates a detached signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a detached signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a COSE Sign1 Message which can be used as a detached signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateDetachedSignatureBytesAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType), "A content type must be specified");
        }

        ReadOnlyMemory<byte> hash = InternalHashAlgorithm.ComputeHash(payload);
        return Task.FromResult(InternalMessageFactory.CreateCoseSign1MessageBytes(
            new MemoryStream(hash.ToArray()),
            signingKeyProvider,
            embedPayload: true,
            contentType: ExtendContentType(contentType)));
    }

    /// <summary>
    /// quick lookup map between algorithm name and mime extension
    /// </summary>
    private static readonly ConcurrentDictionary<string, string> MimeExtensionMap = new(
        new Dictionary<string,string>()
        {
            { HashAlgorithmName.SHA256.Name, "+hash-sha256" },
            { HashAlgorithmName.SHA384.Name, "+hash-sha384" },
            { HashAlgorithmName.SHA512.Name, "+hash-sha512" }
        });

    /// <summary>
    /// Method which produces a mime type extension based on the given content type and hash algorithm name.
    /// </summary>
    /// <param name="contentType">The content type to append the hash value to if not already appended.</param>
    /// <returns></returns>
    private string ExtendContentType(string contentType)
    {
        // extract from the string cache to keep string allocations down.
        string extensionMapping = MimeExtensionMap.GetOrAdd(InternalHashAlgorithmName.Name, (name) => $"+hash-{name.ToLowerInvariant()}");

        // only add the extension mapping, if it's not already present within the contentType
        bool alreadyPresent = contentType.IndexOf("+hash-", StringComparison.InvariantCultureIgnoreCase) != -1;

        return alreadyPresent
            ? contentType
            : $"{contentType}{extensionMapping}";
    }
}

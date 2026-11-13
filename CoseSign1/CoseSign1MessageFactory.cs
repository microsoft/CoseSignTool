// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1;

using System.Formats.Cbor;
using System.Linq;
using System.Threading;

/// <summary>
/// Factory class that creates a CoseSign1Message object.
/// </summary>
public sealed class CoseSign1MessageFactory : ICoseSign1MessageFactory
{
    private readonly HashAlgorithmName? hashAlgorithm;

    /// <summary>
    /// The mime type added to Protected Headers when ContentType is not specified.
    /// </summary>
    public const string DEFAULT_CONTENT_TYPE = "application/cose";

    /// <summary>
    /// Creates a new <see cref="CoseSign1MessageFactory"/>.
    /// </summary>
    public CoseSign1MessageFactory()
    {
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1MessageFactory"/> that uses the specified hash algorithm for signing operations.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use for signing operations.</param>
    public CoseSign1MessageFactory(HashAlgorithmName hashAlgorithm)
    {
        this.hashAlgorithm = hashAlgorithm;
    }

    /// <inheritdoc/>
    public CoseSign1Message CreateCoseSign1Message(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CoseSign1MessageSigningOptions? signingOptions = null
           )
    {
        ReadOnlyMemory<byte> serializedMsg = CreateCoseSign1MessageBytes(payload, signingKeyProvider, embedPayload, contentType, headerExtender, signingOptions);
        return CoseMessage.DecodeSign1(serializedMsg.ToArray());
    }

    /// <inheritdoc/>
    public CoseSign1Message CreateCoseSign1Message(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CoseSign1MessageSigningOptions? signingOptions = null)
    {
        ReadOnlyMemory<byte> serializedMsg = CreateCoseSign1MessageBytes(payload, signingKeyProvider, embedPayload, contentType, headerExtender, signingOptions);
        return CoseMessage.DecodeSign1(serializedMsg.ToArray());
    }

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> CreateCoseSign1MessageBytes(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CoseSign1MessageSigningOptions? signingOptions = null)
    {
        CoseSigner signer = GetSigner(signingKeyProvider, contentType, headerExtender, signingOptions);
        ThrowIfEmpty(payload);

        return embedPayload ?
            CoseSign1Message.SignEmbedded(payload.ToArray(), signer) :
            CoseSign1Message.SignDetached(payload.ToArray(), signer);
    }

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> CreateCoseSign1MessageBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CoseSign1MessageSigningOptions? signingOptions = null)
    {
        CoseSigner signer = GetSigner(signingKeyProvider, contentType, headerExtender, signingOptions);
        ThrowIfEmpty(payload);

        return embedPayload ?
            CoseSign1Message.SignEmbedded(GetPayloadBytesFromStream(payload), signer) :
            Task.Run(() => CoseSign1Message.SignDetachedAsync(payload, signer)).ConfigureAwait(false).GetAwaiter().GetResult();
    }

    // Generate a CoseSigner object from the SigningKeyProvider, content type, and HeaderExtender
    private CoseSigner GetSigner(
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CoseSign1MessageSigningOptions? signingOptions = null,
        RSA? rsaKeyOverride = null)
    {
        // Make sure we have something to sign with.
        if (signingKeyProvider == null)
        {
            throw new ArgumentNullException(null, "Signing key provider is not provided.");
        }

        HashAlgorithmName signingHashAlgorithm = GetSigningHashAlgorithm(signingKeyProvider, signingOptions);

        // Get the protected headers and unprotected headers provided by the signing key provider.
        CoseHeaderMap? protectedHeaders = signingKeyProvider.GetProtectedHeaders();
        CoseHeaderMap? unProtectedHeaders = signingKeyProvider.GetUnProtectedHeaders();

        // Set the Content Type in the protected header.
        // This is a mandatory protected header value in a CoseSign1Message.
        protectedHeaders ??= [];
        protectedHeaders.Add(CoseHeaderLabel.ContentType, contentType);

        // Extend the headers if a Header Extender was specified.
        if (headerExtender != null)
        {
            protectedHeaders = headerExtender.ExtendProtectedHeaders(protectedHeaders);
            unProtectedHeaders = headerExtender.ExtendUnProtectedHeaders(unProtectedHeaders);
        }

        // Get the RSA or ECDSA Signing Key.
        AsymmetricAlgorithm? key = rsaKeyOverride ?? signingKeyProvider.GetRSAKey() as AsymmetricAlgorithm ?? signingKeyProvider.GetECDsaKey();

        // Build the CoseSigner object.
        return key switch
        {
            RSA => new CoseSigner(
                (RSA)key,
                signingOptions?.RsaSignaturePadding ?? RSASignaturePadding.Pss,
                signingHashAlgorithm,
                protectedHeaders,
                unProtectedHeaders),
            ECDsa => new CoseSigner(key, signingHashAlgorithm, protectedHeaders, unProtectedHeaders),
            _ => throw new CoseSigningException("Unsupported certificate type for COSE signing.")
        };
    }

    private HashAlgorithmName GetSigningHashAlgorithm(
        ICoseSigningKeyProvider signingKeyProvider,
        CoseSign1MessageSigningOptions? signingOptions)
    {
        HashAlgorithmName signingHashAlgorithm =
            signingOptions?.HashAlgorithm ?? this.hashAlgorithm ?? signingKeyProvider.HashAlgorithm;
        if (signingKeyProvider is ISupportsHashAlgorithms supportedHashAlgorithms &&
            !supportedHashAlgorithms.SupportedHashAlgorithms.Contains(signingHashAlgorithm))
        {
            throw new CoseSigningException(
                $"The signing key provider does not support the requested hash algorithm '{signingHashAlgorithm.Name}'.");
        }

        return signingHashAlgorithm;
    }

    // Use only for embed signing -- will throw on streams over 2gb
    private static byte[] GetPayloadBytesFromStream(Stream s)
    {
        try
        {
            return s.GetBytes();
        }
        catch (IOException)
        {
            throw new CoseSigningException($"Embed signing not supported for payload of more than 2GB.");
        }
    }

    // Checks to see if the payload is empty
    private static void ThrowIfEmpty(Stream stream)
    {
        if (stream.IsNullOrEmpty(10000))
        {
            throw new ArgumentOutOfRangeException(null, "The payload to sign is empty.");
        }
    }

    // Checks to see if the payload is empty
    private static void ThrowIfEmpty(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            throw new ArgumentOutOfRangeException(null, "The payload to sign is empty.");
        }
    }

    /// <inheritdoc/>
    public async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CancellationToken cancellationToken = default,
        CoseSign1MessageSigningOptions? signingOptions = null)
    {
        // Wrap byte array in MemoryStream to enable true async signing path
        using MemoryStream payloadStream = new(payload.ToArray());
        ReadOnlyMemory<byte> serializedMsg = await CreateCoseSign1MessageBytesAsync(payloadStream, signingKeyProvider, embedPayload, contentType, headerExtender, cancellationToken, signingOptions).ConfigureAwait(false);
        return CoseMessage.DecodeSign1(serializedMsg.ToArray());
    }

    /// <inheritdoc/>
    public async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CancellationToken cancellationToken = default,
        CoseSign1MessageSigningOptions? signingOptions = null)
    {
        ReadOnlyMemory<byte> serializedMsg = await CreateCoseSign1MessageBytesAsync(payload, signingKeyProvider, embedPayload, contentType, headerExtender, cancellationToken, signingOptions).ConfigureAwait(false);
        return CoseMessage.DecodeSign1(serializedMsg.ToArray());
    }

    /// <inheritdoc/>
    public async Task<ReadOnlyMemory<byte>> CreateCoseSign1MessageBytesAsync(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CancellationToken cancellationToken = default,
        CoseSign1MessageSigningOptions? signingOptions = null)
    {
        // Wrap byte array in MemoryStream to enable true async signing path
        using MemoryStream payloadStream = new(payload.ToArray());
        return await CreateCoseSign1MessageBytesAsync(payloadStream, signingKeyProvider, embedPayload, contentType, headerExtender, cancellationToken, signingOptions).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<ReadOnlyMemory<byte>> CreateCoseSign1MessageBytesAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null,
        CancellationToken cancellationToken = default,
        CoseSign1MessageSigningOptions? signingOptions = null)
    {
        if (signingKeyProvider is IAsyncRsaSigningKeyProvider asyncKeyProvider)
        {
            return await CreateWithAsyncKeyAsync(
                payload, asyncKeyProvider, embedPayload, contentType, headerExtender,
                cancellationToken, signingOptions).ConfigureAwait(false);
        }

        CoseSigner signer = GetSigner(signingKeyProvider, contentType, headerExtender, signingOptions);
        ThrowIfEmpty(payload);

        // Wrap in Task.Run with cancellation token to enable cancellation support
        return embedPayload ?
            await Task.Run(() => CoseSign1Message.SignEmbedded(GetPayloadBytesFromStream(payload), signer), cancellationToken).ConfigureAwait(false) :
            await Task.Run(async () => await CoseSign1Message.SignDetachedAsync(payload, signer).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
    }

    private async Task<ReadOnlyMemory<byte>> CreateWithAsyncKeyAsync(
        Stream payload,
        IAsyncRsaSigningKeyProvider signingKeyProvider,
        bool embedPayload,
        string contentType,
        ICoseHeaderExtender? headerExtender,
        CancellationToken cancellationToken,
        CoseSign1MessageSigningOptions? signingOptions)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = GetSigningHashAlgorithm(signingKeyProvider, signingOptions);
        using RSA publicKey = await signingKeyProvider.GetPublicKeyAsync(cancellationToken).ConfigureAwait(false);
        using SigningDigestCaptureRsa digestCapture = new(publicKey.KeySize);
        CoseSigner signer = GetSigner(signingKeyProvider, contentType, headerExtender, signingOptions, digestCapture);
        byte[] preparedMessage;

        // Let .NET validate headers, encode the COSE message and hash its Sig_structure.
        // The zero-filled signature is private preparation data and is replaced only after signing succeeds.
        if (embedPayload)
        {
            using MemoryStream bufferedPayload = new();
            await payload.CopyToAsync(bufferedPayload, 81920, cancellationToken).ConfigureAwait(false);
            if (bufferedPayload.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(payload), "The payload to sign is empty.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            preparedMessage = CoseSign1Message.SignEmbedded(
                bufferedPayload.GetBuffer().AsSpan(0, checked((int)bufferedPayload.Length)), signer);
        }
        else
        {
            if (payload.CanSeek && payload.Position == payload.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(payload), "The payload to sign is empty.");
            }

            preparedMessage = await CoseSign1Message.SignDetachedAsync(
                payload, signer, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        byte[] signature = await signingKeyProvider.SignHashAsync(
            digestCapture.Digest ?? throw new CryptographicException("The COSE signing digest was not produced."),
            signer.HashAlgorithm, signer.RSASignaturePadding, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (signature == null || signature.Length != publicKey.KeySize / 8)
        {
            throw new CryptographicException("The signing provider returned an invalid RSA signature length.");
        }

        CborReader reader = new(preparedMessage);
        if (reader.PeekState() == CborReaderState.Tag)
        {
            _ = reader.ReadTag();
        }

        _ = reader.ReadStartArray();
        reader.SkipValue(); // Protected headers.
        reader.SkipValue(); // Unprotected headers.
        reader.SkipValue(); // Embedded payload or null.
        _ = reader.ReadEncodedValue();
        signature.CopyTo(preparedMessage, preparedMessage.Length - reader.BytesRemaining - signature.Length);
        return preparedMessage;
    }

    private sealed class SigningDigestCaptureRsa : RSA
    {
        internal byte[]? Digest { get; private set; }

        internal SigningDigestCaptureRsa(int keySize)
        {
            KeySizeValue = keySize;
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            Digest = hash.ToArray();
            return new byte[KeySize / 8];
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) => throw new NotSupportedException();

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => throw new NotSupportedException();

        public override RSAParameters ExportParameters(bool includePrivateParameters) => throw new NotSupportedException();

        public override void ImportParameters(RSAParameters parameters) => throw new NotSupportedException();
    }
}

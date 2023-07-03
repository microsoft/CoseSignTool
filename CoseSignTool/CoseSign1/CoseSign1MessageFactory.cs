// ---------------------------------------------------------------------------
// <copyright file="CoseSign1MessageFactory.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1;

/// <summary>
/// Factory class that creates a CoseSign1Message object.
/// </summary>
public sealed class CoseSign1MessageFactory : ICoseSign1MessageFactory
{
    /// <summary>
    /// The mime type added to Protected Headers when ContentType is not specified.
    /// </summary>
    public const string DEFAULT_CONTENT_TYPE = "application/cose";

    /// <summary>
    /// Creates a new <see cref="CoseSign1MessageFactory"/>.
    /// </summary>
    public CoseSign1MessageFactory()
    { }

    /// <inheritdoc/>
    public CoseSign1Message CreateCoseSign1Message(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null
           )
    {
        ReadOnlyMemory<byte> serializedMsg = CreateCoseSign1MessageBytes(payload, signingKeyProvider, embedPayload, contentType, headerExtender);
        return CoseMessage.DecodeSign1(serializedMsg.ToArray());
    }

    /// <inheritdoc/>
    public CoseSign1Message CreateCoseSign1Message(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null)
    {
        ReadOnlyMemory<byte> serializedMsg = CreateCoseSign1MessageBytes(payload, signingKeyProvider, embedPayload, contentType, headerExtender);
        return CoseMessage.DecodeSign1(serializedMsg.ToArray());
    }

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> CreateCoseSign1MessageBytes(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload = false,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null)
    {
        CoseSigner signer = GetSigner(signingKeyProvider, contentType, headerExtender);
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
        ICoseHeaderExtender? headerExtender = null)
    {
        CoseSigner signer = GetSigner(signingKeyProvider, contentType, headerExtender);
        ThrowIfEmpty(payload);

        return embedPayload ?
            CoseSign1Message.SignEmbedded(GetPayloadBytesFromStream(payload), signer) :
            Task.Run(() => CoseSign1Message.SignDetachedAsync(payload, signer)).ConfigureAwait(false).GetAwaiter().GetResult();
    }

    // Generate a CoseSigner object from the SigningKeyProvider, content type, and HeaderExtender
    private static CoseSigner GetSigner(
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType = DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null)
    {
        // Make sure we have something to sign with.
        if (signingKeyProvider == null)
        {
            throw new ArgumentNullException(null, "Signing key provider is not provided.");
        }

        // Get the protected headers and unprotected headers provided by the signing key provider.
        CoseHeaderMap? protectedHeaders = signingKeyProvider.GetProtectedHeaders();
        CoseHeaderMap? unProtectedHeaders = signingKeyProvider.GetUnProtectedHeaders();

        // Set the Content Type in the protected header.
        // This is a mandatory protected header value in a CoseSign1Message.
        protectedHeaders ??= new CoseHeaderMap();
        protectedHeaders.Add(CoseHeaderLabel.ContentType, contentType);

        // Extend the headers if a Header Extender was specified.
        if (headerExtender != null)
        {
            protectedHeaders = headerExtender.ExtendProtectedHeaders(protectedHeaders);
            unProtectedHeaders = headerExtender.ExtendUnProtectedHeaders(unProtectedHeaders);
        }

        // Get the RSA or ECDSA Signing Key.
        AsymmetricAlgorithm? key = signingKeyProvider.GetRSAKey() as AsymmetricAlgorithm ?? signingKeyProvider.GetECDsaKey();

        // Build the CoseSigner object.
        return key switch
        {
            RSA => new CoseSigner((RSA)key, RSASignaturePadding.Pss, signingKeyProvider.HashAlgorithm, protectedHeaders, unProtectedHeaders),
            ECDsa => new CoseSigner(key, signingKeyProvider.HashAlgorithm, protectedHeaders, unProtectedHeaders),
            _ => throw new CoseSigningException("Unsupported certificate type for COSE signing.")
        };
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
        if (stream.IsNullOrEmpty())
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
}


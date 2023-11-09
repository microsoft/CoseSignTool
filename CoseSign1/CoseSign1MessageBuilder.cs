// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1;

/// <summary>
/// Class thats sets the properties required for cosesigning and builds a CoseSign1Message
/// </summary>
public class CoseSign1MessageBuilder
{
    /// <summary>
    /// Gets the <see cref="ICoseSigningKeyProvider"/> which will be used for signing operations.
    /// </summary>
    public ICoseSigningKeyProvider? SigningKeyProvider { get; }

    /// <summary>
    /// Gets the <see cref="ICoseSign1MessageFactory"/> which will be used to create the <see cref="CoseSign1Message"/> object.
    /// </summary>
    public ICoseSign1MessageFactory FactObj { get; }

    /// <summary>
    /// Gets the payload which will be signed by this builder object.
    /// </summary>
    public virtual ReadOnlyMemory<byte> PayloadBytes { get; private set; }

    /// <summary>
    /// Gets the status of embedding the payload.
    /// </summary>
    public virtual bool EmbedPayload { get; private set; }

    /// <summary>
    /// Gets the ContentType of the payload being protected by this <see cref="CoseSign1Message"/>
    /// </summary>
    public virtual string ContentType { get; private set; }

    /// <summary>
    /// Gets the custom header extender for use during signing operations.
    /// </summary>
    public virtual ICoseHeaderExtender? HeaderExtender { get; private set; }

    /// <summary>
    /// Used for Mocking
    /// </summary>
    [ExcludeFromCodeCoverage]
    protected CoseSign1MessageBuilder(string contentType = "application/json")
    {
        FactObj = new CoseSign1MessageFactory();
        ContentType = contentType;
    }

    /// <summary>
    /// Use to instantiate this class with the signingKeyProvider and Factory Class Obj
    /// </summary>
    /// <param name="keyProvider">The <see cref="ICoseSigningKeyProvider"/> to use with signing operations.</param>
    /// <param name="factory">The <see cref="ICoseSign1MessageFactory"/> factory object to use in the building process.</param>
    public CoseSign1MessageBuilder(ICoseSigningKeyProvider keyProvider, ICoseSign1MessageFactory? factory = null, string contentType = "application/json")
    {
        SigningKeyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        FactObj = factory ?? new CoseSign1MessageFactory();
        ContentType = contentType;
    }

    /// <summary>
    /// Sets the Payload Bytes
    /// </summary>
    /// <param name="payloadBytes"></param>
    /// <returns>The updated <see cref="CoseSign1MessageBuilder"/>.</returns>
    public CoseSign1MessageBuilder SetPayloadBytes(ReadOnlyMemory<byte> payloadBytes)
    {
        PayloadBytes = payloadBytes;
        return this;
    }

    /// <summary>
    /// Sets the value of embedPayload
    /// EmbedPayload is a property thats determines whether to embed an encoded copy of the payload content into the signature file.
    /// </summary>
    /// <param name="setEmbedPayload">True for embed signing, false for detached signing.</param>
    /// <returns>The updated <see cref="CoseSign1MessageBuilder"/>.</returns>
    public CoseSign1MessageBuilder SetEmbedPayload(bool setEmbedPayload)
    {
        EmbedPayload = setEmbedPayload;
        return this;
    }

    /// <summary>
    /// Sets the value of Content type
    /// This determines the content type of the payload being protected by this <see cref="CoseSign1Message"/>
    /// </summary>
    /// <param name="contentType">Content type to be set.</param>
    /// <returns>The updated <see cref="CoseSign1MessageBuilder"/>.</returns>
    public CoseSign1MessageBuilder SetContentType(string contentType)
    {
        ContentType = contentType;
        return this;
    }

    /// <summary>
    /// Enables dynamic addition of protected and unprotected headers.
    /// </summary>
    /// <param name="headerExtender">The <see cref="ICoseHeaderExtender"/> to use during signing operations.</param>
    /// <returns>The updated <see cref="CoseSign1MessageBuilder"/>.</returns>
    public CoseSign1MessageBuilder ExtendCoseHeader(ICoseHeaderExtender headerExtender)
    {
        HeaderExtender = headerExtender;
        return this;
    }

    /// <summary>
    /// Builds the CoseSign1Message
    /// </summary>
    /// <returns><see cref="CoseSign1Message"/> signed by the <see cref="ICoseSigningKeyProvider"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key.</exception>
    public CoseSign1Message Build() => FactObj.CreateCoseSign1Message(PayloadBytes, SigningKeyProvider, EmbedPayload, ContentType, HeaderExtender);
}


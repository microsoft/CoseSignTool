// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Interfaces;

using System.Threading;

/// <summary>
/// Interface for Factory class to Create <see cref="CoseSign1Message"/> objects of various forms.
/// </summary>
public interface ICoseSign1MessageFactory
{
    /// <summary>
    /// Creates a CoseSign1Message object that represents a COSE signature.
    /// </summary>
    /// <param name="payload">The content to be signed.</param>
    /// <param name="signingKeyProvider">The key provider used for signing</param>
    /// <param name="embedPayload">Encodes a copy of the specified content and includes it in the CoseSign1Message object.
    /// By default, a detached signature is created, which contains a hash of the payload instead of its contents.</param>
    /// <param name="contentType">An optional MIME type to specify as the ContentType of the current payload. Default value is "application/cose"/></param>
    /// <param name="headerExtender">Optional. Adds headers other than the common headers provided by KeyProvider Instance</param>
    /// <returns>The COSE signature structure as a ReadOnlyMemory block of bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the payload or the signing key provider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key.</exception>
    public CoseSign1Message CreateCoseSign1Message(
           ReadOnlyMemory<byte> payload,
           ICoseSigningKeyProvider signingKeyProvider,
           bool embedPayload = false,
           string contentType = Constants.DEFAULT_CONTENT_TYPE,
           ICoseHeaderExtender? headerExtender = null
           );

    /// <summary>
    /// Creates a CoseSign1Message object that represents a COSE signature.
    /// </summary>
    /// <param name="payload">The content to be signed.</param>
    /// <param name="signingKeyProvider">The key provider used for signing</param>
    /// <param name="embedPayload">Encodes a copy of the specified content and includes it in the CoseSign1Message object.
    /// By default, a detached signature is created, which contains a hash of the payload instead of its contents.</param>
    /// <param name="contentType">An optional MIME type to specify as the ContentType of the current payload. Default value is "application/cose"/></param>
    /// <param name="headerExtender">Optional. Adds headers other than the common headers provided by KeyProvider Instance</param>
    /// <returns>The COSE signature structure as a ReadOnlyMemory block of bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the payload or the signing key provider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key,
    /// or if the user tries to embed-sign a payload strem of >2gb.</exception>
    public CoseSign1Message CreateCoseSign1Message(
           Stream payload,
           ICoseSigningKeyProvider signingKeyProvider,
           bool embedPayload = false,
           string contentType = Constants.DEFAULT_CONTENT_TYPE,
           ICoseHeaderExtender? headerExtender = null
           );

    /// <summary>
    /// Signs the supplied payload and returns the COSE signature as a read-only byte array.
    /// </summary>
    /// <param name="payload">The content to be signed.</param>
    /// <param name="signingKeyProvider">The key provider used for signing</param>
    /// <param name="embedPayload">Encodes a copy of the specified content and includes it in the CoseSign1Message object.
    /// By default, a detached signature is created, which contains a hash of the payload instead of its contents.</param>
    /// <param name="contentType">An optional MIME type to specify as the ContentType of the current payload. Default value is "application/cose"/></param>
    /// <param name="headerExtender">Optional. Adds headers other than the common headers provided by KeyProvider Instance</param>
    /// <returns>The COSE signature structure as a ReadOnlyMemory block of bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the payload or the signing key provider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key,
    /// or if the user tries to embed-sign a payload strem of >2gb.</exception>
    public ReadOnlyMemory<byte> CreateCoseSign1MessageBytes(
           ReadOnlyMemory<byte> payload,
           ICoseSigningKeyProvider signingKeyProvider,
           bool embedPayload = false,
           string contentType = Constants.DEFAULT_CONTENT_TYPE,
           ICoseHeaderExtender? headerExtender = null
           );

    /// <summary>
    /// Signs the supplied payload and returns the COSE signature as a read-only byte array.
    /// </summary>
    /// <param name="payload">The content to be signed.</param>
    /// <param name="signingKeyProvider">The key provider used for signing</param>
    /// <param name="embedPayload">Encodes a copy of the specified content and includes it in the CoseSign1Message object.
    /// By default, a detached signature is created, which contains a hash of the payload instead of its contents.</param>
    /// <param name="contentType">An optional MIME type to specify as the ContentType of the current payload. Default value is "application/cose"/></param>
    /// <param name="headerExtender">Optional. Adds headers other than the common headers provided by KeyProvider Instance</param>
    /// <returns>The COSE signature structure as a ReadOnlyMemory block of bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the payload or the signing key provider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key,
    /// or if the user tries to embed-sign a payload strem of >2gb.</exception>
    public ReadOnlyMemory<byte> CreateCoseSign1MessageBytes(
           Stream payload,
           ICoseSigningKeyProvider signingKeyProvider,
           bool embedPayload = false,
           string contentType = Constants.DEFAULT_CONTENT_TYPE,
           ICoseHeaderExtender? headerExtender = null
           );

    /// <summary>
    /// Asynchronously creates a CoseSign1Message object that represents a COSE signature.
    /// </summary>
    /// <param name="payload">The content to be signed.</param>
    /// <param name="signingKeyProvider">The key provider used for signing</param>
    /// <param name="embedPayload">Encodes a copy of the specified content and includes it in the CoseSign1Message object.
    /// By default, a detached signature is created, which contains a hash of the payload instead of its contents.</param>
    /// <param name="contentType">An optional MIME type to specify as the ContentType of the current payload. Default value is "application/cose"/></param>
    /// <param name="headerExtender">Optional. Adds headers other than the common headers provided by KeyProvider Instance</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the CoseSign1Message.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the payload or the signing key provider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key.</exception>
    public Task<CoseSign1Message> CreateCoseSign1MessageAsync(
           ReadOnlyMemory<byte> payload,
           ICoseSigningKeyProvider signingKeyProvider,
           bool embedPayload = false,
           string contentType = Constants.DEFAULT_CONTENT_TYPE,
           ICoseHeaderExtender? headerExtender = null,
           CancellationToken cancellationToken = default
           );

    /// <summary>
    /// Asynchronously creates a CoseSign1Message object that represents a COSE signature.
    /// </summary>
    /// <param name="payload">The content to be signed.</param>
    /// <param name="signingKeyProvider">The key provider used for signing</param>
    /// <param name="embedPayload">Encodes a copy of the specified content and includes it in the CoseSign1Message object.
    /// By default, a detached signature is created, which contains a hash of the payload instead of its contents.</param>
    /// <param name="contentType">An optional MIME type to specify as the ContentType of the current payload. Default value is "application/cose"/></param>
    /// <param name="headerExtender">Optional. Adds headers other than the common headers provided by KeyProvider Instance</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the CoseSign1Message.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the payload or the signing key provider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key,
    /// or if the user tries to embed-sign a payload stream of >2gb.</exception>
    public Task<CoseSign1Message> CreateCoseSign1MessageAsync(
           Stream payload,
           ICoseSigningKeyProvider signingKeyProvider,
           bool embedPayload = false,
           string contentType = Constants.DEFAULT_CONTENT_TYPE,
           ICoseHeaderExtender? headerExtender = null,
           CancellationToken cancellationToken = default
           );

    /// <summary>
    /// Asynchronously signs the supplied payload and returns the COSE signature as a read-only byte array.
    /// </summary>
    /// <param name="payload">The content to be signed.</param>
    /// <param name="signingKeyProvider">The key provider used for signing</param>
    /// <param name="embedPayload">Encodes a copy of the specified content and includes it in the CoseSign1Message object.
    /// By default, a detached signature is created, which contains a hash of the payload instead of its contents.</param>
    /// <param name="contentType">An optional MIME type to specify as the ContentType of the current payload. Default value is "application/cose"/></param>
    /// <param name="headerExtender">Optional. Adds headers other than the common headers provided by KeyProvider Instance</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the COSE signature structure as a ReadOnlyMemory block of bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the payload or the signing key provider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key.</exception>
    public Task<ReadOnlyMemory<byte>> CreateCoseSign1MessageBytesAsync(
           ReadOnlyMemory<byte> payload,
           ICoseSigningKeyProvider signingKeyProvider,
           bool embedPayload = false,
           string contentType = Constants.DEFAULT_CONTENT_TYPE,
           ICoseHeaderExtender? headerExtender = null,
           CancellationToken cancellationToken = default
           );

    /// <summary>
    /// Asynchronously signs the supplied payload and returns the COSE signature as a read-only byte array.
    /// </summary>
    /// <param name="payload">The content to be signed.</param>
    /// <param name="signingKeyProvider">The key provider used for signing</param>
    /// <param name="embedPayload">Encodes a copy of the specified content and includes it in the CoseSign1Message object.
    /// By default, a detached signature is created, which contains a hash of the payload instead of its contents.</param>
    /// <param name="contentType">An optional MIME type to specify as the ContentType of the current payload. Default value is "application/cose"/></param>
    /// <param name="headerExtender">Optional. Adds headers other than the common headers provided by KeyProvider Instance</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the COSE signature structure as a ReadOnlyMemory block of bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the payload or the signing key provider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the payload is empty or 0 length</exception>
    /// <exception cref="CoseSigningException">Thrown if the certificate has neither a RSA or ECDsa private key,
    /// or if the user tries to embed-sign a payload stream of >2gb.</exception>
    public Task<ReadOnlyMemory<byte>> CreateCoseSign1MessageBytesAsync(
           Stream payload,
           ICoseSigningKeyProvider signingKeyProvider,
           bool embedPayload = false,
           string contentType = Constants.DEFAULT_CONTENT_TYPE,
           ICoseHeaderExtender? headerExtender = null,
           CancellationToken cancellationToken = default
           );
}

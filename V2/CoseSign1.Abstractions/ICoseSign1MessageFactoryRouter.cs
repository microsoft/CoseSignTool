// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions;

using CoseSign1.Abstractions.Transparency;

/// <summary>
/// Router interface for creating COSE_Sign1 messages by selecting a factory based on the
/// requested signing options type.
/// </summary>
/// <remarks>
/// This interface complements <see cref="ICoseSign1MessageFactory{TOptions}"/>. Concrete
/// factories implement <see cref="ICoseSign1MessageFactory{TOptions}"/>, while the router
/// provides a pleasant call-site API that can resolve those factories through DI.
/// </remarks>
public interface ICoseSign1MessageFactoryRouter : IDisposable
{
    /// <summary>
    /// Gets the transparency providers configured for this router.
    /// </summary>
    IReadOnlyList<ITransparencyProvider>? TransparencyProviders { get; }

    /// <summary>
    /// Creates a COSE_Sign1 message and returns it as bytes.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g. "application/json").</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <returns>The encoded COSE_Sign1 bytes.</returns>
    byte[] CreateCoseSign1MessageBytes<TOptions>(
        byte[] payload,
        string contentType,
        TOptions? options = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a COSE_Sign1 message and returns it as bytes.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g. "application/json").</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <returns>The encoded COSE_Sign1 bytes.</returns>
    byte[] CreateCoseSign1MessageBytes<TOptions>(
        ReadOnlySpan<byte> payload,
        string contentType,
        TOptions? options = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a COSE_Sign1 message and returns it as bytes.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g. "application/json").</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task producing the encoded COSE_Sign1 bytes.</returns>
    Task<byte[]> CreateCoseSign1MessageBytesAsync<TOptions>(
        byte[] payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a COSE_Sign1 message and returns it as bytes.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g. "application/json").</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task producing the encoded COSE_Sign1 bytes.</returns>
    Task<byte[]> CreateCoseSign1MessageBytesAsync<TOptions>(
        ReadOnlyMemory<byte> payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a COSE_Sign1 message and returns it as bytes.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload.</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task producing the encoded COSE_Sign1 bytes.</returns>
    Task<byte[]> CreateCoseSign1MessageBytesAsync<TOptions>(
        Stream payloadStream,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a decoded <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload.</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <returns>The decoded COSE_Sign1 message.</returns>
    CoseSign1Message CreateCoseSign1Message<TOptions>(
        byte[] payload,
        string contentType,
        TOptions? options = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a decoded <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload.</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <returns>The decoded COSE_Sign1 message.</returns>
    CoseSign1Message CreateCoseSign1Message<TOptions>(
        ReadOnlySpan<byte> payload,
        string contentType,
        TOptions? options = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a decoded <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload.</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task producing the decoded COSE_Sign1 message.</returns>
    Task<CoseSign1Message> CreateCoseSign1MessageAsync<TOptions>(
        byte[] payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a decoded <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload.</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task producing the decoded COSE_Sign1 message.</returns>
    Task<CoseSign1Message> CreateCoseSign1MessageAsync<TOptions>(
        ReadOnlyMemory<byte> payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions;

    /// <summary>
    /// Creates a decoded <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <typeparam name="TOptions">The options type used to select the underlying factory.</typeparam>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload.</param>
    /// <param name="options">Optional options instance. If null, the underlying factory's defaults apply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task producing the decoded COSE_Sign1 message.</returns>
    Task<CoseSign1Message> CreateCoseSign1MessageAsync<TOptions>(
        Stream payloadStream,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions;
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories;

using System.Security.Cryptography;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;

/// <summary>
/// Routes COSE Sign1 creation to the appropriate implementation based on the runtime type of <see cref="SigningOptions"/>.
/// Pass <see cref="DirectSignatureOptions"/> to produce a direct signature, or <see cref="IndirectSignatureOptions"/> to produce
/// an indirect signature (hash envelope). Options must not be <see langword="null"/>.
/// </summary>
public sealed class CoseSign1MessageFactory : ICoseSign1MessageFactory<SigningOptions>
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorFormatUnsupportedSigningOptionsType =
            "Unsupported signing options type: {0}. Use {1} or {2}.";
    }

    private readonly DirectSignatureFactory _directFactory;
    private readonly IndirectSignatureFactory _indirectFactory;
    private bool Disposed;

    /// <inheritdoc />
    public IReadOnlyList<ITransparencyProvider>? TransparencyProviders => _directFactory.TransparencyProviders;

    /// <summary>
    /// Gets the underlying direct signature factory.
    /// </summary>
    public DirectSignatureFactory DirectFactory => _directFactory;

    /// <summary>
    /// Gets the underlying indirect signature factory.
    /// </summary>
    public IndirectSignatureFactory IndirectFactory => _indirectFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1MessageFactory"/> class.
    /// </summary>
    /// <param name="signingService">The signing service to use for signature creation.</param>
    /// <param name="transparencyProviders">Optional transparency providers to apply to all signed messages.</param>
    /// <param name="loggerFactory">Optional logger factory for creating loggers for internal factories.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signingService"/> is <see langword="null"/>.</exception>
    public CoseSign1MessageFactory(
        ISigningService<SigningOptions> signingService,
        IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
        ILoggerFactory? loggerFactory = null)
    {
        if (signingService is null)
        {
            throw new ArgumentNullException(nameof(signingService));
        }

        var directLogger = loggerFactory?.CreateLogger<DirectSignatureFactory>();
        var directFactory = new DirectSignatureFactory(signingService, transparencyProviders, directLogger);
        _directFactory = directFactory;

        var indirectLogger = loggerFactory?.CreateLogger<IndirectSignatureFactory>();
        _indirectFactory = new IndirectSignatureFactory(directFactory, indirectLogger);
    }

    /// <summary>
    /// Creates COSE_Sign1 message bytes using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <returns>The encoded COSE_Sign1 message bytes.</returns>
    public byte[] CreateDirectCoseSign1MessageBytes(byte[] payload, string contentType)
        => CreateCoseSign1MessageBytes(payload, contentType, new DirectSignatureOptions { EmbedPayload = true });

    /// <summary>
    /// Creates COSE_Sign1 message bytes using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <returns>The encoded COSE_Sign1 message bytes.</returns>
    public byte[] CreateDirectCoseSign1MessageBytes(ReadOnlySpan<byte> payload, string contentType)
        => CreateCoseSign1MessageBytes(payload, contentType, new DirectSignatureOptions { EmbedPayload = true });

    /// <summary>
    /// Creates COSE_Sign1 message bytes using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the encoded COSE_Sign1 message bytes.</returns>
    public Task<byte[]> CreateDirectCoseSign1MessageBytesAsync(
        byte[] payload,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageBytesAsync(payload, contentType, new DirectSignatureOptions { EmbedPayload = true }, cancellationToken);

    /// <summary>
    /// Creates COSE_Sign1 message bytes using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the encoded COSE_Sign1 message bytes.</returns>
    public Task<byte[]> CreateDirectCoseSign1MessageBytesAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageBytesAsync(payload, contentType, new DirectSignatureOptions { EmbedPayload = true }, cancellationToken);

    /// <summary>
    /// Creates COSE_Sign1 message bytes using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the encoded COSE_Sign1 message bytes.</returns>
    public Task<byte[]> CreateDirectCoseSign1MessageBytesAsync(
        Stream payloadStream,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageBytesAsync(payloadStream, contentType, new DirectSignatureOptions { EmbedPayload = true }, cancellationToken);

    /// <summary>
    /// Creates a COSE_Sign1 message using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <returns>The decoded COSE_Sign1 message.</returns>
    public CoseSign1Message CreateDirectCoseSign1Message(byte[] payload, string contentType)
        => CreateCoseSign1Message(payload, contentType, new DirectSignatureOptions { EmbedPayload = true });

    /// <summary>
    /// Creates a COSE_Sign1 message using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <returns>The decoded COSE_Sign1 message.</returns>
    public CoseSign1Message CreateDirectCoseSign1Message(ReadOnlySpan<byte> payload, string contentType)
        => CreateCoseSign1Message(payload, contentType, new DirectSignatureOptions { EmbedPayload = true });

    /// <summary>
    /// Creates a COSE_Sign1 message using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the decoded COSE_Sign1 message.</returns>
    public Task<CoseSign1Message> CreateDirectCoseSign1MessageAsync(
        byte[] payload,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageAsync(payload, contentType, new DirectSignatureOptions { EmbedPayload = true }, cancellationToken);

    /// <summary>
    /// Creates a COSE_Sign1 message using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the decoded COSE_Sign1 message.</returns>
    public Task<CoseSign1Message> CreateDirectCoseSign1MessageAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageAsync(payload, contentType, new DirectSignatureOptions { EmbedPayload = true }, cancellationToken);

    /// <summary>
    /// Creates a COSE_Sign1 message using a direct signature.
    /// Uses the default direct signature behavior (embedded payload).
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the decoded COSE_Sign1 message.</returns>
    public Task<CoseSign1Message> CreateDirectCoseSign1MessageAsync(
        Stream payloadStream,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageAsync(payloadStream, contentType, new DirectSignatureOptions { EmbedPayload = true }, cancellationToken);

    /// <summary>
    /// Creates COSE_Sign1 message bytes using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <returns>The encoded COSE_Sign1 message bytes.</returns>
    public byte[] CreateIndirectCoseSign1MessageBytes(byte[] payload, string contentType)
        => CreateCoseSign1MessageBytes(payload, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 });

    /// <summary>
    /// Creates COSE_Sign1 message bytes using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <returns>The encoded COSE_Sign1 message bytes.</returns>
    public byte[] CreateIndirectCoseSign1MessageBytes(ReadOnlySpan<byte> payload, string contentType)
        => CreateCoseSign1MessageBytes(payload, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 });

    /// <summary>
    /// Creates COSE_Sign1 message bytes using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the encoded COSE_Sign1 message bytes.</returns>
    public Task<byte[]> CreateIndirectCoseSign1MessageBytesAsync(
        byte[] payload,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageBytesAsync(payload, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 }, cancellationToken);

    /// <summary>
    /// Creates COSE_Sign1 message bytes using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the encoded COSE_Sign1 message bytes.</returns>
    public Task<byte[]> CreateIndirectCoseSign1MessageBytesAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageBytesAsync(payload, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 }, cancellationToken);

    /// <summary>
    /// Creates COSE_Sign1 message bytes using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the encoded COSE_Sign1 message bytes.</returns>
    public Task<byte[]> CreateIndirectCoseSign1MessageBytesAsync(
        Stream payloadStream,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageBytesAsync(payloadStream, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 }, cancellationToken);

    /// <summary>
    /// Creates a COSE_Sign1 message using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <returns>The decoded COSE_Sign1 message.</returns>
    public CoseSign1Message CreateIndirectCoseSign1Message(byte[] payload, string contentType)
        => CreateCoseSign1Message(payload, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 });

    /// <summary>
    /// Creates a COSE_Sign1 message using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <returns>The decoded COSE_Sign1 message.</returns>
    public CoseSign1Message CreateIndirectCoseSign1Message(ReadOnlySpan<byte> payload, string contentType)
        => CreateCoseSign1Message(payload, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 });

    /// <summary>
    /// Creates a COSE_Sign1 message using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the decoded COSE_Sign1 message.</returns>
    public Task<CoseSign1Message> CreateIndirectCoseSign1MessageAsync(
        byte[] payload,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageAsync(payload, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 }, cancellationToken);

    /// <summary>
    /// Creates a COSE_Sign1 message using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payload">The payload bytes to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the decoded COSE_Sign1 message.</returns>
    public Task<CoseSign1Message> CreateIndirectCoseSign1MessageAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageAsync(payload, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 }, cancellationToken);

    /// <summary>
    /// Creates a COSE_Sign1 message using an indirect signature (hash envelope).
    /// Uses the default indirect signature behavior (SHA-256).
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the preimage payload (for example, <c>application/json</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that resolves to the decoded COSE_Sign1 message.</returns>
    public Task<CoseSign1Message> CreateIndirectCoseSign1MessageAsync(
        Stream payloadStream,
        string contentType,
        CancellationToken cancellationToken = default)
        => CreateCoseSign1MessageAsync(payloadStream, contentType, new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 }, cancellationToken);

    private static bool UseDirectFactory(SigningOptions? options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (options is DirectSignatureOptions)
        {
            return true;
        }

        if (options is IndirectSignatureOptions)
        {
            return false;
        }

        throw new ArgumentException(
            string.Format(
                ClassStrings.ErrorFormatUnsupportedSigningOptionsType,
                options.GetType().FullName,
                nameof(DirectSignatureOptions),
                nameof(IndirectSignatureOptions)),
            nameof(options));
    }

    /// <inheritdoc />
    public byte[] CreateCoseSign1MessageBytes(byte[] payload, string contentType, SigningOptions? options = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1MessageBytes(payload, contentType, (DirectSignatureOptions?)options)
            : _indirectFactory.CreateCoseSign1MessageBytes(payload, contentType, (IndirectSignatureOptions?)options);
    }

    /// <inheritdoc />
    public byte[] CreateCoseSign1MessageBytes(ReadOnlySpan<byte> payload, string contentType, SigningOptions? options = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1MessageBytes(payload, contentType, (DirectSignatureOptions?)options)
            : _indirectFactory.CreateCoseSign1MessageBytes(payload, contentType, (IndirectSignatureOptions?)options);
    }

    /// <inheritdoc />
    public Task<byte[]> CreateCoseSign1MessageBytesAsync(
        byte[] payload,
        string contentType,
        SigningOptions? options = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1MessageBytesAsync(payload, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : _indirectFactory.CreateCoseSign1MessageBytesAsync(payload, contentType, (IndirectSignatureOptions?)options, cancellationToken);
    }

    /// <inheritdoc />
    public Task<byte[]> CreateCoseSign1MessageBytesAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        SigningOptions? options = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1MessageBytesAsync(payload, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : _indirectFactory.CreateCoseSign1MessageBytesAsync(payload, contentType, (IndirectSignatureOptions?)options, cancellationToken);
    }

    /// <inheritdoc />
    public Task<byte[]> CreateCoseSign1MessageBytesAsync(
        Stream payloadStream,
        string contentType,
        SigningOptions? options = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1MessageBytesAsync(payloadStream, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : _indirectFactory.CreateCoseSign1MessageBytesAsync(payloadStream, contentType, (IndirectSignatureOptions?)options, cancellationToken);
    }

    /// <inheritdoc />
    public CoseSign1Message CreateCoseSign1Message(byte[] payload, string contentType, SigningOptions? options = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1Message(payload, contentType, (DirectSignatureOptions?)options)
            : _indirectFactory.CreateCoseSign1Message(payload, contentType, (IndirectSignatureOptions?)options);
    }

    /// <inheritdoc />
    public CoseSign1Message CreateCoseSign1Message(ReadOnlySpan<byte> payload, string contentType, SigningOptions? options = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1Message(payload, contentType, (DirectSignatureOptions?)options)
            : _indirectFactory.CreateCoseSign1Message(payload, contentType, (IndirectSignatureOptions?)options);
    }

    /// <inheritdoc />
    public Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        byte[] payload,
        string contentType,
        SigningOptions? options = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1MessageAsync(payload, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : _indirectFactory.CreateCoseSign1MessageAsync(payload, contentType, (IndirectSignatureOptions?)options, cancellationToken);
    }

    /// <inheritdoc />
    public Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        SigningOptions? options = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1MessageAsync(payload, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : _indirectFactory.CreateCoseSign1MessageAsync(payload, contentType, (IndirectSignatureOptions?)options, cancellationToken);
    }

    /// <inheritdoc />
    public Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        Stream payloadStream,
        string contentType,
        SigningOptions? options = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? _directFactory.CreateCoseSign1MessageAsync(payloadStream, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : _indirectFactory.CreateCoseSign1MessageAsync(payloadStream, contentType, (IndirectSignatureOptions?)options, cancellationToken);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        _indirectFactory.Dispose();
        Disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (Disposed)
        {
            throw new ObjectDisposedException(nameof(CoseSign1MessageFactory));
        }
    }
}



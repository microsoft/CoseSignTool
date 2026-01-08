// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Abstractions.Transparency;
using CoseSign1.Direct;
using CoseSign1.Indirect;

namespace CoseSign1;

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

    private readonly DirectSignatureFactory DirectFactory;
    private readonly IndirectSignatureFactory IndirectFactory;
    private bool Disposed;

    /// <inheritdoc />
    public IReadOnlyList<ITransparencyProvider>? TransparencyProviders => DirectFactory.TransparencyProviders;

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
        DirectFactory = directFactory;

        var indirectLogger = loggerFactory?.CreateLogger<IndirectSignatureFactory>();
        IndirectFactory = new IndirectSignatureFactory(directFactory, indirectLogger);
    }

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
            ? DirectFactory.CreateCoseSign1MessageBytes(payload, contentType, (DirectSignatureOptions?)options)
            : IndirectFactory.CreateCoseSign1MessageBytes(payload, contentType, (IndirectSignatureOptions?)options);
    }

    /// <inheritdoc />
    public byte[] CreateCoseSign1MessageBytes(ReadOnlySpan<byte> payload, string contentType, SigningOptions? options = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? DirectFactory.CreateCoseSign1MessageBytes(payload, contentType, (DirectSignatureOptions?)options)
            : IndirectFactory.CreateCoseSign1MessageBytes(payload, contentType, (IndirectSignatureOptions?)options);
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
            ? DirectFactory.CreateCoseSign1MessageBytesAsync(payload, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : IndirectFactory.CreateCoseSign1MessageBytesAsync(payload, contentType, (IndirectSignatureOptions?)options, cancellationToken);
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
            ? DirectFactory.CreateCoseSign1MessageBytesAsync(payload, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : IndirectFactory.CreateCoseSign1MessageBytesAsync(payload, contentType, (IndirectSignatureOptions?)options, cancellationToken);
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
            ? DirectFactory.CreateCoseSign1MessageBytesAsync(payloadStream, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : IndirectFactory.CreateCoseSign1MessageBytesAsync(payloadStream, contentType, (IndirectSignatureOptions?)options, cancellationToken);
    }

    /// <inheritdoc />
    public CoseSign1Message CreateCoseSign1Message(byte[] payload, string contentType, SigningOptions? options = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? DirectFactory.CreateCoseSign1Message(payload, contentType, (DirectSignatureOptions?)options)
            : IndirectFactory.CreateCoseSign1Message(payload, contentType, (IndirectSignatureOptions?)options);
    }

    /// <inheritdoc />
    public CoseSign1Message CreateCoseSign1Message(ReadOnlySpan<byte> payload, string contentType, SigningOptions? options = default)
    {
        ThrowIfDisposed();

        var useDirectFactory = UseDirectFactory(options);
        return useDirectFactory
            ? DirectFactory.CreateCoseSign1Message(payload, contentType, (DirectSignatureOptions?)options)
            : IndirectFactory.CreateCoseSign1Message(payload, contentType, (IndirectSignatureOptions?)options);
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
            ? DirectFactory.CreateCoseSign1MessageAsync(payload, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : IndirectFactory.CreateCoseSign1MessageAsync(payload, contentType, (IndirectSignatureOptions?)options, cancellationToken);
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
            ? DirectFactory.CreateCoseSign1MessageAsync(payload, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : IndirectFactory.CreateCoseSign1MessageAsync(payload, contentType, (IndirectSignatureOptions?)options, cancellationToken);
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
            ? DirectFactory.CreateCoseSign1MessageAsync(payloadStream, contentType, (DirectSignatureOptions?)options, cancellationToken)
            : IndirectFactory.CreateCoseSign1MessageAsync(payloadStream, contentType, (IndirectSignatureOptions?)options, cancellationToken);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        IndirectFactory.Dispose();
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

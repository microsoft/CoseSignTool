// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories;

using System.Collections.Concurrent;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;

/// <summary>
/// Routes COSE Sign1 creation to the appropriate implementation based on the requested signing options type.
/// </summary>
public sealed class CoseSign1MessageFactory : ICoseSign1MessageFactoryRouter
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorNoGenericFactoryRegisteredFormat =
            "No ICoseSign1MessageFactory<{0}> is registered.";
    }

    private readonly IServiceProvider? _serviceProvider;
    private readonly ConcurrentDictionary<Type, object> _localFactories = new();
    private readonly IReadOnlyList<ITransparencyProvider>? _transparencyProviders;
    private readonly bool _ownsFactories;
    private readonly IDisposable? _ownedDisposable;
    private bool Disposed;

    /// <inheritdoc />
    public IReadOnlyList<ITransparencyProvider>? TransparencyProviders => _transparencyProviders;

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
        Guard.ThrowIfNull(signingService);

        var directLogger = loggerFactory?.CreateLogger<DirectSignatureFactory>();
        var directFactory = new DirectSignatureFactory(signingService, transparencyProviders, directLogger);

        var indirectLogger = loggerFactory?.CreateLogger<IndirectSignatureFactory>();
        var indirectFactory = new IndirectSignatureFactory(directFactory, indirectLogger);

        _serviceProvider = null;
        _transparencyProviders = transparencyProviders;
        _localFactories.TryAdd(typeof(DirectSignatureOptions), directFactory);
        _localFactories.TryAdd(typeof(IndirectSignatureOptions), indirectFactory);
        _ownsFactories = true;
        _ownedDisposable = indirectFactory;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1MessageFactory"/> class using dependency injection.
    /// </summary>
    /// <param name="serviceProvider">Service provider used to resolve registered <see cref="ICoseSign1MessageFactory{TOptions}"/> implementations.</param>
    /// <param name="loggerFactory">Optional logger factory for creating loggers for internal factories.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="serviceProvider"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// This constructor enables extensibility via package inclusion: packages can register additional
    /// <see cref="ICoseSign1MessageFactory{TOptions}"/> implementations and this router will select them.
    /// </remarks>
    public CoseSign1MessageFactory(
        IServiceProvider serviceProvider,
        ILoggerFactory? loggerFactory = null)
    {
        Guard.ThrowIfNull(serviceProvider);

        _ = loggerFactory;

        _serviceProvider = serviceProvider;
        _transparencyProviders = null;
        _ownsFactories = false;
        _ownedDisposable = null;
    }

    private ICoseSign1MessageFactory<TOptions> ResolveFactory<TOptions>()
        where TOptions : SigningOptions
    {
        if (_serviceProvider is not null)
        {
            var factory = (ICoseSign1MessageFactory<TOptions>?)_serviceProvider.GetService(typeof(ICoseSign1MessageFactory<TOptions>));
            if (factory is null)
            {
                throw new InvalidOperationException(
                    string.Format(ClassStrings.ErrorNoGenericFactoryRegisteredFormat, typeof(TOptions).FullName));
            }

            return factory;
        }

        if (_localFactories.TryGetValue(typeof(TOptions), out var local) && local is ICoseSign1MessageFactory<TOptions> typed)
        {
            return typed;
        }

        throw new InvalidOperationException(
            string.Format(ClassStrings.ErrorNoGenericFactoryRegisteredFormat, typeof(TOptions).FullName));
    }

    /// <inheritdoc />
    public byte[] CreateCoseSign1MessageBytes<TOptions>(byte[] payload, string contentType, TOptions? options = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1MessageBytes(payload, contentType, options);
    }

    /// <inheritdoc />
    public byte[] CreateCoseSign1MessageBytes<TOptions>(ReadOnlySpan<byte> payload, string contentType, TOptions? options = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1MessageBytes(payload, contentType, options);
    }

    /// <inheritdoc />
    public Task<byte[]> CreateCoseSign1MessageBytesAsync<TOptions>(
        byte[] payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1MessageBytesAsync(payload, contentType, options, cancellationToken);
    }

    /// <inheritdoc />
    public Task<byte[]> CreateCoseSign1MessageBytesAsync<TOptions>(
        ReadOnlyMemory<byte> payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1MessageBytesAsync(payload, contentType, options, cancellationToken);
    }

    /// <inheritdoc />
    public Task<byte[]> CreateCoseSign1MessageBytesAsync<TOptions>(
        Stream payloadStream,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1MessageBytesAsync(payloadStream, contentType, options, cancellationToken);
    }

    /// <inheritdoc />
    public CoseSign1Message CreateCoseSign1Message<TOptions>(byte[] payload, string contentType, TOptions? options = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1Message(payload, contentType, options);
    }

    /// <inheritdoc />
    public CoseSign1Message CreateCoseSign1Message<TOptions>(ReadOnlySpan<byte> payload, string contentType, TOptions? options = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1Message(payload, contentType, options);
    }

    /// <inheritdoc />
    public Task<CoseSign1Message> CreateCoseSign1MessageAsync<TOptions>(
        byte[] payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1MessageAsync(payload, contentType, options, cancellationToken);
    }

    /// <inheritdoc />
    public Task<CoseSign1Message> CreateCoseSign1MessageAsync<TOptions>(
        ReadOnlyMemory<byte> payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1MessageAsync(payload, contentType, options, cancellationToken);
    }

    /// <inheritdoc />
    public Task<CoseSign1Message> CreateCoseSign1MessageAsync<TOptions>(
        Stream payloadStream,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default)
        where TOptions : SigningOptions
    {
        ThrowIfDisposed();
        return ResolveFactory<TOptions>().CreateCoseSign1MessageAsync(payloadStream, contentType, options, cancellationToken);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        if (_ownsFactories)
        {
            _ownedDisposable?.Dispose();
        }

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



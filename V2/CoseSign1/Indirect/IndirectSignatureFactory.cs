// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.HighPerformance.Buffers;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Direct;
using CoseSign1.Logging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Indirect;

/// <summary>
/// Factory for creating indirect COSE signatures.
/// Indirect signatures sign a hash of the payload rather than the payload itself.
/// Uses composition to delegate direct signature creation to DirectSignatureFactory.
/// Instance-based design supports dependency injection and testability.
/// Thread-safe: all methods are stateless or use local state only.
/// </summary>
public class IndirectSignatureFactory : ICoseSign1MessageFactory<IndirectSignatureOptions>
{
    private readonly DirectSignatureFactory _directFactory;
    private readonly ILogger<IndirectSignatureFactory> _logger;
    private bool _disposed;

    /// <summary>
    /// Gets the transparency providers configured for this factory.
    /// These providers will be applied to all signed messages unless disabled per-operation.
    /// </summary>
    public IReadOnlyList<ITransparencyProvider>? TransparencyProviders => _directFactory.TransparencyProviders;

    /// <summary>
    /// Initializes a new instance of the <see cref="IndirectSignatureFactory"/> class.
    /// </summary>
    /// <param name="signingService">The signing service to use for signature creation.</param>
    /// <param name="transparencyProviders">Optional transparency providers to apply to all signed messages. Can be overridden per-operation.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    /// <param name="loggerFactory">Optional logger factory for creating loggers for internal factories.</param>
    public IndirectSignatureFactory(
        ISigningService<SigningOptions> signingService,
        IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
        ILogger<IndirectSignatureFactory>? logger = null,
        ILoggerFactory? loggerFactory = null) :
        this(new DirectSignatureFactory(signingService, transparencyProviders, loggerFactory?.CreateLogger<DirectSignatureFactory>()), logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="IndirectSignatureFactory"/> class.
    /// </summary>
    /// <param name="directFactory">The direct signature factory to use for signing hashes.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    public IndirectSignatureFactory(DirectSignatureFactory directFactory, ILogger<IndirectSignatureFactory>? logger = null)
    {
        _directFactory = directFactory ?? throw new ArgumentNullException(nameof(directFactory));
        _logger = logger ?? NullLogger<IndirectSignatureFactory>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="IndirectSignatureFactory"/> class.
    /// Protected parameterless constructor for mocking frameworks like Moq.
    /// </summary>
    protected IndirectSignatureFactory()
    {
        _directFactory = null!;
        _logger = NullLogger<IndirectSignatureFactory>.Instance;
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a byte array payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual byte[] CreateCoseSign1MessageBytes(
        byte[] payload,
        string contentType,
        IndirectSignatureOptions? options = null)
    {
        return CreateCoseSign1MessageBytes(payload, contentType, options, serviceOptions: null);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a byte array payload and returns it as bytes.
    /// Allows passing service-specific options per signing operation.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <param name="serviceOptions">Optional service-specific options to pass to the signing service. If null, service defaults are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual byte[] CreateCoseSign1MessageBytes(
        byte[] payload,
        string contentType,
        IndirectSignatureOptions? options,
        SigningOptions? serviceOptions)
    {
        if (payload == null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        if (contentType == null)
        {
            throw new ArgumentNullException(nameof(contentType));
        }

        ThrowIfDisposed();

        // Delegate to ReadOnlySpan overload
        return CreateCoseSign1MessageBytes(new ReadOnlySpan<byte>(payload), contentType, options, serviceOptions);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a ReadOnlySpan payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual byte[] CreateCoseSign1MessageBytes(
        ReadOnlySpan<byte> payload,
        string contentType,
        IndirectSignatureOptions? options = null)
    {
        return CreateCoseSign1MessageBytes(payload, contentType, options, serviceOptions: null);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a ReadOnlySpan payload and returns it as bytes.
    /// Allows passing service-specific options per signing operation.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <param name="serviceOptions">Optional service-specific options to pass to the signing service. If null, service defaults are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual byte[] CreateCoseSign1MessageBytes(
        ReadOnlySpan<byte> payload,
        string contentType,
        IndirectSignatureOptions? options,
        SigningOptions? serviceOptions)
    {
        if (contentType == null)
        {
            throw new ArgumentNullException(nameof(contentType));
        }

        ThrowIfDisposed();

        return HashAndSign(payload, contentType, options, serviceOptions);
    }

    /// <summary>
    /// Core implementation: hashes payload and signs the hash.
    /// </summary>
    private byte[] HashAndSign(
        ReadOnlySpan<byte> payload,
        string contentType,
        IndirectSignatureOptions? options = null,
        SigningOptions? serviceOptions = null)
    {
        if (contentType == null)
        {
            throw new ArgumentNullException(nameof(contentType));
        }

        ThrowIfDisposed();

        options ??= new IndirectSignatureOptions();

        _logger.LogDebug(
            new EventId(LogEvents.SigningStarted, nameof(LogEvents.SigningStarted)),
            "Starting indirect signature creation. ContentType: {ContentType}, PayloadSize: {PayloadSize}, HashAlgorithm: {HashAlgorithm}",
            contentType,
            payload.Length,
            options.HashAlgorithm);

        // Compute hash of payload using the hash algorithm specified in options
        // Note: This is the hash of the CONTENT. The signature itself may use a different
        // hash algorithm determined by the signing key in DirectSignatureFactory.
        using var owner = SpanOwner<byte>.Allocate(GetHashSize(options.HashAlgorithm));
        var hashSpan = owner.Span;

        if (!TryComputeHash(payload, options.HashAlgorithm, hashSpan, out int bytesWritten))
        {
            _logger.LogError(
                new EventId(LogEvents.SigningFailed, nameof(LogEvents.SigningFailed)),
                "Failed to compute hash of payload using {HashAlgorithm}",
                options.HashAlgorithm);
            throw new InvalidOperationException("Failed to compute hash of payload");
        }

        var hash = hashSpan.Slice(0, bytesWritten);
        _logger.LogTrace(
            new EventId(LogEvents.SigningPayloadInfo, nameof(LogEvents.SigningPayloadInfo)),
            "Computed payload hash. HashSize: {HashSize}",
            bytesWritten);

        // Create CoseHashEnvelope header contributor with protected headers
        var hashEnvelopeContributor = new CoseHashEnvelopeHeaderContributor(
            options.HashAlgorithm,
            contentType,
            options.PayloadLocation);

        // Chain with any additional header contributors
        var headerContributors = options.AdditionalHeaderContributors?.Any() == true
            ? new List<IHeaderContributor>(options.AdditionalHeaderContributors) { hashEnvelopeContributor }
            : new List<IHeaderContributor> { hashEnvelopeContributor };

        // Create DirectSignatureOptions with hash as payload and CoseHashEnvelope headers
        var directOptions = new DirectSignatureOptions
        {
            AdditionalHeaderContributors = headerContributors,
            AdditionalContext = options.AdditionalContext,
            AdditionalData = options.AdditionalData,
            EmbedPayload = true  // Embed the hash (not the original payload)
        };

        // Sign the hash directly (content type added by CoseHashEnvelopeHeaderContributor), passing serviceOptions through
        var result = _directFactory.CreateCoseSign1MessageBytes(hash, contentType, directOptions, serviceOptions);

        _logger.LogDebug(
            new EventId(LogEvents.SigningCompleted, nameof(LogEvents.SigningCompleted)),
            "Indirect signature created successfully. SignatureSize: {SignatureSize}",
            result.Length);

        return result;
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a byte array payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual Task<byte[]> CreateCoseSign1MessageBytesAsync(
        byte[] payload,
        string contentType,
        IndirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (payload == null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        ThrowIfDisposed();

        // Delegate to stream overload
        using var payloadStream = new MemoryStream(payload, writable: false);
        return CreateCoseSign1MessageBytesAsync(payloadStream, contentType, options, cancellationToken);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a ReadOnlyMemory payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual Task<byte[]> CreateCoseSign1MessageBytesAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        IndirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        // Delegate to byte[] overload
        return CreateCoseSign1MessageBytesAsync(payload.ToArray(), contentType, options, cancellationToken);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a stream payload and returns it as bytes.
    /// </summary>
    /// <param name="payloadStream">The payload stream to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/octet-stream").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual Task<byte[]> CreateCoseSign1MessageBytesAsync(
        Stream payloadStream,
        string contentType,
        IndirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (payloadStream == null)
        {
            throw new ArgumentNullException(nameof(payloadStream));
        }

        ThrowIfDisposed();

        // Delegate to implementation
        return HashAndSignAsync(payloadStream, contentType, options, cancellationToken);
    }

    /// <summary>
    /// Core async implementation: hashes stream and signs the hash.
    /// </summary>
    private async Task<byte[]> HashAndSignAsync(
        Stream payloadStream,
        string contentType,
        IndirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (payloadStream == null)
        {
            throw new ArgumentNullException(nameof(payloadStream));
        }

        if (contentType == null)
        {
            throw new ArgumentNullException(nameof(contentType));
        }

        ThrowIfDisposed();

        options ??= new IndirectSignatureOptions();

        _logger.LogDebug(
            new EventId(LogEvents.SigningStarted, nameof(LogEvents.SigningStarted)),
            "Starting async indirect signature creation. ContentType: {ContentType}, HashAlgorithm: {HashAlgorithm}",
            contentType,
            options.HashAlgorithm);

        // Compute hash of stream using MemoryOwner for pooled memory
        // Note: This is the hash of the CONTENT. The signature itself may use a different
        // hash algorithm determined by the signing key in DirectSignatureFactory.
        using var hashOwner = MemoryOwner<byte>.Allocate(GetHashSize(options.HashAlgorithm));
        var hashMemory = hashOwner.Memory;

#if NETSTANDARD2_0
        var hashBytes = await ComputeHashAsync(payloadStream, options.HashAlgorithm, cancellationToken).ConfigureAwait(false);
        hashBytes.CopyTo(hashOwner.Span);
#else
        using var incrementalHash = IncrementalHash.CreateHash(options.HashAlgorithm);
        
        var buffer = ArrayPool<byte>.Shared.Rent(8192); // 8KB buffer for incremental hashing
        try
        {
            int bytesRead;
            while ((bytesRead = await payloadStream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                incrementalHash.AppendData(buffer, 0, bytesRead);
            }
            
            var hash = incrementalHash.GetHashAndReset();
            hash.CopyTo(hashOwner.Span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
#endif

        _logger.LogTrace(
            new EventId(LogEvents.SigningPayloadInfo, nameof(LogEvents.SigningPayloadInfo)),
            "Computed payload hash. HashSize: {HashSize}",
            hashOwner.Length);

        // Create CoseHashEnvelope header contributor with protected headers
        var hashEnvelopeContributor = new CoseHashEnvelopeHeaderContributor(
            options.HashAlgorithm,
            contentType,
            options.PayloadLocation);

        // Chain with any additional header contributors
        var headerContributors = options.AdditionalHeaderContributors?.Any() == true
            ? new List<IHeaderContributor>(options.AdditionalHeaderContributors) { hashEnvelopeContributor }
            : new List<IHeaderContributor> { hashEnvelopeContributor };

        // Create DirectSignatureOptions with hash as payload and CoseHashEnvelope headers
        var directOptions = new DirectSignatureOptions
        {
            AdditionalHeaderContributors = headerContributors,
            AdditionalContext = options.AdditionalContext,
            AdditionalData = options.AdditionalData,
            EmbedPayload = true  // Embed the hash
        };

        // Sign the hash directly (content type added by CoseHashEnvelopeHeaderContributor)
        using var hashStream = new MemoryStream(hashOwner.Memory.ToArray(), writable: false);
        var result = await _directFactory.CreateCoseSign1MessageBytesAsync(hashStream, contentType, directOptions, cancellationToken).ConfigureAwait(false);

        _logger.LogDebug(
            new EventId(LogEvents.SigningCompleted, nameof(LogEvents.SigningCompleted)),
            "Async indirect signature created successfully. SignatureSize: {SignatureSize}",
            result.Length);

        return result;
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a byte array payload.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual CoseSign1Message CreateCoseSign1Message(
        byte[] payload,
        string contentType,
        IndirectSignatureOptions? options = null)
    {
        var messageBytes = CreateCoseSign1MessageBytes(payload, contentType, options);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a ReadOnlySpan payload.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual CoseSign1Message CreateCoseSign1Message(
        ReadOnlySpan<byte> payload,
        string contentType,
        IndirectSignatureOptions? options = null)
    {
        var messageBytes = CreateCoseSign1MessageBytes(payload, contentType, options);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a byte array payload.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        byte[] payload,
        string contentType,
        IndirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageBytes = await CreateCoseSign1MessageBytesAsync(payload, contentType, options, cancellationToken).ConfigureAwait(false);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a ReadOnlyMemory payload.
    /// </summary>
    /// <param name="payload">The payload to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        IndirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageBytes = await CreateCoseSign1MessageBytesAsync(payload.ToArray(), contentType, options, cancellationToken).ConfigureAwait(false);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    /// <summary>
    /// Creates a COSE Sign1 message with indirect signature from a stream payload.
    /// </summary>
    /// <param name="payloadStream">The payload stream to hash and sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/octet-stream").</param>
    /// <param name="options">Optional indirect signature options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        Stream payloadStream,
        string contentType,
        IndirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageBytes = await CreateCoseSign1MessageBytesAsync(payloadStream, contentType, options, cancellationToken).ConfigureAwait(false);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    /// <summary>
    /// Disposes the factory and underlying resources.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _directFactory?.Dispose();
            _disposed = true;
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(IndirectSignatureFactory));
        }
    }

    #region Helper Methods

    private static bool TryComputeHash(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm, Span<byte> destination, out int bytesWritten)
    {
#if NETSTANDARD2_0
        // For .NET Standard 2.0, use HashAlgorithm.ComputeHash
        using var hasher = hashAlgorithm.Name switch
        {
            nameof(SHA256) => (HashAlgorithm)SHA256.Create(),
            nameof(SHA384) => (HashAlgorithm)SHA384.Create(),
            nameof(SHA512) => (HashAlgorithm)SHA512.Create(),
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Name} is not supported")
        };

        var hash = hasher.ComputeHash(data.ToArray());
        bytesWritten = hash.Length;
        hash.CopyTo(destination);
        return true;
#else
        return hashAlgorithm.Name switch
        {
            nameof(SHA256) => SHA256.TryHashData(data, destination, out bytesWritten),
            nameof(SHA384) => SHA384.TryHashData(data, destination, out bytesWritten),
            nameof(SHA512) => SHA512.TryHashData(data, destination, out bytesWritten),
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Name} is not supported")
        };
#endif
    }

#if NETSTANDARD2_0
    private static async Task<byte[]> ComputeHashAsync(Stream stream, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken)
    {
        using var incrementalHash = IncrementalHash.CreateHash(hashAlgorithm);

        var buffer = ArrayPool<byte>.Shared.Rent(8192); // 8KB buffer for incremental hashing
        try
        {
            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                incrementalHash.AppendData(buffer, 0, bytesRead);
            }

            return incrementalHash.GetHashAndReset();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
#endif

    private static int GetHashSize(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            nameof(SHA256) => 32,
            nameof(SHA384) => 48,
            nameof(SHA512) => 64,
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Name} is not supported")
        };
    }

    private static string GetHashAlgorithmName(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            nameof(SHA256) => "sha256",
            nameof(SHA384) => "sha384",
            nameof(SHA512) => "sha512",
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Name} is not supported")
        };
    }

    #endregion
}
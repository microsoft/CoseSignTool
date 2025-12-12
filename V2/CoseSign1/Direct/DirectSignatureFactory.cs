// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.HighPerformance.Buffers;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Logging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Direct;

/// <summary>
/// Factory for creating direct COSE signatures.
/// Instance-based design supports dependency injection and testability.
/// Thread-safe: all methods are stateless or use local state only.
/// </summary>
public class DirectSignatureFactory : ICoseSign1MessageFactory<DirectSignatureOptions>, IDisposable
{
    private static readonly ContentTypeHeaderContributor ContentTypeContributor = new();
    private readonly ISigningService<SigningOptions> SigningService;
    private readonly IReadOnlyList<ITransparencyProvider>? TransparencyProvidersField;
    private readonly ILogger<DirectSignatureFactory> Logger;
    private bool Disposed;

    /// <summary>
    /// Gets the transparency providers configured for this factory.
    /// These providers will be applied to all signed messages unless disabled per-operation.
    /// </summary>
    public IReadOnlyList<ITransparencyProvider>? TransparencyProviders => TransparencyProvidersField;

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectSignatureFactory"/> class.
    /// </summary>
    /// <param name="signingService">The signing service to use for creating signatures.</param>
    /// <param name="transparencyProviders">Optional transparency providers to apply to all signed messages. Can be overridden per-operation.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    public DirectSignatureFactory(
        ISigningService<SigningOptions> signingService,
        IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
        ILogger<DirectSignatureFactory>? logger = null)
    {
        SigningService = signingService ?? throw new ArgumentNullException(nameof(signingService));
        TransparencyProvidersField = transparencyProviders;
        Logger = logger ?? NullLogger<DirectSignatureFactory>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectSignatureFactory"/> class.
    /// Protected parameterless constructor for mocking frameworks like Moq.
    /// </summary>
    protected DirectSignatureFactory()
    {
        SigningService = null!;
        Logger = NullLogger<DirectSignatureFactory>.Instance;
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a ReadOnlySpan payload and returns it as bytes.
    /// This is the core synchronous implementation that all other sync methods delegate to.
    /// Uses ReadOnlySpan to avoid unnecessary array allocations.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual byte[] CreateCoseSign1MessageBytes(
        ReadOnlySpan<byte> payload,
        string contentType,
        DirectSignatureOptions? options = null)
    {
        return CreateCoseSign1MessageBytes(payload, contentType, options, serviceOptions: null);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a ReadOnlySpan payload and returns it as bytes.
    /// Allows passing service-specific options per signing operation.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="serviceOptions">Optional service-specific options to pass to the signing service. If null, service defaults are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual byte[] CreateCoseSign1MessageBytes(
        ReadOnlySpan<byte> payload,
        string contentType,
        DirectSignatureOptions? options,
        SigningOptions? serviceOptions)
    {
        if (contentType == null)
        {
            throw new ArgumentNullException(nameof(contentType));
        }

        ThrowIfDisposed();

        Logger.LogDebug(
            new EventId(LogEvents.SigningStarted, nameof(LogEvents.SigningStarted)),
            "Starting direct signature creation. ContentType: {ContentType}, PayloadSize: {PayloadSize}, EmbedPayload: {EmbedPayload}",
            contentType,
            payload.Length,
            options?.EmbedPayload ?? true);

        options ??= new DirectSignatureOptions();

        // Use SpanOwner to rent from ArrayPool - provides both Span and Memory views
        using var owner = SpanOwner<byte>.Allocate(payload.Length);
        payload.CopyTo(owner.Span);

        // Get Memory<byte> from the owner via DangerousGetArray() and wrap it
        var segment = owner.DangerousGetArray();
        if (segment.Array == null)
        {
            throw new InvalidOperationException("Failed to get underlying array");
        }

        var payloadMemory = new ReadOnlyMemory<byte>(segment.Array, segment.Offset, payload.Length);

        // Create combined header contributors list with ContentTypeHeaderContributor first
        var headerContributors = CreateHeaderContributorsList(options.AdditionalHeaderContributors);
        Logger.LogTrace(
            new EventId(LogEvents.SigningHeaderContribution, nameof(LogEvents.SigningHeaderContribution)),
            "Created header contributors list with {Count} contributors",
            headerContributors.Count);

        // Merge service options into additional context if provided
        var additionalContext = MergeServiceOptions(options.AdditionalContext, serviceOptions);

        // Create context with bytes - using pooled memory
        var context = new SigningContext(
            payloadMemory,
            contentType,
            headerContributors,
            additionalContext);

        Logger.LogTrace(
            new EventId(LogEvents.SigningKeyAcquired, nameof(LogEvents.SigningKeyAcquired)),
            "Acquiring signer from signing service");
        var signer = SigningService.GetCoseSigner(context);

        // Use the original payload span and AdditionalData span - no additional allocations
        ReadOnlySpan<byte> additionalDataSpan = options.AdditionalData.Span;

        var result = options.EmbedPayload
            ? CoseSign1Message.SignEmbedded(payload, signer, additionalDataSpan)
            : CoseSign1Message.SignDetached(payload, signer, additionalDataSpan);

        Logger.LogDebug(
            new EventId(LogEvents.SigningCompleted, nameof(LogEvents.SigningCompleted)),
            "Direct signature created successfully. SignatureSize: {SignatureSize}",
            result.Length);

        return result;
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual byte[] CreateCoseSign1MessageBytes(
        byte[] payload,
        string contentType,
        DirectSignatureOptions? options = null)
    {
        return CreateCoseSign1MessageBytes(payload, contentType, options, serviceOptions: null);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload and returns it as bytes.
    /// Allows passing service-specific options per signing operation.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="serviceOptions">Optional service-specific options to pass to the signing service. If null, service defaults are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual byte[] CreateCoseSign1MessageBytes(
        byte[] payload,
        string contentType,
        DirectSignatureOptions? options,
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

        // Delegate to ReadOnlySpan overload for actual implementation
        return CreateCoseSign1MessageBytes(new ReadOnlySpan<byte>(payload), contentType, options, serviceOptions);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a stream payload and returns it as bytes.
    /// This is the core asynchronous implementation that all other async methods delegate to.
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/octet-stream").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual async Task<byte[]> CreateCoseSign1MessageBytesAsync(
        Stream payloadStream,
        string contentType,
        DirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        return await CreateCoseSign1MessageBytesAsync(payloadStream, contentType, options, serviceOptions: null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a stream payload and returns it as bytes.
    /// Allows passing service-specific options per signing operation.
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/octet-stream").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="serviceOptions">Optional service-specific options to pass to the signing service. If null, service defaults are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual async Task<byte[]> CreateCoseSign1MessageBytesAsync(
        Stream payloadStream,
        string contentType,
        DirectSignatureOptions? options,
        SigningOptions? serviceOptions,
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

        Logger.LogDebug(
            new EventId(LogEvents.SigningStarted, nameof(LogEvents.SigningStarted)),
            "Starting async direct signature creation. ContentType: {ContentType}, StreamLength: {StreamLength}, EmbedPayload: {EmbedPayload}",
            contentType,
            payloadStream.CanSeek ? payloadStream.Length : -1,
            options?.EmbedPayload ?? true);

        options ??= new DirectSignatureOptions();

        // Create combined header contributors list with ContentTypeHeaderContributor first
        var headerContributors = CreateHeaderContributorsList(options.AdditionalHeaderContributors);
        Logger.LogTrace(
            new EventId(LogEvents.SigningHeaderContribution, nameof(LogEvents.SigningHeaderContribution)),
            "Created header contributors list with {Count} contributors",
            headerContributors.Count);

        // Merge service options into additional context if provided
        var additionalContext = MergeServiceOptions(options.AdditionalContext, serviceOptions);

        var context = new SigningContext(
            payloadStream,
            contentType,
            headerContributors,
            additionalContext);

        Logger.LogTrace(
            new EventId(LogEvents.SigningKeyAcquired, nameof(LogEvents.SigningKeyAcquired)),
            "Acquiring signer from signing service");
        var signer = SigningService.GetCoseSigner(context);

        // Get pooled arrays for both payload (if embedded) and additional data
        byte[] payloadArray;
        byte[]? additionalDataArray = null;

        using var payloadOwner = options.EmbedPayload
            ? MemoryOwner<byte>.Allocate((int)payloadStream.Length)
            : default;

        using var additionalDataOwner = options.AdditionalData.IsEmpty
            ? default
            : MemoryOwner<byte>.Allocate(options.AdditionalData.Length);

        // Read payload if embedded
        if (options.EmbedPayload)
        {
#if NETSTANDARD2_0
            var tempBuffer = payloadOwner!.DangerousGetArray();
            var tempArray = tempBuffer.Array!;
            await payloadStream.ReadAsync(tempArray, tempBuffer.Offset, tempBuffer.Count).ConfigureAwait(false);
            payloadArray = tempArray;
#else
            await payloadStream.ReadAsync(payloadOwner!.Memory, cancellationToken).ConfigureAwait(false);
            payloadArray = payloadOwner.DangerousGetArray().Array!;
#endif
        }
        else
        {
            payloadArray = Array.Empty<byte>(); // Not used for detached
        }

        // Copy additional data if present
        if (!options.AdditionalData.IsEmpty)
        {
            options.AdditionalData.Span.CopyTo(additionalDataOwner!.Span);
            additionalDataArray = additionalDataOwner.DangerousGetArray().Array!;
        }

        // Sign with Task.Run for cancellation support
        var result = await Task.Run(async () =>
        {
            if (options.EmbedPayload)
            {
                return additionalDataArray != null
                    ? CoseSign1Message.SignEmbedded(payloadArray, signer, additionalDataArray)
                    : CoseSign1Message.SignEmbedded(payloadArray, signer);
            }
            else
            {
                return additionalDataArray != null
                    ? await CoseSign1Message.SignDetachedAsync(payloadStream, signer, additionalDataArray).ConfigureAwait(false)
                    : await CoseSign1Message.SignDetachedAsync(payloadStream, signer).ConfigureAwait(false);
            }
        }, cancellationToken).ConfigureAwait(false);

        Logger.LogDebug(
            new EventId(LogEvents.SigningCompleted, nameof(LogEvents.SigningCompleted)),
            "Async direct signature created successfully. SignatureSize: {SignatureSize}",
            result.Length);

        return result;
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual Task<byte[]> CreateCoseSign1MessageBytesAsync(
        byte[] payload,
        string contentType,
        DirectSignatureOptions? options = null,
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
    /// Creates a COSE Sign1 message from a ReadOnlyMemory payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    public virtual Task<byte[]> CreateCoseSign1MessageBytesAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        DirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        // Delegate to byte[] overload
        return CreateCoseSign1MessageBytesAsync(payload.ToArray(), contentType, options, cancellationToken);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual CoseSign1Message CreateCoseSign1Message(
        byte[] payload,
        string contentType,
        DirectSignatureOptions? options = null)
    {
        var messageBytes = CreateCoseSign1MessageBytes(payload, contentType, options);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a ReadOnlySpan payload.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual CoseSign1Message CreateCoseSign1Message(
        ReadOnlySpan<byte> payload,
        string contentType,
        DirectSignatureOptions? options = null)
    {
        var messageBytes = CreateCoseSign1MessageBytes(payload, contentType, options);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        byte[] payload,
        string contentType,
        DirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageBytes = await CreateCoseSign1MessageBytesAsync(payload, contentType, options, cancellationToken).ConfigureAwait(false);
        var message = CoseMessage.DecodeSign1(messageBytes);
        return await ApplyTransparencyProofsAsync(message, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a ReadOnlyMemory payload.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        DirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageBytes = await CreateCoseSign1MessageBytesAsync(payload, contentType, options, cancellationToken).ConfigureAwait(false);
        var message = CoseMessage.DecodeSign1(messageBytes);
        return await ApplyTransparencyProofsAsync(message, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a stream payload.
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/octet-stream").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    public virtual async Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        Stream payloadStream,
        string contentType,
        DirectSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageBytes = await CreateCoseSign1MessageBytesAsync(payloadStream, contentType, options, cancellationToken).ConfigureAwait(false);
        var message = CoseMessage.DecodeSign1(messageBytes);
        return await ApplyTransparencyProofsAsync(message, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Merges service-specific options into the additional context dictionary.
    /// </summary>
    private static Dictionary<string, object>? MergeServiceOptions(
        IDictionary<string, object>? existingContext,
        SigningOptions? serviceOptions)
    {
        if (serviceOptions == null)
        {
            return existingContext as Dictionary<string, object>;
        }

        var context = existingContext != null
            ? new Dictionary<string, object>(existingContext)
            : new Dictionary<string, object>();

        // Store service options using the type name as the key
        var key = serviceOptions.GetType().Name;
        context[key] = serviceOptions;

        return context;
    }

    /// <summary>
    /// Creates a list of header contributors with ContentTypeHeaderContributor first.
    /// </summary>
    private static List<IHeaderContributor> CreateHeaderContributorsList(IReadOnlyList<IHeaderContributor>? additionalContributors)
    {
        if (additionalContributors == null || additionalContributors.Count == 0)
        {
            return new List<IHeaderContributor> { ContentTypeContributor };
        }

        var combined = new List<IHeaderContributor>(additionalContributors.Count + 1)
        {
            ContentTypeContributor
        };
        combined.AddRange(additionalContributors);

        return combined;
    }

    /// <summary>
    /// Applies transparency proofs to the message using the factory-configured providers.
    /// Chains through multiple providers in sequence, each augmenting the message headers.
    /// </summary>
    /// <param name="message">The signed COSE message to augment with transparency proofs.</param>
    /// <param name="options">The signing options that may disable transparency for this operation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The message with transparency proofs applied (may be the same instance or a new one).</returns>
    protected virtual async Task<CoseSign1Message> ApplyTransparencyProofsAsync(
        CoseSign1Message message,
        SigningOptions? options,
        CancellationToken cancellationToken)
    {
        // Check if transparency is disabled for this operation
        if (options?.DisableTransparency == true)
        {
            return message;
        }

        // No transparency providers configured at factory level - return message as-is
        if (TransparencyProvidersField == null || TransparencyProvidersField.Count == 0)
        {
            return message;
        }

        var currentMessage = message;
        var errors = new List<string>();

        // Chain through each provider in sequence
        foreach (var provider in TransparencyProvidersField)
        {
            try
            {
                currentMessage = await provider.AddTransparencyProofAsync(currentMessage, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                var error = $"Transparency provider '{provider.ProviderName}' failed: {ex.Message}";
                errors.Add(error);

                // If configured to fail on transparency errors, throw immediately
                if (options.FailOnTransparencyError)
                {
                    throw new InvalidOperationException(
                        $"Failed to add transparency proof. {error}",
                        ex);
                }

                // Otherwise, continue with remaining providers (best-effort mode)
            }
        }

        // If we collected errors but didn't fail fast, log a warning
        // (In production, consider using ILogger here if available via DI)
        if (errors.Any() && !options.FailOnTransparencyError)
        {
            // Best-effort mode: some providers failed but we're continuing
            // Could log to ILogger here if the factory supported it
        }

        return currentMessage;
    }

    /// <summary>
    /// Disposes the factory and the underlying signing service.
    /// </summary>
    public void Dispose()
    {
        if (!Disposed)
        {
            SigningService?.Dispose();
            Disposed = true;
        }
    }

    private void ThrowIfDisposed()
    {
        if (Disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }
}
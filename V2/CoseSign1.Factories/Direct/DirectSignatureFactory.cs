// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Direct;

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.HighPerformance.Buffers;
using CoseSign1.Abstractions.Transparency;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Factory for creating direct COSE signatures.
/// Instance-based design supports dependency injection and testability.
/// Thread-safe: all methods are stateless or use local state only.
/// </summary>
public class DirectSignatureFactory : ICoseSign1MessageFactory<DirectSignatureOptions>, IDisposable
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Formatting
        public static readonly string GuidFormatCompact = "N";

        // Logging scope keys
        public static readonly string KeyOperationId = "OperationId";
        public static readonly string KeySignatureType = "SignatureType";
        public static readonly string KeyAsync = "Async";
        public static readonly string SignatureTypeDirect = "Direct";

        // Error messages
        public static readonly string ErrorFailedToGetArray = "Failed to get underlying array";
        public static readonly string ErrorObjectDisposed = "DirectSignatureFactory has been disposed";
        public static readonly string ErrorTransparencyFailed = "Failed to add transparency proof. {0}";
        public static readonly string ErrorTransparencyProviderFailed = "Transparency provider '{0}' failed: {1}";

        // Log message templates
        public static readonly string LogSigningStarted = "Starting direct signature creation. ContentType: {ContentType}, PayloadSize: {PayloadSize}, EmbedPayload: {EmbedPayload}";
        public static readonly string LogSigningStartedAsync = "Starting async direct signature creation. ContentType: {ContentType}, StreamLength: {StreamLength}, EmbedPayload: {EmbedPayload}";
        public static readonly string LogSigningCompleted = "Direct signature created successfully. SignatureSize: {SignatureSize}, ElapsedMs: {ElapsedMs}";
        public static readonly string LogSigningCompletedAsync = "Async direct signature created successfully. SignatureSize: {SignatureSize}, ElapsedMs: {ElapsedMs}";
        public static readonly string LogSigningFailed = "Direct signature creation failed. ContentType: {ContentType}, PayloadSize: {PayloadSize}, ElapsedMs: {ElapsedMs}";
        public static readonly string LogSigningFailedAsync = "Async direct signature creation failed. ContentType: {ContentType}, StreamLength: {StreamLength}, ElapsedMs: {ElapsedMs}";
        public static readonly string LogHeaderContributorsCreated = "Created header contributors list with {Count} contributors";
        public static readonly string LogAcquiringSigner = "Acquiring signer from signing service";
        public static readonly string LogTransparencyDisabled = "Transparency disabled for this operation, skipping transparency providers";
        public static readonly string LogNoTransparencyProviders = "No transparency providers configured, skipping transparency application";
        public static readonly string LogTransparencyStarted = "Starting transparency proof application. ProviderCount: {ProviderCount}, FailOnError: {FailOnError}";
        public static readonly string LogTransparencyProviderStarted = "Applying transparency provider: {ProviderName}";
        public static readonly string LogTransparencyProviderCompleted = "Transparency provider '{ProviderName}' completed successfully";
        public static readonly string LogTransparencyProviderFailed = "Transparency provider '{ProviderName}' failed. FailOnError: {FailOnError}";
        public static readonly string LogTransparencyAborted = "Transparency application aborted due to provider failure. ProviderName: {ProviderName}, ElapsedMs: {ElapsedMs}";
        public static readonly string LogTransparencyCompletedWithErrors = "Transparency application completed with errors. SuccessCount: {SuccessCount}, FailureCount: {FailureCount}, ElapsedMs: {ElapsedMs}";
        public static readonly string LogTransparencyCompleted = "Transparency application completed successfully. ProviderCount: {ProviderCount}, ElapsedMs: {ElapsedMs}";
    }

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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signingService"/> is <see langword="null"/>.</exception>
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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="contentType"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the underlying buffer could not be acquired.</exception>
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

        var operationId = Guid.NewGuid().ToString(ClassStrings.GuidFormatCompact).Substring(0, 8);
        using var scope = Logger.BeginScope(new Dictionary<string, object>
        {
            [ClassStrings.KeyOperationId] = operationId,
            [ClassStrings.KeySignatureType] = ClassStrings.SignatureTypeDirect
        });

        var stopwatch = Stopwatch.StartNew();

        Logger.LogDebug(
            LogEvents.SigningStartedEvent,
            ClassStrings.LogSigningStarted,
            contentType,
            payload.Length,
            options?.EmbedPayload ?? true);

        try
        {
            options ??= new DirectSignatureOptions();

            // Use SpanOwner to rent from ArrayPool - provides both Span and Memory views
            using var owner = SpanOwner<byte>.Allocate(payload.Length);
            payload.CopyTo(owner.Span);

            // Get Memory<byte> from the owner via DangerousGetArray() and wrap it
            var segment = owner.DangerousGetArray();
            if (segment.Array == null)
            {
                throw new InvalidOperationException(ClassStrings.ErrorFailedToGetArray);
            }

            var payloadMemory = new ReadOnlyMemory<byte>(segment.Array, segment.Offset, payload.Length);

            // Create combined header contributors list with ContentTypeHeaderContributor first
            var headerContributors = CreateHeaderContributorsList(options.AdditionalHeaderContributors);
            Logger.LogTrace(
                LogEvents.SigningHeaderContributionEvent,
                ClassStrings.LogHeaderContributorsCreated,
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
                LogEvents.SigningKeyAcquiredEvent,
                ClassStrings.LogAcquiringSigner);
            var signer = SigningService.GetCoseSigner(context);

            // Use the original payload span and AdditionalData span - no additional allocations
            ReadOnlySpan<byte> additionalDataSpan = options.AdditionalData.Span;

            var result = options.EmbedPayload
                ? CoseSign1Message.SignEmbedded(payload, signer, additionalDataSpan)
                : CoseSign1Message.SignDetached(payload, signer, additionalDataSpan);

            stopwatch.Stop();
            Logger.LogDebug(
                LogEvents.SigningCompletedEvent,
                ClassStrings.LogSigningCompleted,
                result.Length,
                stopwatch.ElapsedMilliseconds);

            return result;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            Logger.LogError(
                LogEvents.SigningFailedEvent,
                ex,
                ClassStrings.LogSigningFailed,
                contentType,
                payload.Length,
                stopwatch.ElapsedMilliseconds);
            throw;
        }
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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payload"/> or <paramref name="contentType"/> is <see langword="null"/>.</exception>
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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payloadStream"/> or <paramref name="contentType"/> is <see langword="null"/>.</exception>
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

        var operationId = Guid.NewGuid().ToString(ClassStrings.GuidFormatCompact).Substring(0, 8);
        using var scope = Logger.BeginScope(new Dictionary<string, object>
        {
            [ClassStrings.KeyOperationId] = operationId,
            [ClassStrings.KeySignatureType] = ClassStrings.SignatureTypeDirect,
            [ClassStrings.KeyAsync] = true
        });

        var stopwatch = Stopwatch.StartNew();
        var streamLength = payloadStream.CanSeek ? payloadStream.Length : -1;

        Logger.LogDebug(
            LogEvents.SigningStartedEvent,
            ClassStrings.LogSigningStartedAsync,
            contentType,
            streamLength,
            options?.EmbedPayload ?? true);

        try
        {
            options ??= new DirectSignatureOptions();

            // Create combined header contributors list with ContentTypeHeaderContributor first
            var headerContributors = CreateHeaderContributorsList(options.AdditionalHeaderContributors);
            Logger.LogTrace(
                LogEvents.SigningHeaderContributionEvent,
                ClassStrings.LogHeaderContributorsCreated,
                headerContributors.Count);

            // Merge service options into additional context if provided
            var additionalContext = MergeServiceOptions(options.AdditionalContext, serviceOptions);

            var context = new SigningContext(
                payloadStream,
                contentType,
                headerContributors,
                additionalContext);

            Logger.LogTrace(
                LogEvents.SigningKeyAcquiredEvent,
                ClassStrings.LogAcquiringSigner);
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

            stopwatch.Stop();
            Logger.LogDebug(
                LogEvents.SigningCompletedEvent,
                ClassStrings.LogSigningCompletedAsync,
                result.Length,
                stopwatch.ElapsedMilliseconds);

            return result;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            Logger.LogError(
                LogEvents.SigningFailedEvent,
                ex,
                ClassStrings.LogSigningFailedAsync,
                contentType,
                streamLength,
                stopwatch.ElapsedMilliseconds);
            throw;
        }
    }

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payload"/> is <see langword="null"/>.</exception>
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
            Logger.LogTrace(
                LogEvents.SigningPayloadInfoEvent,
                ClassStrings.LogTransparencyDisabled);
            return message;
        }

        // No transparency providers configured at factory level - return message as-is
        if (TransparencyProvidersField == null || TransparencyProvidersField.Count == 0)
        {
            Logger.LogTrace(
                LogEvents.SigningPayloadInfoEvent,
                ClassStrings.LogNoTransparencyProviders);
            return message;
        }

        var stopwatch = Stopwatch.StartNew();
        Logger.LogDebug(
            LogEvents.SigningStartedEvent,
            ClassStrings.LogTransparencyStarted,
            TransparencyProvidersField.Count,
            options?.FailOnTransparencyError ?? false);

        var currentMessage = message;
        var errors = new List<string>();
        var successCount = 0;

        // Chain through each provider in sequence
        foreach (var provider in TransparencyProvidersField)
        {
            Logger.LogTrace(
                LogEvents.SigningHeaderContributionEvent,
                ClassStrings.LogTransparencyProviderStarted,
                provider.ProviderName);

            try
            {
                currentMessage = await provider.AddTransparencyProofAsync(currentMessage, cancellationToken).ConfigureAwait(false);
                successCount++;

                Logger.LogTrace(
                    LogEvents.SigningHeaderContributionEvent,
                    ClassStrings.LogTransparencyProviderCompleted,
                    provider.ProviderName);
            }
            catch (Exception ex)
            {
                var error = string.Format(ClassStrings.ErrorTransparencyProviderFailed, provider.ProviderName, ex.Message);
                errors.Add(error);

                Logger.LogWarning(
                    LogEvents.SigningFailedEvent,
                    ex,
                    ClassStrings.LogTransparencyProviderFailed,
                    provider.ProviderName,
                    options?.FailOnTransparencyError ?? false);

                // If configured to fail on transparency errors, throw immediately
                if (options?.FailOnTransparencyError == true)
                {
                    stopwatch.Stop();
                    Logger.LogError(
                        LogEvents.SigningFailedEvent,
                        ex,
                        ClassStrings.LogTransparencyAborted,
                        provider.ProviderName,
                        stopwatch.ElapsedMilliseconds);

                    throw new InvalidOperationException(
                        string.Format(ClassStrings.ErrorTransparencyFailed, error),
                        ex);
                }

                // Otherwise, continue with remaining providers (best-effort mode)
            }
        }

        stopwatch.Stop();

        // Log final status
        if (errors.Count > 0)
        {
            Logger.LogWarning(
                LogEvents.SigningCompletedEvent,
                ClassStrings.LogTransparencyCompletedWithErrors,
                successCount,
                errors.Count,
                stopwatch.ElapsedMilliseconds);
        }
        else
        {
            Logger.LogDebug(
                LogEvents.SigningCompletedEvent,
                ClassStrings.LogTransparencyCompleted,
                successCount,
                stopwatch.ElapsedMilliseconds);
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

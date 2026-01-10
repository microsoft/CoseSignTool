// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Options for configuring COSE Sign1 message validation.
/// </summary>
/// <remarks>
/// This class encapsulates all optional configuration for validation:
/// <list type="bullet">
/// <item><description>Detached payload content (for messages with detached signatures)</description></item>
/// <item><description>Associated data for signature verification</description></item>
/// <item><description>Cancellation token for async operations</description></item>
/// </list>
/// Use <see cref="CoseSign1ValidationOptionsExtensions"/> for fluent configuration.
/// </remarks>
public sealed class CoseSign1ValidationOptions
{
    /// <summary>
    /// Gets or sets the detached payload stream for signature verification.
    /// Required when validating messages with detached content.
    /// </summary>
    /// <remarks>
    /// The caller is responsible for the stream's lifetime. The stream should remain
    /// open and positioned at the start during validation. For seekable streams,
    /// the validator will reset the position as needed.
    /// </remarks>
    public Stream? DetachedPayload { get; set; }

    /// <summary>
    /// Gets or sets the associated data for signature verification.
    /// </summary>
    /// <remarks>
    /// Associated data is additional authenticated data that was included in the
    /// signature computation but is not part of the payload. If the message was
    /// signed with associated data, the same data must be provided for verification.
    /// </remarks>
    public ReadOnlyMemory<byte>? AssociatedData { get; set; }

    /// <summary>
    /// Gets or sets the cancellation token for validation operations.
    /// </summary>
    public CancellationToken CancellationToken { get; set; }

    /// <summary>
    /// Creates a new instance of <see cref="CoseSign1ValidationOptions"/> with default values.
    /// </summary>
    public CoseSign1ValidationOptions()
    {
    }

    /// <summary>
    /// Creates a copy of the options.
    /// </summary>
    /// <returns>A new instance with the same values.</returns>
    public CoseSign1ValidationOptions Clone()
    {
        return new CoseSign1ValidationOptions
        {
            DetachedPayload = DetachedPayload,
            AssociatedData = AssociatedData,
            CancellationToken = CancellationToken
        };
    }
}

/// <summary>
/// Extension methods for fluent configuration of <see cref="CoseSign1ValidationOptions"/>.
/// </summary>
public static class CoseSign1ValidationOptionsExtensions
{
    /// <summary>
    /// Sets the detached payload from a stream.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="payload">The stream containing the detached payload.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public static CoseSign1ValidationOptions WithDetachedPayload(this CoseSign1ValidationOptions options, Stream payload)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.DetachedPayload = payload;
        return options;
    }

    /// <summary>
    /// Sets the detached payload from a byte array.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="payload">The detached payload bytes.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or <paramref name="payload"/> is null.</exception>
    public static CoseSign1ValidationOptions WithDetachedPayload(this CoseSign1ValidationOptions options, byte[] payload)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (payload == null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        options.DetachedPayload = new MemoryStream(payload, writable: false);
        return options;
    }

    /// <summary>
    /// Sets the detached payload from a ReadOnlyMemory.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="payload">The detached payload bytes.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public static CoseSign1ValidationOptions WithDetachedPayload(this CoseSign1ValidationOptions options, ReadOnlyMemory<byte> payload)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.DetachedPayload = new MemoryStream(payload.ToArray(), writable: false);
        return options;
    }

    /// <summary>
    /// Sets the associated data for signature verification.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="associatedData">The associated data bytes.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public static CoseSign1ValidationOptions WithAssociatedData(this CoseSign1ValidationOptions options, ReadOnlyMemory<byte> associatedData)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.AssociatedData = associatedData;
        return options;
    }

    /// <summary>
    /// Sets the associated data for signature verification from a byte array.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="associatedData">The associated data bytes.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or <paramref name="associatedData"/> is null.</exception>
    public static CoseSign1ValidationOptions WithAssociatedData(this CoseSign1ValidationOptions options, byte[] associatedData)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (associatedData == null)
        {
            throw new ArgumentNullException(nameof(associatedData));
        }

        options.AssociatedData = associatedData;
        return options;
    }

    /// <summary>
    /// Sets the cancellation token for validation operations.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public static CoseSign1ValidationOptions WithCancellationToken(this CoseSign1ValidationOptions options, CancellationToken cancellationToken)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.CancellationToken = cancellationToken;
        return options;
    }

    /// <summary>
    /// Configures the options using an action delegate.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="configure">The configuration action.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or <paramref name="configure"/> is null.</exception>
    public static CoseSign1ValidationOptions Configure(this CoseSign1ValidationOptions options, Action<CoseSign1ValidationOptions> configure)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        configure(options);
        return options;
    }
}

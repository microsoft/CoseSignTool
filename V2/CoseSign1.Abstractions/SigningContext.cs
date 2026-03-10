// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions;

/// <summary>
/// Context information for a signing operation.
/// Contains the payload (as stream or bytes) and per-operation metadata.
/// This is passed to the signing service and header contributors at sign-time.
/// </summary>
public class SigningContext
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorPayloadIsBytesNotStream = "Context contains byte payload, not stream. Check HasStream property.";
        public static readonly string ErrorPayloadIsStreamNotBytes = "Context contains stream payload, not bytes. Check HasStream property.";
    }

    private readonly Stream? PayloadStreamField;
    private readonly ReadOnlyMemory<byte> PayloadBytesField;

    /// <summary>
    /// Initializes a new instance of the <see cref="SigningContext"/> class with a stream payload.
    /// </summary>
    /// <param name="payloadStream">The payload stream to be signed.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="additionalHeaderContributors">Optional additional header contributors to apply for this specific operation.</param>
    /// <param name="additionalContext">Optional additional context for custom header contributors.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payloadStream"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="contentType"/> is <see langword="null"/>.</exception>
    public SigningContext(
        Stream payloadStream,
        string contentType,
        IReadOnlyList<IHeaderContributor>? additionalHeaderContributors = null,
        IDictionary<string, object>? additionalContext = null)
    {
        Guard.ThrowIfNull(payloadStream);
        Guard.ThrowIfNull(contentType);

        PayloadStreamField = payloadStream;
        ContentType = contentType;
        AdditionalHeaderContributors = additionalHeaderContributors;
        AdditionalContext = additionalContext;
        HasStream = true;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SigningContext"/> class with byte payload.
    /// </summary>
    /// <param name="payloadBytes">The payload bytes to be signed.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="additionalHeaderContributors">Optional additional header contributors to apply for this specific operation.</param>
    /// <param name="additionalContext">Optional additional context for custom header contributors.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="contentType"/> is <see langword="null"/>.</exception>
    public SigningContext(
        ReadOnlyMemory<byte> payloadBytes,
        string contentType,
        IReadOnlyList<IHeaderContributor>? additionalHeaderContributors = null,
        IDictionary<string, object>? additionalContext = null)
    {
        PayloadBytesField = payloadBytes;
        Guard.ThrowIfNull(contentType);
        ContentType = contentType;
        AdditionalHeaderContributors = additionalHeaderContributors;
        AdditionalContext = additionalContext;
        HasStream = false;
    }

    /// <summary>
    /// Gets a value indicating whether this context contains a stream payload (true) or byte payload (false).
    /// </summary>
    /// <value><see langword="true"/> if this context contains a stream payload; otherwise, <see langword="false"/>.</value>
    public bool HasStream { get; }

    /// <summary>
    /// Gets the payload stream to be signed.
    /// Only valid when <see cref="HasStream"/> is true.
    /// </summary>
    /// <value>The payload stream to be signed.</value>
    /// <exception cref="InvalidOperationException">Thrown when this context contains a byte payload.</exception>
    public Stream PayloadStream => PayloadStreamField ?? throw new InvalidOperationException(ClassStrings.ErrorPayloadIsBytesNotStream);

    /// <summary>
    /// Gets the payload bytes to be signed.
    /// Only valid when <see cref="HasStream"/> is false.
    /// </summary>
    /// <value>The payload bytes to be signed.</value>
    /// <exception cref="InvalidOperationException">Thrown when this context contains a stream payload.</exception>
    public ReadOnlyMemory<byte> PayloadBytes => HasStream ? throw new InvalidOperationException(ClassStrings.ErrorPayloadIsStreamNotBytes) : PayloadBytesField;

    /// <summary>
    /// Gets the content type of the payload (e.g., "application/json").
    /// </summary>
    /// <value>The content type of the payload.</value>
    public string ContentType { get; }

    /// <summary>
    /// Gets additional header contributors to apply for this specific operation.
    /// Applied after the signing service's required contributors.
    /// </summary>
    /// <value>Additional header contributors to apply for this specific operation, or <see langword="null"/>.</value>
    public IReadOnlyList<IHeaderContributor>? AdditionalHeaderContributors { get; }

    /// <summary>
    /// Gets additional context for custom header contributors.
    /// </summary>
    /// <value>Additional context for custom header contributors, or <see langword="null"/>.</value>
    public IDictionary<string, object>? AdditionalContext { get; }
}
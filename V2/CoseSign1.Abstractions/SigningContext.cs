// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;

namespace CoseSign1.Abstractions;

/// <summary>
/// Context information for a signing operation.
/// Contains the payload (as stream or bytes) and per-operation metadata.
/// This is passed to the signing service and header contributors at sign-time.
/// </summary>
public class SigningContext
{
    private readonly Stream? _payloadStream;
    private readonly ReadOnlyMemory<byte> _payloadBytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="SigningContext"/> class with a stream payload.
    /// </summary>
    public SigningContext(
        Stream payloadStream,
        string contentType,
        IReadOnlyList<IHeaderContributor>? additionalHeaderContributors = null,
        IDictionary<string, object>? additionalContext = null)
    {
        _payloadStream = payloadStream ?? throw new ArgumentNullException(nameof(payloadStream));
        ContentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
        AdditionalHeaderContributors = additionalHeaderContributors;
        AdditionalContext = additionalContext;
        HasStream = true;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SigningContext"/> class with byte payload.
    /// </summary>
    public SigningContext(
        ReadOnlyMemory<byte> payloadBytes,
        string contentType,
        IReadOnlyList<IHeaderContributor>? additionalHeaderContributors = null,
        IDictionary<string, object>? additionalContext = null)
    {
        _payloadBytes = payloadBytes;
        ContentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
        AdditionalHeaderContributors = additionalHeaderContributors;
        AdditionalContext = additionalContext;
        HasStream = false;
    }

    /// <summary>
    /// Gets a value indicating whether this context contains a stream payload (true) or byte payload (false).
    /// </summary>
    public bool HasStream { get; }

    /// <summary>
    /// Gets the payload stream to be signed.
    /// Only valid when <see cref="HasStream"/> is true.
    /// </summary>
    public Stream PayloadStream => _payloadStream ?? throw new InvalidOperationException("Context contains byte payload, not stream. Check HasStream property.");
    
    /// <summary>
    /// Gets the payload bytes to be signed.
    /// Only valid when <see cref="HasStream"/> is false.
    /// </summary>
    public ReadOnlyMemory<byte> PayloadBytes => HasStream ? throw new InvalidOperationException("Context contains stream payload, not bytes. Check HasStream property.") : _payloadBytes;

    /// <summary>
    /// Gets the content type of the payload (e.g., "application/json").
    /// </summary>
    public string ContentType { get; }
    
    /// <summary>
    /// Gets additional header contributors to apply for this specific operation.
    /// Applied after the signing service's required contributors.
    /// </summary>
    public IReadOnlyList<IHeaderContributor>? AdditionalHeaderContributors { get; }
    
    /// <summary>
    /// Gets additional context for custom header contributors.
    /// </summary>
    public IDictionary<string, object>? AdditionalContext { get; }
}

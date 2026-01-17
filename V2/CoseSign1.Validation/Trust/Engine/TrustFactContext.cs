// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Engine;

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;

/// <summary>
/// Provides context to fact producers.
/// </summary>
public sealed class TrustFactContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustFactContext"/> class.
    /// </summary>
    /// <param name="messageId">The message ID for the current evaluation.</param>
    /// <param name="subject">The subject being evaluated.</param>
    /// <param name="options">Evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="message">Optional message object (when available) for producers that need access to headers.</param>
    /// <param name="services">Optional service provider for resolving producer dependencies.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="subject"/> or <paramref name="options"/> is null.</exception>
    public TrustFactContext(
        TrustSubjectId messageId,
        TrustSubject subject,
        TrustEvaluationOptions options,
        IMemoryCache? memoryCache,
        CoseSign1Message? message,
        IServiceProvider? services = null)
    {
        MessageId = messageId;
        Guard.ThrowIfNull(subject);
        Guard.ThrowIfNull(options);

        Subject = subject;
        Options = options;
        MemoryCache = memoryCache;
        Message = message;
        Services = services;
    }

    /// <summary>
    /// Gets the message ID for the current validation.
    /// </summary>
    public TrustSubjectId MessageId { get; }

    /// <summary>
    /// Gets the subject being evaluated.
    /// </summary>
    public TrustSubject Subject { get; }

    /// <summary>
    /// Gets evaluation options.
    /// </summary>
    public TrustEvaluationOptions Options { get; }

    /// <summary>
    /// Gets the producer-owned cross-validation cache.
    /// </summary>
    public IMemoryCache? MemoryCache { get; }

    /// <summary>
    /// Gets the current COSE Sign1 message (if available).
    /// </summary>
    /// <remarks>
    /// Some fact producers require access to message headers or encoded bytes.
    /// When a trust plan is evaluated as part of staged validation, this value is provided.
    /// </remarks>
    public CoseSign1Message? Message { get; }

    /// <summary>
    /// Gets the service provider for resolving producer dependencies.
    /// </summary>
    /// <remarks>
    /// This may be null when a trust plan is evaluated outside of DI.
    /// </remarks>
    public IServiceProvider? Services { get; }

    /// <summary>
    /// Creates a stable cache key for the given fact type.
    /// </summary>
    /// <param name="factType">The fact type.</param>
    /// <returns>A cache key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="factType"/> is null.</exception>
    public TrustFactCacheKey CreateCacheKey(Type factType)
    {
        Guard.ThrowIfNull(factType);

        return new TrustFactCacheKey(MessageId, Subject.Id, factType);
    }
}

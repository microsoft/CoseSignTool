// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Engine;

using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// A stable cache key for producer-owned cross-validation caching.
/// </summary>
/// <remarks>
/// Producers may use this as a key in <c>IMemoryCache</c>.
/// </remarks>
public readonly struct TrustFactCacheKey : IEquatable<TrustFactCacheKey>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustFactCacheKey"/> struct.
    /// </summary>
    /// <param name="messageId">The message ID for the current evaluation.</param>
    /// <param name="subjectId">The subject ID.</param>
    /// <param name="factType">The fact type.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="factType"/> is null.</exception>
    public TrustFactCacheKey(TrustSubjectId messageId, TrustSubjectId subjectId, Type factType)
    {
        MessageId = messageId;
        SubjectId = subjectId;
        FactType = factType ?? throw new ArgumentNullException(nameof(factType));
    }

    /// <summary>
    /// Gets the message ID for the current evaluation.
    /// </summary>
    public TrustSubjectId MessageId { get; }

    /// <summary>
    /// Gets the subject ID.
    /// </summary>
    public TrustSubjectId SubjectId { get; }

    /// <summary>
    /// Gets the fact type.
    /// </summary>
    public Type FactType { get; }

    /// <inheritdoc />
    public bool Equals(TrustFactCacheKey other)
    {
        return MessageId.Equals(other.MessageId)
            && SubjectId.Equals(other.SubjectId)
            && FactType == other.FactType;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is TrustFactCacheKey other && Equals(other);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = (hash * 31) + MessageId.GetHashCode();
            hash = (hash * 31) + SubjectId.GetHashCode();
            hash = (hash * 31) + FactType.GetHashCode();
            return hash;
        }
    }

    /// <summary>
    /// Returns a value indicating whether two cache keys are equal.
    /// </summary>
    /// <param name="left">The first cache key.</param>
    /// <param name="right">The second cache key.</param>
    /// <returns><see langword="true"/> if the keys are equal; otherwise <see langword="false"/>.</returns>
    public static bool operator ==(TrustFactCacheKey left, TrustFactCacheKey right) => left.Equals(right);

    /// <summary>
    /// Returns a value indicating whether two cache keys are not equal.
    /// </summary>
    /// <param name="left">The first cache key.</param>
    /// <param name="right">The second cache key.</param>
    /// <returns><see langword="true"/> if the keys are not equal; otherwise <see langword="false"/>.</returns>
    public static bool operator !=(TrustFactCacheKey left, TrustFactCacheKey right) => !left.Equals(right);
}

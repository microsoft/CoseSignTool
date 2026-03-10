// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Engine;

/// <summary>
/// Represents a fact set returned by the trust fact engine.
/// </summary>
public interface ITrustFactSet
{
    /// <summary>
    /// Gets the fact type represented by this set.
    /// </summary>
    Type FactType { get; }

    /// <summary>
    /// Gets the produced value count.
    /// </summary>
    int Count { get; }

    /// <summary>
    /// Gets the missing fact reason (if missing).
    /// </summary>
    TrustFactMissing? MissingReason { get; }

    /// <summary>
    /// Gets a value indicating whether the fact set is missing (not produced).
    /// </summary>
    bool IsMissing { get; }
}

/// <summary>
/// Represents a strongly typed fact set returned by the trust fact engine.
/// </summary>
/// <typeparam name="TFact">The fact type.</typeparam>
public interface ITrustFactSet<TFact> : ITrustFactSet
{
    /// <summary>
    /// Gets the produced fact values.
    /// </summary>
    /// <remarks>
    /// Empty when no facts are present. When <see cref="ITrustFactSet.IsMissing"/> is true, this is always empty.
    /// </remarks>
    IReadOnlyList<TFact> Values { get; }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Engine;

/// <summary>
/// A multi-valued fact set for a given subject.
/// </summary>
/// <remarks>
/// Facts are not required to exist. Missing facts are represented explicitly
/// rather than by exceptions.
/// </remarks>
public sealed class TrustFactSet<TFact> : ITrustFactSet<TFact>
{
    private TrustFactSet(IReadOnlyList<TFact> values, TrustFactMissing? missing)
    {
        Values = values ?? throw new ArgumentNullException(nameof(values));
        MissingReason = missing;
    }

    /// <summary>
    /// Gets the produced fact values.
    /// </summary>
    /// <remarks>
    /// Empty when no facts are present. When <see cref="IsMissing"/> is true, this is always empty.
    /// </remarks>
    public IReadOnlyList<TFact> Values { get; }

    /// <summary>
    /// Gets the produced value count.
    /// </summary>
    public int Count => Values.Count;

    /// <summary>
    /// Gets the fact type represented by this set.
    /// </summary>
    public Type FactType => typeof(TFact);

    /// <summary>
    /// Gets the missing fact reason (if missing).
    /// </summary>
    public TrustFactMissing? MissingReason { get; }

    /// <summary>
    /// Gets a value indicating whether the fact set is missing (not produced).
    /// </summary>
    public bool IsMissing => MissingReason != null;

    /// <summary>
    /// Creates an available fact set.
    /// </summary>
    /// <param name="values">The available fact values.</param>
    /// <returns>An available fact set.</returns>
    public static TrustFactSet<TFact> Available(params TFact[]? values)
    {
        return new TrustFactSet<TFact>(values ?? Array.Empty<TFact>(), missing: null);
    }

    /// <summary>
    /// Creates a missing fact set.
    /// </summary>
    /// <param name="code">A stable missing reason code.</param>
    /// <param name="message">A human-readable description.</param>
    /// <param name="exception">An optional exception captured for diagnostics.</param>
    /// <returns>A missing fact set.</returns>
    public static TrustFactSet<TFact> Missing(string code, string message, Exception? exception = null)
    {
        return new TrustFactSet<TFact>(Array.Empty<TFact>(), new TrustFactMissing(code, message, exception));
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Audit;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// An observation about a fact set used during trust evaluation.
/// </summary>
public sealed class TrustDecisionAuditFactObservation
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustDecisionAuditFactObservation"/> class.
    /// </summary>
    /// <param name="subjectId">The subject ID for which facts were requested.</param>
    /// <param name="factType">The fact type name.</param>
    /// <param name="isMissing">Whether the fact set was missing.</param>
    /// <param name="valueCount">The number of values in the fact set.</param>
    /// <param name="missingReason">The missing reason (if missing).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="factType"/> is null.</exception>
    public TrustDecisionAuditFactObservation(
        TrustSubjectId subjectId,
        string factType,
        bool isMissing,
        int valueCount,
        TrustFactMissing? missingReason)
    {
        SubjectId = subjectId;
        Guard.ThrowIfNull(factType);
        FactType = factType;
        IsMissing = isMissing;
        ValueCount = valueCount;
        MissingReason = missingReason;
    }

    /// <summary>
    /// Gets the subject ID for which the fact was requested.
    /// </summary>
    public TrustSubjectId SubjectId { get; }

    /// <summary>
    /// Gets the fact type name.
    /// </summary>
    public string FactType { get; }

    /// <summary>
    /// Gets a value indicating whether the fact set was missing.
    /// </summary>
    public bool IsMissing { get; }

    /// <summary>
    /// Gets the number of values in the fact set.
    /// </summary>
    public int ValueCount { get; }

    /// <summary>
    /// Gets the missing reason (if missing).
    /// </summary>
    public TrustFactMissing? MissingReason { get; }
}

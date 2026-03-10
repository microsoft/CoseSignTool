// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Audit;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;

[ExcludeFromCodeCoverage]
internal sealed class TrustFactObservationAudit
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustFactObservationAudit"/> class.
    /// </summary>
    /// <param name="factType">The fact type name.</param>
    /// <param name="isMissing">Whether the fact set was missing.</param>
    /// <param name="missingCode">The missing code (when missing).</param>
    /// <param name="missingMessage">The missing message (when missing).</param>
    /// <param name="valueCount">The number of values returned (when available).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="factType"/> is null.</exception>
    public TrustFactObservationAudit(
        string factType,
        bool isMissing,
        string? missingCode,
        string? missingMessage,
        int valueCount)
    {
        Guard.ThrowIfNull(factType);

        FactType = factType;
        IsMissing = isMissing;
        MissingCode = missingCode;
        MissingMessage = missingMessage;
        ValueCount = valueCount;
    }

    /// <summary>
    /// Gets the fact type name.
    /// </summary>
    public string FactType { get; }

    /// <summary>
    /// Gets a value indicating whether the fact set was missing.
    /// </summary>
    public bool IsMissing { get; }

    /// <summary>
    /// Gets the stable missing code.
    /// </summary>
    public string? MissingCode { get; }

    /// <summary>
    /// Gets the missing message.
    /// </summary>
    public string? MissingMessage { get; }

    /// <summary>
    /// Gets the number of returned values.
    /// </summary>
    public int ValueCount { get; }
}

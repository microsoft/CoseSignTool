// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Plan;

/// <summary>
/// Options controlling trust evaluation behavior.
/// </summary>
public sealed class TrustEvaluationOptions
{
    /// <summary>
    /// Gets or sets an overall time budget for trust evaluation.
    /// </summary>
    public TimeSpan? OverallTimeout { get; set; }

    /// <summary>
    /// Gets or sets a per-fact budget.
    /// </summary>
    public TimeSpan? PerFactTimeout { get; set; }

    /// <summary>
    /// Gets or sets a per-producer budget.
    /// </summary>
    public TimeSpan? PerProducerTimeout { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the trust stage should be bypassed.
    /// </summary>
    /// <remarks>
    /// When true, the validator should skip trust evaluation entirely while still
    /// performing cryptographic signature verification.
    /// </remarks>
    public bool BypassTrust { get; set; }
}

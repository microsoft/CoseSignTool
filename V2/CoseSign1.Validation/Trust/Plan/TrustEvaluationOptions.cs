// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Plan;

/// <summary>
/// Options controlling trust evaluation behavior.
/// </summary>
public sealed class TrustEvaluationOptions
{
    internal static class ClassStrings
    {
        public const string BypassTrustObsoleteMessage = "BypassTrust is intended for testing only. Will be removed in a future release.";
    }

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
    /// Bypasses trust evaluation entirely. USE ONLY FOR TESTING.
    /// In production, this property is ignored unless the environment variable
    /// COSESIGNTOOL_ALLOW_BYPASS_TRUST is set to "true".
    /// </summary>
    /// <remarks>
    /// When true, the validator should skip trust evaluation entirely while still
    /// performing cryptographic signature verification. In production builds, this
    /// is guarded by the COSESIGNTOOL_ALLOW_BYPASS_TRUST environment variable.
    /// </remarks>
    [Obsolete(ClassStrings.BypassTrustObsoleteMessage)]
    public bool BypassTrust { get; set; }
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Frontends;

/// <summary>
/// Severity level attached to a <see cref="TrustPolicyTranslationDiagnostic"/>.
/// </summary>
/// <remarks>
/// Per §6.5.4 #2 (totality), every parse-success MUST yield either a valid
/// <see cref="CoseSign1.Validation.Trust.PlanPolicy.Spec.TrustPolicySpec"/> or at least one
/// <see cref="Error"/> diagnostic — never silently partial.
/// </remarks>
public enum TrustPolicySeverity
{
    /// <summary>Translation cannot proceed; the result spec is null.</summary>
    Error,

    /// <summary>Spec is well-formed but the document is suspicious (e.g., redundant clause).</summary>
    Warning,

    /// <summary>Informational note for the author; never gates compilation.</summary>
    Info,
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Audit;

using CoseSign1.Abstractions;

/// <summary>
/// A single rule evaluation event.
/// </summary>
public sealed class TrustDecisionAuditRuleEvaluation
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustDecisionAuditRuleEvaluation"/> class.
    /// </summary>
    /// <param name="ruleKind">The rule kind identifier.</param>
    /// <param name="isTrusted">Whether the rule evaluated to trusted.</param>
    /// <param name="reasons">Deterministic reasons for denial (empty if trusted).</param>
    /// <param name="detail">Optional rule detail.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ruleKind"/> or <paramref name="reasons"/> is null.</exception>
    public TrustDecisionAuditRuleEvaluation(
        string ruleKind,
        bool isTrusted,
        IReadOnlyList<string> reasons,
        string? detail = null)
    {
        Guard.ThrowIfNull(ruleKind);
        Guard.ThrowIfNull(reasons);

        RuleKind = ruleKind;
        IsTrusted = isTrusted;
        Reasons = reasons;
        Detail = detail;
    }

    /// <summary>
    /// Gets the rule kind identifier.
    /// </summary>
    public string RuleKind { get; }

    /// <summary>
    /// Gets a value indicating whether the rule evaluation resulted in trust.
    /// </summary>
    public bool IsTrusted { get; }

    /// <summary>
    /// Gets the deterministic reasons for denial (empty if trusted).
    /// </summary>
    public IReadOnlyList<string> Reasons { get; }

    /// <summary>
    /// Gets optional rule detail.
    /// </summary>
    public string? Detail { get; }
}

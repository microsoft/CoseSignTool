// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Audit;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;

[ExcludeFromCodeCoverage]
internal sealed class TrustRuleEvaluationAudit
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustRuleEvaluationAudit"/> class.
    /// </summary>
    /// <param name="ruleKind">A stable rule kind identifier.</param>
    /// <param name="isTrusted">The rule outcome.</param>
    /// <param name="reasons">The rule reasons (usually empty when trusted).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ruleKind"/> or <paramref name="reasons"/> is null.</exception>
    public TrustRuleEvaluationAudit(string ruleKind, bool isTrusted, IReadOnlyList<string> reasons)
    {
        Guard.ThrowIfNull(ruleKind);
        Guard.ThrowIfNull(reasons);

        RuleKind = ruleKind;
        IsTrusted = isTrusted;
        Reasons = reasons;
    }

    /// <summary>
    /// Gets a stable identifier for the rule kind.
    /// </summary>
    public string RuleKind { get; }

    /// <summary>
    /// Gets a value indicating whether the rule was trusted.
    /// </summary>
    public bool IsTrusted { get; }

    /// <summary>
    /// Gets the rule reasons.
    /// </summary>
    public IReadOnlyList<string> Reasons { get; }
}

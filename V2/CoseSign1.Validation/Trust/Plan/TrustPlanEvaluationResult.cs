// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Plan;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Audit;

/// <summary>
/// The result of evaluating a <see cref="CompiledTrustPlan"/>, including an audit.
/// </summary>
public sealed class TrustPlanEvaluationResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPlanEvaluationResult"/> class.
    /// </summary>
    /// <param name="decision">The trust decision.</param>
    /// <param name="audit">The trust decision audit.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="decision"/> or <paramref name="audit"/> is null.</exception>
    public TrustPlanEvaluationResult(TrustDecision decision, TrustDecisionAudit audit)
    {
        Guard.ThrowIfNull(decision);
        Guard.ThrowIfNull(audit);

        Decision = decision;
        Audit = audit;
    }

    /// <summary>
    /// Gets the trust decision.
    /// </summary>
    public TrustDecision Decision { get; }

    /// <summary>
    /// Gets the trust decision audit.
    /// </summary>
    public TrustDecisionAudit Audit { get; }
}

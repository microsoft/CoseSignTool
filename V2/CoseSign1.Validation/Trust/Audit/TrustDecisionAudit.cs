// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Audit;

using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// A deterministic audit record for a trust evaluation.
/// </summary>
public sealed class TrustDecisionAudit
{
    /// <summary>
    /// The current schema version for this audit payload.
    /// </summary>
    public const int AuditSchemaVersion = 1;

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustDecisionAudit"/> class.
    /// </summary>
    /// <param name="schemaVersion">The audit schema version.</param>
    /// <param name="messageId">The stable message ID for the evaluation.</param>
    /// <param name="subject">The subject being evaluated.</param>
    /// <param name="decision">The final decision.</param>
    /// <param name="ruleEvaluations">The deterministic rule evaluation trace.</param>
    /// <param name="facts">The deterministic fact observations.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="subject"/>, <paramref name="decision"/>, <paramref name="ruleEvaluations"/>, or <paramref name="facts"/> is null.</exception>
    public TrustDecisionAudit(
        int schemaVersion,
        TrustSubjectId messageId,
        TrustSubject subject,
        TrustDecision decision,
        IReadOnlyList<TrustDecisionAuditRuleEvaluation> ruleEvaluations,
        IReadOnlyList<TrustDecisionAuditFactObservation> facts)
    {
        SchemaVersion = schemaVersion;
        MessageId = messageId;
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        Decision = decision ?? throw new ArgumentNullException(nameof(decision));
        RuleEvaluations = ruleEvaluations ?? throw new ArgumentNullException(nameof(ruleEvaluations));
        Facts = facts ?? throw new ArgumentNullException(nameof(facts));
    }

    /// <summary>
    /// Gets the schema version.
    /// </summary>
    public int SchemaVersion { get; }

    /// <summary>
    /// Gets the stable message ID for this evaluation.
    /// </summary>
    public TrustSubjectId MessageId { get; }

    /// <summary>
    /// Gets the subject being evaluated.
    /// </summary>
    public TrustSubject Subject { get; }

    /// <summary>
    /// Gets the final trust decision.
    /// </summary>
    public TrustDecision Decision { get; }

    /// <summary>
    /// Gets a deterministic trace of rule evaluations.
    /// </summary>
    public IReadOnlyList<TrustDecisionAuditRuleEvaluation> RuleEvaluations { get; }

    /// <summary>
    /// Gets the deterministic fact observations recorded during evaluation.
    /// </summary>
    public IReadOnlyList<TrustDecisionAuditFactObservation> Facts { get; }
}

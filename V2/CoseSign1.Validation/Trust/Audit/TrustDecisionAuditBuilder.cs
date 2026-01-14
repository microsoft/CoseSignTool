// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Audit;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Subjects;

internal sealed class TrustDecisionAuditBuilder
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string RuleAllowAll = "allow_all";
        public const string RuleDenyAll = "deny_all";
        public const string RuleAnd = "and";
        public const string RuleOr = "or";
        public const string RuleNot = "not";
        public const string RuleImplies = "implies";
        public const string RuleAnyFact = "any_fact";

        public const string DetailImpliesAntecedentDenied = "antecedent denied";
        public const string DetailImpliesAntecedentTrusted = "antecedent trusted";

        public const string DetailAnyFactMissing = "missing";
        public const string DetailAnyFactEmpty = "empty";
        public const string DetailAnyFactMatched = "matched";
        public const string DetailAnyFactNoMatch = "no_match";
    }

    private readonly List<TrustDecisionAuditRuleEvaluation> RuleEvaluations = new();
    private readonly List<TrustDecisionAuditFactObservation> Facts = new();

    public void RecordRule(string ruleKind, TrustDecision decision, string? detail = null)
    {
        if (ruleKind == null)
        {
            throw new ArgumentNullException(nameof(ruleKind));
        }

        if (decision == null)
        {
            throw new ArgumentNullException(nameof(decision));
        }

        RuleEvaluations.Add(new TrustDecisionAuditRuleEvaluation(ruleKind, decision.IsTrusted, decision.Reasons, detail));
    }

    public void RecordFact(TrustSubjectId subjectId, Type factType, ITrustFactSet factSet)
    {
        if (factType == null)
        {
            throw new ArgumentNullException(nameof(factType));
        }

        if (factSet == null)
        {
            throw new ArgumentNullException(nameof(factSet));
        }

        Facts.Add(
            new TrustDecisionAuditFactObservation(
                subjectId,
                factType.FullName ?? factType.Name,
                factSet.IsMissing,
                factSet.Count,
                factSet.MissingReason));
    }

    public TrustDecisionAudit Build(TrustSubjectId messageId, TrustSubject subject, TrustDecision decision)
    {
        return new TrustDecisionAudit(
            TrustDecisionAudit.AuditSchemaVersion,
            messageId,
            subject,
            decision,
            RuleEvaluations.ToArray(),
            Facts.ToArray());
    }
}

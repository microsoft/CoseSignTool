// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Rules;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Audit;
using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// Factory methods for building trust rules.
/// </summary>
public static class TrustRules
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string DefaultNotReason = "Negated rule was satisfied";
        public const string DefaultOrEmptyReason = "No trust sources were satisfied";
        public const string DefaultWrongSubjectKindReason = "Trust rule evaluated on an unexpected subject kind.";
    }

    /// <summary>
    /// Creates a rule that always evaluates to trusted.
    /// </summary>
    /// <returns>An allow-all rule.</returns>
    public static TrustRule AllowAll() => new AllowAllRule();

    /// <summary>
    /// Creates a rule that always evaluates to denied.
    /// </summary>
    /// <param name="reason">The denial reason.</param>
    /// <returns>A deny-all rule.</returns>
    public static TrustRule DenyAll(string reason) => new DenyAllRule(reason);

    /// <summary>
    /// Creates a rule that requires all child rules to be trusted.
    /// </summary>
    /// <param name="rules">The child rules.</param>
    /// <returns>An AND rule.</returns>
    public static TrustRule And(params TrustRule[] rules) => new AndRule(rules);

    /// <summary>
    /// Creates a rule that requires at least one child rule to be trusted.
    /// </summary>
    /// <param name="rules">The child rules.</param>
    /// <returns>An OR rule.</returns>
    public static TrustRule Or(params TrustRule[] rules) => new OrRule(rules);

    /// <summary>
    /// Creates a rule that inverts the decision of its child.
    /// </summary>
    /// <param name="rule">The rule to invert.</param>
    /// <param name="reason">The denial reason when the inner rule is trusted.</param>
    /// <returns>A NOT rule.</returns>
    public static TrustRule Not(TrustRule rule, string? reason = null) => new NotRule(rule, reason ?? ClassStrings.DefaultNotReason);

    /// <summary>
    /// Creates a rule implementing logical implication.
    /// </summary>
    /// <param name="antecedent">The antecedent rule.</param>
    /// <param name="consequent">The consequent rule.</param>
    /// <returns>An implication rule.</returns>
    public static TrustRule Implies(TrustRule antecedent, TrustRule consequent) => new ImpliesRule(antecedent, consequent);

    /// <summary>
    /// Creates a rule that requires at least one produced fact value to match a predicate.
    /// </summary>
    /// <typeparam name="TFact">The fact type.</typeparam>
    /// <param name="predicate">The predicate to match.</param>
    /// <param name="missingFactMessage">The denial reason when facts are missing.</param>
    /// <param name="predicateFailedMessage">The denial reason when no fact matches the predicate.</param>
    /// <param name="onEmpty">Controls behavior when the fact set is available but empty.</param>
    /// <param name="onEmptyMessage">Optional denial reason when the set is empty and <paramref name="onEmpty"/> is <see cref="OnEmptyBehavior.Deny"/>.</param>
    /// <returns>An any-fact rule.</returns>
    public static TrustRule AnyFact<TFact>(
        Func<TFact, bool> predicate,
        string missingFactMessage,
        string predicateFailedMessage,
        OnEmptyBehavior onEmpty,
        string? onEmptyMessage = null)
    {
        return new AnyFactRule<TFact>(predicate, missingFactMessage, predicateFailedMessage, onEmpty, onEmptyMessage);
    }

    /// <summary>
    /// Creates a rule that evaluates an inner rule on a derived subject.
    /// </summary>
    /// <param name="expectedSubjectKind">The expected kind of the current subject.</param>
    /// <param name="deriveSubject">A function to derive the subject to evaluate the inner rule against.</param>
    /// <param name="inner">The inner rule to evaluate.</param>
    /// <returns>A derived-subject evaluation rule.</returns>
    public static TrustRule OnDerivedSubject(
        TrustSubjectKind expectedSubjectKind,
        Func<TrustRuleContext, TrustSubject> deriveSubject,
        TrustRule inner)
    {
        return new OnDerivedSubjectRule(expectedSubjectKind, deriveSubject, inner);
    }

    private sealed class AllowAllRule : TrustRule
    {
        public override ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            var decision = TrustDecision.Trusted();
            context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleAllowAll, decision);
            return new ValueTask<TrustDecision>(decision);
        }
    }

    private sealed class DenyAllRule : TrustRule
    {
        private readonly string Reason;

        public DenyAllRule(string reason)
        {
            Reason = reason ?? throw new ArgumentNullException(nameof(reason));
        }

        public override ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            var decision = TrustDecision.Denied(Reason);
            context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleDenyAll, decision);
            return new ValueTask<TrustDecision>(decision);
        }
    }

    private sealed class AndRule : TrustRule
    {
        private readonly IReadOnlyList<TrustRule> Rules;

        public AndRule(IReadOnlyList<TrustRule> rules)
        {
            Rules = rules ?? throw new ArgumentNullException(nameof(rules));
        }

        public override async ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            var reasons = new List<string>();

            foreach (var rule in Rules)
            {
                var decision = await rule.EvaluateAsync(context).ConfigureAwait(false);
                if (!decision.IsTrusted)
                {
                    reasons.AddRange(decision.Reasons);
                }
            }

            var result = reasons.Count == 0 ? TrustDecision.Trusted() : TrustDecision.Denied(reasons);
            context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleAnd, result);
            return result;
        }
    }

    private sealed class OrRule : TrustRule
    {
        private readonly IReadOnlyList<TrustRule> Rules;

        public OrRule(IReadOnlyList<TrustRule> rules)
        {
            Rules = rules ?? throw new ArgumentNullException(nameof(rules));
        }

        public override async ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            if (Rules.Count == 0)
            {
                var decision = TrustDecision.Denied(ClassStrings.DefaultOrEmptyReason);
                context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleOr, decision);
                return decision;
            }

            var reasons = new List<string>();

            foreach (var rule in Rules)
            {
                var decision = await rule.EvaluateAsync(context).ConfigureAwait(false);
                if (decision.IsTrusted)
                {
                    context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleOr, TrustDecision.Trusted());
                    return TrustDecision.Trusted();
                }

                reasons.AddRange(decision.Reasons);
            }

            var result = TrustDecision.Denied(reasons);
            context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleOr, result);
            return result;
        }
    }

    private sealed class NotRule : TrustRule
    {
        private readonly TrustRule Inner;
        private readonly string Reason;

        public NotRule(TrustRule inner, string reason)
        {
            Inner = inner ?? throw new ArgumentNullException(nameof(inner));
            Reason = reason ?? throw new ArgumentNullException(nameof(reason));
        }

        public override async ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            var decision = await Inner.EvaluateAsync(context).ConfigureAwait(false);

            var result = decision.IsTrusted ? TrustDecision.Denied(Reason) : TrustDecision.Trusted();
            context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleNot, result);
            return result;
        }
    }

    private sealed class ImpliesRule : TrustRule
    {
        private readonly TrustRule Antecedent;
        private readonly TrustRule Consequent;

        public ImpliesRule(TrustRule antecedent, TrustRule consequent)
        {
            Antecedent = antecedent ?? throw new ArgumentNullException(nameof(antecedent));
            Consequent = consequent ?? throw new ArgumentNullException(nameof(consequent));
        }

        public override async ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            var precondition = await Antecedent.EvaluateAsync(context).ConfigureAwait(false);
            if (!precondition.IsTrusted)
            {
                context.Audit?.RecordRule(
                    TrustDecisionAuditBuilder.ClassStrings.RuleImplies,
                    TrustDecision.Trusted(),
                    detail: TrustDecisionAuditBuilder.ClassStrings.DetailImpliesAntecedentDenied);
                return TrustDecision.Trusted();
            }

            var result = await Consequent.EvaluateAsync(context).ConfigureAwait(false);
            context.Audit?.RecordRule(
                TrustDecisionAuditBuilder.ClassStrings.RuleImplies,
                result,
                detail: TrustDecisionAuditBuilder.ClassStrings.DetailImpliesAntecedentTrusted);
            return result;
        }
    }

    private sealed class OnDerivedSubjectRule : TrustRule
    {
        private readonly TrustSubjectKind ExpectedSubjectKind;
        private readonly Func<TrustRuleContext, TrustSubject> DeriveSubject;
        private readonly TrustRule Inner;

        public OnDerivedSubjectRule(
            TrustSubjectKind expectedSubjectKind,
            Func<TrustRuleContext, TrustSubject> deriveSubject,
            TrustRule inner)
        {
            ExpectedSubjectKind = expectedSubjectKind;
            DeriveSubject = deriveSubject ?? throw new ArgumentNullException(nameof(deriveSubject));
            Inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            if (context.Subject.Kind != ExpectedSubjectKind)
            {
                var denied = TrustDecision.Denied(ClassStrings.DefaultWrongSubjectKindReason);
                context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleAnd, denied);
                return new ValueTask<TrustDecision>(denied);
            }

            var derived = DeriveSubject(context);
            var derivedContext = context.Audit == null
                ? new TrustRuleContext(context.Facts, derived)
                : new TrustRuleContext(context.Facts, derived, context.Audit);

            return Inner.EvaluateAsync(derivedContext);
        }
    }

    private sealed class AnyFactRule<TFact> : TrustRule
    {
        private readonly Func<TFact, bool> Predicate;
        private readonly string MissingFactMessage;
        private readonly string PredicateFailedMessage;
        private readonly OnEmptyBehavior OnEmpty;
        private readonly string? OnEmptyMessage;

        public AnyFactRule(
            Func<TFact, bool> predicate,
            string missingFactMessage,
            string predicateFailedMessage,
            OnEmptyBehavior onEmpty,
            string? onEmptyMessage)
        {
            Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
            MissingFactMessage = missingFactMessage ?? throw new ArgumentNullException(nameof(missingFactMessage));
            PredicateFailedMessage = predicateFailedMessage ?? throw new ArgumentNullException(nameof(predicateFailedMessage));
            OnEmpty = onEmpty;
            OnEmptyMessage = onEmptyMessage;
        }

        public override async ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            var factSet = await context.Facts.GetFactsAsync<TFact>(context.Subject).ConfigureAwait(false);

            context.Audit?.RecordFact(context.Subject.Id, typeof(TFact), factSet);

            if (factSet.IsMissing)
            {
                var decision = TrustDecision.Denied(MissingFactMessage);
                context.Audit?.RecordRule(
                    TrustDecisionAuditBuilder.ClassStrings.RuleAnyFact,
                    decision,
                    detail: TrustDecisionAuditBuilder.ClassStrings.DetailAnyFactMissing);
                return decision;
            }

            if (factSet.Count == 0)
            {
                var decision = OnEmpty == OnEmptyBehavior.Allow
                    ? TrustDecision.Trusted()
                    : TrustDecision.Denied(OnEmptyMessage ?? PredicateFailedMessage);

                context.Audit?.RecordRule(
                    TrustDecisionAuditBuilder.ClassStrings.RuleAnyFact,
                    decision,
                    detail: TrustDecisionAuditBuilder.ClassStrings.DetailAnyFactEmpty);
                return decision;
            }

            foreach (var fact in factSet.Values)
            {
                if (Predicate(fact))
                {
                    var decision = TrustDecision.Trusted();
                    context.Audit?.RecordRule(
                        TrustDecisionAuditBuilder.ClassStrings.RuleAnyFact,
                        decision,
                        detail: TrustDecisionAuditBuilder.ClassStrings.DetailAnyFactMatched);
                    return decision;
                }
            }

            var denied = TrustDecision.Denied(PredicateFailedMessage);
            context.Audit?.RecordRule(
                TrustDecisionAuditBuilder.ClassStrings.RuleAnyFact,
                denied,
                detail: TrustDecisionAuditBuilder.ClassStrings.DetailAnyFactNoMatch);
            return denied;
        }
    }
}

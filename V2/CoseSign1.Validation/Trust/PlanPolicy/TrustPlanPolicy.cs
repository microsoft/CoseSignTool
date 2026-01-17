// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Fluent policy builder that compiles to a <see cref="CompiledTrustPlan"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the policy authoring surface for the Facts + Rules trust model.
/// It is distinct from the legacy assertion-based trust model.
/// </para>
/// <para>
/// A <see cref="TrustPlanPolicy"/> compiles to a <see cref="CompiledTrustPlan"/> and is evaluated starting
/// from a message-scoped <see cref="TrustSubject"/>.
/// </para>
/// </remarks>
public sealed class TrustPlanPolicy
{
    private readonly TrustRule Root;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorMissingFactProducers = "No ITrustPack was registered";
        public const string MissingCounterSignatures = "Counter-signatures could not be discovered";
        public const string EmptyCounterSignaturesDenied = "No counter-signatures were present";
        public const string WrongSubjectKind = "Rule was evaluated on an unexpected subject kind";
    }

    private TrustPlanPolicy(TrustRule root)
    {
        Guard.ThrowIfNull(root);
        Root = root;
    }

    /// <summary>
    /// Creates a policy that evaluates requirements on the message itself.
    /// </summary>
    /// <param name="configure">Configures the message requirements.</param>
    /// <returns>A message-scoped policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    public static TrustPlanPolicy Message(Func<MessagePolicyBuilder, MessagePolicyBuilder> configure)
    {
        Guard.ThrowIfNull(configure);

        var builder = configure(new MessagePolicyBuilder());
        return new TrustPlanPolicy(builder.Build());
    }

    /// <summary>
    /// Creates a policy that evaluates requirements on the primary signing key for the message.
    /// </summary>
    /// <param name="configure">Configures primary signing key requirements.</param>
    /// <returns>A policy scoped to the primary signing key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    public static TrustPlanPolicy PrimarySigningKey(Func<SigningKeyPolicyBuilder, SigningKeyPolicyBuilder> configure)
    {
        Guard.ThrowIfNull(configure);

        var builder = configure(new SigningKeyPolicyBuilder());
        var rule = new EvaluateOnDerivedSubjectRule(
            expectedSubjectKind: TrustSubjectKind.Message,
            deriveSubject: ctx => TrustSubject.PrimarySigningKey(ctx.Facts.MessageId),
            inner: builder.Build());
        return new TrustPlanPolicy(rule);
    }

    /// <summary>
    /// Creates a policy that requires at least one counter-signature on the message to satisfy the configured requirements.
    /// </summary>
    /// <param name="configure">Configures counter-signature requirements.</param>
    /// <returns>A policy scoped to any counter-signature.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    public static TrustPlanPolicy AnyCounterSignature(Func<CounterSignaturePolicyBuilder, CounterSignaturePolicyBuilder> configure)
    {
        Guard.ThrowIfNull(configure);

        var builder = configure(new CounterSignaturePolicyBuilder());
        var rule = new AnyCounterSignatureRule(builder.Build(), builder.OnEmptyBehavior);
        return new TrustPlanPolicy(rule);
    }

    /// <summary>
    /// Creates a policy that represents logical implication: if <paramref name="antecedent"/> is satisfied,
    /// then <paramref name="consequent"/> must also be satisfied.
    /// </summary>
    /// <param name="antecedent">The antecedent policy.</param>
    /// <param name="consequent">The consequent policy.</param>
    /// <returns>A policy representing <c>antecedent =&gt; consequent</c>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="antecedent"/> or <paramref name="consequent"/> is null.</exception>
    public static TrustPlanPolicy Implies(TrustPlanPolicy antecedent, TrustPlanPolicy consequent)
    {
        Guard.ThrowIfNull(antecedent);
        Guard.ThrowIfNull(consequent);

        return new TrustPlanPolicy(TrustRules.Implies(antecedent.Root, consequent.Root));
    }

    /// <summary>
    /// Negates this policy.
    /// </summary>
    /// <returns>A policy that is satisfied when this policy is not satisfied.</returns>
    public TrustPlanPolicy Not() => new(TrustRules.Not(Root));

    /// <summary>
    /// Combines this policy with another using logical OR.
    /// </summary>
    /// <param name="other">The other policy.</param>
    /// <returns>A policy that is satisfied when either policy is satisfied.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="other"/> is null.</exception>
    public TrustPlanPolicy Or(TrustPlanPolicy other)
    {
        Guard.ThrowIfNull(other);

        return new TrustPlanPolicy(TrustRules.Or(Root, other.Root));
    }

    /// <summary>
    /// Combines this policy with another using logical AND.
    /// </summary>
    /// <param name="other">The other policy.</param>
    /// <returns>A policy that is satisfied when both policies are satisfied.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="other"/> is null.</exception>
    public TrustPlanPolicy And(TrustPlanPolicy other)
    {
        Guard.ThrowIfNull(other);

        return new TrustPlanPolicy(TrustRules.And(Root, other.Root));
    }

    /// <summary>
    /// Compiles this policy to a <see cref="CompiledTrustPlan"/> using fact producers registered in the given service provider.
    /// </summary>
    /// <param name="services">The service provider.</param>
    /// <returns>A compiled trust plan.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is null.</exception>
    public CompiledTrustPlan Compile(IServiceProvider services)
    {
        Guard.ThrowIfNull(services);

        var packs = (services.GetService(typeof(IEnumerable<ITrustPack>)) as IEnumerable<ITrustPack>)
            ?.ToArray() ?? Array.Empty<ITrustPack>();

        return new CompiledTrustPlan(Root, packs, services);
    }

    /// <summary>
    /// Builder for message-scoped requirements.
    /// </summary>
    public sealed class MessagePolicyBuilder : SubjectPolicyBuilder<MessagePolicyBuilder>
    {
        /// <summary>
        /// Requires at least one produced fact value of <typeparamref name="TFact"/> to satisfy <paramref name="predicate"/>.
        /// </summary>
        /// <typeparam name="TFact">The fact type.</typeparam>
        /// <param name="predicate">The predicate.</param>
        /// <param name="message">The denial reason if the requirement is not satisfied.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="predicate"/> or <paramref name="message"/> is null.</exception>
        public MessagePolicyBuilder RequireFact<TFact>(Func<TFact, bool> predicate, string message)
            where TFact : IMessageFact
        {
            RequireFactCore(predicate, message);
            return this;
        }
    }

    /// <summary>
    /// Builder for signing-key-scoped requirements.
    /// </summary>
    public sealed class SigningKeyPolicyBuilder : SubjectPolicyBuilder<SigningKeyPolicyBuilder>
    {
        /// <summary>
        /// Requires at least one produced fact value of <typeparamref name="TFact"/> to satisfy <paramref name="predicate"/>.
        /// </summary>
        /// <typeparam name="TFact">The fact type.</typeparam>
        /// <param name="predicate">The predicate.</param>
        /// <param name="message">The denial reason if the requirement is not satisfied.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="predicate"/> or <paramref name="message"/> is null.</exception>
        public SigningKeyPolicyBuilder RequireFact<TFact>(Func<TFact, bool> predicate, string message)
            where TFact : ISigningKeyFact
        {
            RequireFactCore(predicate, message);
            return this;
        }
    }

    /// <summary>
    /// Builder for counter-signature-scoped requirements.
    /// </summary>
    public sealed class CounterSignaturePolicyBuilder : SubjectPolicyBuilder<CounterSignaturePolicyBuilder>
    {
        private OnEmptyBehavior OnEmptyValue = OnEmptyBehavior.Deny;

        /// <summary>
        /// Requires at least one produced fact value of <typeparamref name="TFact"/> to satisfy <paramref name="predicate"/>.
        /// </summary>
        /// <typeparam name="TFact">The fact type.</typeparam>
        /// <param name="predicate">The predicate.</param>
        /// <param name="message">The denial reason if the requirement is not satisfied.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="predicate"/> or <paramref name="message"/> is null.</exception>
        public CounterSignaturePolicyBuilder RequireFact<TFact>(Func<TFact, bool> predicate, string message)
            where TFact : ICounterSignatureFact
        {
            RequireFactCore(predicate, message);
            return this;
        }

        /// <summary>
        /// Gets the configured behavior when no counter-signatures are present.
        /// </summary>
        public OnEmptyBehavior OnEmptyBehavior => OnEmptyValue;

        /// <summary>
        /// Configures behavior when no counter-signatures are present.
        /// </summary>
        /// <param name="behavior">The on-empty behavior.</param>
        /// <returns>This builder.</returns>
        public CounterSignaturePolicyBuilder OnEmpty(OnEmptyBehavior behavior)
        {
            OnEmptyValue = behavior;
            return this;
        }

        /// <summary>
        /// Adds signing-key requirements for the counter-signature's signing key.
        /// </summary>
        /// <param name="configure">Configures signing key requirements.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
        public CounterSignaturePolicyBuilder SigningKey(Func<SigningKeyPolicyBuilder, SigningKeyPolicyBuilder> configure)
        {
            Guard.ThrowIfNull(configure);

            var builder = configure(new SigningKeyPolicyBuilder());

            // Evaluate signing-key requirements on a derived subject.
            AddRule(new EvaluateOnDerivedSubjectRule(
                expectedSubjectKind: TrustSubjectKind.CounterSignature,
                deriveSubject: ctx => TrustSubject.CounterSignatureSigningKey(ctx.Subject.Id),
                inner: builder.Build()));

            return this;
        }
    }

    /// <summary>
    /// Base builder for requirements that evaluate facts for the current subject.
    /// </summary>
    /// <typeparam name="TSelf">The derived builder type.</typeparam>
    public abstract class SubjectPolicyBuilder<TSelf>
        where TSelf : SubjectPolicyBuilder<TSelf>
    {
        private readonly List<TrustRule> Rules = new();

        /// <summary>
        /// Adds a requirement that at least one produced fact of type <typeparamref name="TFact"/> must satisfy
        /// the provided predicate for the current subject.
        /// </summary>
        /// <typeparam name="TFact">The fact type required by this policy.</typeparam>
        /// <param name="predicate">A predicate that must be satisfied by at least one fact value.</param>
        /// <param name="message">The failure message to use when the requirement is not satisfied.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="predicate"/> or <paramref name="message"/> is null.</exception>
        protected void RequireFactCore<TFact>(Func<TFact, bool> predicate, string message)
        {
            Guard.ThrowIfNull(predicate);
            Guard.ThrowIfNull(message);

            AddRule(
                TrustRules.AnyFact(
                    predicate,
                    missingFactMessage: message,
                    predicateFailedMessage: message,
                    onEmpty: OnEmptyBehavior.Deny,
                    onEmptyMessage: message));
        }

        internal TrustRule Build()
        {
            if (Rules.Count == 0)
            {
                return TrustRules.AllowAll();
            }

            return Rules.Count == 1 ? Rules[0] : TrustRules.And(Rules.ToArray());
        }

        internal void AddRule(TrustRule rule)
        {
            Guard.ThrowIfNull(rule);
            Rules.Add(rule);
        }
    }

    private sealed class EvaluateOnDerivedSubjectRule : TrustRule
    {
        private readonly TrustSubjectKind ExpectedSubjectKind;
        private readonly Func<TrustRuleContext, TrustSubject> DeriveSubject;
        private readonly TrustRule Inner;

        public EvaluateOnDerivedSubjectRule(
            TrustSubjectKind expectedSubjectKind,
            Func<TrustRuleContext, TrustSubject> deriveSubject,
            TrustRule inner)
        {
            ExpectedSubjectKind = expectedSubjectKind;
            Guard.ThrowIfNull(deriveSubject);
            Guard.ThrowIfNull(inner);

            DeriveSubject = deriveSubject;
            Inner = inner;
        }

        public override ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            if (context.Subject.Kind != ExpectedSubjectKind)
            {
                var denied = TrustDecision.Denied(ClassStrings.WrongSubjectKind);
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

    private sealed class AnyCounterSignatureRule : TrustRule
    {
        private readonly TrustRule Inner;
        private readonly OnEmptyBehavior OnEmpty;

        public AnyCounterSignatureRule(TrustRule inner, OnEmptyBehavior onEmpty)
        {
            Guard.ThrowIfNull(inner);
            Inner = inner;
            OnEmpty = onEmpty;
        }

        public override async ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            if (context.Subject.Kind != TrustSubjectKind.Message)
            {
                var denied = TrustDecision.Denied(ClassStrings.WrongSubjectKind);
                context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleOr, denied);
                return denied;
            }

            var factSet = await context.Facts.GetFactsAsync<CounterSignatureSubjectFact>(context.Subject).ConfigureAwait(false);
            context.Audit?.RecordFact(context.Subject.Id, typeof(CounterSignatureSubjectFact), factSet);

            if (factSet.IsMissing)
            {
                var denied = TrustDecision.Denied(ClassStrings.MissingCounterSignatures);
                context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleOr, denied);
                return denied;
            }

            if (factSet.Count == 0)
            {
                var decision = OnEmpty == OnEmptyBehavior.Allow
                    ? TrustDecision.Trusted()
                    : TrustDecision.Denied(ClassStrings.EmptyCounterSignaturesDenied);

                context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleOr, decision);
                return decision;
            }

            var reasons = new List<string>();

            foreach (var fact in factSet.Values)
            {
                var csSubject = fact.Subject;
                var csContext = context.Audit == null
                    ? new TrustRuleContext(context.Facts, csSubject)
                    : new TrustRuleContext(context.Facts, csSubject, context.Audit);

                var decision = await Inner.EvaluateAsync(csContext).ConfigureAwait(false);
                if (decision.IsTrusted)
                {
                    context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleOr, TrustDecision.Trusted());
                    return TrustDecision.Trusted();
                }

                reasons.AddRange(decision.Reasons);
            }

            var deniedAll = TrustDecision.Denied(reasons);
            context.Audit?.RecordRule(TrustDecisionAuditBuilder.ClassStrings.RuleOr, deniedAll);
            return deniedAll;
        }
    }
}

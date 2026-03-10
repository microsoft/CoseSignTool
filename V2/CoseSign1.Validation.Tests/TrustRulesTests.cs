// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;


public sealed class TrustRulesTests
{
    private sealed record TestFact(string Value);

    private sealed class InspectSubjectRule : TrustRule
    {
        private readonly Action<TrustRuleContext> Inspect;

        public InspectSubjectRule(Action<TrustRuleContext> inspect)
        {
            Inspect = inspect ?? throw new ArgumentNullException(nameof(inspect));
        }

        public override ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            Inspect(context);
            return new ValueTask<TrustDecision>(TrustDecision.Trusted());
        }
    }

    private sealed class FixedFactProducer : IMultiTrustFactProducer
    {
        public FixedFactProducer(TestFact fact)
        {
            Fact = fact;
        }

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public TestFact Fact { get; }

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult<ITrustFactSet>(TrustFactSet<TestFact>.Available(Fact));
        }
    }

    private static (TrustFactEngine Engine, TrustRuleContext Context, TrustSubjectId MessageId, TrustSubject Subject) CreateContext(params IMultiTrustFactProducer[] producers)
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        var subject = TrustSubject.CounterSignature(messageId, new byte[] { 0x02 });
        var engine = new TrustFactEngine(messageId, producers);
        var context = new TrustRuleContext(engine, subject);
        return (engine, context, messageId, subject);
    }

    [Test]
    public void And_CollectsDenialReasons_InOrder()
    {
        var (_, context, _, _) = CreateContext();

        var rule = TrustRules.And(
            TrustRules.DenyAll("a"),
            TrustRules.DenyAll("b"));

        var decision = rule.Evaluate(context);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.EqualTo(new[] { "a", "b" }));
    }

    [Test]
    public async Task Or_WhenAllDeny_AggregatesReasons()
    {
        var (_, context, _, _) = CreateContext();

        var rule = TrustRules.Or(
            TrustRules.DenyAll("a"),
            TrustRules.DenyAll("b"));

        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.EqualTo(new[] { "a", "b" }));
    }

    [Test]
    public async Task Or_WhenNoRules_Denies()
    {
        var (_, context, _, _) = CreateContext();

        var rule = TrustRules.Or();
        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.Not.Empty);
    }

    [Test]
    public async Task Not_WhenInnerIsTrusted_DeniesWithReason()
    {
        var (_, context, _, _) = CreateContext();

        var rule = TrustRules.Not(TrustRules.AllowAll(), reason: "no");
        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Has.Member("no"));
    }

    [Test]
    public async Task Implies_WhenAntecedentIsDenied_IsTrusted()
    {
        var (_, context, _, _) = CreateContext();

        var rule = TrustRules.Implies(TrustRules.DenyAll("pre"), TrustRules.DenyAll("cons"));
        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public async Task AnyFact_WhenMissing_DeniesWithMissingMessage()
    {
        var (_, context, _, _) = CreateContext();

        var rule = TrustRules.AnyFact<TestFact>(
            _ => true,
            missingFactMessage: "missing",
            predicateFailedMessage: "predicate failed",
            onEmpty: OnEmptyBehavior.Deny);

        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Has.Member("missing"));
    }

    [Test]
    public async Task AnyFact_WhenPredicateMatches_IsTrusted()
    {
        var fact = new TestFact("ok");
        var producer = new FixedFactProducer(fact);
        var (_, context, _, _) = CreateContext(producer);

        var rule = TrustRules.AnyFact<TestFact>(
            f => f.Value == "ok",
            missingFactMessage: "missing",
            predicateFailedMessage: "no match",
            onEmpty: OnEmptyBehavior.Deny);

        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public async Task AnyFact_WhenPredicateNoMatch_DeniesWithPredicateFailedMessage()
    {
        var fact = new TestFact("value");
        var producer = new FixedFactProducer(fact);
        var (_, context, _, _) = CreateContext(producer);

        var rule = TrustRules.AnyFact<TestFact>(
            f => f.Value == "different",
            missingFactMessage: "missing",
            predicateFailedMessage: "no match",
            onEmpty: OnEmptyBehavior.Deny);

        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Has.Member("no match"));
    }

    [Test]
    public async Task OnDerivedSubject_WhenWrongKind_Denies()
    {
        var (_, context, _, _) = CreateContext();

        var rule = TrustRules.OnDerivedSubject(
            expectedSubjectKind: TrustSubjectKind.Message,
            deriveSubject: _ => throw new InvalidOperationException("Should not be called"),
            inner: TrustRules.AllowAll());

        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.Not.Empty);
    }

    [Test]
    public async Task OnDerivedSubject_WhenKindMatches_EvaluatesInnerOnDerivedSubject()
    {
        var (_, context, _, _) = CreateContext();

        var rule = TrustRules.OnDerivedSubject(
            expectedSubjectKind: TrustSubjectKind.CounterSignature,
            deriveSubject: ctx => TrustSubject.PrimarySigningKey(ctx.Subject.ParentId!.Value),
            inner: new InspectSubjectRule(ctx => Assert.That(ctx.Subject.Kind, Is.EqualTo(TrustSubjectKind.PrimarySigningKey))));

        var decision = await rule.EvaluateAsync(context);

        Assert.That(decision.IsTrusted, Is.True);
    }
}

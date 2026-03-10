// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;


public sealed class TrustDecisionAuditTests
{
    private sealed record TestFact(string Value);

    private sealed class FactProducer : IMultiTrustFactProducer
    {
        private readonly ITrustFactSet Set;

        public FactProducer(ITrustFactSet set)
        {
            Set = set;
        }

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            return new ValueTask<ITrustFactSet>(Set);
        }
    }

    [Test]
    public async Task EvaluateWithAuditAsync_EmitsSchemaVersionAndTrace()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        var subject = TrustSubject.CounterSignature(messageId, new byte[] { 0x02, 0x03 });

        var producer = new FactProducer(TrustFactSet<TestFact>.Available(new TestFact("x")));

        var plan = new CompiledTrustPlan(
            TrustRules.And(
                TrustRules.AllowAll(),
                TrustRules.AnyFact<TestFact>(
                    f => f.Value == "x",
                    missingFactMessage: "missing",
                    predicateFailedMessage: "no match",
                    onEmpty: OnEmptyBehavior.Deny)),
            new[] { producer });

        var result = await plan.EvaluateWithAuditAsync(messageId, subject);

        Assert.That(result.Decision.IsTrusted, Is.True);
        Assert.That(result.Audit.SchemaVersion, Is.EqualTo(TrustDecisionAudit.AuditSchemaVersion));
        Assert.That(result.Audit.MessageId, Is.EqualTo(messageId));
        Assert.That(result.Audit.Subject.Id, Is.EqualTo(subject.Id));

        Assert.That(result.Audit.RuleEvaluations, Is.Not.Empty);
        Assert.That(result.Audit.Facts, Is.Not.Empty);

        var fact = result.Audit.Facts.Single(f => f.FactType.Contains(nameof(TestFact), StringComparison.Ordinal));
        Assert.That(fact.SubjectId, Is.EqualTo(subject.Id));
        Assert.That(fact.IsMissing, Is.False);
        Assert.That(fact.ValueCount, Is.EqualTo(1));
        Assert.That(fact.MissingReason, Is.Null);
    }

    [Test]
    public async Task EvaluateWithAuditAsync_WhenFactMissing_RecordsMissingReason()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x09 });
        var subject = TrustSubject.CounterSignature(messageId, new byte[] { 0x10 });

        var producer = new FactProducer(TrustFactSet<TestFact>.Missing("CODE", "msg"));

        var plan = new CompiledTrustPlan(
            TrustRules.AnyFact<TestFact>(
                _ => true,
                missingFactMessage: "missing",
                predicateFailedMessage: "failed",
                onEmpty: OnEmptyBehavior.Deny),
            new[] { producer });

        var result = await plan.EvaluateWithAuditAsync(messageId, subject);

        Assert.That(result.Decision.IsTrusted, Is.False);

        var fact = result.Audit.Facts.Single();
        Assert.That(fact.IsMissing, Is.True);
        Assert.That(fact.MissingReason, Is.Not.Null);
        Assert.That(fact.MissingReason!.Code, Is.EqualTo("CODE"));
    }

    [Test]
    public void TrustDecisionAuditBuilder_RejectsNullInputs()
    {
        var builder = new TrustDecisionAuditBuilder();

        Assert.That(
            () => builder.RecordRule(null!, TrustDecision.Trusted(), detail: null),
            Throws.TypeOf<ArgumentNullException>());

        Assert.That(
            () => builder.RecordRule("x", null!, detail: null),
            Throws.TypeOf<ArgumentNullException>());

        Assert.That(
            () => builder.RecordFact(default, null!, TrustFactSet<TestFact>.Available()),
            Throws.TypeOf<ArgumentNullException>());

        Assert.That(
            () => builder.RecordFact(default, typeof(TestFact), null!),
            Throws.TypeOf<ArgumentNullException>());
    }

    [Test]
    public void EvaluateWithAudit_SynchronousWrapper_Works()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x0A });
        var subject = TrustSubject.CounterSignature(messageId, new byte[] { 0x0B });

        var plan = new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());
        var result = plan.EvaluateWithAudit(messageId, subject);

        Assert.That(result.Decision.IsTrusted, Is.True);
        Assert.That(result.Audit.SchemaVersion, Is.EqualTo(TrustDecisionAudit.AuditSchemaVersion));
    }
}

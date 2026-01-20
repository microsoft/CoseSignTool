// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;

public sealed class TrustPlanTests
{
    private sealed record TestFact(string Value);

    private sealed class CountingProducer : IMultiTrustFactProducer
    {
        private int CallCountValue;

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public int CallCount => CallCountValue;

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCountValue);
            return ValueTask.FromResult<ITrustFactSet>(TrustFactSet<TestFact>.Available(new TestFact("x")));
        }
    }

    private sealed class EmptyProducer : IMultiTrustFactProducer
    {
        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult<ITrustFactSet>(TrustFactSet<TestFact>.Available());
        }
    }

    private sealed class TestPack : ITrustPack
    {
        private readonly TrustPlanDefaults Defaults;
        private readonly IMultiTrustFactProducer Producer;

        public TestPack(TrustPlanDefaults defaults)
        {
            Defaults = defaults;
            Producer = new NoopProducer();
        }

        public TestPack(TrustPlanDefaults defaults, IMultiTrustFactProducer producer)
        {
            Defaults = defaults;
            Producer = producer ?? throw new ArgumentNullException(nameof(producer));
        }

        public IReadOnlyCollection<Type> FactTypes => Producer.FactTypes;

        public CoseSign1.Validation.Interfaces.ISigningKeyResolver? SigningKeyResolver => null;

        public TrustPlanDefaults GetDefaults() => Defaults;

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            return Producer.ProduceAsync(context, factType, cancellationToken);
        }

        private sealed class NoopProducer : IMultiTrustFactProducer
        {
            public IReadOnlyCollection<Type> FactTypes => Array.Empty<Type>();

            public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<object>.Missing(TrustFactMissingCodes.NoProducers, "No facts"));
            }
        }
    }

    private sealed class TestServiceProvider : IServiceProvider
    {
        private readonly Dictionary<Type, object> Services = new();

        public TestServiceProvider Add(Type type, object instance)
        {
            Services[type] = instance;
            return this;
        }

        public object? GetService(Type serviceType)
        {
            Services.TryGetValue(serviceType, out var value);
            return value;
        }
    }

    private static TrustSubject CreateSubject()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 1, 2, 3, 4 });
        return TrustSubject.CounterSignature(messageId, new byte[] { 9, 9, 9 });
    }

    [Test]
    public async Task Or_ShortCircuits_AndAvoidsFactProduction()
    {
        var producer = new CountingProducer();

        var plan = new CompiledTrustPlan(
            TrustRules.Or(
                TrustRules.AllowAll(),
                TrustRules.AnyFact<TestFact>(
                    f => f.Value == "x",
                    missingFactMessage: "missing",
                    predicateFailedMessage: "no match",
                    onEmpty: OnEmptyBehavior.Deny)),
            new[] { producer });

        var decision = await plan.EvaluateAsync(
            messageId: TrustSubjectId.FromSha256OfBytes(new byte[] { 0xAA }),
            subject: CreateSubject());

        Assert.That(decision.IsTrusted, Is.True);
        Assert.That(producer.CallCount, Is.EqualTo(0));
    }

    [Test]
    public void Evaluate_SynchronousWrapper_Works()
    {
        var plan = new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());

        var decision = plan.Evaluate(
            messageId: TrustSubjectId.FromSha256OfBytes(new byte[] { 0xAB }),
            subject: CreateSubject());

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public async Task EvaluateAsync_WithMessageOverload_Works()
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var message = CoseMessage.DecodeSign1(CoseSign1Message.SignEmbedded("payload"u8.ToArray(), signer));

        var subject = TrustSubject.Message(message);
        var plan = new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());

        var decision = await plan.EvaluateAsync(subject.Id, message, subject);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Evaluate_WithMessageOverload_Works()
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var message = CoseMessage.DecodeSign1(CoseSign1Message.SignEmbedded("payload"u8.ToArray(), signer));

        var subject = TrustSubject.Message(message);
        var plan = new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());

        var decision = plan.Evaluate(subject.Id, message, subject);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public async Task EvaluateWithAuditAsync_WithMessageOverload_Works()
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var message = CoseMessage.DecodeSign1(CoseSign1Message.SignEmbedded("payload"u8.ToArray(), signer));

        var subject = TrustSubject.Message(message);
        var plan = new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());

        var result = await plan.EvaluateWithAuditAsync(subject.Id, message, subject);

        Assert.That(result.Decision.IsTrusted, Is.True);
        Assert.That(result.Audit.MessageId, Is.EqualTo(subject.Id));
    }

    [Test]
    public void EvaluateWithAudit_WithMessageOverload_Works()
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var message = CoseMessage.DecodeSign1(CoseSign1Message.SignEmbedded("payload"u8.ToArray(), signer));

        var subject = TrustSubject.Message(message);
        var plan = new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());

        var result = plan.EvaluateWithAudit(subject.Id, message, subject);

        Assert.That(result.Decision.IsTrusted, Is.True);
        Assert.That(result.Audit.MessageId, Is.EqualTo(subject.Id));
    }

    [Test]
    public async Task AnyFact_OnEmpty_Allow_AllowsEmptyAvailableSet()
    {
        var plan = new CompiledTrustPlan(
            TrustRules.AnyFact<TestFact>(
                _ => true,
                missingFactMessage: "missing",
                predicateFailedMessage: "predicate failed",
                onEmpty: OnEmptyBehavior.Allow),
            new[] { new EmptyProducer() });

        var decision = await plan.EvaluateAsync(
            messageId: TrustSubjectId.FromSha256OfBytes(new byte[] { 0xBB }),
            subject: CreateSubject());

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public async Task AnyFact_OnEmpty_Deny_DeniesEmptyAvailableSet()
    {
        var plan = new CompiledTrustPlan(
            TrustRules.AnyFact<TestFact>(
                _ => true,
                missingFactMessage: "missing",
                predicateFailedMessage: "predicate failed",
                onEmpty: OnEmptyBehavior.Deny,
                onEmptyMessage: "empty"),
            new[] { new EmptyProducer() });

        var decision = await plan.EvaluateAsync(
            messageId: TrustSubjectId.FromSha256OfBytes(new byte[] { 0xCC }),
            subject: CreateSubject());

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Has.Member("empty"));
    }

    [Test]
    public async Task CompileDefaults_ComposesConstraintsSourcesAndVetoes()
    {
        var defaults = new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[] { TrustRules.AllowAll() },
            vetoes: TrustRules.AllowAll());

        var sp = new TestServiceProvider()
            .Add(typeof(IEnumerable<ITrustPack>), new[] { new TestPack(defaults) });

        var plan = CompiledTrustPlan.CompileDefaults(sp);

        var decision = await plan.EvaluateAsync(
            messageId: TrustSubjectId.FromSha256OfBytes(new byte[] { 0xDD }),
            subject: CreateSubject());

        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public async Task CompileDefaults_WhenMultiplePacks_ComposesAllDefaults()
    {
        var pack1 = new TestPack(new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[] { TrustRules.AllowAll() },
            vetoes: TrustRules.DenyAll("veto1")));

        var pack2 = new TestPack(new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[] { TrustRules.DenyAll("deny2"), TrustRules.AllowAll() },
            vetoes: TrustRules.DenyAll("veto2")));

        var sp = new TestServiceProvider()
            .Add(typeof(IEnumerable<ITrustPack>), new[] { pack1, pack2 });

        var plan = CompiledTrustPlan.CompileDefaults(sp);

        var decision = await plan.EvaluateAsync(
            messageId: TrustSubjectId.FromSha256OfBytes(new byte[] { 0xDE, 0xAD }),
            subject: CreateSubject());

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public async Task CompileDefaults_WiresRegisteredProducers()
    {
        var producer = new CountingProducer();

        var defaults = new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[]
            {
                TrustRules.AnyFact<TestFact>(
                    f => f.Value == "x",
                    missingFactMessage: "missing",
                    predicateFailedMessage: "no match",
                    onEmpty: OnEmptyBehavior.Deny)
            },
            vetoes: TrustRules.DenyAll("no veto"));

        var sp = new TestServiceProvider()
            .Add(typeof(IEnumerable<ITrustPack>), new[] { new TestPack(defaults, producer) });

        var plan = CompiledTrustPlan.CompileDefaults(sp);

        var decision = await plan.EvaluateAsync(
            messageId: TrustSubjectId.FromSha256OfBytes(new byte[] { 0xEE }),
            subject: CreateSubject());

        Assert.That(decision.IsTrusted, Is.True);
        Assert.That(producer.CallCount, Is.EqualTo(1));
    }

    [Test]
    public void CompileDefaults_WhenMissingProvider_Throws()
    {
        var sp = new TestServiceProvider();
        Assert.That(() => CompiledTrustPlan.CompileDefaults(sp), Throws.InvalidOperationException);
    }

    [Test]
    public void CompileDefaults_WhenServicesNull_ThrowsArgumentNullException()
    {
        Assert.That(() => CompiledTrustPlan.CompileDefaults(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void EvaluateAsync_WithMessageOverload_WhenMessageNull_ThrowsArgumentNullException()
    {
        var plan = new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());
        var subject = TrustSubject.Message(TrustSubjectId.FromSha256OfBytes(new byte[] { 0x11 }));

        Assert.That(
            async () => await plan.EvaluateAsync(subject.Id, message: null!, subject),
            Throws.ArgumentNullException);
    }

    [Test]
    public void EvaluateWithAuditAsync_WithMessageOverload_WhenMessageNull_ThrowsArgumentNullException()
    {
        var plan = new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());
        var subject = TrustSubject.Message(TrustSubjectId.FromSha256OfBytes(new byte[] { 0x12 }));

        Assert.That(
            async () => await plan.EvaluateWithAuditAsync(subject.Id, message: null!, subject),
            Throws.ArgumentNullException);
    }
}

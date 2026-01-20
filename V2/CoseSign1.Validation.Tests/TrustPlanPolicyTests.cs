// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Tests for <see cref="TrustPlanPolicy"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class TrustPlanPolicyTests
{
    private sealed class TestFact : ISigningKeyFact
    {
        public TestFact(bool value)
        {
            Value = value;
        }

        public TrustFactScope Scope => TrustFactScope.SigningKey;

        public bool Value { get; }
    }

    private sealed class TestFactProducer : ITrustPack
    {
        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public CoseSign1.Validation.Interfaces.ISigningKeyResolver? SigningKeyResolver => null;

        public TrustPlanDefaults GetDefaults()
        {
            return new TrustPlanDefaults(
                constraints: TrustRules.AllowAll(),
                trustSources: new[] { TrustRules.DenyAll("Test pack defaults") },
                vetoes: TrustRules.DenyAll("No vetoes"));
        }

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            if (context.Subject.Kind != TrustSubjectKind.PrimarySigningKey)
            {
                return new ValueTask<ITrustFactSet>(TrustFactSet<TestFact>.Available());
            }

            return new ValueTask<ITrustFactSet>(TrustFactSet<TestFact>.Available(new TestFact(true)));
        }
    }

    private sealed class CounterSignatureSubjectsProducer : ITrustPack
    {
        private readonly CounterSignatureSubjectFact[] Facts;

        public CounterSignatureSubjectsProducer(params CounterSignatureSubjectFact[] facts)
        {
            Facts = facts ?? throw new ArgumentNullException(nameof(facts));
        }

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(CounterSignatureSubjectFact) };

        public CoseSign1.Validation.Interfaces.ISigningKeyResolver? SigningKeyResolver => null;

        public TrustPlanDefaults GetDefaults()
        {
            return new TrustPlanDefaults(
                constraints: TrustRules.AllowAll(),
                trustSources: new[] { TrustRules.DenyAll("Test pack defaults") },
                vetoes: TrustRules.DenyAll("No vetoes"));
        }

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            if (context.Subject.Kind != TrustSubjectKind.Message)
            {
                return new ValueTask<ITrustFactSet>(TrustFactSet<CounterSignatureSubjectFact>.Available());
            }

            return new ValueTask<ITrustFactSet>(TrustFactSet<CounterSignatureSubjectFact>.Available(Facts));
        }
    }

    private sealed class MissingCounterSignatureSubjectsProducer : ITrustPack
    {
        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(CounterSignatureSubjectFact) };

        public CoseSign1.Validation.Interfaces.ISigningKeyResolver? SigningKeyResolver => null;

        public TrustPlanDefaults GetDefaults()
        {
            return new TrustPlanDefaults(
                constraints: TrustRules.AllowAll(),
                trustSources: new[] { TrustRules.DenyAll("Test pack defaults") },
                vetoes: TrustRules.DenyAll("No vetoes"));
        }

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<CounterSignatureSubjectFact>.Missing(
                    TrustFactMissingCodes.NoProducers,
                    "Counter-signature discovery not available"));
        }
    }

    private sealed class CounterSignatureAndSigningKeyFactsProducer : ITrustPack
    {
        private readonly CounterSignatureSubjectFact[] CounterSignatureFacts;
        private readonly bool SigningKeyFactValue;

        public CounterSignatureAndSigningKeyFactsProducer(bool signingKeyFactValue, params CounterSignatureSubjectFact[] counterSignatureFacts)
        {
            CounterSignatureFacts = counterSignatureFacts ?? throw new ArgumentNullException(nameof(counterSignatureFacts));
            SigningKeyFactValue = signingKeyFactValue;
        }

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(CounterSignatureSubjectFact), typeof(TestFact) };

        public CoseSign1.Validation.Interfaces.ISigningKeyResolver? SigningKeyResolver => null;

        public TrustPlanDefaults GetDefaults()
        {
            return new TrustPlanDefaults(
                constraints: TrustRules.AllowAll(),
                trustSources: new[] { TrustRules.DenyAll("Test pack defaults") },
                vetoes: TrustRules.DenyAll("No vetoes"));
        }

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            if (factType == typeof(CounterSignatureSubjectFact))
            {
                if (context.Subject.Kind != TrustSubjectKind.Message)
                {
                    return new ValueTask<ITrustFactSet>(TrustFactSet<CounterSignatureSubjectFact>.Available());
                }

                return new ValueTask<ITrustFactSet>(TrustFactSet<CounterSignatureSubjectFact>.Available(CounterSignatureFacts));
            }

            if (factType == typeof(TestFact))
            {
                if (context.Subject.Kind != TrustSubjectKind.CounterSignatureSigningKey)
                {
                    return new ValueTask<ITrustFactSet>(TrustFactSet<TestFact>.Available());
                }

                return new ValueTask<ITrustFactSet>(TrustFactSet<TestFact>.Available(new TestFact(SigningKeyFactValue)));
            }

            return new ValueTask<ITrustFactSet>(
                TrustFactSet<object>.Missing(TrustFactMissingCodes.NoProducers, "Unsupported fact type"));
        }
    }

    [Test]
    public void PrimarySigningKey_RequirementSatisfied_Trusts()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack, TestFactProducer>();
        var sp = services.BuildServiceProvider();

        var policy = TrustPlanPolicy.PrimarySigningKey(k => k
            .RequireFact<TestFact>(f => f.Value, "Expected test fact to be true"));

        var plan = policy.Compile(sp);

        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        TrustSubject message = TrustSubject.Message(messageId);

        var decision = plan.Evaluate(messageId, message);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void AnyCounterSignature_OnEmptyDeny_Denies()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new CounterSignatureSubjectsProducer());
        var sp = services.BuildServiceProvider();

        var policy = TrustPlanPolicy.AnyCounterSignature(cs => cs
            .OnEmpty(OnEmptyBehavior.Deny));

        var plan = policy.Compile(sp);

        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x02 });
        TrustSubject message = TrustSubject.Message(messageId);

        var decision = plan.Evaluate(messageId, message);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.Not.Empty);
    }

    [Test]
    public void Or_PrimaryDenied_CounterSignatureAllows_Trusts()
    {
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x03 });
        var cs = TrustSubject.CounterSignature(messageId, new byte[] { 0xAA });

        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new CounterSignatureSubjectsProducer(
            new CounterSignatureSubjectFact(cs, isProtectedHeader: true)));
        var sp = services.BuildServiceProvider();

        var primary = TrustPlanPolicy.PrimarySigningKey(k => k
            .RequireFact<TestFact>(f => f.Value, "Primary signing key must satisfy test fact"));

        var anyCounterSignature = TrustPlanPolicy.AnyCounterSignature(csBuilder => csBuilder
            .OnEmpty(OnEmptyBehavior.Deny));

        var policy = primary.Or(anyCounterSignature);
        var plan = policy.Compile(sp);

        TrustSubject message = TrustSubject.Message(messageId);
        var decision = plan.Evaluate(messageId, message);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void PrimarySigningKey_WrongSubjectKind_Denies()
    {
        var sp = new ServiceCollection().BuildServiceProvider();

        var policy = TrustPlanPolicy.PrimarySigningKey(k => k);
        var plan = policy.Compile(sp);

        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x10 });
        var subject = TrustSubject.PrimarySigningKey(messageId);

        var result = plan.EvaluateWithAudit(messageId, subject);

        Assert.That(result.Decision.IsTrusted, Is.False);
        Assert.That(result.Decision.Reasons, Has.Member("Rule was evaluated on an unexpected subject kind"));
    }

    [Test]
    public void AnyCounterSignature_WrongSubjectKind_Denies()
    {
        var sp = new ServiceCollection().BuildServiceProvider();

        var policy = TrustPlanPolicy.AnyCounterSignature(cs => cs);
        var plan = policy.Compile(sp);

        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x11 });
        var subject = TrustSubject.PrimarySigningKey(messageId);

        var result = plan.EvaluateWithAudit(messageId, subject);

        Assert.That(result.Decision.IsTrusted, Is.False);
        Assert.That(result.Decision.Reasons, Has.Member("Rule was evaluated on an unexpected subject kind"));
    }

    [Test]
    public void AnyCounterSignature_MissingFacts_DeniesWithMissingCounterSignaturesReason()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack, MissingCounterSignatureSubjectsProducer>();
        var sp = services.BuildServiceProvider();

        var policy = TrustPlanPolicy.AnyCounterSignature(cs => cs);
        var plan = policy.Compile(sp);

        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x12 });
        TrustSubject message = TrustSubject.Message(messageId);

        var result = plan.EvaluateWithAudit(messageId, message);

        Assert.That(result.Decision.IsTrusted, Is.False);
        Assert.That(result.Decision.Reasons, Has.Member("Counter-signatures could not be discovered"));
    }

    [Test]
    public void AnyCounterSignature_OnEmptyAllow_Trusts()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new CounterSignatureSubjectsProducer());
        var sp = services.BuildServiceProvider();

        var policy = TrustPlanPolicy.AnyCounterSignature(cs => cs.OnEmpty(OnEmptyBehavior.Allow));
        var plan = policy.Compile(sp);

        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x13 });
        TrustSubject message = TrustSubject.Message(messageId);

        var result = plan.EvaluateWithAudit(messageId, message);

        Assert.That(result.Decision.IsTrusted, Is.True);
    }

    [Test]
    public void AnyCounterSignature_AllDenied_AggregatesReasons()
    {
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x14 });
        var cs1 = TrustSubject.CounterSignature(messageId, new byte[] { 0x01 });
        var cs2 = TrustSubject.CounterSignature(messageId, new byte[] { 0x02 });

        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new CounterSignatureAndSigningKeyFactsProducer(
            signingKeyFactValue: true,
            new CounterSignatureSubjectFact(cs1, isProtectedHeader: true),
            new CounterSignatureSubjectFact(cs2, isProtectedHeader: false)));
        var sp = services.BuildServiceProvider();

        const string DeniedMessage = "Signing key requirement denied";

        var policy = TrustPlanPolicy.AnyCounterSignature(cs => cs
            .SigningKey(k => k.RequireFact<TestFact>(_ => false, DeniedMessage)));

        var plan = policy.Compile(sp);

        TrustSubject message = TrustSubject.Message(messageId);
        var result = plan.EvaluateWithAudit(messageId, message);

        Assert.That(result.Decision.IsTrusted, Is.False);
        Assert.That(result.Decision.Reasons, Has.Member(DeniedMessage));
    }

    [Test]
    public void PrimarySigningKey_WithTwoRequirements_BuildsAndRule()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack, TestFactProducer>();
        var sp = services.BuildServiceProvider();

        const string DeniedMessage = "Expected test fact to be false";

        var policy = TrustPlanPolicy.PrimarySigningKey(k => k
            .RequireFact<TestFact>(f => f.Value, "Expected test fact to be true")
            .RequireFact<TestFact>(f => !f.Value, DeniedMessage));

        var plan = policy.Compile(sp);

        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x15 });
        TrustSubject message = TrustSubject.Message(messageId);

        var result = plan.EvaluateWithAudit(messageId, message);

        Assert.That(result.Decision.IsTrusted, Is.False);
        Assert.That(result.Decision.Reasons, Has.Member(DeniedMessage));
    }

    [Test]
    public void Message_NullConfigure_ThrowsArgumentNullException()
    {
        Assert.That(() => _ = TrustPlanPolicy.Message(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void PrimarySigningKey_NullConfigure_ThrowsArgumentNullException()
    {
        Assert.That(() => _ = TrustPlanPolicy.PrimarySigningKey(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void AnyCounterSignature_NullConfigure_ThrowsArgumentNullException()
    {
        Assert.That(() => _ = TrustPlanPolicy.AnyCounterSignature(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Implies_NullPolicies_ThrowArgumentNullException()
    {
        var policy = TrustPlanPolicy.Message(m => m);

        Assert.Multiple(() =>
        {
            Assert.That(() => _ = TrustPlanPolicy.Implies(null!, policy), Throws.ArgumentNullException);
            Assert.That(() => _ = TrustPlanPolicy.Implies(policy, null!), Throws.ArgumentNullException);
        });
    }

    [Test]
    public void OrAnd_NullOther_ThrowArgumentNullException()
    {
        var policy = TrustPlanPolicy.Message(m => m);

        Assert.Multiple(() =>
        {
            Assert.That(() => _ = policy.Or(null!), Throws.ArgumentNullException);
            Assert.That(() => _ = policy.And(null!), Throws.ArgumentNullException);
        });
    }

    [Test]
    public void Compile_NullServices_ThrowsArgumentNullException()
    {
        var policy = TrustPlanPolicy.Message(m => m);
        Assert.That(() => _ = policy.Compile(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void RequireFact_NullPredicate_ThrowsArgumentNullException()
    {
        Assert.That(
            () => _ = TrustPlanPolicy.PrimarySigningKey(k => k.RequireFact<TestFact>(null!, "m")),
            Throws.ArgumentNullException);
    }

    [Test]
    public void RequireFact_NullMessage_ThrowsArgumentNullException()
    {
        Assert.That(
            () => _ = TrustPlanPolicy.PrimarySigningKey(k => k.RequireFact<TestFact>(_ => true, null!)),
            Throws.ArgumentNullException);
    }

    [Test]
    public void CounterSignatureSigningKey_NullConfigure_ThrowsArgumentNullException()
    {
        Assert.That(
            () => _ = TrustPlanPolicy.AnyCounterSignature(cs => cs.SigningKey(null!)),
            Throws.ArgumentNullException);
    }
}

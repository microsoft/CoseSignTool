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
/// Ensures the fluent policy shapes shown in proposal.md compile and evaluate.
/// </summary>
[TestFixture]
[Category("Validation")]
public sealed class TrustPlanPolicyProposalShapesTests
{
    private sealed record DetachedPayloadPresentFact(bool Present) : IMessageFact
    {
        public TrustFactScope Scope => TrustFactScope.Message;
    }

    private sealed record ContentTypeFact(string ContentType) : IMessageFact
    {
        public TrustFactScope Scope => TrustFactScope.Message;
    }

    private sealed record X509ChainTrustedFact(bool IsTrusted) : ISigningKeyFact
    {
        public TrustFactScope Scope => TrustFactScope.SigningKey;
    }

    private sealed record MstReceiptTrustedFact(bool IsTrusted) : ICounterSignatureFact
    {
        public TrustFactScope Scope => TrustFactScope.CounterSignature;
    }

    private sealed class ProposalShapesFactProducer : ITrustPack
    {
        public Type FactType { get; }

        public IReadOnlyCollection<Type> FactTypes => new[] { FactType };

        public ProposalShapesFactProducer(Type factType)
        {
            FactType = factType ?? throw new ArgumentNullException(nameof(factType));
        }

        public TrustPlanDefaults GetDefaults()
        {
            return new TrustPlanDefaults(
                constraints: TrustRules.AllowAll(),
                trustSources: new[] { TrustRules.DenyAll("Test pack defaults") },
                vetoes: TrustRules.DenyAll("No vetoes"));
        }

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            if (factType != FactType)
            {
                throw new InvalidOperationException($"Unexpected fact type: {factType}");
            }

            if (FactType == typeof(DetachedPayloadPresentFact))
            {
                return context.Subject.Kind == TrustSubjectKind.Message
                    ? new ValueTask<ITrustFactSet>(TrustFactSet<DetachedPayloadPresentFact>.Available(new DetachedPayloadPresentFact(Present: false)))
                    : new ValueTask<ITrustFactSet>(TrustFactSet<DetachedPayloadPresentFact>.Available());
            }

            if (FactType == typeof(ContentTypeFact))
            {
                return context.Subject.Kind == TrustSubjectKind.Message
                    ? new ValueTask<ITrustFactSet>(TrustFactSet<ContentTypeFact>.Available(new ContentTypeFact(ContentType: "application/cose")))
                    : new ValueTask<ITrustFactSet>(TrustFactSet<ContentTypeFact>.Available());
            }

            if (FactType == typeof(X509ChainTrustedFact))
            {
                return context.Subject.Kind == TrustSubjectKind.PrimarySigningKey
                    ? new ValueTask<ITrustFactSet>(TrustFactSet<X509ChainTrustedFact>.Available(new X509ChainTrustedFact(IsTrusted: true)))
                    : new ValueTask<ITrustFactSet>(TrustFactSet<X509ChainTrustedFact>.Available());
            }

            if (FactType == typeof(MstReceiptTrustedFact))
            {
                return context.Subject.Kind == TrustSubjectKind.CounterSignature
                    ? new ValueTask<ITrustFactSet>(TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: true)))
                    : new ValueTask<ITrustFactSet>(TrustFactSet<MstReceiptTrustedFact>.Available());
            }

            throw new InvalidOperationException($"Unexpected fact type: {FactType}");
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

        public TrustPlanDefaults GetDefaults()
        {
            return new TrustPlanDefaults(
                constraints: TrustRules.AllowAll(),
                trustSources: new[] { TrustRules.DenyAll("Test pack defaults") },
                vetoes: TrustRules.DenyAll("No vetoes"));
        }

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            return context.Subject.Kind == TrustSubjectKind.Message
                ? new ValueTask<ITrustFactSet>(TrustFactSet<CounterSignatureSubjectFact>.Available(Facts))
                : new ValueTask<ITrustFactSet>(TrustFactSet<CounterSignatureSubjectFact>.Available());
        }
    }

    [Test]
    public void ProposalShape_MessageAndPrimarySigningKey_Trusts()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new ProposalShapesFactProducer(typeof(DetachedPayloadPresentFact)));
        services.AddSingleton<ITrustPack>(_ => new ProposalShapesFactProducer(typeof(ContentTypeFact)));
        services.AddSingleton<ITrustPack>(_ => new ProposalShapesFactProducer(typeof(X509ChainTrustedFact)));
        var sp = services.BuildServiceProvider();

        var policy =
            TrustPlanPolicy.Message(m => m
                .RequireFact<DetachedPayloadPresentFact>(f => !f.Present, "Detached payload not allowed")
                .RequireFact<ContentTypeFact>(f => f.ContentType == "application/cose", "Unexpected content type"))
            .And(
                TrustPlanPolicy.PrimarySigningKey(k => k
                    .RequireFact<X509ChainTrustedFact>(f => f.IsTrusted, "Primary cert chain must be trusted")));

        var plan = policy.Compile(sp);

        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x77 });
        TrustSubject message = TrustSubject.Message(messageId);

        var decision = plan.Evaluate(messageId, message);
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void ProposalShape_Implies_MessageConstraintRequiresCounterSignature_Trusts()
    {
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x88 });
        var cs = TrustSubject.CounterSignature(messageId, new byte[] { 0xAA });

        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new ProposalShapesFactProducer(typeof(ContentTypeFact)));
        services.AddSingleton<ITrustPack>(_ => new ProposalShapesFactProducer(typeof(MstReceiptTrustedFact)));
        services.AddSingleton<ITrustPack>(_ => new CounterSignatureSubjectsProducer(
            new CounterSignatureSubjectFact(cs, isProtectedHeader: true)));
        var sp = services.BuildServiceProvider();

        var policy2 = TrustPlanPolicy.Implies(
            TrustPlanPolicy.Message(m => m.RequireFact<ContentTypeFact>(
                f => f.ContentType == "application/cose",
                "Unexpected content type")),
            TrustPlanPolicy.AnyCounterSignature(csBuilder => csBuilder
                .OnEmpty(OnEmptyBehavior.Deny)
                .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt required for this content type")));

        var plan = policy2.Compile(sp);

        TrustSubject message = TrustSubject.Message(messageId);
        var decision = plan.Evaluate(messageId, message);

        Assert.That(decision.IsTrusted, Is.True);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Parameters;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Rules;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Compile spec → TrustPlanPolicy and assert evaluation matches an equivalent fluent-built plan.
/// Mirrors the existing TrustPlanPolicyTests style.
/// </summary>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class TrustPolicySpecCompilerTests
{
    private static IServiceProvider BuildServices(params ITrustPack[] packs)
    {
        var services = new ServiceCollection();
        foreach (var pack in packs)
        {
            services.AddSingleton(pack);
        }

        return services.BuildServiceProvider();
    }

    private static IFactRegistry Registry => TestFactRegistry.Build();

    [Test]
    public void Scenario1_PrimarySigningKey_PropertyAssertion_TrustsWhenFactSatisfies()
    {
        // Spec form
        var spec = new PrimarySigningKeyRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestSigningKey,
            new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
            {
                ["is_trusted"] = JsonValue.Create(true),
            }),
            "Signing key must be trusted"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);

        // Fluent equivalent
        TrustPlanPolicy fluent = TrustPlanPolicy.PrimarySigningKey(b => b.RequireFact<TestSigningKeyFact>(
            f => f.IsTrusted,
            "Signing key must be trusted"));

        var packs = new ITrustPack[] { new FixedFactProducer<TestSigningKeyFact>(TrustSubjectKind.PrimarySigningKey, new TestSigningKeyFact(true, "CN=Test")) };
        AssertSameDecision(policy, fluent, packs, trusted: true);
    }

    [Test]
    public void Scenario2_PrimarySigningKey_PropertyAssertionFails_DeniesWithMessage()
    {
        var spec = new PrimarySigningKeyRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestSigningKey,
            new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
            {
                ["is_trusted"] = JsonValue.Create(true),
            }),
            "Signing key must be trusted"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var packs = new ITrustPack[] { new FixedFactProducer<TestSigningKeyFact>(TrustSubjectKind.PrimarySigningKey, new TestSigningKeyFact(false, "CN=Untrusted")) };
        var sp = BuildServices(packs);
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        TrustSubject message = TrustSubject.Message(messageId);
        var decision = compiled.Evaluate(messageId, message);
        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Has.Member("Signing key must be trusted"));
    }

    [Test]
    public void Scenario3_AnyCounterSignature_OnEmptyDeny_Denies()
    {
        var spec = new AnyCounterSignatureRequirementSpec(new AllowAllSpec(), OnEmptyBehavior.Deny);
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);

        TrustPlanPolicy fluent = TrustPlanPolicy.AnyCounterSignature(b => b.OnEmpty(OnEmptyBehavior.Deny));

        var packs = new ITrustPack[] { new FixedFactProducer<CoseSign1.Validation.Trust.Facts.CounterSignatureSubjectFact>(TrustSubjectKind.Message) };
        AssertSameDecision(policy, fluent, packs, trusted: false);
    }

    [Test]
    public void Scenario4_OrComposition_FirstDenies_SecondAllows_Trusts()
    {
        var spec = new OrSpec(new TrustPolicySpec[]
        {
            new PrimarySigningKeyRequirementSpec(new RequireFactSpec(
                TestFactRegistry.TestSigningKey,
                new PathOperatorPredicateSpec("$.is_trusted", PredicateOperator.Equals, JsonValue.Create(true)),
                "deny")),
            new AnyCounterSignatureRequirementSpec(new AllowAllSpec(), OnEmptyBehavior.Allow),
        });

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);

        var packs = new ITrustPack[]
        {
            new FixedFactProducer<TestSigningKeyFact>(TrustSubjectKind.PrimarySigningKey, new TestSigningKeyFact(false, "CN=No")),
            new FixedFactProducer<CoseSign1.Validation.Trust.Facts.CounterSignatureSubjectFact>(TrustSubjectKind.Message),
        };

        var sp = BuildServices(packs);
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x02 });
        TrustSubject message = TrustSubject.Message(messageId);
        var decision = compiled.Evaluate(messageId, message);
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Scenario5_PathOperatorAndPropertyAssertion_ProduceFunctionallyEquivalentRules()
    {
        // Same logical predicate, two forms.
        var pathForm = new PathOperatorPredicateSpec("$.is_trusted", PredicateOperator.Equals, JsonValue.Create(true));
        var propForm = new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
        {
            ["is_trusted"] = JsonValue.Create(true),
        });

        var pathSpec = new PrimarySigningKeyRequirementSpec(new RequireFactSpec(TestFactRegistry.TestSigningKey, pathForm, "must be trusted"));
        var propSpec = new PrimarySigningKeyRequirementSpec(new RequireFactSpec(TestFactRegistry.TestSigningKey, propForm, "must be trusted"));

        TrustPlanPolicy fromPath = TrustPolicySpecCompiler.Compile(pathSpec, Registry);
        TrustPlanPolicy fromProp = TrustPolicySpecCompiler.Compile(propSpec, Registry);

        var packsTrue = new ITrustPack[] { new FixedFactProducer<TestSigningKeyFact>(TrustSubjectKind.PrimarySigningKey, new TestSigningKeyFact(true, "CN=A")) };
        AssertSameDecision(fromPath, fromProp, packsTrue, trusted: true);

        var packsFalse = new ITrustPack[] { new FixedFactProducer<TestSigningKeyFact>(TrustSubjectKind.PrimarySigningKey, new TestSigningKeyFact(false, "CN=A")) };
        AssertSameDecision(fromPath, fromProp, packsFalse, trusted: false);
    }

    [Test]
    public void Compile_UnknownFactId_Throws_TPX200()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            "totally-bogus/v1",
            new PathOperatorPredicateSpec("$", PredicateOperator.Exists, null),
            "fail"));

        var ex = Assert.Throws<TrustPolicySpecCompilationException>(() => TrustPolicySpecCompiler.Compile(spec, Registry));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.UnknownFactId));
        Assert.That(ex.Message, Does.Contain("totally-bogus/v1"));
    }

    [Test]
    public void Compile_UnknownProperty_Throws_TPX201()
    {
        var spec = new PrimarySigningKeyRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestSigningKey,
            new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
            {
                ["does_not_exist"] = JsonValue.Create(1),
            }),
            "fail"));

        var ex = Assert.Throws<TrustPolicySpecCompilationException>(() => TrustPolicySpecCompiler.Compile(spec, Registry));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.UnknownFactProperty));
    }

    [Test]
    public void Compile_FactScopeMismatch_Throws_TPX204()
    {
        // Put a signing-key fact under a Message scope.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestSigningKey,
            new PathOperatorPredicateSpec("$.is_trusted", PredicateOperator.Equals, JsonValue.Create(true)),
            "fail"));

        var ex = Assert.Throws<TrustPolicySpecCompilationException>(() => TrustPolicySpecCompiler.Compile(spec, Registry));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.FactScopeMismatch));
    }

    [Test]
    public void Compile_RequireFactOutsideRequirement_Throws_TPX204()
    {
        TrustPolicySpec spec = new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$", PredicateOperator.Exists, null),
            "fail");

        var ex = Assert.Throws<TrustPolicySpecCompilationException>(() => TrustPolicySpecCompiler.Compile(spec, Registry));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.FactScopeMismatch));
    }

    [Test]
    public void Compile_NestedRequirement_Throws_TPX204()
    {
        var spec = new MessageRequirementSpec(
            new MessageRequirementSpec(new AllowAllSpec()));

        var ex = Assert.Throws<TrustPolicySpecCompilationException>(() => TrustPolicySpecCompiler.Compile(spec, Registry));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.FactScopeMismatch));
    }

    [Test]
    public void Compile_NullSpec_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => TrustPolicySpecCompiler.Compile(null!, Registry));
    }

    [Test]
    public void Compile_NullRegistry_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => TrustPolicySpecCompiler.Compile(new AllowAllSpec(), null!));
    }

    [Test]
    public void Compile_AllowAll_AlwaysTrusts()
    {
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(new AllowAllSpec(), Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x09 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_DenyAll_AlwaysDenies()
    {
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(new DenyAllSpec("forbidden"), Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x0A });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Has.Member("forbidden"));
    }

    [Test]
    public void Compile_NotSpec_NegatesInner()
    {
        var spec = new NotSpec(new MessageRequirementSpec(new AllowAllSpec()), "negated");
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x0B });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void Compile_Implies_VacuouslyTrustedWhenAntecedentDenies()
    {
        var spec = new ImpliesSpec(
            new MessageRequirementSpec(new DenyAllSpec("ant")),
            new MessageRequirementSpec(new DenyAllSpec("cons")));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x0C });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_Implies_AntecedentTrusted_EvaluatesConsequent()
    {
        var spec = new ImpliesSpec(
            new MessageRequirementSpec(new AllowAllSpec()),
            new MessageRequirementSpec(new DenyAllSpec("must satisfy")));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x0D });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void Compile_EmptyAnd_TrustsVacuously()
    {
        var spec = new AndSpec(Array.Empty<TrustPolicySpec>());
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x0E });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_EmptyOr_Denies()
    {
        var spec = new OrSpec(Array.Empty<TrustPolicySpec>());
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x0F });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void Compile_AndScopedRequireFact_AndsRulesTogether()
    {
        var spec = new MessageRequirementSpec(new AndSpec(new TrustPolicySpec[]
        {
            new RequireFactSpec(TestFactRegistry.TestMessage, new PathOperatorPredicateSpec("$.detached", PredicateOperator.Equals, JsonValue.Create(true)), "must be detached"),
            new RequireFactSpec(TestFactRegistry.TestMessage, new PathOperatorPredicateSpec("$.payload_size", PredicateOperator.GreaterThanOrEqual, JsonValue.Create(0)), "must be non-negative"),
        }));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("application/json", 1024, true)));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x10 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_NotInsideScope_NegatesInnerRequireFact()
    {
        var spec = new MessageRequirementSpec(new NotSpec(
            new RequireFactSpec(TestFactRegistry.TestMessage, new PathOperatorPredicateSpec("$.detached", PredicateOperator.Equals, JsonValue.Create(true)), "fail"),
            "inverted"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("application/json", 1, false)));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x11 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_OrScopedRequireFact_DisjunctionInScope()
    {
        var spec = new MessageRequirementSpec(new OrSpec(new TrustPolicySpec[]
        {
            new RequireFactSpec(TestFactRegistry.TestMessage, new PathOperatorPredicateSpec("$.detached", PredicateOperator.Equals, JsonValue.Create(true)), "fail-1"),
            new RequireFactSpec(TestFactRegistry.TestMessage, new PathOperatorPredicateSpec("$.payload_size", PredicateOperator.LessThan, JsonValue.Create(10)), "fail-2"),
        }));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("any", 5, false)));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x12 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_ImpliesScopedRequireFact_BehavesLikeFluentImplies()
    {
        var spec = new MessageRequirementSpec(new ImpliesSpec(
            new RequireFactSpec(TestFactRegistry.TestMessage, new PathOperatorPredicateSpec("$.detached", PredicateOperator.Equals, JsonValue.Create(true)), "n/a"),
            new RequireFactSpec(TestFactRegistry.TestMessage, new PathOperatorPredicateSpec("$.payload_size", PredicateOperator.GreaterThan, JsonValue.Create(0)), "fail")));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("any", 5, true)));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x13 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_AllowAllInsideScope_Trusts()
    {
        var spec = new MessageRequirementSpec(new AllowAllSpec());
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x14 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_DenyAllInsideScope_DeniesWithReason()
    {
        var spec = new MessageRequirementSpec(new DenyAllSpec("scope-deny"));
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x15 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Has.Member("scope-deny"));
    }

    [Test]
    public void Compile_EmptyAndInsideScope_Trusts()
    {
        var spec = new MessageRequirementSpec(new AndSpec(Array.Empty<TrustPolicySpec>()));
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x16 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void Compile_EmptyOrInsideScope_Denies()
    {
        var spec = new MessageRequirementSpec(new OrSpec(Array.Empty<TrustPolicySpec>()));
        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x17 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void Compile_PathOperatorWithUnboundParameterRefValue_Throws_TPX400()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.content_type", PredicateOperator.Equals, new ParameterRef("x").ToJsonNode()),
            "fail"));

        var ex = Assert.Throws<TrustPolicySpecCompilationException>(() => TrustPolicySpecCompiler.Compile(spec, Registry));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.UnboundParameter));
    }

    [Test]
    public void Compile_PropertyAssertionWithUnboundParameterRef_Throws_TPX400()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
            {
                ["content_type"] = new ParameterRef("ct").ToJsonNode(),
            }),
            "fail"));

        var ex = Assert.Throws<TrustPolicySpecCompilationException>(() => TrustPolicySpecCompiler.Compile(spec, Registry));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.UnboundParameter));
    }

    [Test]
    public void Compile_UnsupportedPredicateOperator_PathRequiresValue_Throws_TPX202()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.content_type", PredicateOperator.Equals, value: null),
            "fail"));

        var ex = Assert.Throws<TrustPolicySpecCompilationException>(() => TrustPolicySpecCompiler.Compile(spec, Registry));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.UnsupportedPredicateOperator));
    }

    [Test]
    public void Compile_NullFactToTypedPredicateAdapter_RuntimeGuardThrows()
    {
        // Build a property-assertion predicate that always returns true regardless of input,
        // wrap it in a RequireFact, compile, then drive the predicate with a null fact via
        // reflection on the compiled adapter to confirm the runtime null guard fires rather
        // than a NullReferenceException leaking out.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
            {
                ["content_type"] = JsonValue.Create("application/json"),
            }),
            "fail"));

        var adapterType = typeof(TrustPolicySpecCompiler)
            .GetNestedType("TypedPredicateAdapter`1", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static)
            !.MakeGenericType(typeof(TestMessageFact));

        object adapter = System.Activator.CreateInstance(adapterType, new System.Func<object, bool>(_ => true))!;
        var evalMethod = adapterType.GetMethod("Evaluate")!;
        var ex = Assert.Throws<System.Reflection.TargetInvocationException>(
            () => evalMethod.Invoke(adapter, new object?[] { null }));
        Assert.That(ex!.InnerException, Is.InstanceOf<ArgumentNullException>());
        TrustPolicySpecCompiler.Compile(spec, Registry);
    }

    [Test]
    public void Compile_PropertyAssertion_ListValue_LowersToInOperator()
    {
        // Putting a JsonArray as the value for a property-assertion entry triggers the In-style
        // semantics; the compiler should accept both string elements and produce a Func that
        // evaluates true when the fact's property matches one of them.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
            {
                ["content_type"] = new JsonArray("application/json", "application/octet-stream"),
            }),
            "ct must be in allowed list"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, Registry);
        var sp = BuildServices(new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("application/json", 1, false)));
        var compiled = policy.Compile(sp);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x18 });
        var decision = compiled.Evaluate(messageId, TrustSubject.Message(messageId));
        Assert.That(decision.IsTrusted, Is.True);
    }

    private static void AssertSameDecision(TrustPlanPolicy a, TrustPlanPolicy b, ITrustPack[] packs, bool trusted)
    {
        var sp1 = BuildServices(packs);
        var sp2 = BuildServices(packs);
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x99 });
        TrustSubject message = TrustSubject.Message(messageId);

        var d1 = a.Compile(sp1).Evaluate(messageId, message);
        var d2 = b.Compile(sp2).Evaluate(messageId, message);

        Assert.Multiple(() =>
        {
            Assert.That(d1.IsTrusted, Is.EqualTo(trusted), "spec-built plan disagrees");
            Assert.That(d2.IsTrusted, Is.EqualTo(trusted), "fluent-built plan disagrees");
        });
    }
}

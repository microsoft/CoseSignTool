// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Argument-validation and structural sanity tests for spec records and helper types.
/// </summary>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class SpecRecordValidationTests
{
    [Test]
    public void MessageRequirementSpec_NullInner_Throws()
        => Assert.Throws<ArgumentNullException>(() => new MessageRequirementSpec(null!));

    [Test]
    public void PrimarySigningKeyRequirementSpec_NullInner_Throws()
        => Assert.Throws<ArgumentNullException>(() => new PrimarySigningKeyRequirementSpec(null!));

    [Test]
    public void AnyCounterSignatureRequirementSpec_NullInner_Throws()
        => Assert.Throws<ArgumentNullException>(() => new AnyCounterSignatureRequirementSpec(null!));

    [Test]
    public void AnyCounterSignatureRequirementSpec_DefaultsToDeny()
    {
        var spec = new AnyCounterSignatureRequirementSpec(new AllowAllSpec());
        Assert.That(spec.OnEmpty, Is.EqualTo(OnEmptyBehavior.Deny));
    }

    [Test]
    public void RequireFactSpec_NullFactId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new RequireFactSpec(
            "",
            new PathOperatorPredicateSpec("$", PredicateOperator.Exists, null),
            "msg"));
    }

    [Test]
    public void RequireFactSpec_NullPredicate_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new RequireFactSpec("x/v1", null!, "msg"));
    }

    [Test]
    public void RequireFactSpec_NullFailureMessage_Throws()
    {
        Assert.Throws<ArgumentException>(() => new RequireFactSpec(
            "x/v1",
            new PathOperatorPredicateSpec("$", PredicateOperator.Exists, null),
            ""));
    }

    [Test]
    public void AndSpec_NullOperands_Throws()
        => Assert.Throws<ArgumentNullException>(() => new AndSpec(null!));

    [Test]
    public void AndSpec_OperandsContainsNull_Throws()
        => Assert.Throws<ArgumentException>(() => new AndSpec(new TrustPolicySpec[] { null! }));

    [Test]
    public void OrSpec_NullOperands_Throws()
        => Assert.Throws<ArgumentNullException>(() => new OrSpec(null!));

    [Test]
    public void OrSpec_OperandsContainsNull_Throws()
        => Assert.Throws<ArgumentException>(() => new OrSpec(new TrustPolicySpec[] { null! }));

    [Test]
    public void NotSpec_NullOperand_Throws()
        => Assert.Throws<ArgumentNullException>(() => new NotSpec(null!));

    [Test]
    public void ImpliesSpec_NullArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => new ImpliesSpec(null!, new AllowAllSpec()));
        Assert.Throws<ArgumentNullException>(() => new ImpliesSpec(new AllowAllSpec(), null!));
    }

    [Test]
    public void DenyAllSpec_NullReason_Throws()
        => Assert.Throws<ArgumentException>(() => new DenyAllSpec(""));

    [Test]
    public void PathOperatorPredicateSpec_NullPath_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new PathOperatorPredicateSpec(null!, PredicateOperator.Exists, null));
    }

    [Test]
    public void PropertyAssertionPredicateSpec_NullAssertions_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new PropertyAssertionPredicateSpec(null!));
    }

    [Test]
    public void TrustPolicySpecCompilationException_DefaultCtor_HasEmptyCode()
    {
        var ex = new TrustPolicySpecCompilationException();
        Assert.That(ex.Code, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TrustPolicySpecCompilationException_MessageCtor_HasEmptyCode()
    {
        var ex = new TrustPolicySpecCompilationException("oops");
        Assert.That(ex.Code, Is.EqualTo(string.Empty));
        Assert.That(ex.Message, Is.EqualTo("oops"));
    }

    [Test]
    public void TrustPolicySpecCompilationException_MessageInnerCtor_HasEmptyCode()
    {
        var inner = new Exception("inner");
        var ex = new TrustPolicySpecCompilationException("oops", inner);
        Assert.That(ex.Code, Is.EqualTo(string.Empty));
        Assert.That(ex.InnerException, Is.SameAs(inner));
    }

    [Test]
    public void TrustPolicySpecCompilationException_CodeMessageInnerCtor_PreservesAll()
    {
        var inner = new Exception("inner");
        var ex = new TrustPolicySpecCompilationException("TPX200", "msg", inner);
        Assert.That(ex.Code, Is.EqualTo("TPX200"));
        Assert.That(ex.Message, Is.EqualTo("msg"));
        Assert.That(ex.InnerException, Is.SameAs(inner));
    }

    [Test]
    public void TrustPolicySpecCompilationException_NullCode_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new TrustPolicySpecCompilationException(null!, "msg"));
    }

    [Test]
    public void TrustPolicySpecCompilationException_NullMessage_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new TrustPolicySpecCompilationException("TPX200", (string)null!));
    }

    [Test]
    public void TrustPolicySpecCompilationException_NullInner_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new TrustPolicySpecCompilationException("TPX200", "msg", null!));
    }

    [Test]
    public void DiagnosticCodes_AreStableConstants()
    {
        Assert.Multiple(() =>
        {
            Assert.That(TrustPolicyDiagnosticCodes.UnknownFactId, Is.EqualTo("TPX200"));
            Assert.That(TrustPolicyDiagnosticCodes.UnknownFactProperty, Is.EqualTo("TPX201"));
            Assert.That(TrustPolicyDiagnosticCodes.UnsupportedPredicateOperator, Is.EqualTo("TPX202"));
            Assert.That(TrustPolicyDiagnosticCodes.UnsupportedPredicatePath, Is.EqualTo("TPX203"));
            Assert.That(TrustPolicyDiagnosticCodes.FactScopeMismatch, Is.EqualTo("TPX204"));
            Assert.That(TrustPolicyDiagnosticCodes.UnboundParameter, Is.EqualTo("TPX400"));
            Assert.That(TrustPolicyDiagnosticCodes.Prefix, Is.EqualTo("TPX"));
        });
    }

    [Test]
    public void SourceLocation_RoundTripsThroughCanonicalJson()
    {
        var spec = new MessageRequirementSpec(new AllowAllSpec
        {
            Location = new SourceLocation("file://policy.json", 5, 10, 42),
        });

        string json = spec.ToCanonicalJson();
        var rehydrated = (MessageRequirementSpec)Json.TrustPolicySpecSerializer.FromCanonicalJson(json);

        Assert.That(rehydrated.Inner, Is.InstanceOf<AllowAllSpec>());
        var inner = (AllowAllSpec)rehydrated.Inner;
        Assert.That(inner.Location, Is.Not.Null);
        Assert.That(inner.Location!.Line, Is.EqualTo(5));
        Assert.That(inner.Location.Column, Is.EqualTo(10));
        Assert.That(inner.Location.Length, Is.EqualTo(42));
        Assert.That(inner.Location.Source, Is.EqualTo("file://policy.json"));
    }

    [Test]
    public void ParameterRefLocation_PreservedThroughBindReturnedSpec()
    {
        // Bind() round-trips through canonical JSON; SourceLocation on the surrounding spec node
        // must survive that.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.content_type", PredicateOperator.Equals, JsonValue.Create("application/json"))
            {
                Location = new SourceLocation("file://x.json", 1, 1, 5),
            },
            "fail"));

        var bound = spec.Bind(new Dictionary<string, JsonNode?>());
        var inner = ((MessageRequirementSpec)bound).Inner as RequireFactSpec;
        Assert.That(inner, Is.Not.Null);
        Assert.That(inner!.Predicate.Location, Is.Not.Null);
        Assert.That(inner.Predicate.Location!.Line, Is.EqualTo(1));
    }
}

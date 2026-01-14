// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Interfaces;
using Moq;

/// <summary>
/// Tests for <see cref="TrustPolicy"/> and <see cref="TrustDecision"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class TrustPolicyTests
{
    #region DenyAll Tests

    [Test]
    public void DenyAll_ReturnsUntrustedDecision()
    {
        var policy = TrustPolicy.DenyAll();
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsTrusted, Is.False);
            Assert.That(result.Reasons, Has.Count.GreaterThan(0));
        });
    }

    [Test]
    public void DenyAll_WithReason_IncludesReason()
    {
        var policy = TrustPolicy.DenyAll("Custom deny reason");
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.Reasons, Has.Some.Contain("Custom deny reason"));
    }

    #endregion

    #region AllowAll Tests

    [Test]
    public void AllowAll_ReturnsTrustedDecision()
    {
        var policy = TrustPolicy.AllowAll();
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void AllowAll_WithReason_ReturnsTrusted()
    {
        var policy = TrustPolicy.AllowAll("Custom allow reason");
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    #endregion

    #region Or Tests

    [Test]
    public void Or_BothDeny_ReturnsFalse()
    {
        var policy = TrustPolicy.Or(TrustPolicy.DenyAll("First"), TrustPolicy.DenyAll("Second"));
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.False);
    }

    [Test]
    public void Or_FirstAllow_ReturnsTrue()
    {
        var policy = TrustPolicy.Or(TrustPolicy.AllowAll("First"), TrustPolicy.DenyAll("Second"));
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Or_SecondAllow_ReturnsTrue()
    {
        var policy = TrustPolicy.Or(TrustPolicy.DenyAll("First"), TrustPolicy.AllowAll("Second"));
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Or_EmptyPolicies_ReturnsTrue()
    {
        var policy = TrustPolicy.Or();
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        // Vacuously satisfied when no policies
        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Or_NullPolicies_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => TrustPolicy.Or(null!));
    }

    #endregion

    #region And Tests

    [Test]
    public void And_BothAllow_ReturnsTrue()
    {
        var policy = TrustPolicy.And(TrustPolicy.AllowAll("First"), TrustPolicy.AllowAll("Second"));
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void And_FirstDeny_ReturnsFalse()
    {
        var policy = TrustPolicy.And(TrustPolicy.DenyAll("First"), TrustPolicy.AllowAll("Second"));
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.False);
    }

    [Test]
    public void And_SecondDeny_ReturnsFalse()
    {
        var policy = TrustPolicy.And(TrustPolicy.AllowAll("First"), TrustPolicy.DenyAll("Second"));
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.False);
    }

    [Test]
    public void And_EmptyPolicies_ReturnsTrue()
    {
        var policy = TrustPolicy.And();
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        // Vacuously satisfied when no policies
        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void And_NullPolicies_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => TrustPolicy.And(null!));
    }

    #endregion

    #region Not Tests

    [Test]
    public void Not_InvertsAllow_ReturnsFalse()
    {
        var policy = TrustPolicy.Not(TrustPolicy.AllowAll());
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.False);
    }

    [Test]
    public void Not_InvertsDeny_ReturnsTrue()
    {
        var policy = TrustPolicy.Not(TrustPolicy.DenyAll());
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Not_NullPolicy_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => TrustPolicy.Not(null!));
    }

    #endregion

    #region Require Tests

    [Test]
    public void Require_AssertionPresentAndMatchesPredicate_ReturnsTrue()
    {
        var mockAssertion = CreateMockAssertion("test-domain");
        var policy = TrustPolicy.Require<ISigningKeyAssertion>(
            a => a.Domain == "test-domain",
            "Domain must be test-domain");
        var assertions = new ISigningKeyAssertion[] { mockAssertion };

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Require_AssertionPresentButDoesNotMatchPredicate_ReturnsFalse()
    {
        var mockAssertion = CreateMockAssertion("other-domain");
        var policy = TrustPolicy.Require<ISigningKeyAssertion>(
            a => a.Domain == "test-domain",
            "Domain must be test-domain");
        var assertions = new ISigningKeyAssertion[] { mockAssertion };

        var result = policy.Evaluate(assertions);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsTrusted, Is.False);
            Assert.That(result.Reasons, Has.Some.Contain("Domain must be test-domain"));
        });
    }

    [Test]
    public void Require_AssertionNotPresent_ReturnsFalse()
    {
        var policy = TrustPolicy.Require<ISigningKeyAssertion>(
            a => true,
            "Assertion required");
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.False);
    }

    [Test]
    public void Require_MultipleAssertions_FirstDoesNotMatch_SecondMatches_ReturnsTrue()
    {
        // Test that when multiple assertions of the same type exist,
        // if any of them satisfies the predicate, trust is granted
        var assertion1 = CreateMockAssertion("domain1");
        var assertion2 = CreateMockAssertion("domain2");
        var policy = TrustPolicy.Require<ISigningKeyAssertion>(
            a => a.Domain == "domain2",
            "Assertion with domain2 required");
        var assertions = new ISigningKeyAssertion[] { assertion1, assertion2 };

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Require_MultipleAssertions_NoneMatch_ReturnsFalse()
    {
        var assertion1 = CreateMockAssertion("domain1");
        var assertion2 = CreateMockAssertion("domain2");
        var policy = TrustPolicy.Require<ISigningKeyAssertion>(
            a => a.Domain == "domain3",
            "Assertion with domain3 required");
        var assertions = new ISigningKeyAssertion[] { assertion1, assertion2 };

        var result = policy.Evaluate(assertions);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsTrusted, Is.False);
            Assert.That(result.Reasons, Has.Some.Contain("domain3"));
        });
    }

    [Test]
    public void Require_NullPredicate_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicy.Require<ISigningKeyAssertion>(null!, "reason"));
    }

    [Test]
    public void Require_NullFailureReason_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicy.Require<ISigningKeyAssertion>(_ => true, null!));
    }

    #endregion

    #region RequirePresent Tests

    [Test]
    public void RequirePresent_AssertionPresent_ReturnsTrue()
    {
        var mockAssertion = CreateMockAssertion("test");
        var policy = TrustPolicy.RequirePresent<ISigningKeyAssertion>("Assertion must be present");
        var assertions = new ISigningKeyAssertion[] { mockAssertion };

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void RequirePresent_AssertionNotPresent_ReturnsFalse()
    {
        var policy = TrustPolicy.RequirePresent<ISigningKeyAssertion>("Assertion must be present");
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.False);
    }

    [Test]
    public void RequirePresent_NullFailureReason_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicy.RequirePresent<ISigningKeyAssertion>(null!));
    }

    #endregion

    #region UseDefault Tests

    [Test]
    public void UseDefault_ReturnsAssertionDefaultPolicy()
    {
        var mockDefaultPolicy = TrustPolicy.AllowAll("Default policy");
        var mockAssertion = new Mock<ISigningKeyAssertion>();
        mockAssertion.Setup(a => a.DefaultTrustPolicy).Returns(mockDefaultPolicy);

        var policy = TrustPolicy.UseDefault(mockAssertion.Object);

        Assert.That(policy, Is.SameAs(mockDefaultPolicy));
    }

    [Test]
    public void UseDefault_NullAssertion_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicy.UseDefault<ISigningKeyAssertion>(null!));
    }

    #endregion

    #region Implies Tests

    [Test]
    public void Implies_AntecedentFalse_ReturnsTrue()
    {
        // If false then anything is true (vacuously)
        var policy = TrustPolicy.Implies(TrustPolicy.DenyAll(), TrustPolicy.DenyAll());
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Implies_AntecedentTrueConsequentTrue_ReturnsTrue()
    {
        var policy = TrustPolicy.Implies(TrustPolicy.AllowAll(), TrustPolicy.AllowAll());
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Implies_AntecedentTrueConsequentFalse_ReturnsFalse()
    {
        var policy = TrustPolicy.Implies(TrustPolicy.AllowAll(), TrustPolicy.DenyAll());
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.False);
    }

    [Test]
    public void Implies_NullAntecedent_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicy.Implies(null!, TrustPolicy.AllowAll()));
    }

    [Test]
    public void Implies_NullConsequent_FiltersNullAndEvaluates()
    {
        // Implies(if, null) becomes Or(Not(if), null)
        // OrPolicy filters out null policies, so this becomes Or(Not(if))
        // With if=AllowAll, Not(AllowAll) = Deny, so Or(Deny) = Deny
        var policy = TrustPolicy.Implies(TrustPolicy.AllowAll(), null!);
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        // Since AllowAll is satisfied, Not(AllowAll) is denied.
        // Or(Denied) = Denied
        Assert.That(result.IsTrusted, Is.False);
    }

    #endregion

    #region FromAssertionDefaults Tests

    [Test]
    public void FromAssertionDefaults_NoAssertions_ReturnsTrue()
    {
        var policy = TrustPolicy.FromAssertionDefaults();
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void FromAssertionDefaults_AllAssertionsAllowAll_ReturnsTrue()
    {
        var mockAssertion1 = new Mock<ISigningKeyAssertion>();
        mockAssertion1.Setup(a => a.DefaultTrustPolicy).Returns(TrustPolicy.AllowAll());
        mockAssertion1.Setup(a => a.Domain).Returns("domain1");

        var mockAssertion2 = new Mock<ISigningKeyAssertion>();
        mockAssertion2.Setup(a => a.DefaultTrustPolicy).Returns(TrustPolicy.AllowAll());
        mockAssertion2.Setup(a => a.Domain).Returns("domain2");

        var policy = TrustPolicy.FromAssertionDefaults();
        var assertions = new ISigningKeyAssertion[] { mockAssertion1.Object, mockAssertion2.Object };

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void FromAssertionDefaults_OneAssertionDenies_ReturnsFalse()
    {
        var mockAssertion1 = new Mock<ISigningKeyAssertion>();
        mockAssertion1.Setup(a => a.DefaultTrustPolicy).Returns(TrustPolicy.AllowAll());
        mockAssertion1.Setup(a => a.Domain).Returns("domain1");

        var mockAssertion2 = new Mock<ISigningKeyAssertion>();
        mockAssertion2.Setup(a => a.DefaultTrustPolicy).Returns(TrustPolicy.DenyAll("Denied by default"));
        mockAssertion2.Setup(a => a.Domain).Returns("domain2");

        var policy = TrustPolicy.FromAssertionDefaults();
        var assertions = new ISigningKeyAssertion[] { mockAssertion1.Object, mockAssertion2.Object };

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.False);
    }

    #endregion

    #region Complex Scenarios

    [Test]
    public void Complex_OrOfAnds_WorksCorrectly()
    {
        // (Allow AND Allow) OR (Deny AND Allow)
        var policy = TrustPolicy.Or(
            TrustPolicy.And(TrustPolicy.AllowAll(), TrustPolicy.AllowAll()),
            TrustPolicy.And(TrustPolicy.DenyAll(), TrustPolicy.AllowAll())
        );
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Complex_AndOfOrs_WorksCorrectly()
    {
        // (Allow OR Deny) AND (Allow OR Deny)
        var policy = TrustPolicy.And(
            TrustPolicy.Or(TrustPolicy.AllowAll(), TrustPolicy.DenyAll()),
            TrustPolicy.Or(TrustPolicy.AllowAll(), TrustPolicy.DenyAll())
        );
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    [Test]
    public void Complex_NestedNot_WorksCorrectly()
    {
        // NOT(NOT(Allow)) = Allow
        var policy = TrustPolicy.Not(TrustPolicy.Not(TrustPolicy.AllowAll()));
        var assertions = Array.Empty<ISigningKeyAssertion>();

        var result = policy.Evaluate(assertions);

        Assert.That(result.IsTrusted, Is.True);
    }

    #endregion

    #region Helper Methods

    private static ISigningKeyAssertion CreateMockAssertion(string domain)
    {
        var mock = new Mock<ISigningKeyAssertion>();
        mock.Setup(a => a.Domain).Returns(domain);
        mock.Setup(a => a.DefaultTrustPolicy).Returns(TrustPolicy.AllowAll());
        return mock.Object;
    }

    #endregion
}

/// <summary>
/// Tests for <see cref="TrustDecision"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class TrustDecisionTests
{
    [Test]
    public void Trusted_CreatesTrustedDecision()
    {
        var decision = TrustDecision.Trusted();

        Assert.Multiple(() =>
        {
            Assert.That(decision.IsTrusted, Is.True);
            Assert.That(decision.Reasons, Is.Empty);
        });
    }

    [Test]
    public void Trusted_WithReasons_CreatesTrustedDecisionWithReasons()
    {
        var decision = TrustDecision.Trusted("Reason 1", "Reason 2");

        Assert.Multiple(() =>
        {
            Assert.That(decision.IsTrusted, Is.True);
            Assert.That(decision.Reasons, Has.Count.EqualTo(2));
        });
    }

    [Test]
    public void Denied_CreatesUntrustedDecision()
    {
        var decision = TrustDecision.Denied("Test reason");

        Assert.Multiple(() =>
        {
            Assert.That(decision.IsTrusted, Is.False);
            Assert.That(decision.Reasons, Has.Some.EqualTo("Test reason"));
        });
    }

    [Test]
    public void Denied_WithMultipleReasons_IncludesAllReasons()
    {
        var decision = TrustDecision.Denied("Reason 1", "Reason 2");

        Assert.Multiple(() =>
        {
            Assert.That(decision.IsTrusted, Is.False);
            Assert.That(decision.Reasons, Has.Count.EqualTo(2));
            Assert.That(decision.Reasons, Contains.Item("Reason 1"));
            Assert.That(decision.Reasons, Contains.Item("Reason 2"));
        });
    }

    [Test]
    public void Denied_WithListReasons_AcceptsList()
    {
        IReadOnlyList<string> reasons = new List<string> { "Reason A", "Reason B" };
        var decision = TrustDecision.Denied(reasons);

        Assert.Multiple(() =>
        {
            Assert.That(decision.IsTrusted, Is.False);
            Assert.That(decision.Reasons, Has.Count.EqualTo(2));
        });
    }

    [Test]
    public void Trusted_ReturnsSameInstance_WhenNoReasons()
    {
        var decision1 = TrustDecision.Trusted();
        var decision2 = TrustDecision.Trusted();

        Assert.That(decision1, Is.SameAs(decision2));
    }

    [Test]
    public void Trusted_WithNullReasons_ReturnsSameInstanceAsTrusted()
    {
        var decision = TrustDecision.Trusted(null!);
        var trustedInstance = TrustDecision.Trusted();

        Assert.That(decision, Is.SameAs(trustedInstance));
    }

    [Test]
    public void Trusted_WithEmptyReasons_ReturnsSameInstanceAsTrusted()
    {
        var decision = TrustDecision.Trusted(Array.Empty<string>());
        var trustedInstance = TrustDecision.Trusted();

        Assert.That(decision, Is.SameAs(trustedInstance));
    }

    [Test]
    public void Denied_WithNullReasons_ReturnsDecisionWithEmptyReasons()
    {
        var decision = TrustDecision.Denied((string[])null!);

        Assert.Multiple(() =>
        {
            Assert.That(decision.IsTrusted, Is.False);
            Assert.That(decision.Reasons, Is.Empty);
        });
    }

    [Test]
    public void Denied_WithNullListReasons_ReturnsDecisionWithEmptyReasons()
    {
        var decision = TrustDecision.Denied((IReadOnlyList<string>)null!);

        Assert.Multiple(() =>
        {
            Assert.That(decision.IsTrusted, Is.False);
            Assert.That(decision.Reasons, Is.Empty);
        });
    }

    [Test]
    public void Denied_WithEmptyReasons_ReturnsUntrustedDecision()
    {
        var decision = TrustDecision.Denied(Array.Empty<string>());

        Assert.Multiple(() =>
        {
            Assert.That(decision.IsTrusted, Is.False);
            Assert.That(decision.Reasons, Is.Empty);
        });
    }
}

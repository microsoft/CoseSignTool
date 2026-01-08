// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

[TestFixture]
public class TrustPolicyTests
{
    [Test]
    public void DenyAll_IsNeverSatisfied_AndExplains()
    {
        var policy = TrustPolicy.DenyAll();
        var claims = new Dictionary<string, bool> { ["a"] = true };

        Assert.That(policy.IsSatisfied(claims), Is.False);

        var reasons = new List<string>();
        policy.Explain(claims, reasons);
        Assert.That(reasons, Is.Not.Empty);
    }

    [Test]
    public void DenyAll_WithReason_ExplainsReason()
    {
        var policy = TrustPolicy.DenyAll("Nope");
        var claims = new Dictionary<string, bool>();

        var reasons = new List<string>();
        policy.Explain(claims, reasons);

        Assert.That(reasons, Does.Contain("Nope"));
    }

    [Test]
    public void AllowAll_IsAlwaysSatisfied_AndExplainsOnlyWhenReasonProvided()
    {
        var claims = new Dictionary<string, bool>();

        var allow = TrustPolicy.AllowAll();
        Assert.That(allow.IsSatisfied(claims), Is.True);

        var reasons = new List<string>();
        allow.Explain(claims, reasons);
        Assert.That(reasons, Is.Empty);

        var allowWithReason = TrustPolicy.AllowAll("Allowed");
        var reasons2 = new List<string>();
        allowWithReason.Explain(claims, reasons2);
        Assert.That(reasons2, Does.Contain("Allowed"));
    }

    [Test]
    public void Claim_IsSatisfiedOnlyWhenTrue()
    {
        var policy = TrustPolicy.Claim("c");

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>()), Is.False);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["c"] = false }), Is.False);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["c"] = true }), Is.True);

        var reasons = new List<string>();
        policy.Explain(new Dictionary<string, bool> { ["c"] = false }, reasons);
        Assert.That(reasons, Has.Some.Contains("Required claim not satisfied"));
    }

    [Test]
    public void Or_WithNoPolicies_IsSatisfied()
    {
        var policy = TrustPolicy.Or();
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>()), Is.True);
    }

    [Test]
    public void Or_ExplainsWhenNotSatisfied()
    {
        var policy = TrustPolicy.Or(
            TrustPolicy.Claim("a"),
            TrustPolicy.Claim("b"));

        var claims = new Dictionary<string, bool> { ["a"] = false, ["b"] = false };
        Assert.That(policy.IsSatisfied(claims), Is.False);

        var reasons = new List<string>();
        policy.Explain(claims, reasons);

        Assert.That(reasons, Has.Some.Contains("None of the Or"));
        Assert.That(reasons, Has.Some.Contains("Required claim not satisfied: a"));
        Assert.That(reasons, Has.Some.Contains("Required claim not satisfied: b"));
    }

    [Test]
    public void And_RequiresAllClaims()
    {
        var policy = TrustPolicy.And(
            TrustPolicy.Claim("a"),
            TrustPolicy.Claim("b"));

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["a"] = true, ["b"] = true }), Is.True);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["a"] = true, ["b"] = false }), Is.False);

        var reasons = new List<string>();
        policy.Explain(new Dictionary<string, bool> { ["a"] = true, ["b"] = false }, reasons);
        Assert.That(reasons, Has.Some.Contains("Required claim not satisfied: b"));
    }

    [Test]
    public void Not_NegatesInnerPolicy()
    {
        var policy = TrustPolicy.Not(TrustPolicy.Claim("a"));

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["a"] = true }), Is.False);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["a"] = false }), Is.True);

        var reasons = new List<string>();
        policy.Explain(new Dictionary<string, bool> { ["a"] = true }, reasons);
        Assert.That(reasons, Has.Some.Contains("Not(...)"));
    }

    [Test]
    public void Implies_IsSatisfiedWhenAntecedentFalseOrConsequentTrue()
    {
        var policy = TrustPolicy.Implies(TrustPolicy.Claim("a"), TrustPolicy.Claim("b"));

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["a"] = false, ["b"] = false }), Is.True);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["a"] = true, ["b"] = true }), Is.True);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { ["a"] = true, ["b"] = false }), Is.False);
    }
}

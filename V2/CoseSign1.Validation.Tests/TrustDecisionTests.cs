// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

public sealed class TrustDecisionTests
{
    [Test]
    public void Trusted_WhenCalledMultipleTimes_ReturnsSameSingletonInstance()
    {
        var a = TrustDecision.Trusted();
        var b = TrustDecision.Trusted();

        Assert.That(a, Is.SameAs(b));
        Assert.That(a.IsTrusted, Is.True);
        Assert.That(a.Reasons, Is.Empty);
    }

    [Test]
    public void Trusted_WithNullOrEmptyReasons_ReturnsSingletonInstance()
    {
        TrustDecision a = TrustDecision.Trusted(null!);
        TrustDecision b = TrustDecision.Trusted();
        TrustDecision c = TrustDecision.Trusted(Array.Empty<string>());

        Assert.Multiple(() =>
        {
            Assert.That(a, Is.SameAs(b));
            Assert.That(c, Is.SameAs(b));
        });
    }

    [Test]
    public void Trusted_WithReasons_PreservesReasons()
    {
        var decision = TrustDecision.Trusted("a", "b");

        Assert.That(decision.IsTrusted, Is.True);
        Assert.That(decision.Reasons, Is.EqualTo(new[] { "a", "b" }));
        Assert.That(decision, Is.Not.SameAs(TrustDecision.Trusted()));
    }

    [Test]
    public void Denied_WithNullParams_YieldsEmptyReasons()
    {
        string[]? reasons = null;

        var decision = TrustDecision.Denied(reasons!);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.Empty);
    }

    [Test]
    public void Denied_WithNullList_YieldsEmptyReasons()
    {
        IReadOnlyList<string>? reasons = null;

        var decision = TrustDecision.Denied(reasons!);

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.Empty);
    }

    [Test]
    public void Denied_WithReasons_PreservesReasons()
    {
        var decision = TrustDecision.Denied("a", "b");

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.EqualTo(new[] { "a", "b" }));
    }
}

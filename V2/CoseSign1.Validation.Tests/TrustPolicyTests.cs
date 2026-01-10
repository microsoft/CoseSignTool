// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;

[TestFixture]
public class TrustPolicyTests
{
    [Test]
    public void DenyAll_IsNeverTrusted()
    {
        var policy = TrustPolicy.DenyAll();
        var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Is.Not.Empty);
    }

    [Test]
    public void DenyAll_WithReason_ExplainsReason()
    {
        var policy = TrustPolicy.DenyAll("Nope");
        var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());

        Assert.That(decision.IsTrusted, Is.False);
        Assert.That(decision.Reasons, Does.Contain("Nope"));
    }

    [Test]
    public void AllowAll_IsAlwaysTrusted()
    {
        var allow = TrustPolicy.AllowAll();
        var decision = allow.Evaluate(Array.Empty<ISigningKeyAssertion>());

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void AllowAll_WithReason_ExplainsReason()
    {
        var allowWithReason = TrustPolicy.AllowAll("Allowed");
        var decision = allowWithReason.Evaluate(Array.Empty<ISigningKeyAssertion>());

        Assert.That(decision.IsTrusted, Is.True);
        Assert.That(decision.Reasons, Does.Contain("Allowed"));
    }

    [Test]
    public void Or_WithNoPolicies_IsTrusted()
    {
        var policy = TrustPolicy.Or();
        var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void And_WithNoPolicies_IsTrusted()
    {
        var policy = TrustPolicy.And();
        var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());

        Assert.That(decision.IsTrusted, Is.True);
    }
}

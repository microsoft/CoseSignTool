// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation.Interfaces;

[TestFixture]
public class MstTrustPoliciesTests
{
    [Test]
    public void RequireReceiptPresent_ReturnsPolicy()
    {
        var policy = MstTrustPolicies.RequireReceiptPresent();
        Assert.That(policy, Is.Not.Null);

        // With no assertions, evaluate should not trust
        var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void RequireReceiptTrusted_ReturnsPolicy()
    {
        var policy = MstTrustPolicies.RequireReceiptTrusted();
        Assert.That(policy, Is.Not.Null);

        // With no assertions, evaluate should not trust
        var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void RequireReceiptPresentAndTrusted_ReturnsPolicy()
    {
        var policy = MstTrustPolicies.RequireReceiptPresentAndTrusted();
        Assert.That(policy, Is.Not.Null);

        // With no assertions, evaluate should not trust
        var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void IfReceiptPresentThenTrusted_ReturnsPolicy()
    {
        var policy = MstTrustPolicies.IfReceiptPresentThenTrusted();
        Assert.That(policy, Is.Not.Null);

        // With no assertions, should trust (no receipt means condition is vacuously true)
        var decision = policy.Evaluate(Array.Empty<ISigningKeyAssertion>());
        Assert.That(decision.IsTrusted, Is.True);
    }
}

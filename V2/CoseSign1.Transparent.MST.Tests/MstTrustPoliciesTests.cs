// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Transparent.MST.Validation;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class MstTrustPoliciesTests
{
    [Test]
    public void RequireReceiptPresent_IsSatisfiedOnlyWhenPresent()
    {
        var policy = MstTrustPolicies.RequireReceiptPresent();

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>()), Is.False);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { [MstTrustClaims.ReceiptPresent] = false }), Is.False);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { [MstTrustClaims.ReceiptPresent] = true }), Is.True);
    }

    [Test]
    public void RequireReceiptTrusted_IsSatisfiedOnlyWhenTrusted()
    {
        var policy = MstTrustPolicies.RequireReceiptTrusted();

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>()), Is.False);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { [MstTrustClaims.ReceiptTrusted] = false }), Is.False);
        Assert.That(policy.IsSatisfied(new Dictionary<string, bool> { [MstTrustClaims.ReceiptTrusted] = true }), Is.True);
    }

    [Test]
    public void RequireReceiptPresentAndTrusted_RequiresBoth()
    {
        var policy = MstTrustPolicies.RequireReceiptPresentAndTrusted();

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>
        {
            [MstTrustClaims.ReceiptPresent] = true,
            [MstTrustClaims.ReceiptTrusted] = true
        }), Is.True);

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>
        {
            [MstTrustClaims.ReceiptPresent] = true,
            [MstTrustClaims.ReceiptTrusted] = false
        }), Is.False);
    }

    [Test]
    public void IfReceiptPresentThenTrusted_AllowsNoReceiptButRequiresTrustedWhenPresent()
    {
        var policy = MstTrustPolicies.IfReceiptPresentThenTrusted();

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>
        {
            [MstTrustClaims.ReceiptPresent] = false,
            [MstTrustClaims.ReceiptTrusted] = false
        }), Is.True);

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>
        {
            [MstTrustClaims.ReceiptPresent] = true,
            [MstTrustClaims.ReceiptTrusted] = true
        }), Is.True);

        Assert.That(policy.IsSatisfied(new Dictionary<string, bool>
        {
            [MstTrustClaims.ReceiptPresent] = true,
            [MstTrustClaims.ReceiptTrusted] = false
        }), Is.False);
    }
}

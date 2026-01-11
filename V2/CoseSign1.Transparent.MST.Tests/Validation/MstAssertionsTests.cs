// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Validation;

using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST.Validation;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for MST assertion records.
/// </summary>
[TestFixture]
[Category("MST")]
[Category("Validation")]
public class MstAssertionsTests
{
    #region MstReceiptPresentAssertion Tests

    [Test]
    public void MstReceiptPresentAssertion_WhenPresent_HasCorrectDescription()
    {
        var assertion = new MstReceiptPresentAssertion(true);

        Assert.Multiple(() =>
        {
            Assert.That(assertion.IsPresent, Is.True);
            Assert.That(assertion.Description, Is.EqualTo("MST receipt is present"));
            Assert.That(assertion.Domain, Is.EqualTo("mst"));
        });
    }

    [Test]
    public void MstReceiptPresentAssertion_WhenNotPresent_HasCorrectDescription()
    {
        var assertion = new MstReceiptPresentAssertion(false);

        Assert.Multiple(() =>
        {
            Assert.That(assertion.IsPresent, Is.False);
            Assert.That(assertion.Description, Is.EqualTo("MST receipt is not present"));
        });
    }

    [Test]
    public void MstReceiptPresentAssertion_HasDefaultTrustPolicy()
    {
        var assertion = new MstReceiptPresentAssertion(true);

        Assert.That(assertion.DefaultTrustPolicy, Is.Not.Null);
    }

    [Test]
    public void MstReceiptPresentAssertion_DefaultTrustPolicy_TrustsWhenPresent()
    {
        var assertion = new MstReceiptPresentAssertion(true);

        var decision = assertion.DefaultTrustPolicy.Evaluate([assertion]);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void MstReceiptPresentAssertion_DefaultTrustPolicy_DoesNotTrustWhenAbsent()
    {
        var assertion = new MstReceiptPresentAssertion(false);

        var decision = assertion.DefaultTrustPolicy.Evaluate([assertion]);

        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void MstReceiptPresentAssertion_CanSetSigningKey()
    {
        var mockKey = new Mock<ISigningKey>();
        var assertion = new MstReceiptPresentAssertion(true) { SigningKey = mockKey.Object };

        Assert.That(assertion.SigningKey, Is.SameAs(mockKey.Object));
    }

    #endregion

    #region MstReceiptTrustedAssertion Tests

    [Test]
    public void MstReceiptTrustedAssertion_WhenTrusted_HasCorrectDescription()
    {
        var assertion = new MstReceiptTrustedAssertion(true);

        Assert.Multiple(() =>
        {
            Assert.That(assertion.IsTrusted, Is.True);
            Assert.That(assertion.Description, Is.EqualTo("MST receipt is trusted"));
            Assert.That(assertion.Domain, Is.EqualTo("mst"));
        });
    }

    [Test]
    public void MstReceiptTrustedAssertion_WhenNotTrusted_WithDetails_HasCorrectDescription()
    {
        var assertion = new MstReceiptTrustedAssertion(false, "signature verification failed");

        Assert.Multiple(() =>
        {
            Assert.That(assertion.IsTrusted, Is.False);
            Assert.That(assertion.Description, Does.Contain("signature verification failed"));
            Assert.That(assertion.Details, Is.EqualTo("signature verification failed"));
        });
    }

    [Test]
    public void MstReceiptTrustedAssertion_WhenNotTrusted_WithoutDetails_HasUnknownInDescription()
    {
        var assertion = new MstReceiptTrustedAssertion(false);

        Assert.That(assertion.Description, Does.Contain("unknown"));
    }

    [Test]
    public void MstReceiptTrustedAssertion_HasDefaultTrustPolicy()
    {
        var assertion = new MstReceiptTrustedAssertion(true);

        Assert.That(assertion.DefaultTrustPolicy, Is.Not.Null);
    }

    [Test]
    public void MstReceiptTrustedAssertion_DefaultTrustPolicy_TrustsWhenVerified()
    {
        var assertion = new MstReceiptTrustedAssertion(true);

        var decision = assertion.DefaultTrustPolicy.Evaluate([assertion]);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void MstReceiptTrustedAssertion_DefaultTrustPolicy_DoesNotTrustWhenNotVerified()
    {
        var assertion = new MstReceiptTrustedAssertion(false, "invalid proof");

        var decision = assertion.DefaultTrustPolicy.Evaluate([assertion]);

        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void MstReceiptTrustedAssertion_CanSetSigningKey()
    {
        var mockKey = new Mock<ISigningKey>();
        var assertion = new MstReceiptTrustedAssertion(true) { SigningKey = mockKey.Object };

        Assert.That(assertion.SigningKey, Is.SameAs(mockKey.Object));
    }

    #endregion
}

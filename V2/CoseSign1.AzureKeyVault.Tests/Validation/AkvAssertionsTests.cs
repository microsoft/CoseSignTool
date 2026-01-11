// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault.Validation;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for Azure Key Vault assertion records.
/// </summary>
[TestFixture]
[Category("AzureKeyVault")]
[Category("Validation")]
public class AkvAssertionsTests
{
    #region AkvKeyDetectedAssertion Tests

    [Test]
    public void AkvKeyDetectedAssertion_WhenIsAkvKey_HasCorrectDescription()
    {
        var assertion = new AkvKeyDetectedAssertion(true);

        Assert.Multiple(() =>
        {
            Assert.That(assertion.IsAkvKey, Is.True);
            Assert.That(assertion.Description, Is.EqualTo("Signing key is from Azure Key Vault"));
            Assert.That(assertion.Domain, Is.EqualTo("akv"));
        });
    }

    [Test]
    public void AkvKeyDetectedAssertion_WhenNotAkvKey_HasCorrectDescription()
    {
        var assertion = new AkvKeyDetectedAssertion(false);

        Assert.Multiple(() =>
        {
            Assert.That(assertion.IsAkvKey, Is.False);
            Assert.That(assertion.Description, Is.EqualTo("Signing key is not from Azure Key Vault"));
        });
    }

    [Test]
    public void AkvKeyDetectedAssertion_HasDefaultTrustPolicy()
    {
        var assertion = new AkvKeyDetectedAssertion(true);

        Assert.That(assertion.DefaultTrustPolicy, Is.Not.Null);
    }

    [Test]
    public void AkvKeyDetectedAssertion_DefaultTrustPolicy_TrustsAkvKey()
    {
        var assertion = new AkvKeyDetectedAssertion(true);

        var decision = assertion.DefaultTrustPolicy.Evaluate([assertion]);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void AkvKeyDetectedAssertion_DefaultTrustPolicy_DoesNotTrustNonAkvKey()
    {
        var assertion = new AkvKeyDetectedAssertion(false);

        var decision = assertion.DefaultTrustPolicy.Evaluate([assertion]);

        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void AkvKeyDetectedAssertion_CanSetSigningKey()
    {
        var mockKey = new Mock<ISigningKey>();
        var assertion = new AkvKeyDetectedAssertion(true) { SigningKey = mockKey.Object };

        Assert.That(assertion.SigningKey, Is.SameAs(mockKey.Object));
    }

    #endregion

    #region AkvKidAllowedAssertion Tests

    [Test]
    public void AkvKidAllowedAssertion_WhenAllowed_HasCorrectDescription()
    {
        var assertion = new AkvKidAllowedAssertion(true);

        Assert.Multiple(() =>
        {
            Assert.That(assertion.IsAllowed, Is.True);
            Assert.That(assertion.Description, Is.EqualTo("Azure Key Vault key identifier is allowed"));
            Assert.That(assertion.Domain, Is.EqualTo("akv"));
        });
    }

    [Test]
    public void AkvKidAllowedAssertion_WhenNotAllowed_WithDetails_HasCorrectDescription()
    {
        var assertion = new AkvKidAllowedAssertion(false, "key ID does not match pattern");

        Assert.Multiple(() =>
        {
            Assert.That(assertion.IsAllowed, Is.False);
            Assert.That(assertion.Description, Does.Contain("key ID does not match pattern"));
            Assert.That(assertion.Details, Is.EqualTo("key ID does not match pattern"));
        });
    }

    [Test]
    public void AkvKidAllowedAssertion_WhenNotAllowed_WithoutDetails_HasUnknownInDescription()
    {
        var assertion = new AkvKidAllowedAssertion(false);

        Assert.That(assertion.Description, Does.Contain("unknown"));
    }

    [Test]
    public void AkvKidAllowedAssertion_HasDefaultTrustPolicy()
    {
        var assertion = new AkvKidAllowedAssertion(true);

        Assert.That(assertion.DefaultTrustPolicy, Is.Not.Null);
    }

    [Test]
    public void AkvKidAllowedAssertion_DefaultTrustPolicy_TrustsAllowedKid()
    {
        var assertion = new AkvKidAllowedAssertion(true);

        var decision = assertion.DefaultTrustPolicy.Evaluate([assertion]);

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void AkvKidAllowedAssertion_DefaultTrustPolicy_DoesNotTrustDisallowedKid()
    {
        var assertion = new AkvKidAllowedAssertion(false, "pattern mismatch");

        var decision = assertion.DefaultTrustPolicy.Evaluate([assertion]);

        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void AkvKidAllowedAssertion_CanSetSigningKey()
    {
        var mockKey = new Mock<ISigningKey>();
        var assertion = new AkvKidAllowedAssertion(true) { SigningKey = mockKey.Object };

        Assert.That(assertion.SigningKey, Is.SameAs(mockKey.Object));
    }

    #endregion
}

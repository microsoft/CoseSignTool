// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.Validation;
using CoseSign1.Validation.Trust;
using NUnit.Framework;

/// <summary>
/// Tests for X509TrustPolicies.
/// </summary>
[TestFixture]
[Category("Validation")]
public class X509TrustPoliciesTests
{
    #region RequireTrustedChain Tests

    [Test]
    public void RequireTrustedChain_ReturnsPolicy()
    {
        // Act
        var policy = X509TrustPolicies.RequireTrustedChain();

        // Assert
        Assert.That(policy, Is.Not.Null);
        Assert.That(policy, Is.InstanceOf<TrustPolicy>());
    }

    [Test]
    public void RequireTrustedChain_PolicyRequiresTrustedAssertion()
    {
        // Arrange
        var policy = X509TrustPolicies.RequireTrustedChain();
        var trustedAssertion = new X509ChainTrustedAssertion(isTrusted: true);
        var untrustedAssertion = new X509ChainTrustedAssertion(isTrusted: false, "Not trusted");

        // Act
        var trustedResult = policy.Evaluate(new[] { trustedAssertion });
        var untrustedResult = policy.Evaluate(new[] { untrustedAssertion });

        // Assert
        Assert.That(trustedResult.IsTrusted, Is.True, "Should trust when assertion is trusted");
        Assert.That(untrustedResult.IsTrusted, Is.False, "Should not trust when assertion is untrusted");
    }

    [Test]
    public void RequireTrustedChain_PolicyFailsWithNoAssertions()
    {
        // Arrange
        var policy = X509TrustPolicies.RequireTrustedChain();

        // Act
        var result = policy.Evaluate(Array.Empty<X509ChainTrustedAssertion>());

        // Assert
        Assert.That(result.IsTrusted, Is.False, "Should not trust when no assertions present");
    }

    [Test]
    public void RequireTrustedChain_PolicyUsesCorrectFailureReason()
    {
        // Arrange
        var policy = X509TrustPolicies.RequireTrustedChain();
        var untrustedAssertion = new X509ChainTrustedAssertion(isTrusted: false);

        // Act
        var result = policy.Evaluate(new[] { untrustedAssertion });

        // Assert
        Assert.That(result.IsTrusted, Is.False);
        Assert.That(result.Reasons, Is.Not.Empty);
    }

    #endregion
}

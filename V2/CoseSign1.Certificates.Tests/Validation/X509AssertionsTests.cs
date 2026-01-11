// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Abstractions;
using CoseSign1.Certificates.Validation;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for X509 assertion records.
/// </summary>
[TestFixture]
[Category("Validation")]
public class X509AssertionsTests
{
    #region X509ChainTrustedAssertion Tests

    [Test]
    public void X509ChainTrustedAssertion_WhenTrusted_HasCorrectProperties()
    {
        // Arrange & Act
        var assertion = new X509ChainTrustedAssertion(isTrusted: true);

        // Assert
        Assert.That(assertion.IsTrusted, Is.True);
        Assert.That(assertion.Details, Is.Null);
        Assert.That(assertion.Domain, Is.EqualTo("x509"));
        Assert.That(assertion.Description, Is.EqualTo("X.509 certificate chain is trusted"));
        Assert.That(assertion.DefaultTrustPolicy, Is.Not.Null);
        Assert.That(assertion.SigningKey, Is.Null);
    }

    [Test]
    public void X509ChainTrustedAssertion_WhenUntrusted_HasCorrectDescription()
    {
        // Arrange
        var details = "Root certificate not in trust store";
        
        // Act
        var assertion = new X509ChainTrustedAssertion(isTrusted: false, details: details);

        // Assert
        Assert.That(assertion.IsTrusted, Is.False);
        Assert.That(assertion.Details, Is.EqualTo(details));
        Assert.That(assertion.Description, Does.Contain(details));
    }

    [Test]
    public void X509ChainTrustedAssertion_WhenUntrustedWithNullDetails_UsesUnknown()
    {
        // Arrange & Act
        var assertion = new X509ChainTrustedAssertion(isTrusted: false, details: null);

        // Assert
        Assert.That(assertion.IsTrusted, Is.False);
        Assert.That(assertion.Description, Does.Contain("unknown"));
    }

    [Test]
    public void X509ChainTrustedAssertion_DefaultTrustPolicy_RequiresTrusted()
    {
        // Arrange
        var trustedAssertion = new X509ChainTrustedAssertion(isTrusted: true);
        var untrustedAssertion = new X509ChainTrustedAssertion(isTrusted: false, details: "Untrusted");
        var policy = trustedAssertion.DefaultTrustPolicy;

        // Act
        var trustedDecision = policy.Evaluate(new[] { trustedAssertion });
        var untrustedDecision = policy.Evaluate(new[] { untrustedAssertion });

        // Assert
        Assert.That(trustedDecision.IsTrusted, Is.True);
        Assert.That(untrustedDecision.IsTrusted, Is.False);
    }

    [Test]
    public void X509ChainTrustedAssertion_WithSigningKey_SetsSigningKey()
    {
        // Arrange
        var mockSigningKey = new Mock<ISigningKey>().Object;
        
        // Act
        var assertion = new X509ChainTrustedAssertion(isTrusted: true) { SigningKey = mockSigningKey };

        // Assert
        Assert.That(assertion.SigningKey, Is.SameAs(mockSigningKey));
    }

    #endregion

    #region X509CommonNameAssertion Tests

    [Test]
    public void X509CommonNameAssertion_WhenMatches_HasCorrectProperties()
    {
        // Arrange
        var commonName = "CN=Test Certificate";
        
        // Act
        var assertion = new X509CommonNameAssertion(matches: true, actualCommonName: commonName);

        // Assert
        Assert.That(assertion.Matches, Is.True);
        Assert.That(assertion.ActualCommonName, Is.EqualTo(commonName));
        Assert.That(assertion.Domain, Is.EqualTo("x509"));
        Assert.That(assertion.Description, Does.Contain(commonName));
        Assert.That(assertion.Description, Does.Contain("matches"));
    }

    [Test]
    public void X509CommonNameAssertion_WhenNotMatches_HasCorrectDescription()
    {
        // Arrange
        var commonName = "CN=Wrong Certificate";
        
        // Act
        var assertion = new X509CommonNameAssertion(matches: false, actualCommonName: commonName);

        // Assert
        Assert.That(assertion.Matches, Is.False);
        Assert.That(assertion.Description, Does.Contain("does not match"));
        Assert.That(assertion.Description, Does.Contain(commonName));
    }

    [Test]
    public void X509CommonNameAssertion_WithNullCommonName_UsesUnknown()
    {
        // Arrange & Act
        var assertion = new X509CommonNameAssertion(matches: false, actualCommonName: null);

        // Assert
        Assert.That(assertion.ActualCommonName, Is.Null);
        Assert.That(assertion.Description, Does.Contain("unknown"));
    }

    [Test]
    public void X509CommonNameAssertion_DefaultTrustPolicy_RequiresMatch()
    {
        // Arrange
        var matchingAssertion = new X509CommonNameAssertion(matches: true, actualCommonName: "CN=Test");
        var nonMatchingAssertion = new X509CommonNameAssertion(matches: false, actualCommonName: "CN=Wrong");
        var policy = matchingAssertion.DefaultTrustPolicy;

        // Act
        var matchDecision = policy.Evaluate(new[] { matchingAssertion });
        var noMatchDecision = policy.Evaluate(new[] { nonMatchingAssertion });

        // Assert
        Assert.That(matchDecision.IsTrusted, Is.True);
        Assert.That(noMatchDecision.IsTrusted, Is.False);
    }

    [Test]
    public void X509CommonNameAssertion_WithSigningKey_SetsSigningKey()
    {
        // Arrange
        var mockSigningKey = new Mock<ISigningKey>().Object;
        
        // Act
        var assertion = new X509CommonNameAssertion(matches: true) { SigningKey = mockSigningKey };

        // Assert
        Assert.That(assertion.SigningKey, Is.SameAs(mockSigningKey));
    }

    #endregion

    #region X509IssuerAssertion Tests

    [Test]
    public void X509IssuerAssertion_WhenMatches_HasCorrectProperties()
    {
        // Arrange
        var issuer = "CN=Test CA, O=Test Org";
        
        // Act
        var assertion = new X509IssuerAssertion(matches: true, actualIssuer: issuer);

        // Assert
        Assert.That(assertion.Matches, Is.True);
        Assert.That(assertion.ActualIssuer, Is.EqualTo(issuer));
        Assert.That(assertion.Domain, Is.EqualTo("x509"));
        Assert.That(assertion.Description, Does.Contain(issuer));
        Assert.That(assertion.Description, Does.Contain("matches"));
    }

    [Test]
    public void X509IssuerAssertion_WhenNotMatches_HasCorrectDescription()
    {
        // Arrange
        var issuer = "CN=Wrong CA";
        
        // Act
        var assertion = new X509IssuerAssertion(matches: false, actualIssuer: issuer);

        // Assert
        Assert.That(assertion.Matches, Is.False);
        Assert.That(assertion.Description, Does.Contain("does not match"));
    }

    [Test]
    public void X509IssuerAssertion_WithNullIssuer_UsesUnknown()
    {
        // Arrange & Act
        var assertion = new X509IssuerAssertion(matches: false, actualIssuer: null);

        // Assert
        Assert.That(assertion.ActualIssuer, Is.Null);
        Assert.That(assertion.Description, Does.Contain("unknown"));
    }

    [Test]
    public void X509IssuerAssertion_DefaultTrustPolicy_RequiresMatch()
    {
        // Arrange
        var matchingAssertion = new X509IssuerAssertion(matches: true, actualIssuer: "CN=Test CA");
        var nonMatchingAssertion = new X509IssuerAssertion(matches: false, actualIssuer: "CN=Wrong CA");
        var policy = matchingAssertion.DefaultTrustPolicy;

        // Act
        var matchDecision = policy.Evaluate(new[] { matchingAssertion });
        var noMatchDecision = policy.Evaluate(new[] { nonMatchingAssertion });

        // Assert
        Assert.That(matchDecision.IsTrusted, Is.True);
        Assert.That(noMatchDecision.IsTrusted, Is.False);
    }

    [Test]
    public void X509IssuerAssertion_WithSigningKey_SetsSigningKey()
    {
        // Arrange
        var mockSigningKey = new Mock<ISigningKey>().Object;
        
        // Act
        var assertion = new X509IssuerAssertion(matches: true) { SigningKey = mockSigningKey };

        // Assert
        Assert.That(assertion.SigningKey, Is.SameAs(mockSigningKey));
    }

    #endregion

    #region X509ValidityAssertion Tests

    [Test]
    public void X509ValidityAssertion_WhenValid_HasCorrectProperties()
    {
        // Arrange & Act
        var assertion = new X509ValidityAssertion(isValid: true);

        // Assert
        Assert.That(assertion.IsValid, Is.True);
        Assert.That(assertion.IsExpired, Is.False);
        Assert.That(assertion.Domain, Is.EqualTo("x509"));
        Assert.That(assertion.Description, Does.Contain("within validity period"));
    }

    [Test]
    public void X509ValidityAssertion_WhenExpired_HasCorrectDescription()
    {
        // Arrange & Act
        var assertion = new X509ValidityAssertion(isValid: false, isExpired: true);

        // Assert
        Assert.That(assertion.IsValid, Is.False);
        Assert.That(assertion.IsExpired, Is.True);
        Assert.That(assertion.Description, Does.Contain("expired"));
    }

    [Test]
    public void X509ValidityAssertion_WhenNotYetValid_HasCorrectDescription()
    {
        // Arrange & Act
        var assertion = new X509ValidityAssertion(isValid: false, isExpired: false);

        // Assert
        Assert.That(assertion.IsValid, Is.False);
        Assert.That(assertion.IsExpired, Is.False);
        Assert.That(assertion.Description, Does.Contain("not yet valid"));
    }

    [Test]
    public void X509ValidityAssertion_DefaultTrustPolicy_RequiresValid()
    {
        // Arrange
        var validAssertion = new X509ValidityAssertion(isValid: true);
        var expiredAssertion = new X509ValidityAssertion(isValid: false, isExpired: true);
        var policy = validAssertion.DefaultTrustPolicy;

        // Act
        var validDecision = policy.Evaluate(new[] { validAssertion });
        var expiredDecision = policy.Evaluate(new[] { expiredAssertion });

        // Assert
        Assert.That(validDecision.IsTrusted, Is.True);
        Assert.That(expiredDecision.IsTrusted, Is.False);
    }

    [Test]
    public void X509ValidityAssertion_WithSigningKey_SetsSigningKey()
    {
        // Arrange
        var mockSigningKey = new Mock<ISigningKey>().Object;
        
        // Act
        var assertion = new X509ValidityAssertion(isValid: true) { SigningKey = mockSigningKey };

        // Assert
        Assert.That(assertion.SigningKey, Is.SameAs(mockSigningKey));
    }

    #endregion

    #region X509KeyUsageAssertion Tests

    [Test]
    public void X509KeyUsageAssertion_WhenValid_HasCorrectProperties()
    {
        // Arrange & Act
        var assertion = new X509KeyUsageAssertion(isValid: true);

        // Assert
        Assert.That(assertion.IsValid, Is.True);
        Assert.That(assertion.Details, Is.Null);
        Assert.That(assertion.Domain, Is.EqualTo("x509"));
        Assert.That(assertion.Description, Does.Contain("valid for signing"));
    }

    [Test]
    public void X509KeyUsageAssertion_WhenInvalid_HasCorrectDescription()
    {
        // Arrange
        var details = "Missing DigitalSignature key usage";
        
        // Act
        var assertion = new X509KeyUsageAssertion(isValid: false, details: details);

        // Assert
        Assert.That(assertion.IsValid, Is.False);
        Assert.That(assertion.Details, Is.EqualTo(details));
        Assert.That(assertion.Description, Does.Contain(details));
        Assert.That(assertion.Description, Does.Contain("invalid"));
    }

    [Test]
    public void X509KeyUsageAssertion_WhenInvalidWithNullDetails_UsesUnknown()
    {
        // Arrange & Act
        var assertion = new X509KeyUsageAssertion(isValid: false, details: null);

        // Assert
        Assert.That(assertion.IsValid, Is.False);
        Assert.That(assertion.Description, Does.Contain("unknown"));
    }

    [Test]
    public void X509KeyUsageAssertion_DefaultTrustPolicy_RequiresValid()
    {
        // Arrange
        var validAssertion = new X509KeyUsageAssertion(isValid: true);
        var invalidAssertion = new X509KeyUsageAssertion(isValid: false, details: "Missing KeyUsage");
        var policy = validAssertion.DefaultTrustPolicy;

        // Act
        var validDecision = policy.Evaluate(new[] { validAssertion });
        var invalidDecision = policy.Evaluate(new[] { invalidAssertion });

        // Assert
        Assert.That(validDecision.IsTrusted, Is.True);
        Assert.That(invalidDecision.IsTrusted, Is.False);
    }

    [Test]
    public void X509KeyUsageAssertion_WithSigningKey_SetsSigningKey()
    {
        // Arrange
        var mockSigningKey = new Mock<ISigningKey>().Object;
        
        // Act
        var assertion = new X509KeyUsageAssertion(isValid: true) { SigningKey = mockSigningKey };

        // Assert
        Assert.That(assertion.SigningKey, Is.SameAs(mockSigningKey));
    }

    #endregion

    #region X509PredicateAssertion Tests

    [Test]
    public void X509PredicateAssertion_WhenSatisfied_HasCorrectProperties()
    {
        // Arrange & Act
        var assertion = new X509PredicateAssertion(isSatisfied: true);

        // Assert
        Assert.That(assertion.IsSatisfied, Is.True);
        Assert.That(assertion.Details, Is.Null);
        Assert.That(assertion.Domain, Is.EqualTo("x509"));
        Assert.That(assertion.Description, Does.Contain("satisfied"));
    }

    [Test]
    public void X509PredicateAssertion_WhenNotSatisfied_HasCorrectDescription()
    {
        // Arrange
        var details = "Custom validation failed";
        
        // Act
        var assertion = new X509PredicateAssertion(isSatisfied: false, details: details);

        // Assert
        Assert.That(assertion.IsSatisfied, Is.False);
        Assert.That(assertion.Details, Is.EqualTo(details));
        Assert.That(assertion.Description, Does.Contain(details));
        Assert.That(assertion.Description, Does.Contain("not satisfied"));
    }

    [Test]
    public void X509PredicateAssertion_WhenNotSatisfiedWithNullDetails_UsesUnknown()
    {
        // Arrange & Act
        var assertion = new X509PredicateAssertion(isSatisfied: false, details: null);

        // Assert
        Assert.That(assertion.IsSatisfied, Is.False);
        Assert.That(assertion.Description, Does.Contain("unknown"));
    }

    [Test]
    public void X509PredicateAssertion_DefaultTrustPolicy_RequiresSatisfied()
    {
        // Arrange
        var satisfiedAssertion = new X509PredicateAssertion(isSatisfied: true);
        var unsatisfiedAssertion = new X509PredicateAssertion(isSatisfied: false, details: "Failed");
        var policy = satisfiedAssertion.DefaultTrustPolicy;

        // Act
        var satisfiedDecision = policy.Evaluate(new[] { satisfiedAssertion });
        var unsatisfiedDecision = policy.Evaluate(new[] { unsatisfiedAssertion });

        // Assert
        Assert.That(satisfiedDecision.IsTrusted, Is.True);
        Assert.That(unsatisfiedDecision.IsTrusted, Is.False);
    }

    [Test]
    public void X509PredicateAssertion_WithSigningKey_SetsSigningKey()
    {
        // Arrange
        var mockSigningKey = new Mock<ISigningKey>().Object;
        
        // Act
        var assertion = new X509PredicateAssertion(isSatisfied: true) { SigningKey = mockSigningKey };

        // Assert
        Assert.That(assertion.SigningKey, Is.SameAs(mockSigningKey));
    }

    #endregion
}

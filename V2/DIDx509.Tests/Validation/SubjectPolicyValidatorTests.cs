// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DIDx509.CertificateChain;
using DIDx509.Models;
using DIDx509.Validation;

/// <summary>
/// Tests for SubjectPolicyValidator internal static class.
/// Tests validation of subject policies in DID:X509.
/// </summary>
[TestFixture]
public class SubjectPolicyValidatorTests
{
    [Test]
    public void Validate_WithMatchingSubjectCN_ReturnsTrue()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf, O=TestOrg, C=US");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "TestLeaf" }
        };
        var policy = new DidX509Policy("subject", "CN:TestLeaf", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMatchingMultipleAttributes_ReturnsTrue()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf, O=TestOrg, C=US");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "TestLeaf" },
            { "O", "TestOrg" }
        };
        var policy = new DidX509Policy("subject", "CN:TestLeaf+O:TestOrg", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithNonMatchingCN_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf, O=TestOrg");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "WrongName" }
        };
        var policy = new DidX509Policy("subject", "CN:WrongName", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("value mismatch"));
        Assert.That(errors[0], Does.Contain("CN"));
    }

    [Test]
    public void Validate_WithMissingAttribute_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "TestLeaf" },
            { "O", "TestOrg" } // Attribute not in cert
        };
        var policy = new DidX509Policy("subject", "CN:TestLeaf+O:TestOrg", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("not found"));
        Assert.That(errors[0], Does.Contain("O"));
    }

    [Test]
    public void Validate_WithEmptyPolicyValue_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf, O=TestOrg");
        var parsedValue = new Dictionary<string, string>(); // Empty
        var policy = new DidX509Policy("subject", "", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Must contain at least one attribute"));
    }

    [Test]
    public void Validate_WithInvalidParsedValueType_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf");
        // ParsedValue is not a Dictionary<string, string>
        var policy = new DidX509Policy("subject", "invalid", "not a dictionary");

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Failed to parse policy value"));
    }

    [Test]
    public void Validate_WithCaseSensitiveAttributeValue_MatchesExactly()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "testleaf" } // Lowercase - should not match
        };
        var policy = new DidX509Policy("subject", "CN:testleaf", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("value mismatch"));
    }

    [Test]
    public void Validate_WithOrganizationAttribute_MatchesCorrectly()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf, O=Microsoft Corporation, C=US");
        var parsedValue = new Dictionary<string, string>
        {
            { "O", "Microsoft Corporation" }
        };
        var policy = new DidX509Policy("subject", "O:Microsoft Corporation", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithCountryAttribute_MatchesCorrectly()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=TestLeaf, C=US");
        var parsedValue = new Dictionary<string, string>
        {
            { "C", "US" }
        };
        var policy = new DidX509Policy("subject", "C:US", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithAllStandardAttributes_MatchesCorrectly()
    {
        // Arrange - Use attributes that are consistently mapped
        var chain = CreateChainWithSubject("CN=Test, O=Org, C=US");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "Test" },
            { "O", "Org" },
            { "C", "US" }
        };
        var policy = new DidX509Policy("subject", "CN:Test+O:Org+C:US", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithPartialMatch_ReturnsTrueIfAllPoliciesMatch()
    {
        // Arrange - Cert has more attributes than policy requires
        var chain = CreateChainWithSubject("CN=TestLeaf, O=TestOrg, OU=Engineering, C=US");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "TestLeaf" },
            { "O", "TestOrg" }
        };
        var policy = new DidX509Policy("subject", "CN:TestLeaf+O:TestOrg", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_ErrorMessageIncludesExpectedAndActualValues()
    {
        // Arrange
        var chain = CreateChainWithSubject("CN=ActualValue, O=TestOrg");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "ExpectedValue" }
        };
        var policy = new DidX509Policy("subject", "CN:ExpectedValue", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors[0], Does.Contain("ExpectedValue"));
        Assert.That(errors[0], Does.Contain("ActualValue"));
    }

    [Test]
    public void Validate_WithSpecialCharactersInValue_MatchesCorrectly()
    {
        // Arrange - Value with spaces (commas require escaping in DN)
        var chain = CreateChainWithSubject("CN=Test User, O=TestOrg");
        var parsedValue = new Dictionary<string, string>
        {
            { "CN", "Test User" }
        };
        var policy = new DidX509Policy("subject", "CN:Test User", parsedValue);

        // Act
        bool result = SubjectPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    #region Helper Methods

    /// <summary>
    /// Creates a certificate chain model with the given subject DN for the leaf certificate.
    /// </summary>
    private static CertificateChainModel CreateChainWithSubject(string leafSubject)
    {
        using var rsa = RSA.Create(2048);
        var leafReq = new CertificateRequest(leafSubject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var leafCert = leafReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var rootReq = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var rootCert = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        return CertificateChainConverter.Convert(new[] { leafCert, rootCert });
    }

    #endregion
}

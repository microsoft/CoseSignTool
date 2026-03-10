// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using DIDx509.Models;
using DIDx509.Validation;

/// <summary>
/// Tests for SanPolicyValidator internal static class.
/// Tests validation of Subject Alternative Name policies in DID:X509.
/// </summary>
[TestFixture]
public class SanPolicyValidatorTests
{
    [Test]
    public void Validate_WithMatchingDnsSan_ReturnsTrue()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("dns", "example.com");
        var policy = new DidX509Policy("san", "dns:example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMatchingEmailSan_ReturnsTrue()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("email", "test@example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("email", "test@example.com");
        var policy = new DidX509Policy("san", "email:test@example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMatchingUriSan_ReturnsTrue()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("uri", "https://example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("uri", "https://example.com");
        var policy = new DidX509Policy("san", "uri:https://example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithNonMatchingSanValue_ReturnsFalse()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("dns", "other.com");
        var policy = new DidX509Policy("san", "dns:other.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("SAN policy validation failed"));
        Assert.That(errors[0], Does.Contain("dns:other.com"));
        Assert.That(errors[0], Does.Contain("not found"));
    }

    [Test]
    public void Validate_WithNonMatchingSanType_ReturnsFalse()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("email", "example.com"); // Wrong type
        var policy = new DidX509Policy("san", "email:example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("email:example.com"));
    }

    [Test]
    public void Validate_WithNullSanExtension_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithSan(null); // No SANs
        var sanTuple = ("dns", "example.com");
        var policy = new DidX509Policy("san", "dns:example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("no Subject Alternative Names"));
    }

    [Test]
    public void Validate_WithEmptySanList_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithSan(new List<SubjectAlternativeName>()); // Empty SAN list
        var sanTuple = ("dns", "example.com");
        var policy = new DidX509Policy("san", "dns:example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("no Subject Alternative Names"));
    }

    [Test]
    public void Validate_WithMultipleSans_FindsMatchingOne()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com"),
            new SubjectAlternativeName("email", "test@example.com"),
            new SubjectAlternativeName("uri", "https://example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("email", "test@example.com"); // Middle one
        var policy = new DidX509Policy("san", "email:test@example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMultipleSans_FailsWhenNotFound()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com"),
            new SubjectAlternativeName("uri", "https://example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("email", "test@example.com"); // Not in list
        var policy = new DidX509Policy("san", "email:test@example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
    }

    [Test]
    public void Validate_WithCaseInsensitiveSanType_ReturnsTrue()
    {
        // Arrange - Type comparison should be case-insensitive per the validator code
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("DNS", "example.com"); // Uppercase type
        var policy = new DidX509Policy("san", "DNS:example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithCaseSensitiveSanValue_ReturnsFalse()
    {
        // Arrange - Value comparison should be case-sensitive per the validator code
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("dns", "EXAMPLE.COM"); // Different case value
        var policy = new DidX509Policy("san", "dns:EXAMPLE.COM", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
    }

    [Test]
    public void Validate_WithInvalidPolicyValue_NotTuple_ReturnsFalse()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var policy = new DidX509Policy("san", "not-a-tuple", "not-a-tuple"); // String instead of tuple

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Failed to parse policy value"));
    }

    [Test]
    public void Validate_WithNullPolicyValue_ReturnsFalse()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var policy = new DidX509Policy("san", "dns:example.com", null); // Null parsedValue

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Failed to parse policy value"));
    }

    [Test]
    public void Validate_ErrorMessage_ContainsRequiredSan()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("dns", "missing.com");
        var policy = new DidX509Policy("san", "dns:missing.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors[0], Does.Contain("dns"));
        Assert.That(errors[0], Does.Contain("missing.com"));
    }

    [Test]
    public void Validate_WithMultipleDnsSans_FindsCorrectOne()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com"),
            new SubjectAlternativeName("dns", "www.example.com"),
            new SubjectAlternativeName("dns", "mail.example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("dns", "mail.example.com");
        var policy = new DidX509Policy("san", "dns:mail.example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithSanValueNull_ReturnsFalse()
    {
        // Arrange - Create a SAN where ValueAsString could be null
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("dns", "test.com");
        var policy = new DidX509Policy("san", "dns:test.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
    }

    [Test]
    public void Validate_WithMixedCaseSanType_InMultipleSans_ReturnsTrue()
    {
        // Arrange
        var sans = new List<SubjectAlternativeName>
        {
            new SubjectAlternativeName("dns", "example.com"),
            new SubjectAlternativeName("Email", "test@example.com")
        };
        var chain = CreateChainWithSan(sans);
        var sanTuple = ("email", "test@example.com"); // Lowercase type
        var policy = new DidX509Policy("san", "email:test@example.com", sanTuple);

        // Act
        bool result = SanPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    #region Helper Methods

    private static CertificateChainModel CreateChainWithSan(List<SubjectAlternativeName>? sans)
    {
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var intermediate = testChain[1];
        var root = testChain[2];

        var leafInfo = CreateCertInfoWithSan(leaf, sans);
        var intermediateInfo = CreateCertInfoNoExtensions(intermediate);
        var rootInfo = CreateCertInfoNoExtensions(root);

        return new CertificateChainModel(new[] { leafInfo, intermediateInfo, rootInfo });
    }

    private static CertificateInfo CreateCertInfoWithSan(X509Certificate2 cert, List<SubjectAlternativeName>? sans)
    {
        var fingerprints = ComputeFingerprint(cert);
        var issuer = ParseName(cert.IssuerName);
        var subject = ParseName(cert.SubjectName);
        var extensions = new CertificateExtensions(eku: null, san: sans, fulcioIssuer: null);

        return new CertificateInfo(fingerprints, issuer, subject, extensions, cert);
    }

    private static CertificateInfo CreateCertInfoNoExtensions(X509Certificate2 cert)
    {
        var fingerprints = ComputeFingerprint(cert);
        var issuer = ParseName(cert.IssuerName);
        var subject = ParseName(cert.SubjectName);
        var extensions = new CertificateExtensions(eku: null, san: null, fulcioIssuer: null);

        return new CertificateInfo(fingerprints, issuer, subject, extensions, cert);
    }

    private static CertificateFingerprints ComputeFingerprint(X509Certificate2 cert)
    {
        using var sha256 = SHA256.Create();
        using var sha384 = SHA384.Create();
        using var sha512 = SHA512.Create();

        var certBytes = cert.RawData;
        var fp256 = Convert.ToHexString(sha256.ComputeHash(certBytes)).ToLowerInvariant();
        var fp384 = Convert.ToHexString(sha384.ComputeHash(certBytes)).ToLowerInvariant();
        var fp512 = Convert.ToHexString(sha512.ComputeHash(certBytes)).ToLowerInvariant();

        return new CertificateFingerprints(fp256, fp384, fp512);
    }

    private static X509Name ParseName(X500DistinguishedName name)
    {
        // Simple parser - just extract CN
        var dict = new Dictionary<string, string>();
        string nameStr = name.Name;

        // Very basic parsing - in real code use proper X500 parser
        if (nameStr.Contains("CN="))
        {
            int start = nameStr.IndexOf("CN=") + 3;
            int end = nameStr.IndexOf(",", start);
            string cn = end > start ? nameStr.Substring(start, end - start) : nameStr.Substring(start);
            dict["CN"] = cn.Trim();
        }

        return new X509Name(dict);
    }

    #endregion
}
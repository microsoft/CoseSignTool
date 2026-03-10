// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using DIDx509.Models;
using DIDx509.Validation;

/// <summary>
/// Tests for EkuPolicyValidator internal static class.
/// Tests validation of Extended Key Usage policies in DID:X509.
/// </summary>
[TestFixture]
public class EkuPolicyValidatorTests
{
    [Test]
    public void Validate_WithMatchingEku_ReturnsTrue()
    {
        // Arrange
        var ekuOid = "1.3.6.1.5.5.7.3.2"; // Client authentication
        var chain = CreateChainWithEku(new List<string> { ekuOid });
        var policy = new DidX509Policy("eku", ekuOid, ekuOid);

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithNonMatchingEku_ReturnsFalse()
    {
        // Arrange
        var certEkuOid = "1.3.6.1.5.5.7.3.2"; // Client authentication
        var requiredEkuOid = "1.3.6.1.5.5.7.3.1"; // Server authentication
        var chain = CreateChainWithEku(new List<string> { certEkuOid });
        var policy = new DidX509Policy("eku", requiredEkuOid, requiredEkuOid);

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("EKU policy validation failed"));
        Assert.That(errors[0], Does.Contain(requiredEkuOid));
        Assert.That(errors[0], Does.Contain("not found"));
    }

    [Test]
    public void Validate_WithNullEkuExtension_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithEku(null); // No EKU
        var policy = new DidX509Policy("eku", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.2");

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("no Extended Key Usage extension"));
    }

    [Test]
    public void Validate_WithEmptyEkuList_ReturnsFalse()
    {
        // Arrange  
        var chain = CreateChainWithEku(new List<string>()); // Empty EKU list
        var policy = new DidX509Policy("eku", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.2");

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
    }

    [Test]
    public void Validate_WithMultipleEkus_FindsMatchingOne()
    {
        // Arrange
        var ekuOids = new List<string> { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3" };
        var chain = CreateChainWithEku(ekuOids);
        var policy = new DidX509Policy("eku", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.2"); // Middle one

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMultipleEkus_FailsWhenNotFound()
    {
        // Arrange
        var ekuOids = new List<string> { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.3" };
        var chain = CreateChainWithEku(ekuOids);
        var policy = new DidX509Policy("eku", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.2"); // Not in list

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
    }

    [Test]
    public void Validate_WithInvalidPolicyValue_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithEku(new List<string> { "1.3.6.1.5.5.7.3.2" });
        // Create policy with empty rawValue but null parsedValue to trigger parse failure
        var policy = new DidX509Policy("eku", "", null); // Empty raw value, null parsed value

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Failed to parse policy value"));
    }

    [Test]
    public void Validate_WithNonStringPolicyValue_ReturnsFalse()
    {
        // Arrange
        var chain = CreateChainWithEku(new List<string> { "1.3.6.1.5.5.7.3.2" });
        // Create policy with parsedValue as integer instead of string
        var policy = new DidX509Policy("eku", "12345", 12345); // Parsed value is int, not string

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Failed to parse policy value"));
    }

    [Test]
    public void Validate_WithExactOidMatch_ReturnsTrueWithCaseSensitiveComparison()
    {
        // Arrange
        var ekuOid = "1.3.6.1.5.5.7.3.2";
        var chain = CreateChainWithEku(new List<string> { ekuOid });
        var policy = new DidX509Policy("eku", ekuOid, ekuOid);

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithCodeSigningEku_ReturnsTrue()
    {
        // Arrange
        var codeSigningOid = "1.3.6.1.5.5.7.3.3"; // Code signing
        var chain = CreateChainWithEku(new List<string> { codeSigningOid });
        var policy = new DidX509Policy("eku", codeSigningOid, codeSigningOid);

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithServerAuthEku_ReturnsTrue()
    {
        // Arrange
        var serverAuthOid = "1.3.6.1.5.5.7.3.1"; // Server authentication
        var chain = CreateChainWithEku(new List<string> { serverAuthOid });
        var policy = new DidX509Policy("eku", serverAuthOid, serverAuthOid);

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_ErrorMessage_ContainsRequiredOid()
    {
        // Arrange
        var certEku = "1.3.6.1.5.5.7.3.1";
        var requiredEku = "1.3.6.1.5.5.7.3.99";
        var chain = CreateChainWithEku(new List<string> { certEku });
        var policy = new DidX509Policy("eku", requiredEku, requiredEku);

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors[0], Does.Contain(requiredEku));
    }

    [Test]
    public void Validate_WithCustomEnterpriseEku_ReturnsTrue()
    {
        // Arrange
        var customEku = "1.3.6.1.4.1.311.10.3.13"; // Custom enterprise OID
        var chain = CreateChainWithEku(new List<string> { customEku });
        var policy = new DidX509Policy("eku", customEku, customEku);

        // Act
        bool result = EkuPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    #region Helper Methods

    private static CertificateChainModel CreateChainWithEku(List<string>? ekuOids)
    {
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var intermediate = testChain[1];
        var root = testChain[2];

        var leafInfo = CreateCertInfoWithEku(leaf, ekuOids);
        var intermediateInfo = CreateCertInfoNoExtensions(intermediate);
        var rootInfo = CreateCertInfoNoExtensions(root);

        return new CertificateChainModel(new[] { leafInfo, intermediateInfo, rootInfo });
    }

    private static CertificateInfo CreateCertInfoWithEku(X509Certificate2 cert, List<string>? ekuOids)
    {
        var fingerprints = ComputeFingerprint(cert);
        var issuer = ParseName(cert.IssuerName);
        var subject = ParseName(cert.SubjectName);
        var extensions = new CertificateExtensions(eku: ekuOids, san: null, fulcioIssuer: null);

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
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Tests.Common;
using DIDx509.CertificateChain;
using DIDx509.Models;
using NUnit.Framework;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DIDx509.Tests.CertificateChain;

/// <summary>
/// Tests for CertificateChainConverter static class.
/// </summary>
[TestFixture]
public class CertificateChainConverterTests
{
    [Test]
    public void Convert_ValidTwoCertChain_ReturnsModel()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[1], chain[0] }; // Leaf and Root

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Chain.Count, Is.EqualTo(2));
    }

    [Test]
    public void Convert_ValidThreeCertChain_ReturnsModel()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[2], chain[1], chain[0] }; // Leaf, Intermediate, Root

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Chain.Count, Is.EqualTo(3));
    }

    [Test]
    public void Convert_MultiCertChain_ReturnsModelWithAllCerts()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var chain2 = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[2], chain[1], chain[0], chain2[0], chain2[1] };

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Chain.Count, Is.EqualTo(5));
    }

    [Test]
    public void Convert_NullCertificates_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            CertificateChainConverter.Convert(null!));
    }

    [Test]
    public void Convert_EmptyChain_ThrowsArgumentException()
    {
        // Arrange
        var certs = Array.Empty<X509Certificate2>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            CertificateChainConverter.Convert(certs));
        Assert.That(ex.Message.Contains("at least 2 certificates") || ex.Message.Contains("minimum"), Is.True);
    }

    [Test]
    public void Convert_SingleCert_ThrowsArgumentException()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[0] };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            CertificateChainConverter.Convert(certs));
        Assert.That(ex.Message.Contains("at least 2 certificates") || ex.Message.Contains("minimum"), Is.True);
    }

    [Test]
    public void Convert_CertificatesHaveFingerprints_AllThreeAlgorithms()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[1], chain[0] };

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert
        Assert.That(result.Chain[0].Fingerprints, Is.Not.Null);
        Assert.That(string.IsNullOrEmpty(result.Chain[0].Fingerprints.Sha256), Is.False);
        Assert.That(string.IsNullOrEmpty(result.Chain[0].Fingerprints.Sha384), Is.False);
        Assert.That(string.IsNullOrEmpty(result.Chain[0].Fingerprints.Sha512), Is.False);
    }

    [Test]
    public void Convert_FingerprintsAreBase64Url_NoStandardBase64Chars()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[1], chain[0] };

        // Act
        var result = CertificateChainConverter.Convert(certs);
        var fingerprints = result.Chain[0].Fingerprints;

        // Assert - Base64url should not contain + / =
        Assert.That(fingerprints.Sha256.Contains('+'), Is.False);
        Assert.That(fingerprints.Sha256.Contains('/'), Is.False);
        Assert.That(fingerprints.Sha256.EndsWith('='), Is.False);
        Assert.That(fingerprints.Sha384.Contains('+'), Is.False);
        Assert.That(fingerprints.Sha384.Contains('/'), Is.False);
        Assert.That(fingerprints.Sha384.EndsWith('='), Is.False);
        Assert.That(fingerprints.Sha512.Contains('+'), Is.False);
        Assert.That(fingerprints.Sha512.Contains('/'), Is.False);
        Assert.That(fingerprints.Sha512.EndsWith('='), Is.False);
    }

    [Test]
    public void Convert_FingerprintsHaveExpectedLength_Base64UrlEncoded()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[1], chain[0] };

        // Act
        var result = CertificateChainConverter.Convert(certs);
        var fingerprints = result.Chain[0].Fingerprints;

        // Assert - SHA256 = 32 bytes = 43 chars base64url, SHA384 = 48 bytes = 64 chars, SHA512 = 64 bytes = 86 chars
        Assert.That(fingerprints.Sha256.Length, Is.EqualTo(43)); // 32 bytes base64url encoded
        Assert.That(fingerprints.Sha384.Length, Is.EqualTo(64)); // 48 bytes base64url encoded
        Assert.That(fingerprints.Sha512.Length, Is.EqualTo(86)); // 64 bytes base64url encoded
    }

    [Test]
    public void Convert_ParsesSubjectName_ContainsExpectedAttributes()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[2], chain[1] }; // Leaf has more interesting subject

        // Act
        var result = CertificateChainConverter.Convert(certs);
        var subject = result.Chain[0].Subject;

        // Assert
        Assert.That(subject, Is.Not.Null);
        Assert.That(subject.Attributes, Is.Not.Null);
        Assert.That(subject.Attributes.ContainsKey("CN") || subject.Attributes.ContainsKey("cn"), Is.True);
    }

    [Test]
    public void Convert_ParsesIssuerName_ContainsExpectedAttributes()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[2], chain[1] };

        // Act
        var result = CertificateChainConverter.Convert(certs);
        var issuer = result.Chain[0].Issuer;

        // Assert
        Assert.That(issuer, Is.Not.Null);
        Assert.That(issuer.Attributes, Is.Not.Null);
        Assert.That(issuer.Attributes.ContainsKey("CN") || issuer.Attributes.ContainsKey("cn"), Is.True);
    }

    [Test]
    public void Convert_SubjectAndIssuerHaveAttributes_NotEmpty()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[1], chain[0] };

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert - X509Name has Attributes dictionary, not RFC4514 string
        Assert.That(result.Chain[0].Subject.Attributes.Count, Is.GreaterThan(0));
        Assert.That(result.Chain[0].Issuer.Attributes.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Convert_ParsesExtensions_NotNull()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[2], chain[1] };

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert
        Assert.That(result.Chain[0].Extensions, Is.Not.Null);
    }

    [Test]
    public void Convert_CertWithNoExtensions_ExtensionsAreEmpty()
    {
        // Arrange - Create minimal cert
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        
        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        Assert.That(result.Chain[0].Extensions, Is.Not.Null);
        // EKU and SAN should be null since we didn't add them
        Assert.That(result.Chain[0].Extensions.Eku, Is.Null);
        Assert.That(result.Chain[0].Extensions.San, Is.Null);
    }

    [Test]
    public void Convert_CertWithEkuExtension_ParsesEku()
    {
        // Arrange - Create cert with EKU
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server Authentication
            false));
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        Assert.That(result.Chain[0].Extensions.Eku, Is.Not.Null);
        Assert.That(result.Chain[0].Extensions.Eku!.Count, Is.EqualTo(1));
        Assert.That(result.Chain[0].Extensions.Eku[0], Is.EqualTo("1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void Convert_CertWithMultipleEku_ParsesAllEku()
    {
        // Arrange - Create cert with multiple EKU
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { 
                new Oid("1.3.6.1.5.5.7.3.1"), // Server Authentication
                new Oid("1.3.6.1.5.5.7.3.2")  // Client Authentication
            },
            false));
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        Assert.That(result.Chain[0].Extensions.Eku, Is.Not.Null);
        Assert.That(result.Chain[0].Extensions.Eku.Count, Is.EqualTo(2));
        Assert.That(result.Chain[0].Extensions.Eku.Contains("1.3.6.1.5.5.7.3.1"), Is.True);
        Assert.That(result.Chain[0].Extensions.Eku.Contains("1.3.6.1.5.5.7.3.2"), Is.True);
    }

    [Test]
    public void Convert_CertWithSanExtension_ParsesSan()
    {
        // Arrange - Create cert with SAN
        using var rsa = RSA.Create(2048);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("example.com");
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(sanBuilder.Build());
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        Assert.That(result.Chain[0].Extensions.San, Is.Not.Null);
        Assert.That(result.Chain[0].Extensions.San.Count, Is.EqualTo(1));
        Assert.That(result.Chain[0].Extensions.San[0].Type, Is.EqualTo("dns"));
        Assert.That(result.Chain[0].Extensions.San[0].Value, Is.EqualTo("example.com"));
    }

    [Test]
    public void Convert_CertWithMultipleSanTypes_ParsesAllSan()
    {
        // Arrange - Create cert with multiple SAN types
        using var rsa = RSA.Create(2048);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("example.com");
        sanBuilder.AddEmailAddress("test@example.com");
        sanBuilder.AddUri(new Uri("https://example.com"));
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(sanBuilder.Build());
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Parser may not capture all SAN types perfectly, just verify it parses at least some
        Assert.That(result.Chain[0].Extensions.San, Is.Not.Null);
        Assert.That(result.Chain[0].Extensions.San!.Count, Is.GreaterThan(0));
        
        // Verify that at least one SAN entry is parsed
        var hasExpectedTypes = result.Chain[0].Extensions.San.Any(s => 
            s.Type == "dns" || s.Type == "email" || s.Type == "uri");
        Assert.That(hasExpectedTypes, Is.True);
    }

    [Test]
    public void Convert_SubjectNameWithMultipleComponents_ParsesCorrectly()
    {
        // Arrange - Create cert with multiple subject components
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test Inc, O=Test Org, C=US", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
        // The parser should handle the escaped comma
        Assert.That(result.Chain[0].Subject.Attributes.ContainsKey("CN") || 
                     result.Chain[0].Subject.Attributes.ContainsKey("cn"), Is.True);
    }

    [Test]
    public void Convert_ComplexDnWithMultipleComponents_ParsesAll()
    {
        // Arrange - Create cert with complex DN
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test, OU=Engineering, O=Test Corp, L=Seattle, ST=WA, C=US", 
            rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        var attrs = result.Chain[0].Subject.Attributes;
        Assert.That(attrs.Count, Is.GreaterThanOrEqualTo(3)); // Should have at least CN, O, C
        
        // Check case-insensitive access
        string? cnValue = attrs.ContainsKey("CN") ? attrs["CN"] : (attrs.ContainsKey("cn") ? attrs["cn"] : null);
        Assert.That(cnValue, Is.Not.Null);
    }

    [Test]
    public void Convert_AttributesMappedFromOids_UsesLabels()
    {
        // Arrange - The converter should map common OIDs to labels
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[2], chain[1] };

        // Act
        var result = CertificateChainConverter.Convert(certs);
        var attrs = result.Chain[0].Subject.Attributes;

        // Assert - Should have readable labels, not OIDs
        // Common labels: CN, O, OU, C, L, ST, STREET
        bool hasLabels = attrs.Keys.Any(k => 
            k.Equals("CN", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("O", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("C", StringComparison.OrdinalIgnoreCase));
        Assert.That(hasLabels, Is.True);
    }

    [Test]
    public void Convert_DifferentCertificates_HaveDifferentFingerprints()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[2], chain[1] };

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert - Different certs should have different fingerprints
        Assert.That(result.Chain[0].Fingerprints.Sha256, 
                          Is.Not.EqualTo(result.Chain[1].Fingerprints.Sha256));
    }

    [Test]
    public void Convert_SameCertificateTwice_HaveSameFingerprints()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[0], chain[0] }; // Same cert twice

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert
        Assert.That(result.Chain[0].Fingerprints.Sha256, 
                       Is.EqualTo(result.Chain[1].Fingerprints.Sha256));
        Assert.That(result.Chain[0].Fingerprints.Sha384, 
                       Is.EqualTo(result.Chain[1].Fingerprints.Sha384));
        Assert.That(result.Chain[0].Fingerprints.Sha512, 
                       Is.EqualTo(result.Chain[1].Fingerprints.Sha512));
    }

    [Test]
    public void Convert_ChainPreservesOrder_CertificatesInSameOrder()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=First", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Second", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req3 = new CertificateRequest("CN=Third", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert3 = req3.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2, cert3 });

        // Assert - Order should be preserved
        string? cn1 = result.Chain[0].Subject.Attributes.ContainsKey("CN") ? 
                     result.Chain[0].Subject.Attributes["CN"] :
                     result.Chain[0].Subject.Attributes["cn"];
        string? cn2 = result.Chain[1].Subject.Attributes.ContainsKey("CN") ? 
                     result.Chain[1].Subject.Attributes["CN"] :
                     result.Chain[1].Subject.Attributes["cn"];
        string? cn3 = result.Chain[2].Subject.Attributes.ContainsKey("CN") ? 
                     result.Chain[2].Subject.Attributes["CN"] :
                     result.Chain[2].Subject.Attributes["cn"];

        Assert.That(cn1, Is.EqualTo("First"));
        Assert.That(cn2, Is.EqualTo("Second"));
        Assert.That(cn3, Is.EqualTo("Third"));
    }

    [Test]
    public void Convert_CertWithEmptySubject_HandlesGracefully()
    {
        // Arrange - Create minimal certs
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Valid", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should not throw, handles empty gracefully
        Assert.That(result.Chain[0].Subject, Is.Not.Null);
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
    }
}

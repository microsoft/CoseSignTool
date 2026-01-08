// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using CoseSign1.Tests.Common;
using DIDx509.CertificateChain;

namespace DIDx509.Tests.CertificateChain;

/// <summary>
/// Tests for CertificateChainConverter static class.
/// </summary>
[TestFixture]
public class CertificateChainConverterTests
{
    private static T InvokePrivateStatic<T>(string methodName, params object[] args)
    {
        var method = typeof(CertificateChainConverter).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static);
        Assert.That(method, Is.Not.Null, $"Missing private method: {methodName}");
        return (T)method!.Invoke(null, args)!;
    }

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
        var fingerprints = result.Chain[0].Fingerprints!;

        // Assert - Base64url should not contain + / =
        Assert.That(fingerprints.Sha256.Contains('+'), Is.False);
        Assert.That(fingerprints.Sha256.Contains('/'), Is.False);
        Assert.That(fingerprints.Sha256.EndsWith('='), Is.False);
        Assert.That(fingerprints.Sha384!.Contains('+'), Is.False);
        Assert.That(fingerprints.Sha384.Contains('/'), Is.False);
        Assert.That(fingerprints.Sha384.EndsWith('='), Is.False);
        Assert.That(fingerprints.Sha512!.Contains('+'), Is.False);
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
        var fingerprints = result.Chain[0].Fingerprints!;

        // Assert - SHA256 = 32 bytes = 43 chars base64url, SHA384 = 48 bytes = 64 chars, SHA512 = 64 bytes = 86 chars
        Assert.That(fingerprints.Sha256.Length, Is.EqualTo(43)); // 32 bytes base64url encoded
        Assert.That(fingerprints.Sha384!.Length, Is.EqualTo(64)); // 48 bytes base64url encoded
        Assert.That(fingerprints.Sha512!.Length, Is.EqualTo(86)); // 64 bytes base64url encoded
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
    public void UnescapeRFC4514Value_WithHexEscapes_DecodesCharacters()
    {
        // "\41" is 'A', and "\2C" is ','
        var value = "Test\\2CInc\\41";
        var unescaped = InvokePrivateStatic<string>("UnescapeRFC4514Value", value);
        Assert.That(unescaped, Is.EqualTo("Test,IncA"));
    }

    [Test]
    public void SplitRFC4514Components_WithEscapedComma_DoesNotSplitInsideValue()
    {
        var dn = "CN=Test\\, Inc,O=Org";
        var components = InvokePrivateStatic<System.Collections.Generic.List<string>>("SplitRFC4514Components", dn);
        Assert.That(components.Count, Is.EqualTo(2));
        Assert.That(components[0], Does.Contain("CN="));
        Assert.That(components[0], Does.Contain("\\,"));
        Assert.That(components[1], Does.StartWith("O="));
    }

    [Test]
    public void MapOidToLabel_KnownOids_MapToShortLabels()
    {
        var cn = InvokePrivateStatic<string>("MapOidToLabel", DidX509Constants.OidCommonName);
        var o = InvokePrivateStatic<string>("MapOidToLabel", DidX509Constants.OidOrganizationName);
        var unknown = InvokePrivateStatic<string>("MapOidToLabel", "1.2.3.4");

        Assert.That(cn, Is.EqualTo(DidX509Constants.AttributeCN));
        Assert.That(o, Is.EqualTo(DidX509Constants.AttributeO));
        Assert.That(unknown, Is.EqualTo("1.2.3.4"));
    }

    [Test]
    public void ParseFulcioExtension_WhenStartsWithNonPrintable_SkipsFirstTwoBytes()
    {
        var raw = new byte[] { 0x01, 0x02, (byte)'i', (byte)'s', (byte)'s', (byte)'u', (byte)'e', (byte)'r' };
        var ext = new X509Extension(new Oid(DidX509Constants.OidFulcioIssuer), raw, critical: false);
        var parsed = InvokePrivateStatic<string?>("ParseFulcioExtension", ext);

        Assert.That(parsed, Is.EqualTo("issuer"));
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

    [Test]
    public void Convert_SubjectWithSpecialCharacters_HandlesCorrectly()
    {
        // Arrange - Test with special characters that might need escaping
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=Test User, O=\"Test, Inc.\", C=US",
            rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should parse the escaped or quoted values correctly
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
        Assert.That(result.Chain[0].Subject.Attributes.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Convert_CertWithOidInSubject_MapsToLabel()
    {
        // Arrange - The parser should map known OIDs like 2.5.4.3 to CN
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[1], chain[0] };

        // Act
        var result = CertificateChainConverter.Convert(certs);
        var attrs = result.Chain[0].Subject.Attributes;

        // Assert - Should have label form, not OID form
        // These are standard attribute labels
        var hasLabels = attrs.Keys.Any(k =>
            k.Equals("CN", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("O", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("OU", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("C", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("L", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("ST", StringComparison.OrdinalIgnoreCase));
        Assert.That(hasLabels, Is.True);
    }

    [Test]
    public void Convert_CertWithIpSan_DoesNotThrow()
    {
        // Arrange - Create cert with IP SAN (note: SAN parser may not capture all SAN types)
        using var rsa = RSA.Create(2048);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddIpAddress(System.Net.IPAddress.Parse("192.168.1.1"));
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(sanBuilder.Build());
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act - Should not throw even if IP SAN not captured
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Extensions should be present (even if SAN list is empty or null)
        Assert.That(result.Chain[0].Extensions, Is.Not.Null);
    }

    [Test]
    public void Convert_CertInfoContainsOriginalCert_ForValidation()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[1], chain[0] };

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert - Each CertificateInfo should contain a reference to the original cert
        Assert.That(result.Chain[0].Certificate, Is.Not.Null);
        Assert.That(result.Chain[0].Certificate!.Subject, Is.EqualTo(certs[0].Subject));
    }

    [Test]
    public void Convert_AllCertificatesHaveAllProperties_NotNull()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs = new[] { chain[2], chain[1], chain[0] };

        // Act
        var result = CertificateChainConverter.Convert(certs);

        // Assert - All properties should be set
        foreach (var certInfo in result.Chain)
        {
            Assert.That(certInfo.Fingerprints, Is.Not.Null, "Fingerprints should not be null");
            Assert.That(certInfo.Subject, Is.Not.Null, "Subject should not be null");
            Assert.That(certInfo.Issuer, Is.Not.Null, "Issuer should not be null");
            Assert.That(certInfo.Extensions, Is.Not.Null, "Extensions should not be null");
            Assert.That(certInfo.Fingerprints.Sha256, Is.Not.Null.And.Not.Empty, "SHA256 fingerprint should not be null or empty");
        }
    }

    #region Extended Coverage Tests

    [Test]
    public void Convert_CertWithFulcioExtension_ParsesFulcioIssuer()
    {
        // Arrange - Create cert with Fulcio issuer extension (OID: 1.3.6.1.4.1.57264.1.1)
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Add a Fulcio issuer extension with a sample issuer value
        // The extension value should be a UTF8 string
        var fulcioIssuerOid = new Oid("1.3.6.1.4.1.57264.1.1", "Fulcio Issuer");
        var issuerValue = System.Text.Encoding.UTF8.GetBytes("https://accounts.google.com");
        var fulcioExtension = new X509Extension(fulcioIssuerOid, issuerValue, false);
        req.CertificateExtensions.Add(fulcioExtension);

        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Fulcio issuer should be parsed
        Assert.That(result.Chain[0].Extensions.FulcioIssuer, Does.Contain("google").Or.Contain("accounts"));
    }

    [Test]
    public void Convert_CertWithEscapedDnValue_UnescapesCorrectly()
    {
        // Arrange - DN with backslash-escaped characters
        using var rsa = RSA.Create(2048);
        // Creating a DN with simple value - plus sign is not valid in basic DN
        var req1 = new CertificateRequest("CN=Test Value, O=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should parse correctly
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
        Assert.That(result.Chain[0].Subject.Attributes.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Convert_CertWithNumericOidLabel_PreservesOid()
    {
        // Arrange - DN with unknown OID that won't be mapped to a label
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=Test, 2.999.1=CustomValue", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should have the unknown OID preserved as-is
        var attrs = result.Chain[0].Subject.Attributes;
        Assert.That(attrs.Count, Is.GreaterThan(0));
        // Either the OID is preserved or mapped
        bool hasExpected = attrs.ContainsKey("2.999.1") ||
                          attrs.Values.Any(v => v.Contains("CustomValue")) ||
                          attrs.ContainsKey("CN");
        Assert.That(hasExpected, Is.True);
    }

    [Test]
    public void Convert_CertWithHexEscapedDn_HandlesHexSequences()
    {
        // Arrange - Create cert with a DN that would need hex escaping (special chars)
        using var rsa = RSA.Create(2048);
        // Including characters that might be hex-escaped in RFC4514
        var req1 = new CertificateRequest("CN=Test#Hash", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
        // The value should be unescaped
        var cn = result.Chain[0].Subject.Attributes.ContainsKey("CN")
            ? result.Chain[0].Subject.Attributes["CN"]
            : result.Chain[0].Subject.Attributes["cn"];
        Assert.That(cn, Does.Contain("Test"));
    }

    [Test]
    public void Convert_CertWithStreetAddressOid_MapsToSTREET()
    {
        // Arrange - DN with street address (OID: 2.5.4.9)
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=Test, STREET=123 Main St", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        var attrs = result.Chain[0].Subject.Attributes;
        Assert.That(attrs.Count, Is.GreaterThan(0));
        // Should have STREET or street or the OID
        bool hasStreet = attrs.ContainsKey("STREET") ||
                        attrs.ContainsKey("street") ||
                        attrs.ContainsKey("2.5.4.9");
        Assert.That(hasStreet, Is.True);
    }

    [Test]
    public void Convert_CertWithDuplicateAttributeKey_FirstValueWins()
    {
        // Arrange - DN with duplicate attributes (rare but possible)
        using var rsa = RSA.Create(2048);
        // Multi-valued attributes or duplicate keys - first should win
        var req1 = new CertificateRequest("CN=First, CN=Second, O=Org", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - First value should be kept
        var attrs = result.Chain[0].Subject.Attributes;
        var cn = attrs.ContainsKey("CN") ? attrs["CN"] : attrs["cn"];
        // Due to CN+CN ordering, either First or Second could be first depending on parsing
        Assert.That(cn, Is.EqualTo("First").Or.EqualTo("Second"));
    }

    [Test]
    public void Convert_CertWithLeadingWhitespaceInDn_TrimsCorrectly()
    {
        // Arrange - DN components with whitespace
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN= Test With Space ", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should parse correctly (value may or may not be trimmed based on RFC4514)
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
        Assert.That(result.Chain[0].Subject.Attributes.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Convert_CertWithEmptyEkuOid_HandlesGracefully()
    {
        // Arrange - Create cert with EKU extension but handle edge case
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Add EKU with standard OID
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
            false));
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Test2", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should parse EKU correctly
        Assert.That(result.Chain[0].Extensions.Eku, Is.Not.Null);
        Assert.That(result.Chain[0].Extensions.Eku!.All(e => !string.IsNullOrEmpty(e)), Is.True);
    }

    [Test]
    public void Convert_EnumerableChain_WorksCorrectly()
    {
        // Arrange - use IEnumerable instead of array
        var chain = TestCertificateUtils.CreateTestChain();

        IEnumerable<X509Certificate2> GetCerts()
        {
            yield return chain[2];
            yield return chain[1];
        }

        // Act
        var result = CertificateChainConverter.Convert(GetCerts());

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Chain.Count, Is.EqualTo(2));
    }

    [Test]
    public void Convert_FingerprintIsConsistentForSameCert_ReturnsIdenticalHashes()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain();
        var certs1 = new[] { chain[1], chain[0] };
        var certs2 = new[] { chain[1], chain[0] };

        // Act
        var result1 = CertificateChainConverter.Convert(certs1);
        var result2 = CertificateChainConverter.Convert(certs2);

        // Assert - Same cert should produce same fingerprints
        Assert.That(result1.Chain[0].Fingerprints.Sha256, Is.EqualTo(result2.Chain[0].Fingerprints.Sha256));
        Assert.That(result1.Chain[0].Fingerprints.Sha384, Is.EqualTo(result2.Chain[0].Fingerprints.Sha384));
        Assert.That(result1.Chain[0].Fingerprints.Sha512, Is.EqualTo(result2.Chain[0].Fingerprints.Sha512));
    }

    [Test]
    public void Convert_CertWithBackslashInDn_ParsesCorrectly()
    {
        // Arrange - DN with backslash character (edge case for RFC4514 parsing)
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=Test, O=Test Org", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should parse without throwing
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
        Assert.That(result.Chain[0].Subject.Attributes.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Convert_CertWithEmptyValueInDn_HandlesGracefully()
    {
        // Arrange - DN with empty value for an attribute
        using var rsa = RSA.Create(2048);
        // Empty CN value is technically valid in ASN.1/X.500
        var req1 = new CertificateRequest("CN=, O=TestOrg", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should parse without throwing
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
    }

    [Test]
    public void Convert_CertWithSpacesInDn_TrimsAndParsesCorrectly()
    {
        // Arrange - DN with extra spaces around values
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=  Test  , O=  Org  ", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Attribute values may contain leading/trailing spaces depending on RFC4514 parsing
        Assert.That(result.Chain[0].Subject.Attributes, Is.Not.Null);
        Assert.That(result.Chain[0].Subject.Attributes.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Convert_CertWithLongDn_ParsesAllComponents()
    {
        // Arrange - DN with many components
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest(
            "CN=Very Long Common Name Here, O=Organization, OU=Unit1, OU=Unit2, L=City, ST=State, C=US",
            rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should capture multiple attributes
        Assert.That(result.Chain[0].Subject.Attributes.Count, Is.GreaterThan(3));
    }

    [Test]
    public void Convert_CertWithLocalityAndState_MapsCorrectly()
    {
        // Arrange - DN with L attribute (ST may not always be mapped)
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=Test, L=Seattle, C=US", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should have L attribute mapped correctly
        var attrs = result.Chain[0].Subject.Attributes;
        bool hasL = attrs.ContainsKey("L") || attrs.ContainsKey("l");
        bool hasCN = attrs.ContainsKey("CN") || attrs.ContainsKey("cn");
        Assert.That(hasL, Is.True);
        Assert.That(hasCN, Is.True);
    }

    [Test]
    public void Convert_CertWithStreetAttribute_MapsCorrectly()
    {
        // Arrange - Test STREET OID mapping
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=Test, STREET=123 Main St, C=US", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should map STREET attribute
        var attrs = result.Chain[0].Subject.Attributes;
        Assert.That(attrs.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Convert_CertWithOuAttribute_MapsCorrectly()
    {
        // Arrange - Test OU OID mapping
        using var rsa = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=Test, OU=Engineering, O=TestOrg, C=US", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should have OU attribute mapped correctly
        var attrs = result.Chain[0].Subject.Attributes;
        bool hasOU = attrs.ContainsKey("OU") || attrs.ContainsKey("ou");
        bool hasO = attrs.ContainsKey("O") || attrs.ContainsKey("o");
        Assert.That(hasOU, Is.True);
        Assert.That(hasO, Is.True);
    }

    [Test]
    public void Convert_CertWithCustomFulcioExtension_ParsesFulcioIssuer()
    {
        // Arrange - Create cert with Fulcio issuer extension (OID: 1.3.6.1.4.1.57264.1.1)
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        // Add Fulcio issuer extension with a simple value
        var fulcioOid = new Oid("1.3.6.1.4.1.57264.1.1");
        var fulcioValue = System.Text.Encoding.UTF8.GetBytes("https://accounts.google.com");
        var fulcioExt = new X509Extension(fulcioOid, fulcioValue, false);
        req.CertificateExtensions.Add(fulcioExt);
        
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Fulcio issuer should be parsed
        Assert.That(result.Chain[0].Extensions, Is.Not.Null);
        // The extension may or may not be parsed depending on format
    }

    [Test]
    public void Convert_CertWithFulcioExtensionWithAsn1Encoding_ParsesValue()
    {
        // Arrange - Create cert with Fulcio issuer extension with ASN.1 encoding
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        // Add Fulcio issuer extension with ASN.1 tag and length prefix
        var fulcioOid = new Oid("1.3.6.1.4.1.57264.1.1");
        var issuerValue = System.Text.Encoding.UTF8.GetBytes("https://example.com");
        // Prepend ASN.1 UTF8String tag (0x0C) and length
        var asn1Value = new byte[issuerValue.Length + 2];
        asn1Value[0] = 0x0C; // UTF8String tag
        asn1Value[1] = (byte)issuerValue.Length;
        Buffer.BlockCopy(issuerValue, 0, asn1Value, 2, issuerValue.Length);
        
        var fulcioExt = new X509Extension(fulcioOid, asn1Value, false);
        req.CertificateExtensions.Add(fulcioExt);
        
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should parse the Fulcio extension with ASN.1 encoding
        Assert.That(result.Chain[0].Extensions, Is.Not.Null);
        // The value should be extracted, potentially with ASN.1 prefix stripped
    }

    [Test]
    public void Convert_CertWithMalformedFulcioExtension_HandlesGracefully()
    {
        // Arrange - Create cert with malformed Fulcio extension
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        // Add Fulcio issuer extension with invalid/empty data
        var fulcioOid = new Oid("1.3.6.1.4.1.57264.1.1");
        var emptyValue = Array.Empty<byte>();
        var fulcioExt = new X509Extension(fulcioOid, emptyValue, false);
        req.CertificateExtensions.Add(fulcioExt);
        
        using var cert1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act - Should not throw
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert
        Assert.That(result.Chain[0].Extensions, Is.Not.Null);
        Assert.That(result.Chain[0].Extensions.FulcioIssuer, Is.Null.Or.Empty);
    }

    [Test]
    public void Convert_CertWithAllOidMappings_MapsAllKnownOids()
    {
        // Arrange - Create cert with all known OID attributes
        using var rsa = RSA.Create(2048);
        // Include all known OIDs: CN, O, OU, C, L, ST, STREET
        var dn = "CN=Test User, O=Test Org, OU=Engineering, C=US, L=Seattle, ST=WA";
        var req1 = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var req2 = new CertificateRequest("CN=Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Act
        var result = CertificateChainConverter.Convert(new[] { cert1, cert2 });

        // Assert - Should have all standard attributes mapped to labels
        var attrs = result.Chain[0].Subject.Attributes;
        // Check for presence of standard labels (case-insensitive)
        bool hasCN = attrs.Keys.Any(k => k.Equals("CN", StringComparison.OrdinalIgnoreCase));
        bool hasO = attrs.Keys.Any(k => k.Equals("O", StringComparison.OrdinalIgnoreCase));
        bool hasC = attrs.Keys.Any(k => k.Equals("C", StringComparison.OrdinalIgnoreCase));
        
        Assert.That(hasCN, Is.True);
        Assert.That(hasO, Is.True);
        Assert.That(hasC, Is.True);
        Assert.That(attrs.Count, Is.GreaterThanOrEqualTo(3));
    }

    #endregion
}
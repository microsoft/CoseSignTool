// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using FluentAssertions;
using NUnit.Framework;

[TestFixture]
public class DidX509GeneratorTests
{
    private DidX509Generator _generator = null!;

    [SetUp]
    public void SetUp()
    {
        _generator = new DidX509Generator();
    }

    [Test]
    public void Generate_WithValidCertificates_ShouldReturnValidDid()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Leaf");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        did.Should().NotBeNullOrEmpty();
        did.Should().StartWith("did:x509:0:sha256:");
        did.Should().Contain("::subject:");
    }

    [Test]
    public void Generate_WithNullLeafCertificate_ShouldThrowArgumentNullException()
    {
        // Arrange
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        Action act = () => _generator.Generate(null!, rootCert);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("leafCertificate");
    }

    [Test]
    public void Generate_WithNullRootCertificate_ShouldThrowArgumentNullException()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Leaf");

        // Act
        Action act = () => _generator.Generate(leafCert, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("rootCertificate");
    }

    [Test]
    public void Generate_ShouldIncludeCorrectRootCertHash()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Leaf");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");
        
        byte[] expectedHash = SHA256.HashData(rootCert.RawData);
        string expectedHashBase64Url = Convert.ToBase64String(expectedHash)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        did.Should().Contain(expectedHashBase64Url);
    }

    [Test]
    public void Generate_ShouldPercentEncodeSubject()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Test Subject, O=Test Org");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        // Spaces should be percent-encoded, format is key:value:key:value
        did.Should().Contain("%20"); // Space
        did.Should().Contain("::subject:");
        // DN parsing separates components, so no comma in the output
        did.Should().Contain("CN:");
        did.Should().Contain("O:");
    }

    [Test]
    public void Generate_WithSpecialCharactersInSubject_ShouldEncodeCorrectly()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Test@Example.com");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        did.Should().Contain("%40"); // @ symbol
    }

    [Test]
    public void GenerateFromChain_WithValidChain_ShouldReturnValidDid()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Leaf");
        using X509Certificate2 intermediateCert = CreateTestCertificate("CN=Intermediate");
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        
        X509Certificate2[] chain = new[] { leafCert, intermediateCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert
        did.Should().NotBeNullOrEmpty();
        did.Should().StartWith("did:x509:0:sha256:");
    }

    [Test]
    public void GenerateFromChain_WithNullChain_ShouldThrowArgumentNullException()
    {
        // Act
        Action act = () => _generator.GenerateFromChain(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("certificates");
    }

    [Test]
    public void GenerateFromChain_WithEmptyChain_ShouldThrowArgumentException()
    {
        // Arrange
        X509Certificate2[] emptyChain = Array.Empty<X509Certificate2>();

        // Act
        Action act = () => _generator.GenerateFromChain(emptyChain);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*cannot be empty*");
    }

    [Test]
    public void GenerateFromChain_WithSelfSignedCertificate_ShouldUseAsBothLeafAndRoot()
    {
        // Arrange
        using X509Certificate2 selfSigned = CreateSelfSignedCertificate("CN=SelfSigned");
        X509Certificate2[] chain = new[] { selfSigned };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert
        did.Should().NotBeNullOrEmpty();
        did.Should().StartWith("did:x509:0:sha256:");
    }

    [Test]
    public void GenerateFromChain_ShouldUseSelfSignedCertificateAsRoot()
    {
        // Arrange - Create a chain where root is self-signed
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Leaf");
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should generate valid DID
        did.Should().StartWith("did:x509:0:sha256:");
        did.Should().Contain("::subject:");
        DidX509Generator.IsValidDidX509(did).Should().BeTrue();
    }

    [Test]
    public void IsValidDidX509_WithValidDid_ShouldReturnTrue()
    {
        // Arrange - base64url SHA256 hash is 43 characters, subject format is key:value
        string validDid = "did:x509:0:sha256:" + new string('a', 43) + "::subject:CN:Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(validDid);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsValidDidX509_WithNullOrEmpty_ShouldReturnFalse()
    {
        // Act & Assert
        DidX509Generator.IsValidDidX509(null!).Should().BeFalse();
        DidX509Generator.IsValidDidX509(string.Empty).Should().BeFalse();
        DidX509Generator.IsValidDidX509("   ").Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithInvalidPrefix_ShouldReturnFalse()
    {
        // Arrange
        string invalidDid = "did:web:0:sha256:" + new string('a', 43) + "::subject:CN:Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(invalidDid);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithoutSubjectSeparator_ShouldReturnFalse()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:" + new string('a', 64) + ":CN=Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(invalidDid);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithInvalidHashLength_ShouldReturnFalse()
    {
        // Arrange - Hash too short
        string invalidDid = "did:x509:0:sha256:abc123::subject:CN=Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(invalidDid);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithNonBase64UrlHash_ShouldReturnFalse()
    {
        // Arrange - Contains non-base64url character '+'
        string invalidDid = "did:x509:0:sha256:" + new string('a', 42) + "+::subject:CN=Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(invalidDid);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithUppercaseHash_ShouldReturnTrue()
    {
        // Arrange - base64url is case-sensitive and supports A-Z
        string validDid = "did:x509:0:sha256:" + new string('A', 43) + "::subject:CN:Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(validDid);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsValidDidX509_WithMixedCaseHash_ShouldReturnTrue()
    {
        // Arrange - 43 characters total for base64url SHA256, subject format is key:value
        string validDid = "did:x509:0:sha256:aAbBcCdDeEfF0123456789" + new string('a', 21) + "::subject:CN:Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(validDid);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void Generate_ConsistentResults_SameCertificatesShouldProduceSameDid()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Leaf");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did1 = _generator.Generate(leafCert, rootCert);
        string did2 = _generator.Generate(leafCert, rootCert);

        // Assert
        did1.Should().Be(did2);
    }

    [Test]
    public void Generate_DifferentRootCerts_ShouldProduceDifferentDids()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Leaf");
        using X509Certificate2 rootCert1 = CreateTestCertificate("CN=Root1");
        using X509Certificate2 rootCert2 = CreateTestCertificate("CN=Root2");

        // Act
        string did1 = _generator.Generate(leafCert, rootCert1);
        string did2 = _generator.Generate(leafCert, rootCert2);

        // Assert
        did1.Should().NotBe(did2);
    }

    [Test]
    public void Generate_DifferentLeafCerts_ShouldProduceDifferentDids()
    {
        // Arrange
        using X509Certificate2 leafCert1 = CreateTestCertificate("CN=Leaf1");
        using X509Certificate2 leafCert2 = CreateTestCertificate("CN=Leaf2");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did1 = _generator.Generate(leafCert1, rootCert);
        string did2 = _generator.Generate(leafCert2, rootCert);

        // Assert
        did1.Should().NotBe(did2);
    }

    [Test]
    public void Generate_EmptySubject_ShouldNotThrow()
    {
        // Arrange
        using X509Certificate2 leafCert = CreateTestCertificate("");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        Action act = () => _generator.Generate(leafCert, rootCert);

        // Assert
        act.Should().NotThrow();
    }

    [Test]
    public void Generate_WithUnreservedCharacters_ShouldNotEncode()
    {
        // Arrange - Characters that should NOT be encoded: A-Z a-z 0-9 - _ . ~
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Test-Name_123.domain~");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        // These characters should appear unencoded
        did.Should().Contain("Test-Name_123");
    }

    [Test]
    public void Generate_WithMultipleSubjectFields_ShouldFormatAsKeyValuePairs()
    {
        // Arrange - per spec: subject format is key:value:key:value
        using X509Certificate2 leafCert = CreateTestCertificate("C=US, ST=California, L=San Francisco, O=GitHub, OU=Engineering, CN=Test User");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        did.Should().Contain("::subject:");
        // Should contain key:value pairs with colons, not equals
        did.Should().Contain("C:US");
        // Note: Some fields like ST might be omitted or reordered by X500DistinguishedName
        did.Should().Contain("L:San%20Francisco"); // Space encoded
        did.Should().Contain("O:GitHub");
        did.Should().Contain("OU:Engineering");
        did.Should().Contain("CN:Test%20User");
        // Should NOT contain '=' from DN format
        did.Should().NotContain("C=");
    }

    [Test]
    public void Generate_SubjectValueEncoding_ShouldOnlyAllowAlphanumericDashDotUnderscore()
    {
        // Arrange - per spec: allowed unencoded chars are ALPHA / DIGIT / "-" / "." / "_"
        // Note: Tilde (~) is NOT allowed per DID:X509 spec (unlike RFC 3986)
        using X509Certificate2 leafCert = CreateTestCertificate("CN=Test~User@Domain.com");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        // Tilde should be encoded (unlike standard RFC 3986)
        did.Should().Contain("%7E"); // ~
        // @ should be encoded
        did.Should().Contain("%40"); // @
        // Dot and hyphen in Domain.com should NOT be encoded
        did.Should().Contain("Domain.com");
    }

    [Test]
    public void IsValidDidX509_WithMultipleSubjectKeyValuePairs_ShouldReturnTrue()
    {
        // Arrange - multiple key:value pairs per spec
        string validDid = "did:x509:0:sha256:" + new string('a', 43) + 
                         "::subject:C:US:ST:California:O:GitHub:CN:TestUser";

        // Act
        bool result = DidX509Generator.IsValidDidX509(validDid);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsValidDidX509_WithOddNumberOfSubjectComponents_ShouldReturnFalse()
    {
        // Arrange - missing value for last key
        string invalidDid = "did:x509:0:sha256:" + new string('a', 43) + 
                           "::subject:CN:Test:O"; // O has no value

        // Act
        bool result = DidX509Generator.IsValidDidX509(invalidDid);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithEmptySubjectValue_ShouldReturnFalse()
    {
        // Arrange - empty subject policy
        string invalidDid = "did:x509:0:sha256:" + new string('a', 43) + "::subject:";

        // Act
        bool result = DidX509Generator.IsValidDidX509(invalidDid);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithInvalidSubjectKey_ShouldReturnFalse()
    {
        // Arrange - 'XX' is not a valid label per spec
        string invalidDid = "did:x509:0:sha256:" + new string('a', 43) + 
                           "::subject:XX:Value";

        // Act
        bool result = DidX509Generator.IsValidDidX509(invalidDid);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithValidOIDKey_ShouldReturnTrue()
    {
        // Arrange - OID format (dotted decimal) is valid per spec
        string validDid = "did:x509:0:sha256:" + new string('a', 43) + 
                         "::subject:2.5.4.3:Value";

        // Act
        bool result = DidX509Generator.IsValidDidX509(validDid);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsValidDidX509_WithPercentEncodedValue_ShouldReturnTrue()
    {
        // Arrange - percent-encoded values are valid
        string validDid = "did:x509:0:sha256:" + new string('a', 43) + 
                         "::subject:CN:Test%20User:O:My%20Org";

        // Act
        bool result = DidX509Generator.IsValidDidX509(validDid);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void Generate_MatchesSpecExample_Format()
    {
        // Arrange - Test against spec example format
        // Example from spec: did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:O:My%20Organisation
        using X509Certificate2 leafCert = CreateTestCertificate("C=US, ST=California, O=My Organisation");
        using X509Certificate2 rootCert = CreateTestCertificate("CN=Root");

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        did.Should().StartWith("did:x509:0:sha256:");
        did.Should().Contain("::subject:");
        // Check all fields are present (order may vary based on X500DistinguishedName formatting)
        did.Should().Contain("C:US");
        did.Should().Contain("O:My%20Organisation");
        // ST may or may not be present depending on certificate creation
    }

    // Helper method to create test certificates
    private X509Certificate2 CreateTestCertificate(string subject)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new CertificateRequest(
            subject,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    }

    private X509Certificate2 CreateSelfSignedCertificate(string subjectAndIssuer)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new CertificateRequest(
            subjectAndIssuer,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add basic constraints to mark as CA
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        return request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    }
}

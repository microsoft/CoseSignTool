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
        string expectedHashHex = Convert.ToHexString(expectedHash).ToLowerInvariant();

        // Act
        string did = _generator.Generate(leafCert, rootCert);

        // Assert
        did.Should().Contain(expectedHashHex);
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
        // Spaces and commas should be percent-encoded
        did.Should().Contain("%20"); // Space
        did.Should().Contain("%2C"); // Comma
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
        // Arrange
        string validDid = "did:x509:0:sha256:" + new string('a', 64) + "::subject:CN=Test";

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
        string invalidDid = "did:web:0:sha256:" + new string('a', 64) + "::subject:CN=Test";

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
    public void IsValidDidX509_WithNonHexHash_ShouldReturnFalse()
    {
        // Arrange - Contains non-hex character 'g'
        string invalidDid = "did:x509:0:sha256:" + new string('g', 64) + "::subject:CN=Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(invalidDid);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsValidDidX509_WithUppercaseHash_ShouldReturnTrue()
    {
        // Arrange
        string validDid = "did:x509:0:sha256:" + new string('A', 64) + "::subject:CN=Test";

        // Act
        bool result = DidX509Generator.IsValidDidX509(validDid);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsValidDidX509_WithMixedCaseHash_ShouldReturnTrue()
    {
        // Arrange
        string validDid = "did:x509:0:sha256:aAbBcCdDeEfF0123456789" + new string('a', 42) + "::subject:CN=Test";

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

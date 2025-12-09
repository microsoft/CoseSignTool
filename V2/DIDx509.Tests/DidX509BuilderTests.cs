// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DIDx509.Builder;
using NUnit.Framework;

[TestFixture]
public class DidX509BuilderTests : DIDx509TestBase
{
    [Test]
    public void Build_WithLeafCaCertificateAndSubjectPolicy_ReturnsValidDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate();

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null.And.Not.Empty);
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
    }

    [Test]
    public void Build_WithoutLeafCertificate_ThrowsInvalidOperationException()
    {
        // Arrange
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var attributes = new Dictionary<string, string> { { "CN", "Test" } };
        var builder = new DidX509Builder()
            .WithCaCertificate(root)
            .WithSubjectPolicy(attributes);

        // Act
        Action act = () => builder.Build();

        // Assert
        var ex = Assert.Throws<InvalidOperationException>(() => act());
        Assert.That(ex!.Message, Does.Contain("Leaf certificate must be set"));
    }

    [Test]
    public void Build_WithoutCaCertificate_ThrowsInvalidOperationException()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithSubjectFromCertificate();

        // Act
        Action act = () => builder.Build();

        // Assert
        var ex = Assert.Throws<InvalidOperationException>(() => act());
        Assert.That(ex!.Message, Does.Contain("CA certificate must be set"));
    }

    [Test]
    public void Build_WithoutAnyPolicy_ThrowsInvalidOperationException()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root);

        // Act
        Action act = () => builder.Build();

        // Assert
        var ex = Assert.Throws<InvalidOperationException>(() => act());
        Assert.That(ex!.Message, Does.Contain("At least one policy must be added"));
    }

    [Test]
    public void WithHashAlgorithm_Sha256_BuildsCorrectDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithHashAlgorithm(DidX509Constants.HashAlgorithmSha256)
            .WithSubjectFromCertificate();

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
    }

    [Test]
    public void WithHashAlgorithm_Sha384_BuildsCorrectDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithHashAlgorithm(DidX509Constants.HashAlgorithmSha384)
            .WithSubjectFromCertificate();

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha384", root, "subject");
        AssertDidContainsCertHash(did, root, "sha384");
    }

    [Test]
    public void WithHashAlgorithm_Sha512_BuildsCorrectDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithHashAlgorithm(DidX509Constants.HashAlgorithmSha512)
            .WithSubjectFromCertificate();

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha512", root, "subject");
        AssertDidContainsCertHash(did, root, "sha512");
    }

    [Test]
    public void WithHashAlgorithm_InvalidAlgorithm_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithHashAlgorithm("md5");

        // Assert
        var ex = Assert.Throws<ArgumentException>(() => act());
        Assert.That(ex!.Message, Does.Contain("Unsupported hash algorithm"));
    }

    [Test]
    public void WithHashAlgorithm_NullOrEmpty_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act1 = () => builder.WithHashAlgorithm(null!);
        Action act2 = () => builder.WithHashAlgorithm("");

        // Assert
        Assert.Throws<ArgumentException>(() => act1());
        Assert.Throws<ArgumentException>(() => act2());
    }

    [Test]
    public void WithSubjectPolicy_WithValidAttributes_IncludesSubjectInDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var attributes = new Dictionary<string, string>
        {
            { "CN", "Test User" },
            { "O", "Test Org" }
        };

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectPolicy(attributes);

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha256", root, "subject", "CN:Test%20User:O:Test%20Org");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::subject:CN:Test%20User:O:Test%20Org"));
    }

    [Test]
    public void WithSubjectPolicy_NullAttributes_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithSubjectPolicy(null!);

        // Assert
        var ex = Assert.Throws<ArgumentException>(() => act());
        Assert.That(ex!.Message, Does.Contain("cannot be null or empty"));
    }

    [Test]
    public void WithSubjectPolicy_EmptyAttributes_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithSubjectPolicy(new Dictionary<string, string>());

        // Assert
        var ex = Assert.Throws<ArgumentException>(() => act());
        Assert.That(ex!.Message, Does.Contain("cannot be null or empty"));
    }

    [Test]
    public void WithSubjectFromCertificate_ExtractsSubjectCorrectly()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Test User, O=Test Org");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate();

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("CN:"));
        Assert.That(did, Does.Contain("O:"));
    }

    [Test]
    public void WithSubjectFromCertificate_WithoutLeafCert_ThrowsInvalidOperationException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithSubjectFromCertificate();

        // Assert
        var ex = Assert.Throws<InvalidOperationException>(() => act());
        Assert.That(ex!.Message, Does.Contain("Leaf certificate must be set"));
    }

    [Test]
    public void WithSanPolicy_WithDnsType_IncludesSanInDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSanPolicy("dns", "example.com");

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha256", root, "san", "dns:example.com");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::san:dns:example.com"));
    }

    [Test]
    public void WithSanPolicy_WithEmailType_IncludesSanInDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSanPolicy("email", "user@example.com");

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha256", root, "san", "email:user%40example.com");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::san:email:user%40example.com"));
    }

    [Test]
    public void WithSanPolicy_WithUriType_IncludesSanInDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSanPolicy("uri", "https://example.com");

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha256", root, "san", "uri:https%3A%2F%2Fexample.com");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::san:uri:https%3A%2F%2Fexample.com"));
    }

    [Test]
    public void WithSanPolicy_InvalidType_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithSanPolicy("invalid", "value");

        // Assert
        var ex = Assert.Throws<ArgumentException>(() => act());
        Assert.That(ex!.Message, Does.Contain("Invalid SAN type"));
    }

    [Test]
    public void WithSanPolicy_NullOrEmptyType_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act1 = () => builder.WithSanPolicy(null!, "value");
        Action act2 = () => builder.WithSanPolicy("", "value");

        // Assert
        Assert.Throws<ArgumentException>(() => act1());
        Assert.Throws<ArgumentException>(() => act2());
    }

    [Test]
    public void WithSanPolicy_NullOrEmptyValue_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act1 = () => builder.WithSanPolicy("dns", null!);
        Action act2 = () => builder.WithSanPolicy("dns", "");

        // Assert
        Assert.Throws<ArgumentException>(() => act1());
        Assert.Throws<ArgumentException>(() => act2());
    }

    [Test]
    public void WithEkuPolicy_WithValidOid_IncludesEkuInDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1");

        // Act
        string did = builder.Build();

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void WithEkuPolicy_NullOrEmptyOid_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act1 = () => builder.WithEkuPolicy(null!);
        Action act2 = () => builder.WithEkuPolicy("");

        // Assert
        Assert.Throws<ArgumentException>(() => act1());
        Assert.Throws<ArgumentException>(() => act2());
    }

    [Test]
    public void WithEkuPolicy_InvalidOidFormat_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithEkuPolicy("invalid-oid");

        // Assert
        var ex = Assert.Throws<ArgumentException>(() => act());
        Assert.That(ex!.Message, Does.Contain("Invalid OID format"));
    }

    [Test]
    public void WithFulcioIssuerPolicy_WithValidIssuer_IncludesFulcioInDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithFulcioIssuerPolicy("accounts.google.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Does.Contain("::fulcio-issuer:accounts.google.com"));
    }

    [Test]
    public void WithFulcioIssuerPolicy_WithHttpsPrefix_RemovesPrefix()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithFulcioIssuerPolicy("https://accounts.google.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Does.Contain("::fulcio-issuer:accounts.google.com"));
        Assert.That(did, Does.Not.Contain("https://"));
    }

    [Test]
    public void WithFulcioIssuerPolicy_NullOrEmpty_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act1 = () => builder.WithFulcioIssuerPolicy(null!);
        Action act2 = () => builder.WithFulcioIssuerPolicy("");

        // Assert
        Assert.Throws<ArgumentException>(() => act1());
        Assert.Throws<ArgumentException>(() => act2());
    }

    [Test]
    public void Build_WithMultiplePolicies_IncludesAllPolicies()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf, O=Org");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithSanPolicy("dns", "example.com")
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("::san:dns:example.com"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void WithCertificateChain_WithValidChain_SetsLeafAndRoot()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var intermediate = CreateTestCertificate("CN=Intermediate");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, intermediate, root };
        
        var builder = new DidX509Builder()
            .WithCertificateChain(chain)
            .WithSubjectFromCertificate();

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::subject:"));
    }

    [Test]
    public void WithCertificateChain_NullChain_ThrowsArgumentNullException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithCertificateChain(null!);

        // Assert
        Assert.Throws<ArgumentNullException>(() => act());
    }

    [Test]
    public void WithCertificateChain_EmptyChain_ThrowsArgumentException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithCertificateChain(Array.Empty<X509Certificate2>());

        // Assert
        var ex = Assert.Throws<ArgumentException>(() => act());
        Assert.That(ex!.Message, Does.Contain("cannot be empty"));
    }

    [Test]
    public void WithLeafCertificate_NullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithLeafCertificate(null!);

        // Assert
        Assert.Throws<ArgumentNullException>(() => act());
    }

    [Test]
    public void WithCaCertificate_NullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        var builder = new DidX509Builder();

        // Act
        Action act = () => builder.WithCaCertificate(null!);

        // Assert
        Assert.Throws<ArgumentNullException>(() => act());
    }

    [Test]
    public void Build_FluentInterface_ChainsCorrectly()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        // Act
        string did = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithHashAlgorithm(DidX509Constants.HashAlgorithmSha512)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .Build();

        // Assert
        Assert.That(did, Does.StartWith("did:x509:0:sha512:"));
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("::eku:"));
    }

    [Test]
    public void Build_ConsistentResults_SameInputsProduceSameDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder1 = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate();

        var builder2 = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate();

        // Act
        string did1 = builder1.Build();
        string did2 = builder2.Build();

        // Assert
        Assert.That(did1, Is.EqualTo(did2));
    }

    [Test]
    public void Build_PercentEncodesSpecialCharacters()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Test@User, O=My Org");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate();

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Does.Contain("%40")); // @
        Assert.That(did, Does.Contain("%20")); // space
    }

    [Test]
    public void Build_IncludesCorrectCaFingerprint()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        
        byte[] expectedHash = SHA256.HashData(root.RawData);
        string expectedHashBase64Url = Convert.ToBase64String(expectedHash)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate();

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Does.Contain(expectedHashBase64Url));
    }

}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

[TestFixture]
public class X509Certificate2ExtensionsTests : DIDx509TestBase
{
    [Test]
    [TestCaseSource(nameof(AllAlgorithms))]
    public void GetDidBuilder_WithValidCertificate_ReturnsBuilder(CertAlgorithm algorithm)
    {
        // Arrange
        using var cert = CreateTestCertificate("CN=Test", algorithm);

        // Act
        var builder = cert.GetDidBuilder();

        // Assert
        Assert.That(builder, Is.Not.Null);
    }

    [Test]
    public void GetDidBuilder_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2 cert = null!;

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => cert.GetDidBuilder());
        Assert.That(ex!.ParamName, Is.EqualTo("certificate"));
    }

    [Test]
    [TestCaseSource(nameof(AllAlgorithms))]
    public void GetDidWithRoot_WithValidChain_ReturnsValidDid(CertAlgorithm algorithm)
    {
        // Arrange
        var chain = CreateTestChain(algorithm);
        using var leaf = chain[0];
        using var root = chain[2];

        // Act
        string did = leaf.GetDidWithRoot(chain);

        // Assert
        Assert.That(did, Is.Not.Null.And.Not.Empty);
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
    }

    [Test]
    [TestCaseSource(nameof(AllAlgorithms))]
    public void GetDidWithRoot_ConsistentResults_SameCertificatesProduceSameDid(CertAlgorithm algorithm)
    {
        // Arrange
        var chain = CreateTestChain(algorithm);
        using var leaf = chain[0];

        // Act
        string did1 = leaf.GetDidWithRoot(chain);
        string did2 = leaf.GetDidWithRoot(chain);

        // Assert
        Assert.That(did1, Is.EqualTo(did2));
    }

    [Test]
    public void GetDidWithRoot_DifferentRoots_ProducesDifferentDids()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root1 = CreateSelfSignedCertificate("CN=Root1");
        using var root2 = CreateSelfSignedCertificate("CN=Root2");
        var chain1 = new[] { leaf, root1 };
        var chain2 = new[] { leaf, root2 };

        // Act
        string did1 = leaf.GetDidWithRoot(chain1);
        string did2 = leaf.GetDidWithRoot(chain2);

        // Assert
        Assert.That(did1, Is.Not.EqualTo(did2));
    }

    [Test]
    public void GetDidWithRoot_DifferentLeafCerts_ProducesDifferentDids()
    {
        // Arrange
        using var leaf1 = CreateTestCertificate("CN=Leaf1");
        using var leaf2 = CreateTestCertificate("CN=Leaf2");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain1 = new[] { leaf1, root };
        var chain2 = new[] { leaf2, root };

        // Act
        string did1 = leaf1.GetDidWithRoot(chain1);
        string did2 = leaf2.GetDidWithRoot(chain2);

        // Assert
        Assert.That(did1, Is.Not.EqualTo(did2));
    }

    [Test]
    public void GetDidWithRoot_WithSha384_ReturnsValidDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRoot(chain, DidX509Constants.HashAlgorithmSha384);

        // Assert
        AssertDidStructure(did, "sha384", root, "subject");
        AssertDidContainsCertHash(did, root, "sha384");
    }

    [Test]
    public void GetDidWithRoot_WithSha512_ReturnsValidDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRoot(chain, DidX509Constants.HashAlgorithmSha512);

        // Assert
        AssertDidStructure(did, "sha512", root, "subject");
        AssertDidContainsCertHash(did, root, "sha512");
    }

    [Test]
    public void GetDidWithRoot_IncludesCorrectRootHash()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        byte[] expectedHash = SHA256.HashData(root.RawData);
        string expectedHashBase64Url = Convert.ToBase64String(expectedHash)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        // Act
        string did = leaf.GetDidWithRoot(chain);

        // Assert
        Assert.That(did, Does.Contain(expectedHashBase64Url));
        AssertDidStructure(did, "sha256", root, "subject");
    }

    [Test]
    public void GetDidWithRoot_PercentEncodesSubject()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Test Subject, O=Test Org");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRoot(chain);

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("%20")); // Space
        Assert.That(did, Does.Contain("CN:"));
        Assert.That(did, Does.Contain("O:"));
    }

    [Test]
    public void GetDidWithRoot_WithSpecialCharactersInSubject_EncodesCorrectly()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Test@Example.com");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRoot(chain);

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("%40")); // @ symbol
    }

    [Test]
    public void GetDidWithRoot_WithMultipleSubjectFields_FormatsAsKeyValuePairs()
    {
        // Arrange
        using var leaf = CreateTestCertificate("C=US, ST=California, L=San Francisco, O=GitHub, OU=Engineering, CN=Test User");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRoot(chain);

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
        // The subject DN is encoded as a single field by CreateTestCertificate
        Assert.That(did, Does.Contain("CN:"));
        Assert.That(did, Does.Contain("OU:Engineering"));
        Assert.That(did, Does.Contain("O:GitHub"));
        Assert.That(did, Does.Not.Contain("C=")); // Should not contain DN format
    }

    [Test]
    public void GetDidWithPca_WithValidChain_ReturnsValidDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var intermediate = CreateTestCertificate("CN=Intermediate");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, intermediate, root };

        // Act
        string did = leaf.GetDidWithPca(chain);

        // Assert
        AssertDidStructure(did, "sha256", intermediate, "subject");
        AssertDidContainsCertHash(did, intermediate, "sha256");
        // Should use intermediate (PCA) cert, not root
        byte[] pcaHash = SHA256.HashData(intermediate.RawData);
        string pcaHashBase64Url = Convert.ToBase64String(pcaHash)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.That(did, Does.Contain(pcaHashBase64Url));
    }

    [Test]
    public void GetDidWithIntermediate_WithValidIndex_ReturnsValidDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var pca = CreateTestCertificate("CN=PCA");
        using var intermediate = CreateTestCertificate("CN=Intermediate");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, pca, intermediate, root };

        // Act
        string did = leaf.GetDidWithIntermediate(chain, 2); // Second intermediate

        // Assert
        AssertDidStructure(did, "sha256", intermediate, "subject");
        AssertDidContainsCertHash(did, intermediate, "sha256");
        byte[] interHash = SHA256.HashData(intermediate.RawData);
        string interHashBase64Url = Convert.ToBase64String(interHash)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.That(did, Does.Contain(interHashBase64Url));
    }

    [Test]
    public void GetDidWithIntermediate_WithInvalidIndex_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => leaf.GetDidWithIntermediate(chain, 0));
        Assert.That(ex!.Message, Does.Contain("Intermediate index must be >= 1"));
    }

    [Test]
    public void GetDidWithCertAtLocationInChain_WithForwardIndex_ReturnsValidDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var intermediate = CreateTestCertificate("CN=Intermediate");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, intermediate, root };

        // Act
        string did = leaf.GetDidWithCertAtLocationInChain(chain, 1); // PCA

        // Assert
        AssertDidStructure(did, "sha256", intermediate, "subject");
        AssertDidContainsCertHash(did, intermediate, "sha256");
        byte[] interHash = SHA256.HashData(intermediate.RawData);
        string interHashBase64Url = Convert.ToBase64String(interHash)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.That(did, Does.Contain(interHashBase64Url));
    }

    [Test]
    public void GetDidWithCertAtLocationInChain_WithBackwardIndex_ReturnsValidDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var intermediate = CreateTestCertificate("CN=Intermediate");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, intermediate, root };

        // Act
        string did = leaf.GetDidWithCertAtLocationInChain(chain, chain.Length - 1); // Root (last)

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
        byte[] rootHash = SHA256.HashData(root.RawData);
        string rootHashBase64Url = Convert.ToBase64String(rootHash)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.That(did, Does.Contain(rootHashBase64Url));
    }

    [Test]
    public void GetDidWithCertAtLocationInChain_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2 cert = null!;
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { root };

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => cert.GetDidWithCertAtLocationInChain(chain, 0));
        Assert.That(ex!.ParamName, Is.EqualTo("certificate"));
    }

    [Test]
    public void GetDidWithCertAtLocationInChain_WithNullChain_ThrowsArgumentNullException()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => leaf.GetDidWithCertAtLocationInChain(null!, 0));
        Assert.That(ex!.ParamName, Is.EqualTo("chain"));
    }

    [Test]
    public void GetDidWithCertAtLocationInChain_WithChainTooShort_ThrowsArgumentException()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        var chain = new[] { leaf };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => leaf.GetDidWithCertAtLocationInChain(chain, 0));
        Assert.That(ex!.Message, Does.Contain("at least 2 certificates"));
    }

    [Test]
    public void GetDidWithCertAtLocationInChain_WithIndexOutOfRange_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => leaf.GetDidWithCertAtLocationInChain(chain, 10));
        Assert.That(ex!.Message, Does.Contain("out of range"));
    }

    [Test]
    public void GetDidWithRootAndEku_WithEkuExtension_IncludesEkuPolicy()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain);

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void GetDidWithRootAndEku_WithoutEkuExtension_OnlyIncludesSubject()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain);

        // Assert
        AssertDidStructure(did, "sha256", root, "subject");
        AssertDidContainsCertHash(did, root, "sha256");
        // Note: TestCertificateUtils creates certificates with default EKUs
        // so this test verifies that GetDidWithRootAndEku includes EKU when present
        Assert.That(did, Does.Contain("::subject:"));
    }

    [Test]
    public void GetDidWithRootAndEku_WithMultipleEkus_FirstPreference_SelectsFirst()
    {
        // Arrange - First EKU should be selected
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.10.3.13"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.First);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.3.6.1.5.5.7.3.1");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void GetDidWithRootAndEku_WithMultipleEkus_MostSpecificPreference_SelectsMostSegments()
    {
        // Arrange - MostSpecific selects the one with most segments (10 segments)
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.4.1.311.10.3.13", "1.2.3.4"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecific);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.3.6.1.4.1.311.10.3.13");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.13"));
    }

    [Test]
    public void GetDidWithRootAndEku_WithMultipleEkus_LargestPreference_SelectsNumericallyLargest()
    {
        // Arrange - Largest selects numerically largest (2 > 1)
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "2.5.29.17"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.Largest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "2.5.29.17");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:2.5.29.17"));
    }

    [Test]
    public void GetDidWithRootAndEku_WithMultipleEkus_MostSpecificAndLargestPreference_PrioritizesSpecificity()
    {
        // Arrange - Same segment count, larger last segment wins
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["2.5.29.17", "1.2.3.4.5", "1.2.3.4.100"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecificAndLargest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.2.3.4.100");
        AssertDidContainsCertHash(did, root, "sha256");
        // Should select based on last segment (100 > 5) when segments are equal
        Assert.That(did, Does.Contain("::eku:1.2.3.4.100"));
    }

    [Test]
    public void GetDidWithRootAndEku_WithEkuPrefixFilter_FiltersCorrectly()
    {
        // Arrange - Mix of standard and Microsoft-specific EKUs
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.4.1.311.10.3.13", "1.3.6.1.5.5.7.3.2"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.First, "1.3.6.1.4.1");

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.3.6.1.4.1.311.10.3.13");
        AssertDidContainsCertHash(did, root, "sha256");
        // Should only select Microsoft OID starting with 1.3.6.1.4.1
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.13"));
        Assert.That(did, Does.Not.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void GetDidWithRootAndSan_WithDnsName_IncludesSanPolicy()
    {
        // Arrange - Create certificate with specific DNS SAN
        using var cert = CreateTestCertificate("CN=Leaf", customSans: [("dns", "example.com")]);
        var chain = new[] { cert };

        // Act
        string? did = cert.GetDidWithRootAndSan(chain);

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::san:dns:example.com"));
        AssertDidContainsCertHash(did!, cert, "sha256");
    }

    [Test]
    public void GetDidWithRootAndSan_WithEmail_IncludesSanPolicy()
    {
        // Arrange - Create certificate with email SAN
        using var cert = CreateTestCertificate("CN=Leaf", customSans: [("email", "user@example.com")]);
        var chain = new[] { cert };

        // Act
        string? did = cert.GetDidWithRootAndSan(chain, "email");

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::san:email:user%40example.com"));
        AssertDidContainsCertHash(did!, cert, "sha256");
    }

    [Test]
    public void GetDidWithRootAndSan_WithoutSanExtension_ReturnsNull()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        // Note: Request a SAN type that doesn't exist in the certificate
        string? did = leaf.GetDidWithRootAndSan(chain, "email");

        // Assert
        // Should return null when requested SAN type is not present
        Assert.That(did, Is.Null);
    }

    [Test]
    public void GetDidWithRootAndSan_WithNonMatchingSanType_ReturnsNull()
    {
        // Arrange
        // CreateCertificateWithSan creates a self-signed cert
        using var cert = CreateTestCertificate("CN=Leaf");
        var chain = new[] { cert };

        // Act - Request email but cert only has DNS
        string? did = cert.GetDidWithRootAndSan(chain, "email");

        // Assert
        Assert.That(did, Is.Null);
    }

    [Test]
    public void GetDidWithCertAtLocationInChainAndEku_WithSpecificLocation_UsesCorrectCert()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]);
        using var intermediate = CreateTestCertificate("CN=Intermediate");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, intermediate, root };

        // Act
        string did = leaf.GetDidWithCertAtLocationInChainAndEku(chain, 1); // Use PCA

        // Assert
        AssertDidStructure(did, "sha256", intermediate, "eku", "1.3.6.1.5.5.7.3.1");
        AssertDidContainsCertHash(did, intermediate, "sha256");
        byte[] interHash = SHA256.HashData(intermediate.RawData);
        string interHashBase64Url = Convert.ToBase64String(interHash)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.That(did, Does.Contain(interHashBase64Url));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

}
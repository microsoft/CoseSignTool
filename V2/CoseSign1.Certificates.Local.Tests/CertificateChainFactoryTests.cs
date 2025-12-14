// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Tests;

/// <summary>
/// Tests for <see cref="CertificateChainFactory"/>.
/// </summary>
[TestFixture]
public class CertificateChainFactoryTests
{
    [Test]
    public void CreateChain_WithDefaults_Creates3TierChain()
    {
        // Arrange
        var factory = new CertificateChainFactory();

        // Act
        var chain = factory.CreateChain();

        // Assert
        Assert.That(chain.Count, Is.EqualTo(3));
        Assert.That(chain[0].Subject, Does.Contain("Root"));
        Assert.That(chain[1].Subject, Does.Contain("Intermediate"));
        Assert.That(chain[2].Subject, Does.Contain("Leaf"));
    }

    [Test]
    public void CreateChain_WithoutIntermediate_Creates2TierChain()
    {
        // Arrange
        var factory = new CertificateChainFactory();

        // Act
        var chain = factory.CreateChain(o => o.WithoutIntermediate());

        // Assert
        Assert.That(chain.Count, Is.EqualTo(2));
        Assert.That(chain[0].Subject, Does.Contain("Root"));
        Assert.That(chain[1].Subject, Does.Contain("Leaf"));
    }

    [TestCase(KeyAlgorithm.RSA)]
    [TestCase(KeyAlgorithm.ECDSA)]
    [TestCase(KeyAlgorithm.MLDSA)]
    public void CreateChain_WithDifferentAlgorithms_AllCertificatesUseAlgorithm(KeyAlgorithm algorithm)
    {
        // Arrange
        var factory = new CertificateChainFactory();

        // Act
        var chain = factory.CreateChain(o => o.WithKeyAlgorithm(algorithm));

        // Assert
        foreach (var cert in chain)
        {
            Assert.That(cert.HasPrivateKey, Is.True);
        }
    }

    [Test]
    public void CreateChain_LeafFirstOrder_ReturnsLeafFirst()
    {
        // Arrange
        var factory = new CertificateChainFactory();

        // Act
        var chain = factory.CreateChain(o => o.LeafFirstOrder());

        // Assert
        Assert.That(chain[0].Subject, Does.Contain("Leaf"));
        Assert.That(chain[chain.Count - 1].Subject, Does.Contain("Root"));
    }

    [Test]
    public void CreateChain_ForPfxExport_OnlyLeafHasPrivateKey()
    {
        // Arrange
        var factory = new CertificateChainFactory();

        // Act
        var chain = factory.CreateChain(o => o.ForPfxExport());

        // Assert
        Assert.That(chain[0].HasPrivateKey, Is.False); // Root
        Assert.That(chain[1].HasPrivateKey, Is.False); // Intermediate  
        Assert.That(chain[2].HasPrivateKey, Is.True);  // Leaf
    }

    [Test]
    public void CreateChain_CustomNames_UsesSpecifiedNames()
    {
        // Arrange
        var factory = new CertificateChainFactory();

        // Act
        var chain = factory.CreateChain(o => o
            .WithRootName("CN=My Root")
            .WithIntermediateName("CN=My Intermediate")
            .WithLeafName("CN=My Leaf"));

        // Assert
        Assert.That(chain[0].Subject, Is.EqualTo("CN=My Root"));
        Assert.That(chain[1].Subject, Is.EqualTo("CN=My Intermediate"));
        Assert.That(chain[2].Subject, Is.EqualTo("CN=My Leaf"));
    }

    [Test]
    public void CreateChain_VerifiesChainStructure()
    {
        // Arrange
        var factory = new CertificateChainFactory();

        // Act
        var chain = factory.CreateChain();

        // Assert - Verify issuer relationships
        var root = chain[0];
        var intermediate = chain[1];
        var leaf = chain[2];

        // Root is self-signed
        Assert.That(root.Issuer, Is.EqualTo(root.Subject));

        // Intermediate is signed by root
        Assert.That(intermediate.Issuer, Is.EqualTo(root.Subject));

        // Leaf is signed by intermediate
        Assert.That(leaf.Issuer, Is.EqualTo(intermediate.Subject));
    }

    [Test]
    public void CreateChain_WithCustomLeafEkus_LeafHasCorrectEkus()
    {
        // Arrange
        var factory = new CertificateChainFactory();
        const string serverAuthOid = "1.3.6.1.5.5.7.3.1";
        const string clientAuthOid = "1.3.6.1.5.5.7.3.2";

        // Act
        var chain = factory.CreateChain(o => o
            .WithLeafEkus(serverAuthOid, clientAuthOid));

        // Assert
        var leaf = chain[^1];
        var eku = leaf.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        Assert.That(eku, Is.Not.Null);
        Assert.That(eku!.EnhancedKeyUsages.Count, Is.EqualTo(2));
    }
}
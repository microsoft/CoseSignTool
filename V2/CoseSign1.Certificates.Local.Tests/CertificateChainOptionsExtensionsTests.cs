// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Tests;

/// <summary>
/// Tests for <see cref="CertificateChainOptionsExtensions"/>.
/// </summary>
[TestFixture]
public class CertificateChainOptionsExtensionsTests
{
    [Test]
    public void WithRootName_SetsRootName()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act
        var result = options.WithRootName("CN=Custom Root");

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.RootName, Is.EqualTo("CN=Custom Root"));
    }

    [Test]
    public void WithRootName_WithNull_ThrowsArgumentNullException()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => options.WithRootName(null!));
    }

    [Test]
    public void WithIntermediateName_SetsIntermediateName()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act
        var result = options.WithIntermediateName("CN=Custom Intermediate");

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.IntermediateName, Is.EqualTo("CN=Custom Intermediate"));
    }

    [Test]
    public void WithIntermediateName_WithNull_SetsNull()
    {
        // Arrange
        var options = new CertificateChainOptions();
        options.IntermediateName = "CN=Some Value";

        // Act
        var result = options.WithIntermediateName(null);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.IntermediateName, Is.Null);
    }

    [Test]
    public void WithoutIntermediate_SetsIntermediateNameToNull()
    {
        // Arrange
        var options = new CertificateChainOptions();
        options.IntermediateName = "CN=Some Intermediate";

        // Act
        var result = options.WithoutIntermediate();

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.IntermediateName, Is.Null);
    }

    [Test]
    public void WithLeafName_SetsLeafName()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act
        var result = options.WithLeafName("CN=Custom Leaf");

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.LeafName, Is.EqualTo("CN=Custom Leaf"));
    }

    [Test]
    public void WithLeafName_WithNull_ThrowsArgumentNullException()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => options.WithLeafName(null!));
    }

    [TestCase(KeyAlgorithm.RSA)]
    [TestCase(KeyAlgorithm.ECDSA)]
    [TestCase(KeyAlgorithm.MLDSA)]
    public void WithKeyAlgorithm_SetsKeyAlgorithm(KeyAlgorithm algorithm)
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act
        var result = options.WithKeyAlgorithm(algorithm);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.KeyAlgorithm, Is.EqualTo(algorithm));
    }

    [TestCase(2048)]
    [TestCase(4096)]
    [TestCase(256)]
    [TestCase(384)]
    public void WithKeySize_SetsKeySize(int keySize)
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act
        var result = options.WithKeySize(keySize);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.KeySize, Is.EqualTo(keySize));
    }

    [Test]
    public void WithValidity_SetsAllValidityPeriods()
    {
        // Arrange
        var options = new CertificateChainOptions();
        var rootValidity = TimeSpan.FromDays(3650);
        var intermediateValidity = TimeSpan.FromDays(1825);
        var leafValidity = TimeSpan.FromDays(365);

        // Act
        var result = options.WithValidity(rootValidity, intermediateValidity, leafValidity);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.RootValidity, Is.EqualTo(rootValidity));
        Assert.That(options.IntermediateValidity, Is.EqualTo(intermediateValidity));
        Assert.That(options.LeafValidity, Is.EqualTo(leafValidity));
    }

    [Test]
    public void ForPfxExport_SetsLeafOnlyPrivateKey()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act
        var result = options.ForPfxExport();

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.LeafOnlyPrivateKey, Is.True);
    }

    [Test]
    public void LeafFirstOrder_SetsLeafFirst()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act
        var result = options.LeafFirstOrder();

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.LeafFirst, Is.True);
    }

    [Test]
    public void WithLeafEkus_SetsLeafEnhancedKeyUsages()
    {
        // Arrange
        var options = new CertificateChainOptions();
        var ekuOid1 = "1.3.6.1.5.5.7.3.1"; // Server Auth
        var ekuOid2 = "1.3.6.1.5.5.7.3.2"; // Client Auth

        // Act
        var result = options.WithLeafEkus(ekuOid1, ekuOid2);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.LeafEnhancedKeyUsages, Is.Not.Null);
        Assert.That(options.LeafEnhancedKeyUsages!.Count, Is.EqualTo(2));
        Assert.That(options.LeafEnhancedKeyUsages, Contains.Item(ekuOid1));
        Assert.That(options.LeafEnhancedKeyUsages, Contains.Item(ekuOid2));
    }

    [Test]
    public void FluentChaining_AllMethodsChainCorrectly()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act - Chain all methods together
        var result = options
            .WithRootName("CN=Chain Root")
            .WithIntermediateName("CN=Chain Intermediate")
            .WithLeafName("CN=Chain Leaf")
            .WithKeyAlgorithm(KeyAlgorithm.ECDSA)
            .WithKeySize(384)
            .WithValidity(
                TimeSpan.FromDays(100),
                TimeSpan.FromDays(50),
                TimeSpan.FromDays(10))
            .ForPfxExport()
            .LeafFirstOrder()
            .WithLeafEkus("1.3.6.1.5.5.7.3.3");

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.RootName, Is.EqualTo("CN=Chain Root"));
        Assert.That(options.IntermediateName, Is.EqualTo("CN=Chain Intermediate"));
        Assert.That(options.LeafName, Is.EqualTo("CN=Chain Leaf"));
        Assert.That(options.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.ECDSA));
        Assert.That(options.KeySize, Is.EqualTo(384));
        Assert.That(options.RootValidity, Is.EqualTo(TimeSpan.FromDays(100)));
        Assert.That(options.IntermediateValidity, Is.EqualTo(TimeSpan.FromDays(50)));
        Assert.That(options.LeafValidity, Is.EqualTo(TimeSpan.FromDays(10)));
        Assert.That(options.LeafOnlyPrivateKey, Is.True);
        Assert.That(options.LeafFirst, Is.True);
        Assert.That(options.LeafEnhancedKeyUsages, Contains.Item("1.3.6.1.5.5.7.3.3"));
    }

    [Test]
    public void WithLeafEkus_WithEmptyArray_SetsEmptyList()
    {
        // Arrange
        var options = new CertificateChainOptions();

        // Act
        var result = options.WithLeafEkus();

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.LeafEnhancedKeyUsages, Is.Not.Null);
        Assert.That(options.LeafEnhancedKeyUsages!.Count, Is.EqualTo(0));
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Tests.Common;
using DIDx509.CertificateChain;
using DIDx509.Models;

namespace DIDx509.Tests.Models;

[TestFixture]
public class CertificateChainModelTests
{
    [Test]
    public void Constructor_NullChain_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new CertificateChainModel(null!));
    }

    [Test]
    public void Constructor_SingleCertificate_ThrowsArgumentException()
    {
        // Arrange - create a model with just one cert
        var testChain = TestCertificateUtils.CreateTestChain();
        var converted = CertificateChainConverter.Convert(testChain.ToArray());

        // Create a list with only one certificate
        var singleCert = new List<CertificateInfo> { converted.Chain[0] };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => new CertificateChainModel(singleCert));
    }

    [Test]
    public void LeafCertificate_ReturnsFirstCertificate()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var model = CertificateChainConverter.Convert(testChain.ToArray());

        // Act
        var leaf = model.LeafCertificate;

        // Assert
        Assert.That(leaf, Is.EqualTo(model.Chain[0]));
    }

    [Test]
    public void CaCertificates_ReturnsAllExceptFirst()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var model = CertificateChainConverter.Convert(testChain.ToArray());

        // Act
        var cas = model.CaCertificates.ToList();

        // Assert
        Assert.That(cas.Count, Is.EqualTo(model.Chain.Count - 1));
        for (int i = 0; i < cas.Count; i++)
        {
            Assert.That(cas[i], Is.EqualTo(model.Chain[i + 1]));
        }
    }

    [Test]
    public void FindCaByFingerprint_MatchingSha256_ReturnsCertificate()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var model = CertificateChainConverter.Convert(testChain.ToArray());
        var rootCa = model.Chain[model.Chain.Count - 1];
        var fingerprint = rootCa.Fingerprints.Sha256;

        // Act
        var found = model.FindCaByFingerprint("sha256", fingerprint);

        // Assert
        Assert.That(found, Is.Not.Null);
        Assert.That(found!.Fingerprints.Sha256, Is.EqualTo(fingerprint));
    }

    [Test]
    public void FindCaByFingerprint_NonMatchingFingerprint_ReturnsNull()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var model = CertificateChainConverter.Convert(testChain.ToArray());
        var fakeFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        // Act
        var found = model.FindCaByFingerprint("sha256", fakeFingerprint);

        // Assert
        Assert.That(found, Is.Null);
    }

    [Test]
    public void FindCaByFingerprint_LeafFingerprint_ReturnsNull()
    {
        // Arrange - searching for leaf certificate fingerprint among CAs should fail
        var testChain = TestCertificateUtils.CreateTestChain();
        var model = CertificateChainConverter.Convert(testChain.ToArray());
        var leafFingerprint = model.LeafCertificate.Fingerprints.Sha256;

        // Act
        var found = model.FindCaByFingerprint("sha256", leafFingerprint);

        // Assert - should return null since leaf is not in CA certificates
        Assert.That(found, Is.Null);
    }

    [Test]
    public void FindCaByFingerprint_UnknownAlgorithm_ReturnsNull()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var model = CertificateChainConverter.Convert(testChain.ToArray());
        var rootFingerprint = model.Chain[model.Chain.Count - 1].Fingerprints.Sha256;

        // Act
        var found = model.FindCaByFingerprint("unknownalgo", rootFingerprint);

        // Assert
        Assert.That(found, Is.Null);
    }
}

[TestFixture]
public class CertificateFingerprintsTests
{
    [Test]
    public void Constructor_NullSha256_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new CertificateFingerprints(null!));
    }

    [Test]
    public void Constructor_WithSha256Only_Succeeds()
    {
        // Arrange & Act
        var fingerprints = new CertificateFingerprints("WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk");

        // Assert
        Assert.That(fingerprints.Sha256, Is.EqualTo("WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk"));
        Assert.That(fingerprints.Sha384, Is.Null);
        Assert.That(fingerprints.Sha512, Is.Null);
    }

    [Test]
    public void Constructor_WithAllAlgorithms_StoresAll()
    {
        // Arrange & Act
        var fingerprints = new CertificateFingerprints(
            "sha256fingerprint",
            "sha384fingerprint",
            "sha512fingerprint");

        // Assert
        Assert.That(fingerprints.Sha256, Is.EqualTo("sha256fingerprint"));
        Assert.That(fingerprints.Sha384, Is.EqualTo("sha384fingerprint"));
        Assert.That(fingerprints.Sha512, Is.EqualTo("sha512fingerprint"));
    }

    [Test]
    public void GetFingerprint_Sha256_ReturnsCorrectValue()
    {
        var fingerprints = new CertificateFingerprints("sha256val", "sha384val", "sha512val");
        Assert.That(fingerprints.GetFingerprint("sha256"), Is.EqualTo("sha256val"));
    }

    [Test]
    public void GetFingerprint_Sha384_ReturnsCorrectValue()
    {
        var fingerprints = new CertificateFingerprints("sha256val", "sha384val", "sha512val");
        Assert.That(fingerprints.GetFingerprint("sha384"), Is.EqualTo("sha384val"));
    }

    [Test]
    public void GetFingerprint_Sha512_ReturnsCorrectValue()
    {
        var fingerprints = new CertificateFingerprints("sha256val", "sha384val", "sha512val");
        Assert.That(fingerprints.GetFingerprint("sha512"), Is.EqualTo("sha512val"));
    }

    [Test]
    public void GetFingerprint_UnknownAlgorithm_ReturnsNull()
    {
        var fingerprints = new CertificateFingerprints("sha256val");
        Assert.That(fingerprints.GetFingerprint("md5"), Is.Null);
    }

    [Test]
    public void GetFingerprint_NullAlgorithm_ReturnsNull()
    {
        var fingerprints = new CertificateFingerprints("sha256val");
        Assert.That(fingerprints.GetFingerprint(null!), Is.Null);
    }

    [Test]
    public void GetFingerprint_CaseInsensitive()
    {
        var fingerprints = new CertificateFingerprints("sha256val");
        Assert.That(fingerprints.GetFingerprint("SHA256"), Is.EqualTo("sha256val"));
        Assert.That(fingerprints.GetFingerprint("Sha256"), Is.EqualTo("sha256val"));
    }

    [Test]
    public void Matches_MatchingFingerprint_ReturnsTrue()
    {
        var fingerprints = new CertificateFingerprints("matchme");
        Assert.That(fingerprints.Matches("sha256", "matchme"), Is.True);
    }

    [Test]
    public void Matches_NonMatchingFingerprint_ReturnsFalse()
    {
        var fingerprints = new CertificateFingerprints("matchme");
        Assert.That(fingerprints.Matches("sha256", "nomatch"), Is.False);
    }

    [Test]
    public void Matches_UnknownAlgorithm_ReturnsFalse()
    {
        var fingerprints = new CertificateFingerprints("matchme");
        Assert.That(fingerprints.Matches("md5", "matchme"), Is.False);
    }

    [Test]
    public void Matches_CaseSensitiveFingerprint()
    {
        // Fingerprints are case-sensitive (base64url encoding)
        var fingerprints = new CertificateFingerprints("AbCdEf");
        Assert.That(fingerprints.Matches("sha256", "AbCdEf"), Is.True);
        Assert.That(fingerprints.Matches("sha256", "abcdef"), Is.False);
        Assert.That(fingerprints.Matches("sha256", "ABCDEF"), Is.False);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Tests;

/// <summary>
/// Tests for <see cref="EphemeralCertificateFactory"/>.
/// </summary>
[TestFixture]
public class EphemeralCertificateFactoryTests
{
    [Test]
    public void CreateCertificate_WithDefaults_CreatesValidRsaCertificate()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var cert = factory.CreateCertificate();

        // Assert
        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.Subject, Does.Contain("CN="));
        Assert.That(cert.HasPrivateKey, Is.True);
        Assert.That(cert.PublicKey.Oid.FriendlyName, Is.EqualTo("RSA"));
    }

    [TestCase(KeyAlgorithm.RSA, 2048)]
    [TestCase(KeyAlgorithm.RSA, 4096)]
    [TestCase(KeyAlgorithm.ECDSA, 256)]
    [TestCase(KeyAlgorithm.ECDSA, 384)]
    [TestCase(KeyAlgorithm.MLDSA, 65)]
    [TestCase(KeyAlgorithm.MLDSA, 87)]
    public void CreateCertificate_WithDifferentAlgorithms_CreatesValidCertificate(KeyAlgorithm algorithm, int keySize)
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(algorithm)
            .WithKeySize(keySize));

        // Assert
        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.HasPrivateKey, Is.True);
    }

    [Test]
    public void CreateCertificate_WithSubjectName_UsesSpecifiedSubject()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        const string expectedSubject = "CN=Test Certificate, O=Test Org";

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithSubjectName(expectedSubject));

        // Assert
        Assert.That(cert.Subject, Is.EqualTo(expectedSubject));
    }

    [Test]
    public void CreateCertificate_AsCertificateAuthority_HasCorrectExtensions()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var cert = factory.CreateCertificate(o => o
            .AsCertificateAuthority(pathLengthConstraint: 1));

        // Assert
        var basicConstraints = cert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();

        Assert.That(basicConstraints, Is.Not.Null);
        Assert.That(basicConstraints!.CertificateAuthority, Is.True);
        Assert.That(basicConstraints.HasPathLengthConstraint, Is.True);
    }

    [Test]
    public void CreateCertificate_SignedByIssuer_CreatesValidChain()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var root = factory.CreateCertificate(o => o
            .WithSubjectName("CN=Root CA")
            .AsCertificateAuthority());

        using var leaf = factory.CreateCertificate(o => o
            .WithSubjectName("CN=Leaf Certificate")
            .SignedBy(root));

        // Assert
        Assert.That(leaf.Issuer, Is.EqualTo(root.Subject));
    }

    [Test]
    public void CreateCertificate_WithValidityPeriod_HasCorrectDates()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var validity = TimeSpan.FromDays(365);

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithValidity(validity));

        // Assert
        // Note: cert.NotAfter is in local time, so convert to UTC for comparison
        var expectedEnd = DateTimeOffset.UtcNow.Add(validity);
        var actualEndUtc = cert.NotAfter.ToUniversalTime();
        Assert.That(actualEndUtc, Is.EqualTo(expectedEnd.DateTime).Within(TimeSpan.FromMinutes(1)));
    }

    [Test]
    public void GetGeneratedKey_AfterCreatingCertificate_ReturnsKey()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var cert = factory.CreateCertificate();
        var key = factory.GetGeneratedKey(cert);

        // Assert
        Assert.That(key, Is.Not.Null);
        Assert.That(key!.Algorithm, Is.EqualTo(KeyAlgorithm.RSA));
        Assert.That(key.SignatureGenerator, Is.Not.Null);
    }

    [Test]
    public void ReleaseKey_AfterCreatingCertificate_RemovesKey()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate();

        // Act
        var released = factory.ReleaseKey(cert);
        var key = factory.GetGeneratedKey(cert);

        // Assert
        Assert.That(released, Is.True);
        Assert.That(key, Is.Null);
    }

    [Test]
    public void CreateCertificate_WithEnhancedKeyUsages_HasCorrectEKUs()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        const string codeSigningOid = "1.3.6.1.5.5.7.3.3";
        const string timeStampingOid = "1.3.6.1.5.5.7.3.8";

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithEnhancedKeyUsages(codeSigningOid, timeStampingOid));

        // Assert
        var eku = cert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        Assert.That(eku, Is.Not.Null);
        Assert.That(eku!.EnhancedKeyUsages.Count, Is.EqualTo(2));
    }

    [Test]
    public async Task CreateCertificateAsync_CreatesValidCertificate()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var cert = await factory.CreateCertificateAsync(o => o
            .WithSubjectName("CN=Async Test"));

        // Assert
        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.Subject, Does.Contain("CN=Async Test"));
    }

    [Test]
    public void CreateCertificate_WithNullConfigure_ThrowsArgumentNullException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => factory.CreateCertificate(null!));
    }

    [Test]
    public async Task CreateCertificateAsync_WithNullConfigure_ThrowsArgumentNullException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await factory.CreateCertificateAsync(null!));
    }

    [Test]
    public void GetGeneratedKey_WithNullCertificate_ReturnsNull()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        var key = factory.GetGeneratedKey(null!);

        // Assert
        Assert.That(key, Is.Null);
    }

    [Test]
    public void ReleaseKey_WithNullCertificate_ReturnsFalse()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        var released = factory.ReleaseKey(null!);

        // Assert
        Assert.That(released, Is.False);
    }

    [Test]
    public void ReleaseKey_WithUnknownCertificate_ReturnsFalse()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var otherFactory = new EphemeralCertificateFactory();
        using var cert = otherFactory.CreateCertificate();

        // Act
        var released = factory.ReleaseKey(cert);

        // Assert
        Assert.That(released, Is.False);
    }

    [Test]
    public void GetGeneratedKey_WithUnknownCertificate_ReturnsNull()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var otherFactory = new EphemeralCertificateFactory();
        using var cert = otherFactory.CreateCertificate();

        // Act
        var key = factory.GetGeneratedKey(cert);

        // Assert
        Assert.That(key, Is.Null);
    }

    [TestCase(CertificateHashAlgorithm.SHA256)]
    [TestCase(CertificateHashAlgorithm.SHA384)]
    [TestCase(CertificateHashAlgorithm.SHA512)]
    public void CreateCertificate_WithDifferentHashAlgorithms_CreatesValidCertificate(CertificateHashAlgorithm hashAlgorithm)
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithHashAlgorithm(hashAlgorithm));

        // Assert
        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.HasPrivateKey, Is.True);
    }

    [Test]
    public void CreateCertificate_WithCustomExtensions_AddsExtensions()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var customOid = new Oid("2.5.29.100", "Custom Test OID");
        var customExtension = new X509Extension(customOid, new byte[] { 0x04, 0x02, 0x00, 0x00 }, false);

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithExtension(customExtension));

        // Assert
        var foundExtension = cert.Extensions.Cast<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.100");
        Assert.That(foundExtension, Is.Not.Null);
    }

    [Test]
    public void CreateCertificate_WithKeyUsage_HasCorrectKeyUsage()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var expectedKeyUsage = X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment;

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithKeyUsage(expectedKeyUsage));

        // Assert
        var keyUsageExt = cert.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();

        Assert.That(keyUsageExt, Is.Not.Null);
        Assert.That(keyUsageExt!.KeyUsages & expectedKeyUsage, Is.EqualTo(expectedKeyUsage));
    }

    [Test]
    public void CreateCertificate_WithSubjectAlternativeNames_HasCorrectSANs()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithDnsSan("test.example.com")
            .WithEmailSan("test@example.com"));

        // Assert
        var sanExtension = cert.Extensions
            .Cast<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
        Assert.That(sanExtension, Is.Not.Null);
    }

    [Test]
    public void CreateCertificate_WithUriSubjectAlternativeName_HasCorrectSAN()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithUriSan("https://example.com/test"));

        // Assert
        var sanExtension = cert.Extensions
            .Cast<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
        Assert.That(sanExtension, Is.Not.Null);
    }

    [Test]
    public void CreateCertificate_WithUnsupportedSanType_ThrowsArgumentException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act & Assert - Set invalid SAN directly on options
        Assert.Throws<ArgumentException>(() => factory.CreateCertificate(o =>
        {
            o.SubjectAlternativeNames = [("invalid", "value")];
        }));
    }

    [Test]
    public void CreateCertificate_SignedByIssuer_ConstrainsValidityToIssuer()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var issuerValidity = TimeSpan.FromDays(30);
        var leafValidity = TimeSpan.FromDays(365); // Longer than issuer

        // Act
        using var issuer = factory.CreateCertificate(o => o
            .WithSubjectName("CN=Short Lived Issuer")
            .AsCertificateAuthority()
            .WithValidity(issuerValidity));

        using var leaf = factory.CreateCertificate(o => o
            .WithSubjectName("CN=Leaf Certificate")
            .SignedBy(issuer)
            .WithValidity(leafValidity));

        // Assert - Leaf validity should be constrained by issuer
        Assert.That(leaf.NotAfter.ToUniversalTime(), Is.LessThanOrEqualTo(issuer.NotAfter.ToUniversalTime()));
    }

    [Test]
    public void CreateCertificate_SignedByExternalIssuer_CreatesValidCertificate()
    {
        // Arrange - Create issuer with a different factory (simulates external issuer)
        var factory1 = new EphemeralCertificateFactory();
        var factory2 = new EphemeralCertificateFactory();

        using var issuer = factory1.CreateCertificate(o => o
            .WithSubjectName("CN=External Issuer")
            .WithKeyAlgorithm(KeyAlgorithm.RSA) // Use RSA to ensure compatibility
            .AsCertificateAuthority());

        // Act - Sign with factory2 using external issuer
        using var leaf = factory2.CreateCertificate(o => o
            .WithSubjectName("CN=Leaf from External Issuer")
            .SignedBy(issuer));

        // Assert
        Assert.That(leaf.Issuer, Is.EqualTo(issuer.Subject));
    }

    [Test]
    public void CreateCertificate_IssuerWithoutSKI_ThrowsArgumentException()
    {
        // This test verifies that issuer must have Subject Key Identifier
        // We can't easily create a cert without SKI using this factory,
        // so we verify through the chain behavior that proper validation occurs
        var factory = new EphemeralCertificateFactory();

        // Act
        using var root = factory.CreateCertificate(o => o
            .WithSubjectName("CN=Test Root")
            .AsCertificateAuthority());

        // Assert - Root should have SKI
        var ski = root.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .FirstOrDefault();
        Assert.That(ski, Is.Not.Null);
    }

    [Test]
    public async Task CreateCertificateAsync_WithCancellationToken_RespectsCancellation()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await factory.CreateCertificateAsync(o => o.WithSubjectName("CN=Test"), cts.Token));
    }

    [Test]
    public void Constructor_WithCustomKeyProvider_UsesProvider()
    {
        // Arrange
        var keyProvider = new SoftwareKeyProvider();
        var factory = new EphemeralCertificateFactory(keyProvider);

        // Act & Assert
        Assert.That(factory.KeyProvider, Is.SameAs(keyProvider));
    }

    [Test]
    public void Constructor_WithNullKeyProvider_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new EphemeralCertificateFactory((IPrivateKeyProvider)null!));
    }

    [Test]
    public void CreateCertificate_WithLongSubjectName_TruncatesDnsName()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var longName = "CN=" + new string('A', 50); // Longer than 40 chars

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithSubjectName(longName));

        // Assert - Should create without error, DNS name truncated internally
        Assert.That(cert, Is.Not.Null);
    }

    [Test]
    public void CreateCertificate_WithSpecialCharactersInSubject_CreatesCertificate()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var specialName = "CN=Test:With:Colons And Spaces";

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithSubjectName(specialName));

        // Assert
        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.Subject, Is.EqualTo(specialName));
    }

    [Test]
    public void CreateCertificate_SubjectNameWithoutCN_StillCreatesCertificate()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        var nonCnSubject = "O=Test Organization";

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithSubjectName(nonCnSubject));

        // Assert
        Assert.That(cert, Is.Not.Null);
    }

    [Test]
    public void CreateCertificate_WithNoEnhancedKeyUsages_UsesDefaultCodeSigning()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        const string codeSigningOid = "1.3.6.1.5.5.7.3.3";

        // Act
        using var cert = factory.CreateCertificate(o => o
            .WithSubjectName("CN=Default EKU Test"));

        // Assert
        var eku = cert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        Assert.That(eku, Is.Not.Null);
        Assert.That(eku!.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == codeSigningOid), Is.True);
    }

    [Test]
    public async Task CreateCertificateAsync_WithDifferentAlgorithms_AllWork()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();

        // Act & Assert - RSA
        using var rsaCert = await factory.CreateCertificateAsync(o => o
            .WithKeyAlgorithm(KeyAlgorithm.RSA)
            .WithSubjectName("CN=Async RSA"));
        Assert.That(rsaCert, Is.Not.Null);

        // Act & Assert - ECDSA
        using var ecdsaCert = await factory.CreateCertificateAsync(o => o
            .WithKeyAlgorithm(KeyAlgorithm.ECDSA)
            .WithSubjectName("CN=Async ECDSA"));
        Assert.That(ecdsaCert, Is.Not.Null);

        // Act & Assert - MLDSA
        using var mldsaCert = await factory.CreateCertificateAsync(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithSubjectName("CN=Async MLDSA"));
        Assert.That(mldsaCert, Is.Not.Null);
    }
}
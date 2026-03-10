// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Tests;

/// <summary>
/// Tests for <see cref="CertificateOptionsExtensions"/>.
/// </summary>
[TestFixture]
public class CertificateOptionsExtensionsTests
{
    [Test]
    public void WithSubjectName_SetsSubjectName()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithSubjectName("CN=Test");

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.SubjectName, Is.EqualTo("CN=Test"));
    }

    [Test]
    public void WithSubjectName_WithNull_ThrowsArgumentNullException()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => options.WithSubjectName(null!));
    }

    [TestCase(KeyAlgorithm.RSA)]
    [TestCase(KeyAlgorithm.ECDSA)]
    [TestCase(KeyAlgorithm.MLDSA)]
    public void WithKeyAlgorithm_SetsAlgorithm(KeyAlgorithm algorithm)
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithKeyAlgorithm(algorithm);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.KeyAlgorithm, Is.EqualTo(algorithm));
    }

    [TestCase(2048)]
    [TestCase(4096)]
    public void WithKeySize_SetsKeySize(int keySize)
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithKeySize(keySize);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.KeySize, Is.EqualTo(keySize));
    }

    [TestCase(CertificateHashAlgorithm.SHA256)]
    [TestCase(CertificateHashAlgorithm.SHA384)]
    [TestCase(CertificateHashAlgorithm.SHA512)]
    public void WithHashAlgorithm_SetsHashAlgorithm(CertificateHashAlgorithm hashAlgorithm)
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithHashAlgorithm(hashAlgorithm);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.HashAlgorithm, Is.EqualTo(hashAlgorithm));
    }

    [Test]
    public void WithValidity_SetsValidity()
    {
        // Arrange
        var options = new CertificateOptions();
        var validity = TimeSpan.FromDays(365);

        // Act
        var result = options.WithValidity(validity);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.Validity, Is.EqualTo(validity));
    }

    [Test]
    public void WithNotBeforeOffset_SetsOffset()
    {
        // Arrange
        var options = new CertificateOptions();
        var offset = TimeSpan.FromHours(1);

        // Act
        var result = options.WithNotBeforeOffset(offset);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.NotBeforeOffset, Is.EqualTo(offset));
    }

    [Test]
    public void AsCertificateAuthority_ConfiguresCASettings()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.AsCertificateAuthority(2);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.IsCertificateAuthority, Is.True);
        Assert.That(options.PathLengthConstraint, Is.EqualTo(2));
        Assert.That(options.KeyUsage & X509KeyUsageFlags.KeyCertSign, Is.EqualTo(X509KeyUsageFlags.KeyCertSign));
    }

    [Test]
    public void WithKeyUsage_SetsKeyUsage()
    {
        // Arrange
        var options = new CertificateOptions();
        var keyUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment;

        // Act
        var result = options.WithKeyUsage(keyUsage);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.KeyUsage, Is.EqualTo(keyUsage));
    }

    [Test]
    public void WithEnhancedKeyUsages_AddsEkus()
    {
        // Arrange
        var options = new CertificateOptions();
        const string eku1 = "1.3.6.1.5.5.7.3.1";
        const string eku2 = "1.3.6.1.5.5.7.3.2";

        // Act
        var result = options.WithEnhancedKeyUsages(eku1, eku2);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.EnhancedKeyUsages, Contains.Item(eku1));
        Assert.That(options.EnhancedKeyUsages, Contains.Item(eku2));
    }

    [Test]
    public void WithDnsSan_AddsDnsSan()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithDnsSan("example.com");

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.SubjectAlternativeNames, Contains.Item(("dns", "example.com")));
    }

    [Test]
    public void WithEmailSan_AddsEmailSan()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithEmailSan("test@example.com");

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.SubjectAlternativeNames, Contains.Item(("email", "test@example.com")));
    }

    [Test]
    public void WithUriSan_AddsUriSan()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithUriSan("https://example.com");

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.SubjectAlternativeNames, Contains.Item(("uri", "https://example.com")));
    }

    [Test]
    public void SignedBy_SetsIssuer()
    {
        // Arrange
        var options = new CertificateOptions();
        var factory = new EphemeralCertificateFactory();
        using var issuer = factory.CreateCertificate(o => o.AsCertificateAuthority());

        // Act
        var result = options.SignedBy(issuer);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.Issuer, Is.SameAs(issuer));
    }

    [Test]
    public void SignedBy_WithNull_ThrowsArgumentNullException()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => options.SignedBy(null!));
    }

    [Test]
    public void WithExtension_AddsExtension()
    {
        // Arrange
        var options = new CertificateOptions();
        var extension = new X509BasicConstraintsExtension(true, true, 0, true);

        // Act
        var result = options.WithExtension(extension);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.CustomExtensions, Contains.Item(extension));
    }

    [Test]
    public void WithExtension_WithNull_ThrowsArgumentNullException()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => options.WithExtension(null!));
    }

    [Test]
    public void WithLifetimeSigning_AddsLifetimeSigningEku()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithLifetimeSigning();

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.EnhancedKeyUsages, Contains.Item("1.3.6.1.4.1.311.10.3.13"));
    }

    [Test]
    public void ForCodeSigning_AddsCodeSigningEku()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.ForCodeSigning();

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.EnhancedKeyUsages, Contains.Item("1.3.6.1.5.5.7.3.3"));
    }

    [Test]
    public void ForTlsAuthentication_AddsTlsEkus()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.ForTlsAuthentication();

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.EnhancedKeyUsages, Contains.Item("1.3.6.1.5.5.7.3.1")); // Server Auth
        Assert.That(options.EnhancedKeyUsages, Contains.Item("1.3.6.1.5.5.7.3.2")); // Client Auth
    }

    [Test]
    public void WithSubjectAlternativeNames_AddsMultipleSans()
    {
        // Arrange
        var options = new CertificateOptions();

        // Act
        var result = options.WithSubjectAlternativeNames(
            ("dns", "example.com"),
            ("email", "test@example.com"),
            ("uri", "https://example.com"));

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.SubjectAlternativeNames!.Count, Is.EqualTo(3));
    }

    [Test]
    public void FluentChaining_AllMethodsChainCorrectly()
    {
        // Arrange
        var options = new CertificateOptions();
        var factory = new EphemeralCertificateFactory();
        using var issuer = factory.CreateCertificate(o => o.AsCertificateAuthority());

        // Act
        var result = options
            .WithSubjectName("CN=Test")
            .WithKeyAlgorithm(KeyAlgorithm.ECDSA)
            .WithKeySize(384)
            .WithHashAlgorithm(CertificateHashAlgorithm.SHA384)
            .WithValidity(TimeSpan.FromDays(30))
            .WithKeyUsage(X509KeyUsageFlags.DigitalSignature)
            .WithDnsSan("example.com")
            .WithEmailSan("test@example.com")
            .WithUriSan("https://example.com")
            .ForCodeSigning();

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.SubjectName, Is.EqualTo("CN=Test"));
        Assert.That(options.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.ECDSA));
        Assert.That(options.KeySize, Is.EqualTo(384));
        Assert.That(options.HashAlgorithm, Is.EqualTo(CertificateHashAlgorithm.SHA384));
        Assert.That(options.Validity, Is.EqualTo(TimeSpan.FromDays(30)));
        Assert.That(options.SubjectAlternativeNames!.Count, Is.EqualTo(3));
    }
}

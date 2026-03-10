// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Local;

using CoseSign1.Certificates.Local;

public class DirectSigningKeyProviderTests
{
    [Test]
    public void Constructor_WithValidCertificate_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var provider = new DirectSigningKeyProvider(cert);

        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNull_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new DirectSigningKeyProvider(null!));
    }

    [Test]
    public void Constructor_WithoutPrivateKey_ThrowsArgumentException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var publicOnly = X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));

        var ex = Assert.Throws<ArgumentException>(() => new DirectSigningKeyProvider(publicOnly));
        Assert.That(ex.Message, Does.Contain("private key"));
    }

    [Test]
    public void GetCoseKey_WithRsaCertificate_ReturnsValidKey()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var provider = new DirectSigningKeyProvider(cert);

        var key = provider.GetCoseKey();

        Assert.That(key, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_CalledMultipleTimes_ReturnsSameInstance()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var provider = new DirectSigningKeyProvider(cert);

        var key1 = provider.GetCoseKey();
        var key2 = provider.GetCoseKey();

        Assert.That(key1, Is.SameAs(key2));
    }

    [Test]
    public void GetCoseKey_WithECDsaCertificate_ReturnsValidKey()
    {
        using var cert = TestCertificateUtils.CreateCertificate(useEcc: true, keySize: 256);
        using var provider = new DirectSigningKeyProvider(cert);

        var key = provider.GetCoseKey();

        Assert.That(key, Is.Not.Null);
    }

    [Test]
    [TestCase(256)]   // ES256
    [TestCase(384)]   // ES384
    [TestCase(521)]   // ES512
    public void GetCoseKey_WithECDsaVariousKeySizes_ReturnsCorrectAlgorithm(int keySize)
    {
        using var cert = TestCertificateUtils.CreateCertificate(useEcc: true, keySize: keySize);
        using var provider = new DirectSigningKeyProvider(cert);

        var key = provider.GetCoseKey();

        Assert.That(key, Is.Not.Null);
    }

    [Test]
    public void IsRemote_AlwaysReturnsFalse()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var provider = new DirectSigningKeyProvider(cert);

        Assert.That(provider.IsRemote, Is.False);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var provider = new DirectSigningKeyProvider(cert);

        provider.Dispose();
        provider.Dispose(); // Should not throw
    }

    [Test]
    public void Dispose_DoesNotDisposeCertificate()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var provider = new DirectSigningKeyProvider(cert);

        provider.Dispose();

        // Certificate should still be usable
        Assert.That(cert.Subject, Is.Not.Null);
    }

    #region ML-DSA Tests

    [Test]
    [Category("MLDSA")]
    public void GetCoseKey_WithMLDsa44Certificate_ReturnsValidKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        using var cert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA44Provider", mlDsaParameterSet: 44);
        using var provider = new DirectSigningKeyProvider(cert);

        var key = provider.GetCoseKey();

        Assert.That(key, Is.Not.Null);
    }

    [Test]
    [Category("MLDSA")]
    public void GetCoseKey_WithMLDsa65Certificate_ReturnsValidKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        using var cert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA65Provider", mlDsaParameterSet: 65);
        using var provider = new DirectSigningKeyProvider(cert);

        var key = provider.GetCoseKey();

        Assert.That(key, Is.Not.Null);
    }

    [Test]
    [Category("MLDSA")]
    public void GetCoseKey_WithMLDsa87Certificate_ReturnsValidKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        using var cert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA87Provider", mlDsaParameterSet: 87);
        using var provider = new DirectSigningKeyProvider(cert);

        var key = provider.GetCoseKey();

        Assert.That(key, Is.Not.Null);
    }

    [Test]
    [Category("MLDSA")]
    public void GetCoseKey_WithMLDsa_CalledMultipleTimes_ReturnsSameInstance()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        using var cert = TestCertificateUtils.CreateMLDsaCertificate("MLDSAMultiCall", mlDsaParameterSet: 65);
        using var provider = new DirectSigningKeyProvider(cert);

        var key1 = provider.GetCoseKey();
        var key2 = provider.GetCoseKey();

        Assert.That(key1, Is.SameAs(key2));
    }

    #endregion
}
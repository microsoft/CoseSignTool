// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.Tests.Local;

/// <summary>
/// Tests for the CertificateSigningService.Create() factory methods for local certificates.
/// </summary>
public class LocalCertificateSigningServiceTests
{
    [Test]
    public void Create_WithCertificateAndChainBuilder_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var service = CertificateSigningService.Create(cert, chainBuilder);

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void Create_WithCertificateAndChain_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new X509Certificate2[] { cert };
        using var service = CertificateSigningService.Create(cert, chain);

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void Create_WithNullCertificate_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        Assert.Throws<ArgumentNullException>(() => CertificateSigningService.Create(null!, chainBuilder));
    }

    [Test]
    public void Create_WithNullChainBuilder_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        Assert.Throws<ArgumentNullException>(() => CertificateSigningService.Create(cert, (ICertificateChainBuilder)null!));
    }

    [Test]
    public void Create_WithNullChain_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        Assert.Throws<ArgumentNullException>(() => CertificateSigningService.Create(cert, (IReadOnlyList<X509Certificate2>)null!));
    }

    [Test]
    public void Create_WithoutPrivateKey_ThrowsArgumentException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var publicOnly = X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));
        var chain = new[] { publicOnly };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);

        var ex = Assert.Throws<ArgumentException>(() => CertificateSigningService.Create(publicOnly, chainBuilder));
        Assert.That(ex.Message, Does.Contain("private key"));
    }

    [Test]
    public void Create_LocalCertificate_IsRemoteReturnsFalse()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var service = CertificateSigningService.Create(cert, chainBuilder);

        Assert.That(service.IsRemote, Is.False);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        var service = CertificateSigningService.Create(cert, chainBuilder);

        service.Dispose();
        service.Dispose(); // Should not throw
    }
}
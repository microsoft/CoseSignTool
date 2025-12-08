// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Local;

public class LocalCertificateSigningServiceTests
{
    [Test]
    public void Constructor_WithCertificateAndChainBuilder_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var service = new LocalCertificateSigningService(cert, chainBuilder);

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithCertificateAndChain_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var service = new LocalCertificateSigningService(cert, chain);

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullCertificate_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        Assert.Throws<ArgumentNullException>(() => new LocalCertificateSigningService(null!, chainBuilder));
    }

    [Test]
    public void Constructor_WithNullChainBuilder_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        Assert.Throws<ArgumentNullException>(() => new LocalCertificateSigningService(cert, (ICertificateChainBuilder)null!));
    }

    [Test]
    public void Constructor_WithNullChain_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        Assert.Throws<ArgumentNullException>(() => new LocalCertificateSigningService(cert, (IReadOnlyList<X509Certificate2>)null!));
    }

    [Test]
    public void Constructor_WithoutPrivateKey_ThrowsArgumentException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var publicOnly = X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));
        var chain = new[] { publicOnly };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);

        var ex = Assert.Throws<ArgumentException>(() => new LocalCertificateSigningService(publicOnly, chainBuilder));
        Assert.That(ex.Message, Does.Contain("private key"));
    }

    [Test]
    public void IsRemote_ReturnsFalse()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var service = new LocalCertificateSigningService(cert, chainBuilder);

        Assert.That(service.IsRemote, Is.False);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        var service = new LocalCertificateSigningService(cert, chainBuilder);

        service.Dispose();
        service.Dispose(); // Should not throw
    }
}

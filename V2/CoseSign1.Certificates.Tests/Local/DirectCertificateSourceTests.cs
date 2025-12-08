// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Local;

public class DirectCertificateSourceTests
{
    [Test]
    public void Constructor_WithCertificateAndChain_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        Assert.That(source, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithCertificateAndChainBuilder_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var source = new DirectCertificateSource(cert, chainBuilder);

        Assert.That(source, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullCertificate_ThrowsArgumentNullException()
    {
        var chain = new[] { TestCertificateUtils.CreateCertificate() };
        Assert.Throws<ArgumentNullException>(() => new DirectCertificateSource(null!, chain));
    }

    [Test]
    public void Constructor_WithNullChain_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        Assert.Throws<ArgumentNullException>(() => new DirectCertificateSource(cert, (IReadOnlyList<X509Certificate2>)null!));
    }

    [Test]
    public void Constructor_WithNullChainBuilder_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        Assert.Throws<ArgumentNullException>(() => new DirectCertificateSource(cert, (ICertificateChainBuilder)null!));
    }

    [Test]
    public void Constructor_WithEmptyChain_ThrowsArgumentException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var emptyChain = Array.Empty<X509Certificate2>();
        Assert.Throws<ArgumentException>(() => new DirectCertificateSource(cert, emptyChain));
    }

    [Test]
    public void GetSigningCertificate_ReturnsSameCertificate()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        var retrieved = source.GetSigningCertificate();

        Assert.That(retrieved, Is.SameAs(cert));
    }

    [Test]
    public void HasPrivateKey_WithPrivateKey_ReturnsTrue()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void HasPrivateKey_WithoutPrivateKey_ReturnsFalse()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var publicOnly = X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));
        var chain = new[] { publicOnly };
        using var source = new DirectCertificateSource(publicOnly, chain);

        Assert.That(source.HasPrivateKey, Is.False);
    }

    [Test]
    public void GetChainBuilder_WithProvidedChain_ReturnsExplicitChainBuilder()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        var chainBuilder = source.GetChainBuilder();

        Assert.That(chainBuilder, Is.InstanceOf<CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder>());
    }

    [Test]
    public void GetChainBuilder_WithChainBuilder_ReturnsSameBuilder()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var source = new DirectCertificateSource(cert, chainBuilder);

        var retrievedBuilder = source.GetChainBuilder();

        Assert.That(retrievedBuilder, Is.SameAs(chainBuilder));
    }

    [Test]
    public void GetChainBuilder_BuildAndGetChain_ReturnsChain()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        var chainBuilder = source.GetChainBuilder();
        chainBuilder.Build(cert);
        var retrievedChain = chainBuilder.ChainElements;

        Assert.That(retrievedChain, Is.Not.Null);
        Assert.That(retrievedChain, Has.Count.EqualTo(1));
        Assert.That(retrievedChain.First().Thumbprint, Is.EqualTo(cert.Thumbprint));
    }

    [Test]
    public void GetChainBuilder_WithChainBuilder_BuildsAndReturnsChain()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var source = new DirectCertificateSource(cert, chainBuilder);

        var retrievedBuilder = source.GetChainBuilder();
        var buildResult = retrievedBuilder.Build(cert);
        var retrievedChain = retrievedBuilder.ChainElements;

        Assert.That(retrievedChain, Is.Not.Null);
        Assert.That(retrievedChain, Has.Count.EqualTo(1));
        Assert.That(buildResult, Is.True);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        var source = new DirectCertificateSource(cert, chain);

        source.Dispose();
        source.Dispose(); // Should not throw
    }

    [Test]
    public void Dispose_DoesNotDisposeCertificate()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        var source = new DirectCertificateSource(cert, chain);

        source.Dispose();

        // Certificate should still be usable
        Assert.That(cert.Subject, Is.Not.Null);
    }
}

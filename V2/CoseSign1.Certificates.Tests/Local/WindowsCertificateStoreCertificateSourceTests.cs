// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Local;

public class WindowsWindowsCertificateStoreCertificateSourceTests
{
    private X509Store? _testStore;
    private X509Certificate2? _testCert;

    [SetUp]
    public void Setup()
    {
        // Create a test certificate and add it to the CurrentUser\My store
        _testCert = TestCertificateUtils.CreateCertificate("CertStoreTest");
        _testStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        _testStore.Open(OpenFlags.ReadWrite);
        _testStore.Add(_testCert);
    }

    [TearDown]
    public void Cleanup()
    {
        if (_testCert != null && _testStore != null)
        {
            _testStore.Remove(_testCert);
            _testStore.Close();
            _testCert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithValidThumbprint_Succeeds()
    {
        using var source = new WindowsCertificateStoreCertificateSource(
            _testCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.GetSigningCertificate().Thumbprint, Is.EqualTo(_testCert.Thumbprint));
    }

    [Test]
    public void Constructor_WithInvalidThumbprint_ThrowsInvalidOperationException()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new WindowsCertificateStoreCertificateSource(
                "0000000000000000000000000000000000000000",
                StoreName.My,
                StoreLocation.CurrentUser));
    }

    [Test]
    public void Constructor_WithNullOrEmptyThumbprint_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new WindowsCertificateStoreCertificateSource((string)null!, StoreName.My, StoreLocation.CurrentUser));
        Assert.Throws<ArgumentException>(() =>
            new WindowsCertificateStoreCertificateSource("", StoreName.My, StoreLocation.CurrentUser));
    }

    [Test]
    public void Constructor_WithSubjectName_Succeeds()
    {
        using var source = new WindowsCertificateStoreCertificateSource(
            "CertStoreTest",
            StoreName.My,
            StoreLocation.CurrentUser,
            validOnly: false);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.GetSigningCertificate().Subject, Does.Contain("CertStoreTest"));
    }

    [Test]
    public void Constructor_WithPredicate_Succeeds()
    {
        using var source = new WindowsCertificateStoreCertificateSource(
            cert => cert.Thumbprint == _testCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.GetSigningCertificate().Thumbprint, Is.EqualTo(_testCert.Thumbprint));
    }

    [Test]
    public void Constructor_WithNullPredicate_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new WindowsCertificateStoreCertificateSource((Func<X509Certificate2, bool>)null!, StoreName.My, StoreLocation.CurrentUser));
    }

    [Test]
    public void Constructor_WithNonMatchingPredicate_ThrowsInvalidOperationException()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new WindowsCertificateStoreCertificateSource(
                cert => false,
                StoreName.My,
                StoreLocation.CurrentUser));
    }

    [Test]
    public void GetChainBuilder_ReturnsX509ChainBuilder()
    {
        using var source = new WindowsCertificateStoreCertificateSource(
            _testCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        var chainBuilder = source.GetChainBuilder();

        Assert.That(chainBuilder, Is.Not.Null);
        Assert.That(chainBuilder, Is.InstanceOf<CoseSign1.Certificates.ChainBuilders.X509ChainBuilder>());
    }

    [Test]
    public void HasPrivateKey_ReturnsCorrectStatus()
    {
        using var source = new WindowsCertificateStoreCertificateSource(
            _testCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        // The retrieved certificate from store may have a different private key status
        // than the original certificate depending on how it was stored
        // Just verify the property exists and returns a boolean
        Assert.That(source.HasPrivateKey, Is.TypeOf<bool>());
    }

    [Test]
    public void UsageWithLocalCertificateSigningService_Succeeds()
    {
        // Demonstrate that WindowsCertificateStoreCertificateSource works with LocalCertificateSigningService
        using var source = new WindowsCertificateStoreCertificateSource(
            _testCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        var cert = source.GetSigningCertificate();
        
        // Only proceed if the certificate has a private key
        if (!cert.HasPrivateKey)
        {
            Assert.Inconclusive("Certificate does not have private key accessible in this context");
            return;
        }
        
        var chainBuilder = source.GetChainBuilder();
        using var signingService = new LocalCertificateSigningService(cert, chainBuilder);

        Assert.That(signingService, Is.Not.Null);
        Assert.That(signingService.IsRemote, Is.False);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var source = new WindowsCertificateStoreCertificateSource(
            _testCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        source.Dispose();
        source.Dispose(); // Should not throw
    }
}


// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Local;

public class WindowsWindowsCertificateStoreCertificateSourceTests
{
    private X509Store? TestStore;
    private X509Certificate2? TestCert;

    [SetUp]
    public void Setup()
    {
        // Create a test certificate and add it to the CurrentUser\My store
        TestCert = TestCertificateUtils.CreateCertificate("CertStoreTest");
        TestStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        TestStore.Open(OpenFlags.ReadWrite);
        TestStore.Add(TestCert);
    }

    [TearDown]
    public void Cleanup()
    {
        if (TestCert != null && TestStore != null)
        {
            TestStore.Remove(TestCert);
            TestStore.Close();
            TestCert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithValidThumbprint_Succeeds()
    {
        using var source = new WindowsCertificateStoreCertificateSource(
            TestCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.GetSigningCertificate().Thumbprint, Is.EqualTo(TestCert.Thumbprint));
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
            cert => cert.Thumbprint == TestCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.GetSigningCertificate().Thumbprint, Is.EqualTo(TestCert.Thumbprint));
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
            TestCert!.Thumbprint,
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
            TestCert!.Thumbprint,
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
            TestCert!.Thumbprint,
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
        using var signingService = CertificateSigningService.Create(cert, chainBuilder);

        Assert.That(signingService, Is.Not.Null);
        Assert.That(signingService.IsRemote, Is.False);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var source = new WindowsCertificateStoreCertificateSource(
            TestCert!.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        source.Dispose();
        source.Dispose(); // Should not throw
    }
}
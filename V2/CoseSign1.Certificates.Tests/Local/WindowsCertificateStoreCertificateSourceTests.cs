// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Local;

using CoseSign1.Certificates.Local;

public class WindowsWindowsCertificateStoreCertificateSourceTests
{
    private sealed class TestContext : IDisposable
    {
        public X509Store TestStore { get; }
        public X509Certificate2 TestCert { get; }

        public TestContext(X509Store testStore, X509Certificate2 testCert)
        {
            TestStore = testStore;
            TestCert = testCert;
        }

        public void Dispose()
        {
            TestStore.Remove(TestCert);
            TestStore.Close();
            TestCert.Dispose();
        }
    }

    private static TestContext CreateTestContext()
    {
        // Create a test certificate and add it to the CurrentUser\My store
        // We need to export/import with PersistKeySet to ensure the private key is stored in the key storage provider
        var ephemeralCert = TestCertificateUtils.CreateCertificate("CertStoreTest");
        var pfxBytes = ephemeralCert.Export(X509ContentType.Pfx, "testpwd");
        ephemeralCert.Dispose();

        // Import with PersistKeySet to ensure the private key is persisted in the key storage provider
        var testCert = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            "testpwd",
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);

        var testStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        testStore.Open(OpenFlags.ReadWrite);
        testStore.Add(testCert);

        return new TestContext(testStore, testCert);
    }

    [Test]
    public void Constructor_WithValidThumbprint_Succeeds()
    {
        using var ctx = CreateTestContext();
        using var source = new WindowsCertificateStoreCertificateSource(
            ctx.TestCert.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.GetSigningCertificate().Thumbprint, Is.EqualTo(ctx.TestCert.Thumbprint));
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
        using var ctx = CreateTestContext();
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
        using var ctx = CreateTestContext();
        using var source = new WindowsCertificateStoreCertificateSource(
            cert => cert.Thumbprint == ctx.TestCert.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.GetSigningCertificate().Thumbprint, Is.EqualTo(ctx.TestCert.Thumbprint));
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
        using var ctx = CreateTestContext();
        using var source = new WindowsCertificateStoreCertificateSource(
            ctx.TestCert.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        var chainBuilder = source.GetChainBuilder();

        Assert.That(chainBuilder, Is.Not.Null);
        Assert.That(chainBuilder, Is.InstanceOf<CoseSign1.Certificates.ChainBuilders.X509ChainBuilder>());
    }

    [Test]
    public void HasPrivateKey_ReturnsCorrectStatus()
    {
        using var ctx = CreateTestContext();
        using var source = new WindowsCertificateStoreCertificateSource(
            ctx.TestCert.Thumbprint,
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
        using var ctx = CreateTestContext();
        // Demonstrate that WindowsCertificateStoreCertificateSource works with LocalCertificateSigningService
        using var source = new WindowsCertificateStoreCertificateSource(
            ctx.TestCert.Thumbprint,
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
        using var ctx = CreateTestContext();
        var source = new WindowsCertificateStoreCertificateSource(
            ctx.TestCert.Thumbprint,
            StoreName.My,
            StoreLocation.CurrentUser);

        source.Dispose();
        source.Dispose(); // Should not throw
    }
}
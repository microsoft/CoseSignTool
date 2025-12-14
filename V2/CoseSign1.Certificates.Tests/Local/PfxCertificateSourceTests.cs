// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Local;

public class PfxCertificateSourceTests
{
    private string TempPfxPath = null!;

    [SetUp]
    public void Setup()
    {
        TempPfxPath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.pfx");
    }

    [TearDown]
    public void Cleanup()
    {
        if (File.Exists(TempPfxPath))
        {
            File.Delete(TempPfxPath);
        }
    }

    [Test]
    public void Constructor_WithValidPfxFile_Succeeds()
    {
        // Create a test PFX file
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var source = new PfxCertificateSource(TempPfxPath, password);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void Constructor_WithNonExistentFile_ThrowsFileNotFoundException()
    {
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.pfx");

        Assert.Throws<FileNotFoundException>(() => new PfxCertificateSource(nonExistentPath));
    }

    [Test]
    public void Constructor_WithNullOrEmptyPath_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentNullException>(() => new PfxCertificateSource((string)null!));
        Assert.Throws<ArgumentException>(() => new PfxCertificateSource(""));
        Assert.Throws<ArgumentException>(() => new PfxCertificateSource("   "));
    }

    [Test]
    public void Constructor_WithIncorrectPassword_ThrowsCryptographicException()
    {
        // Create a test PFX file with password
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "correctpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            new PfxCertificateSource(TempPfxPath, "wrongpassword"));
    }

    [Test]
    public void Constructor_WithByteArray_Succeeds()
    {
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        var pfxData = chain.Export(X509ContentType.Pfx, password)!;

        using var source = new PfxCertificateSource(pfxData, password);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void Constructor_WithNullByteArray_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new PfxCertificateSource((byte[])null!));
    }

    [Test]
    public void GetSigningCertificate_ReturnsLeafCertificate()
    {
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var source = new PfxCertificateSource(TempPfxPath, password);
        var cert = source.GetSigningCertificate();

        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.HasPrivateKey, Is.True);
    }

    [Test]
    public void GetChainBuilder_ReturnsExplicitChainBuilder()
    {
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var source = new PfxCertificateSource(TempPfxPath, password);
        var chainBuilder = source.GetChainBuilder();

        Assert.That(chainBuilder, Is.Not.Null);
    }

    [Test]
    public void GetChainBuilder_CanBuildChain()
    {
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var source = new PfxCertificateSource(TempPfxPath, password);
        var cert = source.GetSigningCertificate();
        var chainBuilder = source.GetChainBuilder();

        var result = chainBuilder.Build(cert);

        Assert.That(result, Is.True);
        Assert.That(chainBuilder.ChainElements.Count, Is.GreaterThan(0));
    }

    [Test]
    public void UsageWithLocalCertificateSigningService_Succeeds()
    {
        // Demonstrate that PfxCertificateSource works with LocalCertificateSigningService
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var source = new PfxCertificateSource(TempPfxPath, password);
        var cert = source.GetSigningCertificate();
        var chainBuilder = source.GetChainBuilder();

        using var signingService = new LocalCertificateSigningService(cert, chainBuilder);

        Assert.That(signingService, Is.Not.Null);
        Assert.That(signingService.IsRemote, Is.False);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        var source = new PfxCertificateSource(TempPfxPath, password);

        source.Dispose();
        source.Dispose(); // Should not throw
    }

    #region SecureString Tests

    [Test]
    public void Constructor_WithSecureStringPassword_FromFile_Succeeds()
    {
        // Create a test PFX file
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var securePassword = ConvertToSecureString(password);
        using var source = new PfxCertificateSource(TempPfxPath, securePassword);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void Constructor_WithSecureStringPassword_FromBytes_Succeeds()
    {
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        var pfxData = chain.Export(X509ContentType.Pfx, password)!;

        using var securePassword = ConvertToSecureString(password);
        using var source = new PfxCertificateSource(pfxData, securePassword);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void Constructor_WithNullSecureString_FromFile_SucceedsForUnprotectedPfx()
    {
        // Create unprotected PFX
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, (string?)null)!);

        using var source = new PfxCertificateSource(TempPfxPath, (SecureString?)null);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void Constructor_WithNullSecureString_FromBytes_SucceedsForUnprotectedPfx()
    {
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var pfxData = chain.Export(X509ContentType.Pfx, (string?)null)!;

        using var source = new PfxCertificateSource(pfxData, (SecureString?)null);

        Assert.That(source, Is.Not.Null);
        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void Constructor_WithIncorrectSecureStringPassword_ThrowsCryptographicException()
    {
        // Create a test PFX file with password
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "correctpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var wrongPassword = ConvertToSecureString("wrongpassword");

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            new PfxCertificateSource(TempPfxPath, wrongPassword));
    }

    [Test]
    public void GetSigningCertificate_WithSecureString_ReturnsLeafCertificate()
    {
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var securePassword = ConvertToSecureString(password);
        using var source = new PfxCertificateSource(TempPfxPath, securePassword);
        var cert = source.GetSigningCertificate();

        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.HasPrivateKey, Is.True);
    }

    [Test]
    public void UsageWithLocalCertificateSigningService_WithSecureString_Succeeds()
    {
        // Demonstrate that PfxCertificateSource works with LocalCertificateSigningService
        var chain = TestCertificateUtils.CreateTestChainForPfx();
        var password = "testpassword";
        File.WriteAllBytes(TempPfxPath, chain.Export(X509ContentType.Pfx, password)!);

        using var securePassword = ConvertToSecureString(password);
        using var source = new PfxCertificateSource(TempPfxPath, securePassword);
        var cert = source.GetSigningCertificate();
        var chainBuilder = source.GetChainBuilder();

        using var signingService = new LocalCertificateSigningService(cert, chainBuilder);

        Assert.That(signingService, Is.Not.Null);
        Assert.That(signingService.IsRemote, Is.False);
    }

    private static SecureString ConvertToSecureString(string plainString)
    {
        var secure = new SecureString();
        foreach (char c in plainString)
        {
            secure.AppendChar(c);
        }
        secure.MakeReadOnly();
        return secure;
    }

    #endregion
}
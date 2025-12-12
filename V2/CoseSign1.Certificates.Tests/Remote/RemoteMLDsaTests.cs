// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Remote;
using NUnit.Framework;

#pragma warning disable CA2252 // Preview Features
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview

namespace CoseSign1.Certificates.Tests.Remote;

[TestFixture]
public class RemoteMLDsaTests
{
    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void Constructor_WithMLDsa44_CreatesInstance()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void Constructor_WithMLDsa65_CreatesInstance()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void Constructor_WithMLDsa87_CreatesInstance()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    public void Constructor_WithNullSource_ThrowsArgumentNullException()
    {
        // Arrange
        var publicKey = new byte[1312]; // ML-DSA-44 public key size

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new RemoteMLDsa(null!, publicKey, 44));
    }

    [Test]
    public void Constructor_WithNullPublicKey_ThrowsArgumentNullException()
    {
        // This test requires a mock RemoteCertificateSource, skipping for now
        Assert.Inconclusive("Requires mock RemoteCertificateSource implementation");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void SignData_DelegatesToRemoteSource()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void SignPreHash_WithSHA256_DelegatesToRemoteSource()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void SignPreHash_WithSHA384_DelegatesToRemoteSource()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void SignPreHash_WithSHA512_DelegatesToRemoteSource()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void ExportMLDsaPublicKey_ReturnsPublicKey()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void ExportMLDsaPrivateKey_ThrowsCryptographicException()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void ExportMLDsaPrivateSeed_ThrowsCryptographicException()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void TryExportPkcs8PrivateKey_ThrowsCryptographicException()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void VerifyData_ThrowsNotSupportedException()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void VerifyPreHash_ThrowsNotSupportedException()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }

    [Test]
    [Ignore("ML-DSA test infrastructure not yet implemented")]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // TODO: Implement when ML-DSA test helpers are available
        Assert.Inconclusive("ML-DSA test infrastructure not yet implemented");
    }
}

#pragma warning restore SYSLIB5006
#pragma warning restore CA2252
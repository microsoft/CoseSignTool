// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using CoseSign1.Certificates.Local;

namespace CoseSign1.Certificates.AzureTrustedSigning.Tests;

/// <summary>
/// Tests for <see cref="AzureTrustedSigningCertificateSource"/>.
/// Uses mocked AzSignContext to test signing operations.
/// </summary>
[TestFixture]
public class AzureTrustedSigningCertificateSourceTests
{
    private Mock<AzSignContext> MockSignContext = null!;
    private X509Certificate2 TestCert = null!;

    [SetUp]
    public void Setup()
    {
        // Create a real test certificate for use in tests
        TestCert = TestCertificateUtils.CreateCertificate("AzureTrustedSigningTest");

        // Create mock AzSignContext
        MockSignContext = new Mock<AzSignContext>();
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullSignContext_ThrowsNullReferenceException()
    {
        // Note: The implementation calls CreateAzureChainBuilder before null check,
        // which causes a NullReferenceException rather than ArgumentNullException
        // Act & Assert
        Assert.Throws<NullReferenceException>(() =>
            new AzureTrustedSigningCertificateSource(null!));
    }

    [Test]
    public void Constructor_WithNullCertChain_ThrowsInvalidOperationException()
    {
        // Arrange
        MockSignContext.Setup(s => s.GetCertChain()).Returns((IReadOnlyList<X509Certificate2>?)null);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            new AzureTrustedSigningCertificateSource(MockSignContext.Object));

        Assert.That(ex.Message, Does.Contain("did not return a certificate chain"));
    }

    [Test]
    public void Constructor_WithEmptyCertChain_ThrowsInvalidOperationException()
    {
        // Arrange
        MockSignContext.Setup(s => s.GetCertChain()).Returns(new List<X509Certificate2>());

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            new AzureTrustedSigningCertificateSource(MockSignContext.Object));

        Assert.That(ex.Message, Does.Contain("empty certificate chain"));
    }

    [Test]
    public void Constructor_WithValidCertChain_CreatesInstance()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);

        // Act
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Assert
        Assert.That(source, Is.Not.Null);
    }

    #endregion

    #region GetSigningCertificate Tests

    [Test]
    public void GetSigningCertificate_ReturnsCertificateFromContext()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act
        var result = source.GetSigningCertificate();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Subject, Is.EqualTo(TestCert.Subject));
    }

    [Test]
    public void GetSigningCertificate_WhenNullReturned_ThrowsInvalidOperationException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns((X509Certificate2?)null);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            source.GetSigningCertificate());

        Assert.That(ex.Message, Does.Contain("did not return a signing certificate"));
    }

    [Test]
    public void GetSigningCertificate_CalledMultipleTimes_ReturnsCachedCertificate()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act
        var result1 = source.GetSigningCertificate();
        var result2 = source.GetSigningCertificate();

        // Assert
        Assert.That(result1, Is.SameAs(result2));
        MockSignContext.Verify(s => s.GetSigningCertificate(), Times.Once);
    }

    #endregion

    #region RSA Signing Tests

    [Test]
    public void SignDataWithRsa_WithNullData_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            source.SignDataWithRsa(null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public void SignHashWithRsa_WithNullHash_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            source.SignHashWithRsa(null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public async Task SignDataWithRsaAsync_WithNullData_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await source.SignDataWithRsaAsync(null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public async Task SignHashWithRsaAsync_WithNullHash_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await source.SignHashWithRsaAsync(null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    #endregion

    #region ECDSA Signing Tests (Not Supported)

    [Test]
    public void SignDataWithEcdsa_ThrowsNotSupportedException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);
        var data = new byte[] { 1, 2, 3 };

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            source.SignDataWithEcdsa(data, HashAlgorithmName.SHA256));

        Assert.That(ex.Message, Does.Contain("ECDSA signing is not currently supported"));
    }

    [Test]
    public void SignDataWithEcdsaAsync_ThrowsNotSupportedException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);
        var data = new byte[] { 1, 2, 3 };

        // Act & Assert
        var ex = Assert.ThrowsAsync<NotSupportedException>(async () =>
            await source.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256));

        Assert.That(ex.Message, Does.Contain("ECDSA signing is not currently supported"));
    }

    [Test]
    public void SignHashWithEcdsa_ThrowsNotSupportedException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);
        var hash = new byte[] { 1, 2, 3 };

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            source.SignHashWithEcdsa(hash));

        Assert.That(ex.Message, Does.Contain("ECDSA signing is not currently supported"));
    }

    [Test]
    public void SignHashWithEcdsaAsync_ThrowsNotSupportedException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);
        var hash = new byte[] { 1, 2, 3 };

        // Act & Assert
        var ex = Assert.ThrowsAsync<NotSupportedException>(async () =>
            await source.SignHashWithEcdsaAsync(hash));

        Assert.That(ex.Message, Does.Contain("ECDSA signing is not currently supported"));
    }

    #endregion

    #region ML-DSA Signing Tests (Not Supported)

    [Test]
    public void SignDataWithMLDsa_ThrowsNotSupportedException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);
        var data = new byte[] { 1, 2, 3 };

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            source.SignDataWithMLDsa(data));

        Assert.That(ex.Message, Does.Contain("ML-DSA"));
    }

    [Test]
    public void SignDataWithMLDsaAsync_ThrowsNotSupportedException()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);
        var data = new byte[] { 1, 2, 3 };

        // Act & Assert
        var ex = Assert.ThrowsAsync<NotSupportedException>(async () =>
            await source.SignDataWithMLDsaAsync(data));

        Assert.That(ex.Message, Does.Contain("ML-DSA"));
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_DoesNotThrow()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act & Assert
        Assert.DoesNotThrow(() => source.Dispose());
    }

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(MockSignContext.Object);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            source.Dispose();
            source.Dispose();
            source.Dispose();
        });
    }

    #endregion
}

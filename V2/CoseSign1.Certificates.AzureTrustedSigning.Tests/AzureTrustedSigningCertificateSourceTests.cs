// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureTrustedSigning.Tests;

using Azure.Developer.TrustedSigning.CryptoProvider;

/// <summary>
/// Tests for <see cref="AzureTrustedSigningCertificateSource"/>.
/// Uses mocked AzSignContext to test signing operations.
/// </summary>
[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class AzureTrustedSigningCertificateSourceTests
{
    /// <summary>
    /// Creates a test certificate for use in tests.
    /// </summary>
    private static X509Certificate2 CreateTestCert(string name = "AzureTrustedSigningTest")
        => TestCertificateUtils.CreateCertificate(name);

    /// <summary>
    /// Creates a mock AzSignContext for use in tests.
    /// </summary>
    private static Mock<AzSignContext> CreateMockSignContext()
        => new Mock<AzSignContext>();

    #region Constructor Tests

    [Test]
        public void Constructor_WithNullSignContext_ThrowsArgumentNullException()
    {
        // Note: The implementation calls CreateAzureChainBuilder before null check,
        // which causes a NullReferenceException rather than ArgumentNullException
        // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
            new AzureTrustedSigningCertificateSource(null!));
    }

    [Test]
    public void Constructor_WithNullCertChain_ThrowsInvalidOperationException()
    {
        // Arrange
        var mockSignContext = CreateMockSignContext();
        mockSignContext.Setup(s => s.GetCertChain()).Returns((IReadOnlyList<X509Certificate2>?)null);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            new AzureTrustedSigningCertificateSource(mockSignContext.Object));

        Assert.That(ex.Message, Does.Contain("did not return a certificate chain"));
    }

    [Test]
    public void Constructor_WithEmptyCertChain_ThrowsInvalidOperationException()
    {
        // Arrange
        var mockSignContext = CreateMockSignContext();
        mockSignContext.Setup(s => s.GetCertChain()).Returns(new List<X509Certificate2>());

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            new AzureTrustedSigningCertificateSource(mockSignContext.Object));

        Assert.That(ex.Message, Does.Contain("empty certificate chain"));
    }

    [Test]
    public void Constructor_WithValidCertChain_CreatesInstance()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);

        // Act
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

        // Assert
        Assert.That(source, Is.Not.Null);
    }

    #endregion

    #region GetSigningCertificate Tests

    [Test]
    public void GetSigningCertificate_ReturnsCertificateFromContext()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

        // Act
        var result = source.GetSigningCertificate();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Subject, Is.EqualTo(testCert.Subject));
    }

    [Test]
    public void GetSigningCertificate_WhenNullReturned_ThrowsInvalidOperationException()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns((X509Certificate2?)null);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            source.GetSigningCertificate());

        Assert.That(ex.Message, Does.Contain("did not return a signing certificate"));
    }

    [Test]
    public void GetSigningCertificate_CalledMultipleTimes_ReturnsCachedCertificate()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

        // Act
        var result1 = source.GetSigningCertificate();
        var result2 = source.GetSigningCertificate();

        // Assert
        Assert.That(result1, Is.SameAs(result2));
        mockSignContext.Verify(s => s.GetSigningCertificate(), Times.Once);
    }

    #endregion

    #region RSA Signing Tests

    [Test]
    public void SignDataWithRsa_WithNullData_ThrowsArgumentNullException()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            source.SignDataWithRsa(null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public void SignHashWithRsa_WithNullHash_ThrowsArgumentNullException()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            source.SignHashWithRsa(null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public async Task SignDataWithRsaAsync_WithNullData_ThrowsArgumentNullException()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await source.SignDataWithRsaAsync(null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public async Task SignHashWithRsaAsync_WithNullHash_ThrowsArgumentNullException()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

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
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);
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
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);
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
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);
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
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);
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
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);
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
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);
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
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

        // Act & Assert
        Assert.DoesNotThrow(() => source.Dispose());
    }

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        var source = new AzureTrustedSigningCertificateSource(mockSignContext.Object);

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

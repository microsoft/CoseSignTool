// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Abstractions;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Remote;
using Moq;

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// TDD tests for CertificateSigningService (shared base for local and remote).
/// Tests follow V3 architecture with dynamic key acquisition pattern.
/// </summary>
[TestFixture]
public class CertificateSigningServiceTests
{
    #region Factory Method Tests

    [Test]
    public void Create_WithCertificateAndChainBuilder_ReturnsSigningService()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        using var chainBuilder = new X509ChainBuilder();

        // Act
        using var service = CertificateSigningService.Create(cert, chainBuilder);

        // Assert
        Assert.That(service, Is.Not.Null);
        Assert.That(service.IsRemote, Is.False);
    }

    [Test]
    public void Create_WithCertificateAndExplicitChain_ReturnsSigningService()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        var chain = new List<X509Certificate2> { cert };

        // Act
        using var service = CertificateSigningService.Create(cert, chain);

        // Assert
        Assert.That(service, Is.Not.Null);
        Assert.That(service.IsRemote, Is.False);
    }

    [Test]
    public void Create_WithChainBuilder_NullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2? cert = null;
        using var chainBuilder = new X509ChainBuilder();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            CertificateSigningService.Create(cert!, chainBuilder));
    }

    [Test]
    public void Create_WithChainBuilder_NullChainBuilder_ThrowsArgumentNullException()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        ICertificateChainBuilder? chainBuilder = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            CertificateSigningService.Create(cert, chainBuilder!));
    }

    [Test]
    public void Create_WithExplicitChain_NullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2? cert = null;
        var chain = new List<X509Certificate2>();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            CertificateSigningService.Create(cert!, chain));
    }

    [Test]
    public void Create_WithExplicitChain_NullChain_ThrowsArgumentNullException()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        IReadOnlyList<X509Certificate2>? chain = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            CertificateSigningService.Create(cert, chain!));
    }

    [Test]
    public void Create_WithChainBuilder_CertificateWithoutPrivateKey_ThrowsArgumentException()
    {
        // Arrange - create cert then export without private key
        using var certWithKey = LocalCertificateFactory.CreateRsaCertificate();
        using var certWithoutKey = X509CertificateLoader.LoadCertificate(certWithKey.Export(X509ContentType.Cert));
        using var chainBuilder = new X509ChainBuilder();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            CertificateSigningService.Create(certWithoutKey, chainBuilder));
        Assert.That(ex!.Message, Does.Contain("private key"));
    }

    [Test]
    public void Create_WithExplicitChain_CertificateWithoutPrivateKey_ThrowsArgumentException()
    {
        // Arrange - create cert then export without private key
        using var certWithKey = LocalCertificateFactory.CreateRsaCertificate();
        using var certWithoutKey = X509CertificateLoader.LoadCertificate(certWithKey.Export(X509ContentType.Cert));
        var chain = new List<X509Certificate2> { certWithoutKey };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            CertificateSigningService.Create(certWithoutKey, chain));
        Assert.That(ex!.Message, Does.Contain("private key"));
    }

    [Test]
    public void Create_WithRemoteSource_NullSource_ThrowsArgumentNullException()
    {
        // Arrange
        RemoteCertificateSource? source = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            CertificateSigningService.Create(source!));
    }

    #endregion

    #region SCITT Compliance Tests

    [Test]
    public void GetCoseSigner_WithScittCompliance_AddsCwtClaims()
    {
        // Arrange - Use a certificate chain (not self-signed) or provide custom claims
        // DID:x509 requires at least 2 certificates in the chain for auto-generated issuer
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);

        // Since we're using a self-signed cert (1 cert chain), we need to provide custom claims
        var customClaims = new CoseSign1.Headers.CwtClaims
        {
            Issuer = "did:x509:test:issuer",
            Subject = "test-subject"
        };

        var options = new CertificateSigningOptions
        {
            EnableScittCompliance = true,
            CustomCwtClaims = customClaims
        };

        var additionalContext = new Dictionary<string, object>
        {
            [CertificateSigningOptionsExtensions.CertificateSigningOptionsKey] = options
        };

        var context = new SigningContext(
            new byte[] { 1, 2, 3 },
            "application/test",
            additionalContext: additionalContext);

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer, Is.Not.Null);
        Assert.That(signer.ProtectedHeaders, Is.Not.Null);
        // SCITT compliance adds CWT claims header (label 15)
        var hasCwtClaims = signer.ProtectedHeaders.Any(h =>
            h.Key == new CoseHeaderLabel(15)); // 15 = CWT claims label
        Assert.That(hasCwtClaims, Is.True, "SCITT compliance should add CWT claims header");
    }

    [Test]
    public void GetCoseSigner_WithCustomCwtClaims_UsesProvidedClaims()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);

        var customClaims = new CoseSign1.Headers.CwtClaims
        {
            Issuer = "custom-issuer",
            Subject = "custom-subject"
        };

        var options = new CertificateSigningOptions
        {
            EnableScittCompliance = true,
            CustomCwtClaims = customClaims
        };

        var additionalContext = new Dictionary<string, object>
        {
            [CertificateSigningOptionsExtensions.CertificateSigningOptionsKey] = options
        };

        var context = new SigningContext(
            new byte[] { 1, 2, 3 },
            "application/test",
            additionalContext: additionalContext);

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer, Is.Not.Null);
        var hasCwtClaims = signer.ProtectedHeaders.Any(h =>
            h.Key == new CoseHeaderLabel(15));
        Assert.That(hasCwtClaims, Is.True, "Should add CWT claims header with custom claims");
    }

    [Test]
    public void GetCoseSigner_WithScittComplianceAndDefaultClaims_UsesCertificateChain()
    {
        // Arrange - DID:x509 default issuer generation requires a chain with at least leaf + root.
        var chain = TestCertificateUtils.CreateTestChain(testName: nameof(GetCoseSigner_WithScittComplianceAndDefaultClaims_UsesCertificateChain), leafFirst: true);
        var certs = chain.Cast<X509Certificate2>().ToList();
        var leaf = certs[0];

        try
        {
            using var service = CertificateSigningService.Create(leaf, certs);

            var options = new CertificateSigningOptions
            {
                EnableScittCompliance = true,
                CustomCwtClaims = null
            };

            var additionalContext = new Dictionary<string, object>
            {
                [CertificateSigningOptionsExtensions.CertificateSigningOptionsKey] = options
            };

            var context = new SigningContext(
                new byte[] { 1, 2, 3 },
                "application/test",
                additionalContext: additionalContext);

            // Act
            var signer = service.GetCoseSigner(context);

            // Assert
            Assert.That(signer, Is.Not.Null);
            var hasCwtClaims = signer.ProtectedHeaders.Any(h => h.Key == new CoseHeaderLabel(15));
            Assert.That(hasCwtClaims, Is.True, "SCITT compliance should add CWT claims header");
        }
        finally
        {
            foreach (var c in certs)
            {
                c.Dispose();
            }
        }
    }

    [Test]
    public void GetCoseSigner_WithScittComplianceButNonCertificateSigningKey_ThrowsInvalidOperationException()
    {
        // Arrange - default SCITT claims require an ICertificateSigningKey
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);

        var options = new CertificateSigningOptions
        {
            EnableScittCompliance = true,
            CustomCwtClaims = null
        };

        var additionalContext = new Dictionary<string, object>
        {
            [CertificateSigningOptionsExtensions.CertificateSigningOptionsKey] = options
        };

        var context = new SigningContext(
            new byte[] { 1, 2, 3 },
            "application/test",
            additionalContext: additionalContext);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => service.GetCoseSigner(context));
        Assert.That(ex!.Message, Does.Contain("certificate-based signing key"));
    }

    [Test]
    public void GetCoseSigner_WithoutScittCompliance_NoCwtClaims()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);

        var options = new CertificateSigningOptions
        {
            EnableScittCompliance = false
        };

        var additionalContext = new Dictionary<string, object>
        {
            [CertificateSigningOptionsExtensions.CertificateSigningOptionsKey] = options
        };

        var context = new SigningContext(
            new byte[] { 1, 2, 3 },
            "application/test",
            additionalContext: additionalContext);

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer, Is.Not.Null);
        // Without SCITT compliance, no CWT claims should be added
        var hasCwtClaims = signer.ProtectedHeaders.Any(h =>
            h.Key == new CoseHeaderLabel(15));
        Assert.That(hasCwtClaims, Is.False, "Without SCITT compliance, should not add CWT claims");
    }

    #endregion

    #region CreateSigningOptions Tests

    [Test]
    public void CreateSigningOptions_ReturnsNewCertificateSigningOptions()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);

        // Act
        var options1 = service.CreateSigningOptions();
        var options2 = service.CreateSigningOptions();

        // Assert
        Assert.That(options1, Is.Not.Null);
        Assert.That(options2, Is.Not.Null);
        Assert.That(options1, Is.Not.SameAs(options2), "Should return new instance each time");
        Assert.That(options1.EnableScittCompliance, Is.False, "Default should be false");
    }

    #endregion

    #region GetCoseSigner with Null Context Tests

    [Test]
    public void GetCoseSigner_WithNullContext_ThrowsArgumentNullException()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => service.GetCoseSigner(null!));
    }

    #endregion

    #region Constructor with Signing Key Tests

    [Test]
    public void Constructor_WithSigningKey_NullSigningKey_ThrowsArgumentNullException()
    {
        // Arrange
        ICertificateSigningKey? signingKey = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateSigningService(signingKey!));
    }

    [Test]
    public void Constructor_WithSigningKey_SetsIsRemoteFromMetadata()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        using var chainBuilder = new X509ChainBuilder();
        var certificateSource = new DirectCertificateSource(cert, chainBuilder);
        var signingKeyProvider = new DirectSigningKeyProvider(cert);

        // Create a test service to pass to CertificateSigningKey
        using var testService = CertificateSigningService.Create(cert, chainBuilder);
        var signingKey = new CertificateSigningKey(certificateSource, signingKeyProvider, testService);

        // Act
        using var service = new CertificateSigningService(signingKey);

        // Assert
        Assert.That(service.IsRemote, Is.False, "IsRemote should match signing key metadata");
    }

    #endregion

    #region TDD Pattern Tests

    [Test]
    public void Constructor_WithValidParameters_ShouldSucceed()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();

        // Act
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);

        // Assert
        Assert.That(service, Is.Not.Null);
        Assert.That(service.IsRemote, Is.False);
    }

    [Test]
    public void GetCoseSigner_ShouldAcquireKeyDynamically()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);
        var context = CreateSigningContext("test payload");

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer, Is.Not.Null);
        mockSigningKey.Verify(k => k.GetCoseKey(), Times.Once);
    }

    [Test]
    public void GetCoseSigner_CalledMultipleTimes_ShouldAcquireKeyEachTime()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);
        var context1 = CreateSigningContext("payload1");
        var context2 = CreateSigningContext("payload2");

        // Act
        var signer1 = service.GetCoseSigner(context1);
        var signer2 = service.GetCoseSigner(context2);

        // Assert
        Assert.That(signer1, Is.Not.Null);
        Assert.That(signer2, Is.Not.Null);
        mockSigningKey.Verify(k => k.GetCoseKey(), Times.Exactly(2));
    }

    [Test]
    public void IsRemote_WhenSetToFalse_ShouldReturnFalse()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, isRemote: false);

        // Act & Assert
        Assert.That(service.IsRemote, Is.False);
    }

    [Test]
    public void IsRemote_WhenSetToTrue_ShouldReturnTrue()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, isRemote: true);

        // Act & Assert
        Assert.That(service.IsRemote, Is.True);
    }

    [Test]
    public void ServiceMetadata_ShouldReturnProvidedMetadata()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var metadata = new SigningServiceMetadata("TestService", "Test service description");
        var service = new TestCertificateSigningService(mockSigningKey.Object, false, metadata);

        // Act
        var result = service.ServiceMetadata;

        // Assert
        Assert.That(result, Is.SameAs(metadata));
        Assert.That(result.ServiceName, Is.EqualTo("TestService"));
        Assert.That(result.Description, Is.EqualTo("Test service description"));
    }

    [Test]
    public void ServiceMetadata_WhenNotProvided_ShouldReturnDefaultMetadata()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);

        // Act
        var result = service.ServiceMetadata;

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.ServiceName, Is.Not.Null.Or.Empty);
    }

    [Test]
    public void GetCoseSigner_ShouldIncludeProtectedHeaders()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);
        var context = CreateSigningContext("test payload");

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer.ProtectedHeaders, Is.Not.Null);
        // Note: Algorithm header is automatically added by CoseSign1Message.Sign(), not by the service
        // The service only adds headers via contributors (e.g., ContentType, X5T, X5Chain)
    }

    [Test]
    public void GetCoseSigner_WithAdditionalHeaderContributors_ShouldApplyThem()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);

        var mockContributor = new Mock<IHeaderContributor>();
        mockContributor.Setup(c => c.MergeStrategy).Returns(HeaderMergeStrategy.Replace);
        mockContributor.Setup(c => c.ContributeProtectedHeaders(It.IsAny<CoseHeaderMap>(), It.IsAny<HeaderContributorContext>()))
            .Callback<CoseHeaderMap, HeaderContributorContext>((headers, ctx) =>
            {
                headers.Add(new CoseHeaderLabel(999), CoseHeaderValue.FromString("custom"));
            });

        var context = CreateSigningContext("test payload", new[] { mockContributor.Object });

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        mockContributor.Verify(c => c.ContributeProtectedHeaders(It.IsAny<CoseHeaderMap>(), It.IsAny<HeaderContributorContext>()), Times.Once);
    }

    [Test]
    public void GetCoseSigner_WithAdditionalUnprotectedHeaderContributor_SetsUnprotectedHeaders()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);

        var mockContributor = new Mock<IHeaderContributor>();
        mockContributor.Setup(c => c.MergeStrategy).Returns(HeaderMergeStrategy.Replace);
        mockContributor.Setup(c => c.ContributeUnprotectedHeaders(It.IsAny<CoseHeaderMap>(), It.IsAny<HeaderContributorContext>()))
            .Callback<CoseHeaderMap, HeaderContributorContext>((headers, _) =>
            {
                headers.Add(new CoseHeaderLabel(998), CoseHeaderValue.FromString("custom-unprotected"));
            });

        var context = CreateSigningContext("test payload", new[] { mockContributor.Object });

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer.UnprotectedHeaders, Is.Not.Null);
        Assert.That(signer.UnprotectedHeaders!.Any(h => h.Key == new CoseHeaderLabel(998)), Is.True);
    }

    [Test]
    public void GetCoseSigner_WhenNoSigningKeyProvided_ThrowsInvalidOperationException()
    {
        // Arrange
        var service = new NoKeyCertificateSigningService();
        var context = CreateSigningContext("test payload");

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => service.GetCoseSigner(context));
        Assert.That(ex!.Message, Does.Contain("No signing key available"));
    }

    [Test]
    public void GetCoseSigner_ShouldProvideKeyWithServiceContext()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);
        var context = CreateSigningContext("test payload");

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        // Verify key was acquired and used
        Assert.That(signer, Is.Not.Null);
        mockSigningKey.Verify(k => k.GetCoseKey(), Times.Once);
    }

    [Test]
    public void Dispose_ShouldCompleteSuccessfully()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);

        // Act & Assert
        Assert.DoesNotThrow(() => service.Dispose());
    }

    [Test]
    public void Dispose_CalledMultipleTimes_ShouldNotThrow()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            service.Dispose();
            service.Dispose(); // Second call
        });
    }

    [Test]
    public void GetCoseSigner_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var mockSigningKey = CreateMockSigningKey();
        var service = new TestCertificateSigningService(mockSigningKey.Object, false);
        service.Dispose();
        var context = CreateSigningContext("test payload");

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => service.GetCoseSigner(context));
    }

    #endregion

    #region Helper Methods

    private static Mock<ISigningKey> CreateMockSigningKey()
    {
        var mockKey = new Mock<ISigningKey>();

        // Create a real RSA key for CoseKey
        var rsa = RSA.Create(2048);
        var coseKey = new CoseKey(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);

        mockKey.Setup(k => k.GetCoseKey()).Returns(coseKey);
        mockKey.Setup(k => k.Metadata).Returns(new SigningKeyMetadata(
            -37, // PS256
            CryptographicKeyType.RSA,
            false, // isRemote not relevant - service determines this
            HashAlgorithmName.SHA256,
            2048,
            new Dictionary<string, object>()));

        return mockKey;
    }

    private static SigningContext CreateSigningContext(
        string payload,
        IReadOnlyList<IHeaderContributor>? additionalContributors = null)
    {
        return new SigningContext(
            System.Text.Encoding.UTF8.GetBytes(payload),
            "application/test",
            additionalContributors,
            null);
    }

    #endregion
}

/// <summary>
/// Test implementation of CertificateSigningService for testing base class behavior.
/// </summary>
internal class TestCertificateSigningService : CertificateSigningService
{
    private readonly ISigningKey SigningKey;

    public TestCertificateSigningService(
        ISigningKey signingKey,
        bool isRemote,
        SigningServiceMetadata? serviceMetadata = null)
        : base(isRemote, serviceMetadata)
    {
        SigningKey = signingKey;
    }

    protected override ISigningKey GetSigningKey(SigningContext context)
    {
        return SigningKey;
    }
}

internal sealed class NoKeyCertificateSigningService : CertificateSigningService
{
    public NoKeyCertificateSigningService()
        : base(isRemote: false)
    {
    }
}

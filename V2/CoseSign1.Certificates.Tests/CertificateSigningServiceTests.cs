// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using Moq;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// TDD tests for CertificateSigningService (shared base for local and remote).
/// Tests follow V3 architecture with dynamic key acquisition pattern.
/// </summary>
[TestFixture]
public class CertificateSigningServiceTests
{
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

    // Helper methods
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
            System.Text.Encoding.UTF8.GetBytes(payload).AsMemory(),
            "application/test",
            additionalContributors,
            null);
    }
}

/// <summary>
/// Test implementation of CertificateSigningService for testing base class behavior.
/// </summary>
internal class TestCertificateSigningService : CertificateSigningService
{
    private readonly ISigningKey _signingKey;

    public TestCertificateSigningService(
        ISigningKey signingKey,
        bool isRemote,
        SigningServiceMetadata? serviceMetadata = null)
        : base(isRemote, serviceMetadata)
    {
        _signingKey = signingKey;
    }

    protected override ISigningKey GetSigningKey(SigningContext context)
    {
        return _signingKey;
    }
}
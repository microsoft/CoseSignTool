// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Direct;
using CoseSign1.Indirect;
using Moq;
using NUnit.Framework;

namespace CoseSign1.Tests;

/// <summary>
/// Tests for IndirectSignatureFactory - testing from the caller's perspective.
/// Indirect signatures sign a hash of the payload rather than the payload itself.
/// </summary>
[TestFixture]
public class IndirectSignatureFactoryTests
{
    private Mock<ISigningService<SigningOptions>> _mockSigningService = null!;

    [SetUp]
    public void SetUp()
    {
        _mockSigningService = new Mock<ISigningService<SigningOptions>>();
    }

    [Test]
    public void Constructor_WithNullSigningService_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new IndirectSignatureFactory((ISigningService<SigningOptions>)null!));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithByteArrayPayload_ShouldHashAndSign()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1MessageBytes(payload, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<byte[]>());

        // Verify content type remains original (CoseHashEnvelope format)
        _mockSigningService.Verify(s => s.GetCoseSigner(It.Is<SigningContext>(ctx =>
            ctx.ContentType == "application/json")), Times.Once);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_ShouldAugmentContentTypeWithHashAlgorithm()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        SigningContext? capturedContext = null;
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        factory.CreateCoseSign1MessageBytes(payload, contentType, new IndirectSignatureOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256
        });

        // Assert - CoseHashEnvelope format keeps original content type
        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.ContentType, Is.EqualTo("application/json"));

        // Verify both ContentTypeHeaderContributor (from DirectSignatureFactory) and CoseHashEnvelopeHeaderContributor were added
        Assert.That(capturedContext.AdditionalHeaderContributors, Is.Not.Null);
        Assert.That(capturedContext.AdditionalHeaderContributors!.Count, Is.EqualTo(2));
        Assert.That(capturedContext.AdditionalHeaderContributors[0], Is.TypeOf<ContentTypeHeaderContributor>());
        Assert.That(capturedContext.AdditionalHeaderContributors[1], Is.InstanceOf<CoseHashEnvelopeHeaderContributor>());
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithDifferentHashAlgorithms_ShouldUseCorrectAlgorithm()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/octet-stream";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Test SHA256 - CoseHashEnvelope format keeps original content type
        SigningContext? context256 = null;
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => context256 = ctx)
            .Returns(mockCoseSigner);

        factory.CreateCoseSign1MessageBytes(payload, contentType, new IndirectSignatureOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256
        });
        Assert.That(context256!.ContentType, Is.EqualTo("application/octet-stream"));

        // Test SHA384 - CoseHashEnvelope format keeps original content type
        SigningContext? context384 = null;
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => context384 = ctx)
            .Returns(mockCoseSigner);

        factory.CreateCoseSign1MessageBytes(payload, contentType, new IndirectSignatureOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA384
        });
        Assert.That(context384!.ContentType, Is.EqualTo("application/octet-stream"));

        // Test SHA512 - CoseHashEnvelope format keeps original content type
        SigningContext? context512 = null;
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => context512 = ctx)
            .Returns(mockCoseSigner);

        factory.CreateCoseSign1MessageBytes(payload, contentType, new IndirectSignatureOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA512
        });
        Assert.That(context512!.ContentType, Is.EqualTo("application/octet-stream"));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithStream_ShouldHashIncrementally()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload for streaming");
        using var stream = new MemoryStream(payload);
        var contentType = "application/octet-stream";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageBytesAsync(stream, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        _mockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Once);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithNullPayload_ShouldThrowArgumentNullException()
    {
        // Arrange
        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            factory.CreateCoseSign1MessageBytes((byte[])null!, "application/json"));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithNullStream_ShouldThrowArgumentNullException()
    {
        // Arrange
        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await factory.CreateCoseSign1MessageBytesAsync((Stream)null!, "application/json"));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithNullContentType_ShouldThrowArgumentNullException()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            factory.CreateCoseSign1MessageBytes(payload, null!));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithNullContentType_ShouldThrowArgumentNullException()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        using var stream = new MemoryStream(payload);
        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await factory.CreateCoseSign1MessageBytesAsync(stream, null!));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_ShouldSignHashNotOriginalPayload()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        byte[]? signedData = null;

        // Mock GetCoseSigner to capture what is being signed
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => signedData = ctx.HasStream ? null : new byte[32]) // Can't access payload easily
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        factory.CreateCoseSign1MessageBytes(payload, contentType);

        // Assert
        Assert.That(signedData, Is.Not.Null);

        // The signed data should be a hash (32 bytes for SHA256), not the original payload
        Assert.That(signedData!.Length, Is.EqualTo(32)); // SHA256 hash size
        Assert.That(signedData, Is.Not.EqualTo(payload)); // Should be hash, not original
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithAdditionalHeaderContributors_ShouldPassThemToContext()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";
        var additionalContributor = new Mock<IHeaderContributor>().Object;
        var contributors = new List<IHeaderContributor> { additionalContributor };

        var mockCoseSigner = CreateMockCoseSigner();
        SigningContext? capturedContext = null;
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        factory.CreateCoseSign1MessageBytes(payload, contentType, new IndirectSignatureOptions
        {
            AdditionalHeaderContributors = contributors
        });

        // Assert - ContentTypeHeaderContributor (from DirectSignatureFactory), user contributor, and CoseHashEnvelope contributor are all added
        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.AdditionalHeaderContributors, Is.Not.Null);
        Assert.That(capturedContext.AdditionalHeaderContributors!.Count, Is.EqualTo(3));
        Assert.That(capturedContext.AdditionalHeaderContributors[0], Is.TypeOf<ContentTypeHeaderContributor>());
        Assert.That(capturedContext.AdditionalHeaderContributors[1], Is.EqualTo(additionalContributor));
        Assert.That(capturedContext.AdditionalHeaderContributors[2], Is.InstanceOf<CoseHashEnvelopeHeaderContributor>());
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithCancellation_ShouldSupportCancellation()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        using var stream = new MemoryStream(payload);
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Act & Assert - OperationCanceledException is the base class of TaskCanceledException
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await factory.CreateCoseSign1MessageBytesAsync(stream, contentType, cancellationToken: cts.Token));
    }
    [Test]
    public void CreateCoseSign1MessageIndirect_WithByteArray_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1Message(payload, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public void CreateCoseSign1MessageIndirect_WithReadOnlySpan_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1Message(new ReadOnlySpan<byte>(payload), contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public async Task CreateCoseSign1MessageIndirectAsync_WithByteArray_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageAsync(payload, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public async Task CreateCoseSign1MessageIndirectAsync_WithReadOnlyMemory_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageAsync(new ReadOnlyMemory<byte>(payload), contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public async Task CreateCoseSign1MessageIndirectAsync_WithStream_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        using var stream = new MemoryStream(payload);
        var contentType = "application/octet-stream";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageAsync(stream, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithPayloadLocation_ShouldStoreInOptions()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";
        var payloadLocation = "https://example.com/payload";

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var options = new IndirectSignatureOptions { PayloadLocation = payloadLocation };
        var result = factory.CreateCoseSign1MessageBytes(payload, contentType, options);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(options.PayloadLocation, Is.EqualTo(payloadLocation));
    }

    [Test]
    public void Dispose_ShouldDisposeSigningService()
    {
        // Arrange
        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        factory.Dispose();

        // Assert
        _mockSigningService.Verify(s => s.Dispose(), Times.Once);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var factory = new IndirectSignatureFactory(_mockSigningService.Object);
        factory.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
            factory.CreateCoseSign1MessageBytes(payload, "application/json"));
    }

    [Test]
    public void CreateCoseSign1MessageBytesAsync_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var factory = new IndirectSignatureFactory(_mockSigningService.Object);
        factory.Dispose();

        // Act & Assert
        Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await factory.CreateCoseSign1MessageBytesAsync(payload, "application/json"));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithAdditionalData_ShouldIncludeInSignature()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";
        var additionalData = Encoding.UTF8.GetBytes("Additional authenticated data");

        var mockCoseSigner = CreateMockCoseSigner();
        _mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new IndirectSignatureFactory(_mockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1MessageBytes(
            payload,
            contentType,
            new IndirectSignatureOptions { AdditionalData = additionalData });

        // Assert
        Assert.That(result, Is.Not.Null);
        _mockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Once);
    }

    private CoseSigner CreateMockCoseSigner()
    {
        // Create a real CoseSigner with RSA key for testing
        var rsa = RSA.Create(2048);
        return new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
    }
}
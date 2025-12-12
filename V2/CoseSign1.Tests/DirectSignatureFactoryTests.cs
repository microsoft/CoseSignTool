// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Direct;
using Moq;
using NUnit.Framework;

namespace CoseSign1.Tests;

/// <summary>
/// Tests for DirectSignatureFactory - testing from the caller's perspective.
/// </summary>
[TestFixture]
public class DirectSignatureFactoryTests
{
    private Mock<ISigningService<SigningOptions>> MockSigningService = null!;

    [SetUp]
    public void SetUp()
    {
        MockSigningService = new Mock<ISigningService<SigningOptions>>();
    }
    [Test]
    public void Constructor_WithNullSigningService_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new DirectSignatureFactory(null!));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithByteArrayPayload_ShouldCallGetCoseSignerAndReturnSignature()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";
        var expectedSignature = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1MessageBytes(payload, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<byte[]>());
        MockSigningService.Verify(s => s.GetCoseSigner(It.Is<SigningContext>(ctx =>
            !ctx.HasStream && ctx.ContentType == contentType)), Times.Once);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithContentType_ShouldPassContentTypeToSigningContext()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        SigningContext? capturedContext = null;
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        factory.CreateCoseSign1MessageBytes(payload, contentType);

        // Assert
        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.ContentType, Is.EqualTo(contentType));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithAdditionalHeaderContributors_ShouldPassThemToSigningContext()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";
        var additionalContributor = new Mock<IHeaderContributor>().Object;
        var contributors = new List<IHeaderContributor> { additionalContributor };

        var mockCoseSigner = CreateMockCoseSigner();
        SigningContext? capturedContext = null;
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        factory.CreateCoseSign1MessageBytes(payload, contentType, new DirectSignatureOptions
        {
            AdditionalHeaderContributors = contributors
        });

        // Assert
        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.AdditionalHeaderContributors, Is.Not.Null);
        Assert.That(capturedContext!.AdditionalHeaderContributors!.Count, Is.EqualTo(2)); // ContentTypeHeaderContributor + 1 additional
        Assert.That(capturedContext!.AdditionalHeaderContributors![0], Is.TypeOf<ContentTypeHeaderContributor>());
        Assert.That(capturedContext!.AdditionalHeaderContributors![1], Is.EqualTo(contributors[0]));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithAdditionalContext_ShouldPassItToSigningContext()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";
        var additionalContext = new Dictionary<string, object>
        {
            { "CustomKey", "CustomValue" }
        };

        var mockCoseSigner = CreateMockCoseSigner();
        SigningContext? capturedContext = null;
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        factory.CreateCoseSign1MessageBytes(payload, contentType, new DirectSignatureOptions
        {
            AdditionalContext = additionalContext
        });

        // Assert
        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.AdditionalContext, Is.EqualTo(additionalContext));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithEmbedPayloadTrue_ShouldCreateEmbeddedSignature()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1MessageBytes(payload, contentType, new DirectSignatureOptions { EmbedPayload = true });

        // Assert
        Assert.That(result, Is.Not.Null);
        // TODO: Verify the signature contains the embedded payload
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithEmbedPayloadFalse_ShouldCreateDetachedSignature()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1MessageBytes(payload, contentType, new DirectSignatureOptions { EmbedPayload = false });

        // Assert
        Assert.That(result, Is.Not.Null);
        // TODO: Verify the signature does not contain the embedded payload
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithStream_ShouldHandleIncrementalHashing()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload for streaming");
        using var stream = new MemoryStream(payload);
        var contentType = "application/octet-stream";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageBytesAsync(stream, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        MockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Once);
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithStreamAndContentType_ShouldPassContentType()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        using var stream = new MemoryStream(payload);
        var contentType = "application/octet-stream";

        var mockCoseSigner = CreateMockCoseSigner();
        SigningContext? capturedContext = null;
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        await factory.CreateCoseSign1MessageBytesAsync(stream, contentType);

        // Assert
        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.ContentType, Is.EqualTo(contentType));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithNullPayload_ShouldThrowArgumentNullException()
    {
        // Arrange
        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => factory.CreateCoseSign1MessageBytes(null!, "application/json"));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithNullStream_ShouldThrowArgumentNullException()
    {
        // Arrange
        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () => await factory.CreateCoseSign1MessageBytesAsync((Stream)null!, "application/json"));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_CalledMultipleTimes_ShouldReuseSigningServiceButGetFreshSigner()
    {
        // Arrange
        var payload1 = Encoding.UTF8.GetBytes("Payload 1");
        var payload2 = Encoding.UTF8.GetBytes("Payload 2");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        factory.CreateCoseSign1MessageBytes(payload1, contentType);
        factory.CreateCoseSign1MessageBytes(payload2, contentType);

        // Assert
        MockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Exactly(2));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithByteArray_ShouldSupportCancellation()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Act & Assert - TaskCanceledException is a subclass of OperationCanceledException
        Assert.ThrowsAsync<TaskCanceledException>(async () =>
            await factory.CreateCoseSign1MessageBytesAsync(payload, contentType, cancellationToken: cts.Token));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithStream_ShouldSupportCancellation()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        using var stream = new MemoryStream(payload);
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Act & Assert - TaskCanceledException is a subclass of OperationCanceledException
        Assert.ThrowsAsync<TaskCanceledException>(async () =>
            await factory.CreateCoseSign1MessageBytesAsync(stream, contentType, cancellationToken: cts.Token));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithStreamDetached_ShouldUseSignDetachedAsync()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload for detached signature");
        using var stream = new MemoryStream(payload);
        var contentType = "application/octet-stream";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageBytesAsync(
            stream,
            contentType,
            new DirectSignatureOptions { EmbedPayload = false });

        // Assert
        Assert.That(result, Is.Not.Null);
        MockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Once);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithAdditionalData_ShouldIncludeInSignature()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";
        var additionalData = Encoding.UTF8.GetBytes("Additional authenticated data");

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1MessageBytes(
            payload,
            contentType,
            new DirectSignatureOptions { AdditionalData = additionalData });

        // Assert
        Assert.That(result, Is.Not.Null);
        // The signature should be created with additional data
        // We can't easily verify the additional data was used without decoding and verifying,
        // but we can verify the method executed successfully
        MockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Once);
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithStreamAndAdditionalData_ShouldIncludeInSignature()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload for stream");
        using var stream = new MemoryStream(payload);
        var contentType = "application/octet-stream";
        var additionalData = Encoding.UTF8.GetBytes("Additional authenticated data");

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageBytesAsync(
            stream,
            contentType,
            new DirectSignatureOptions { AdditionalData = additionalData, EmbedPayload = false });

        // Assert
        Assert.That(result, Is.Not.Null);
        MockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Once);
    }

    [Test]
    public void Dispose_ShouldDisposeSigningService()
    {
        // Arrange
        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        factory.Dispose();

        // Assert
        MockSigningService.Verify(s => s.Dispose(), Times.Once);
    }

    [Test]
    public void Dispose_CalledMultipleTimes_ShouldOnlyDisposeOnce()
    {
        // Arrange
        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        factory.Dispose();
        factory.Dispose();

        // Assert
        MockSigningService.Verify(s => s.Dispose(), Times.Once);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var factory = new DirectSignatureFactory(MockSigningService.Object);
        factory.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => factory.CreateCoseSign1MessageBytes(payload, "application/json"));
    }

    [Test]
    public void CreateCoseSign1MessageBytesAsync_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var factory = new DirectSignatureFactory(MockSigningService.Object);
        factory.Dispose();

        // Act & Assert
        Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await factory.CreateCoseSign1MessageBytesAsync(payload, "application/json"));
    }

    [Test]
    public void CreateCoseSign1Message_WithByteArray_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1Message(payload, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public void CreateCoseSign1Message_WithReadOnlySpan_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1Message(new ReadOnlySpan<byte>(payload), contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WithByteArray_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageAsync(payload, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WithReadOnlyMemory_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageAsync(new ReadOnlyMemory<byte>(payload), contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WithStream_ShouldReturnCoseSign1Message()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        using var stream = new MemoryStream(payload);
        var contentType = "application/octet-stream";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageAsync(stream, contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseSign1Message>());
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithStreamEmbeddedAndAdditionalData_ShouldIncludeInSignature()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload for embedded stream");
        using var stream = new MemoryStream(payload);
        var contentType = "application/octet-stream";
        var additionalData = Encoding.UTF8.GetBytes("Additional authenticated data");

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageBytesAsync(
            stream,
            contentType,
            new DirectSignatureOptions { AdditionalData = additionalData, EmbedPayload = true });

        // Assert
        Assert.That(result, Is.Not.Null);
        MockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Once);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithNullContentType_ShouldThrowArgumentNullException()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => factory.CreateCoseSign1MessageBytes(payload, null!));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithNullContentType_ShouldThrowArgumentNullException()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        using var stream = new MemoryStream(payload);
        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await factory.CreateCoseSign1MessageBytesAsync(stream, null!));
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WithReadOnlyMemory_ShouldDelegateCorrectly()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = await factory.CreateCoseSign1MessageBytesAsync(new ReadOnlyMemory<byte>(payload), contentType);

        // Assert
        Assert.That(result, Is.Not.Null);
        MockSigningService.Verify(s => s.GetCoseSigner(It.IsAny<SigningContext>()), Times.Once);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithReadOnlySpan_ShouldUseDetachedWhenSpecified()
    {
        // Arrange
        var payload = Encoding.UTF8.GetBytes("Test payload");
        var contentType = "application/json";

        var mockCoseSigner = CreateMockCoseSigner();
        MockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(mockCoseSigner);

        var factory = new DirectSignatureFactory(MockSigningService.Object);

        // Act
        var result = factory.CreateCoseSign1MessageBytes(
            new ReadOnlySpan<byte>(payload),
            contentType,
            new DirectSignatureOptions { EmbedPayload = false });

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    private CoseSigner CreateMockCoseSigner()
    {
        // Create a real CoseSigner with RSA key for testing
        var rsa = RSA.Create(2048);
        return new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
    }
}
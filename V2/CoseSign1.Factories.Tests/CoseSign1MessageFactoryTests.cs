// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Tests;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;
using Moq;

[TestFixture]
public class CoseSign1MessageFactoryTests
{
    private static Mock<ISigningService<SigningOptions>> CreateMockSigningService()
        => new Mock<ISigningService<SigningOptions>>();

    private static int ReadInt32FromCoseHeaderValue(CoseHeaderValue value)
    {
        var reader = new CborReader(value.EncodedValue);
        return reader.ReadInt32();
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WhenOptionsIsNull_ThrowsArgumentNullException()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        SigningContext? capturedContext = null;
        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);

        var ex = Assert.Throws<ArgumentNullException>(() =>
            _ = factory.CreateCoseSign1MessageBytes(payload, "text/plain", options: null));

        Assert.That(ex!.ParamName, Is.EqualTo("options"));
        Assert.That(capturedContext, Is.Null);
    }

    [Test]
    public void DirectFactory_And_IndirectFactory_ExposeUnderlyingFactories()
    {
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();
        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);

        Assert.That(factory.DirectFactory, Is.Not.Null);
        Assert.That(factory.IndirectFactory, Is.Not.Null);
        Assert.That(factory.DirectFactory, Is.TypeOf<DirectSignatureFactory>());
        Assert.That(factory.IndirectFactory, Is.TypeOf<IndirectSignatureFactory>());
    }

    [Test]
    public void CreateDirectCoseSign1MessageBytes_WhenOptionsNull_DefaultsToEmbedPayload()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);

        var messageBytes = factory.CreateDirectCoseSign1MessageBytes(payload, "text/plain");
        var message = CoseMessage.DecodeSign1(messageBytes);

        Assert.That(message.Content, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(payload));
    }

    [Test]
    public void CreateIndirectCoseSign1MessageBytes_WhenOptionsNull_DefaultsToSha256HashEnvelope()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        SigningContext? capturedContext = null;

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);

        var messageBytes = factory.CreateIndirectCoseSign1MessageBytes(payload, "text/plain");
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Indirect signatures embed the hash bytes (defaults to SHA-256)
        Assert.That(message.Content, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(32));

        // Note: The signing service is mocked, so it does not apply header contributors.
        // Validate the factory wires up the expected contributors and that they produce the
        // expected hash-envelope protected header values.
        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.AdditionalHeaderContributors, Is.Not.Null);
        Assert.That(capturedContext.AdditionalHeaderContributors!.Count, Is.GreaterThanOrEqualTo(2));
        Assert.That(capturedContext.AdditionalHeaderContributors[0], Is.TypeOf<ContentTypeHeaderContributor>());
        Assert.That(capturedContext.AdditionalHeaderContributors[1], Is.TypeOf<CoseHashEnvelopeHeaderContributor>());

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var mockSigningKey = new Mock<ISigningKey>();
        var contributorContext = new HeaderContributorContext(capturedContext, mockSigningKey.Object);

        foreach (var contributor in capturedContext.AdditionalHeaderContributors)
        {
            contributor.ContributeProtectedHeaders(protectedHeaders, contributorContext);
            contributor.ContributeUnprotectedHeaders(unprotectedHeaders, contributorContext);
        }

        // Hash envelope header: PayloadHashAlg (258) should be -16 (SHA-256)
        var payloadHashAlgLabel = new CoseHeaderLabel(258);
        Assert.That(protectedHeaders.ContainsKey(payloadHashAlgLabel), Is.True);
        Assert.That(ReadInt32FromCoseHeaderValue(protectedHeaders[payloadHashAlgLabel]), Is.EqualTo(-16));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WhenOptionsIsDirectSignatureOptions_RoutesToDirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        SigningContext? capturedContext = null;
        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        _ = factory.CreateCoseSign1MessageBytes(payload, "text/plain", new DirectSignatureOptions());

        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.AdditionalHeaderContributors, Is.Not.Null);
        Assert.That(capturedContext.AdditionalHeaderContributors!.Count, Is.EqualTo(1));
        Assert.That(capturedContext.AdditionalHeaderContributors[0], Is.TypeOf<ContentTypeHeaderContributor>());
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WhenOptionsIsIndirectSignatureOptions_RoutesToIndirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        SigningContext? capturedContext = null;
        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Callback<SigningContext>(ctx => capturedContext = ctx)
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        _ = factory.CreateCoseSign1MessageBytes(payload, "text/plain", new IndirectSignatureOptions());

        Assert.That(capturedContext, Is.Not.Null);
        Assert.That(capturedContext!.AdditionalHeaderContributors, Is.Not.Null);
        Assert.That(capturedContext.AdditionalHeaderContributors!.Count, Is.EqualTo(2));
        Assert.That(capturedContext.AdditionalHeaderContributors[0], Is.TypeOf<ContentTypeHeaderContributor>());
        Assert.That(capturedContext.AdditionalHeaderContributors[1], Is.TypeOf<CoseHashEnvelopeHeaderContributor>());
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WhenOptionsIsBaseSigningOptions_ThrowsArgumentException()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);

        var ex = Assert.Throws<ArgumentException>(() =>
            _ = factory.CreateCoseSign1MessageBytes(payload, "text/plain", new SigningOptions()));

        Assert.That(ex!.ParamName, Is.EqualTo("options"));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WhenFactoryDisposed_ThrowsObjectDisposedException()
    {
        var mockSigningService = CreateMockSigningService();
        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        factory.Dispose();

        _ = Assert.Throws<ObjectDisposedException>(() =>
            _ = factory.CreateCoseSign1MessageBytes(new byte[] { 1, 2, 3 }, "text/plain", new DirectSignatureOptions()));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WhenPayloadIsSpan_RoutesToDirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var cose = factory.CreateCoseSign1MessageBytes(payload.AsSpan(), "text/plain", new DirectSignatureOptions());

        Assert.That(cose, Is.Not.Empty);
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WhenPayloadIsSpan_RoutesToIndirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var cose = factory.CreateCoseSign1MessageBytes(payload.AsSpan(), "text/plain", new IndirectSignatureOptions());

        Assert.That(cose, Is.Not.Empty);
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WhenPayloadIsByteArray_RoutesToDirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var cose = await factory.CreateCoseSign1MessageBytesAsync(payload, "text/plain", new DirectSignatureOptions());

        Assert.That(cose, Is.Not.Empty);
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WhenPayloadIsByteArray_RoutesToIndirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var cose = await factory.CreateCoseSign1MessageBytesAsync(payload, "text/plain", new IndirectSignatureOptions());

        Assert.That(cose, Is.Not.Empty);
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WhenPayloadIsReadOnlyMemory_RoutesToDirect()
    {
        var payload = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("hello"));
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var cose = await factory.CreateCoseSign1MessageBytesAsync(payload, "text/plain", new DirectSignatureOptions());

        Assert.That(cose, Is.Not.Empty);
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WhenPayloadIsReadOnlyMemory_RoutesToIndirect()
    {
        var payload = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("hello"));
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var cose = await factory.CreateCoseSign1MessageBytesAsync(payload, "text/plain", new IndirectSignatureOptions());

        Assert.That(cose, Is.Not.Empty);
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WhenPayloadIsStream_RoutesToDirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var payloadStream = new MemoryStream(payload);
        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var cose = await factory.CreateCoseSign1MessageBytesAsync(payloadStream, "text/plain", new DirectSignatureOptions());

        Assert.That(cose, Is.Not.Empty);
    }

    [Test]
    public async Task CreateCoseSign1MessageBytesAsync_WhenPayloadIsStream_RoutesToIndirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var payloadStream = new MemoryStream(payload);
        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var cose = await factory.CreateCoseSign1MessageBytesAsync(payloadStream, "text/plain", new IndirectSignatureOptions());

        Assert.That(cose, Is.Not.Empty);
    }

    [Test]
    public void CreateCoseSign1Message_WhenPayloadIsByteArray_RoutesToDirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = factory.CreateCoseSign1Message(payload, "text/plain", new DirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public void CreateCoseSign1Message_WhenPayloadIsByteArray_RoutesToIndirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = factory.CreateCoseSign1Message(payload, "text/plain", new IndirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public void CreateCoseSign1Message_WhenPayloadIsSpan_RoutesToDirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = factory.CreateCoseSign1Message(payload.AsSpan(), "text/plain", new DirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public void CreateCoseSign1Message_WhenPayloadIsSpan_RoutesToIndirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = factory.CreateCoseSign1Message(payload.AsSpan(), "text/plain", new IndirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WhenPayloadIsByteArray_RoutesToDirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = await factory.CreateCoseSign1MessageAsync(payload, "text/plain", new DirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WhenPayloadIsByteArray_RoutesToIndirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = await factory.CreateCoseSign1MessageAsync(payload, "text/plain", new IndirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WhenPayloadIsReadOnlyMemory_RoutesToDirect()
    {
        var payload = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("hello"));
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = await factory.CreateCoseSign1MessageAsync(payload, "text/plain", new DirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WhenPayloadIsReadOnlyMemory_RoutesToIndirect()
    {
        var payload = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("hello"));
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = await factory.CreateCoseSign1MessageAsync(payload, "text/plain", new IndirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WhenPayloadIsStream_RoutesToDirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var payloadStream = new MemoryStream(payload);
        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = await factory.CreateCoseSign1MessageAsync(payloadStream, "text/plain", new DirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    [Test]
    public async Task CreateCoseSign1MessageAsync_WhenPayloadIsStream_RoutesToIndirect()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var payloadStream = new MemoryStream(payload);
        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);
        var message = await factory.CreateCoseSign1MessageAsync(payloadStream, "text/plain", new IndirectSignatureOptions());

        Assert.That(message, Is.Not.Null);
    }

    private static CoseSigner CreateMockCoseSigner()
    {
        var rsa = RSA.Create(2048);
        return new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
    }
}


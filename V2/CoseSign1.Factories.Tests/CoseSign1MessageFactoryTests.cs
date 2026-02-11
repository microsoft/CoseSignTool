// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Tests;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;
using Microsoft.Extensions.DependencyInjection;
using Moq;

[TestFixture]
public class CoseSign1MessageFactoryTests
{
    private static Mock<ISigningService<SigningOptions>> CreateMockSigningService()
    {
        var mock = new Mock<ISigningService<SigningOptions>>();
        mock.Setup(s => s.VerifySignature(It.IsAny<CoseSign1Message>(), It.IsAny<SigningContext>()))
            .Returns(true);
        return mock;
    }

    private static int ReadInt32FromCoseHeaderValue(CoseHeaderValue value)
    {
        var reader = new CborReader(value.EncodedValue);
        return reader.ReadInt32();
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WhenOptionsIsNull_UsesDirectDefaults()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);

        DirectSignatureOptions? options = null;
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "text/plain", options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        Assert.That(message.Content, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(payload));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithDirectSignatureOptions_EmbedsPayload()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);

        var messageBytes = factory.CreateCoseSign1MessageBytes(
            payload,
            "text/plain",
            new DirectSignatureOptions { EmbedPayload = true });
        var message = CoseMessage.DecodeSign1(messageBytes);

        Assert.That(message.Content, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(payload));
    }

    [Test]
    public void CreateCoseSign1MessageBytes_WithIndirectSignatureOptions_ProducesSha256HashEnvelope()
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

        var messageBytes = factory.CreateCoseSign1MessageBytes(
            payload,
            "text/plain",
            new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 });
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
    public void CreateCoseSign1MessageBytes_WhenOptionsIsBaseSigningOptions_ThrowsInvalidOperationException()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var signer = CreateMockCoseSigner();
        var mockSigningService = CreateMockSigningService();

        mockSigningService
            .Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
            .Returns(signer);

        using var factory = new CoseSign1MessageFactory(mockSigningService.Object);

        _ = Assert.Throws<InvalidOperationException>(() =>
            _ = factory.CreateCoseSign1MessageBytes(payload, "text/plain", new SigningOptions()));
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

    private sealed class CustomSigningOptions : SigningOptions
    {
    }

    private sealed class CustomFactory : ICoseSign1MessageFactory<CustomSigningOptions>
    {
        private static readonly byte[] Marker = new byte[] { 0xC5, 0x5A };

        public IReadOnlyList<ITransparencyProvider>? TransparencyProviders => null;

        public byte[] CreateCoseSign1MessageBytes(byte[] payload, string contentType, CustomSigningOptions? options = default)
            => Marker;

        public byte[] CreateCoseSign1MessageBytes(ReadOnlySpan<byte> payload, string contentType, CustomSigningOptions? options = default)
            => Marker;

        public Task<byte[]> CreateCoseSign1MessageBytesAsync(byte[] payload, string contentType, CustomSigningOptions? options = default, CancellationToken cancellationToken = default)
            => Task.FromResult(Marker);

        public Task<byte[]> CreateCoseSign1MessageBytesAsync(ReadOnlyMemory<byte> payload, string contentType, CustomSigningOptions? options = default, CancellationToken cancellationToken = default)
            => Task.FromResult(Marker);

        public Task<byte[]> CreateCoseSign1MessageBytesAsync(Stream payloadStream, string contentType, CustomSigningOptions? options = default, CancellationToken cancellationToken = default)
            => Task.FromResult(Marker);

        public CoseSign1Message CreateCoseSign1Message(byte[] payload, string contentType, CustomSigningOptions? options = default)
            => throw new NotSupportedException();

        public CoseSign1Message CreateCoseSign1Message(ReadOnlySpan<byte> payload, string contentType, CustomSigningOptions? options = default)
            => throw new NotSupportedException();

        public Task<CoseSign1Message> CreateCoseSign1MessageAsync(byte[] payload, string contentType, CustomSigningOptions? options = default, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<CoseSign1Message> CreateCoseSign1MessageAsync(ReadOnlyMemory<byte> payload, string contentType, CustomSigningOptions? options = default, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<CoseSign1Message> CreateCoseSign1MessageAsync(Stream payloadStream, string contentType, CustomSigningOptions? options = default, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public void Dispose()
        {
        }
    }

    [Test]
    public void DI_Extensibility_CanRouteToCustomFactory_Generic()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTransient<ICoseSign1MessageFactory<CustomSigningOptions>, CustomFactory>();
        services.AddTransient<ICoseSign1MessageFactoryRouter, CoseSign1MessageFactory>();

        using var provider = services.BuildServiceProvider();

        var router = provider.GetRequiredService<ICoseSign1MessageFactoryRouter>();

        var payload = Encoding.UTF8.GetBytes("hello");

        var genericBytes = router.CreateCoseSign1MessageBytes<CustomSigningOptions>(payload, "text/plain");
        Assert.That(genericBytes, Is.EqualTo(new byte[] { 0xC5, 0x5A }));

        var genericBytesSpan = router.CreateCoseSign1MessageBytes<CustomSigningOptions>(payload.AsSpan(), "text/plain");
        Assert.That(genericBytesSpan, Is.EqualTo(new byte[] { 0xC5, 0x5A }));
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


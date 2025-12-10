// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests;

/// <summary>
/// Class for Testing Methods of <see cref="CoseSign1MessageFactory"/>
/// </summary>
public class CoseSign1MessageFactoryTests
{
    [SetUp]
    public void Setup()
    {
    }

    /// <summary>
    /// Testing with RSA Signing Key
    /// </summary>
    [Test]
    public void TestEmbedCoseSigningWithRSASuccess()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 selfSignedCertWithRSA = TestCertificateUtils.CreateCertificate();

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(selfSignedCertWithRSA.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object, true);

        mockedSignerKeyProvider.Object.IsRSA.Should().BeTrue();
        response.Should().NotBeNull();
    }

    /// <summary>
    ///  Testing with ECDsa Signing Key and embed payload true.
    /// </summary>
    [Test]
    public void TestEmbedCoseSigningWithECDsaSuccess()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 selfSignedCertwithECDsA = TestCertificateUtils.CreateCertificate(useEcc: true);

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns(selfSignedCertwithECDsA.GetECDsaPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns<RSA>(null);
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(false);

        mockedHeaderExtender.Setup(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Verifiable();
        mockedHeaderExtender.Setup(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Verifiable();

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object, true, ContentTypeConstants.Cose, mockedHeaderExtender.Object);

        response.Should().NotBeNull();
        mockedHeaderExtender.Verify(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>()), Times.Once);
        mockedHeaderExtender.Verify(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>()), Times.Once);
    }

    /// <summary>
    /// Testing with HeaderExtenders
    /// </summary>
    [Test]
    public void TestEmbedCoseSigningWithHeaderExtender()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 selfSignedCertwithECDsA = TestCertificateUtils.CreateCertificate(useEcc: true);

        CoseHeaderLabel testHeaderLabel = new("test-header-label");
        CoseHeaderLabel testHeaderLabel2 = new("test-header-label2");
        CoseHeaderMap testProtectedHeaders = new()
        {
            { testHeaderLabel, "test-header-value" }
        };

        CoseHeaderMap testProtectedHeaders2 = new()
        {
            { testHeaderLabel, "test-header-value" },
            { testHeaderLabel2, "test-header-value2" }
        };

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns(selfSignedCertwithECDsA.GetECDsaPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns<RSA>(null);
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(false);

        mockedHeaderExtender.Setup(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(testProtectedHeaders2);
        mockedHeaderExtender.Setup(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns<CoseHeaderMap>(null);

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object, true, ContentTypeConstants.Cose, mockedHeaderExtender.Object);

        response.Should().NotBeNull();
        response.ProtectedHeaders.Count.Should().Be(3);
        response.ProtectedHeaders.First().Key.Should().Be(CoseHeaderLabel.Algorithm); // this is the algo header added by the CoseSigner
        response.ProtectedHeaders.ElementAt(1).Key.Should().Be(testProtectedHeaders2.Keys.First());
        response.ProtectedHeaders.Last().Key.Should().Be(testProtectedHeaders2.Keys.Last());
    }

    /// <summary>
    /// Test when both Keys are provided
    /// </summary>
    [Test]
    public void TestEmbedCoseSigningWithBothKeysSuccess()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 selfSignedCertwithRSA = TestCertificateUtils.CreateCertificate();
        X509Certificate2 selfSignedCertwithECDsA = TestCertificateUtils.CreateCertificate(useEcc: true);

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns(selfSignedCertwithECDsA.GetECDsaPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(selfSignedCertwithRSA.GetRSAPrivateKey()); ;
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object, true);

        mockedSignerKeyProvider.Object.IsRSA.Should().BeTrue();
        response.Should().NotBeNull();
    }

    /// <summary>
    /// Testing for Detached CoseSign1Message
    /// </summary>
    [Test]
    public void TestDetachedCoseSigningSuccess()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 selfSignedCertwithRSA = TestCertificateUtils.CreateCertificate();

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(selfSignedCertwithRSA.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object, embedPayload: false);

        mockedSignerKeyProvider.Object.IsRSA.Should().BeTrue();
        response.Should().NotBeNull();
    }

    /// <summary>
    /// Testing When Signing Key is not provided
    /// </summary>
    [Test]
    public void TestCoseSigningException()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns<RSA>(null);
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(false);

        CoseSigningException? exceptionText = Assert.Throws<CoseSigningException>(
                           () => coseSign1MessageFactory.CreateCoseSign1Message(testPayload,
                                 mockedSignerKeyProvider.Object));

        exceptionText.Message.Should().Be("Unsupported certificate type for COSE signing.");
    }

    /// <summary>
    /// Testing when no payload is provided
    /// </summary>
    [Test]
    public void EmptyPayloadTest()
    {
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        X509Certificate2 selfSignedCertwithRSA = TestCertificateUtils.CreateCertificate();
        ICoseSigningKeyProvider keyProvider = new X509Certificate2CoseSigningKeyProvider(null, selfSignedCertwithRSA);

        ReadOnlyMemory<byte> bytesPayload = ReadOnlyMemory<byte>.Empty;
        ArgumentOutOfRangeException? bytesException = Assert.Throws<ArgumentOutOfRangeException>(() => coseSign1MessageFactory.CreateCoseSign1Message(bytesPayload, keyProvider));
        bytesException.Message.Should().Be("The payload to sign is empty.");

        Stream streamPayload = new MemoryStream();
        ArgumentOutOfRangeException? streamException = Assert.Throws<ArgumentOutOfRangeException>(() => coseSign1MessageFactory.CreateCoseSign1Message(streamPayload, keyProvider));
        streamException.Message.Should().Be("The payload to sign is empty.");

#pragma warning disable CS8604 // Intentional null reference argument for testing.
        ArgumentOutOfRangeException? nullException = Assert.Throws<ArgumentOutOfRangeException>(() => coseSign1MessageFactory.CreateCoseSign1Message(null as Stream, keyProvider));
#pragma warning restore CS8604 // Test complete.
        nullException.Message.Should().Be("The payload to sign is empty.");
    }

    /// <summary>
    /// Testing with No testPayload and No Signing Key
    /// </summary>
    [Test]
    public void TestWhenNoPayloadAndNoSigningKey()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        ReadOnlyMemory<byte> testPayload = ReadOnlyMemory<byte>.Empty;

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns<RSA>(null);
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(false);

        CoseSigningException? exceptionText = Assert.Throws<CoseSigningException>(() =>
            coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object));

        exceptionText.Message.Should().Be("Unsupported certificate type for COSE signing.");
    }

    /// <summary>
    /// Testing when Signing Key Provider is not supplied
    /// </summary>
    [Test]
    public void TestNullKeyProviderException()
    {
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");

#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type. Disabled for test.
        ArgumentNullException? exceptionText = Assert.Throws<ArgumentNullException>(() => coseSign1MessageFactory.CreateCoseSign1Message(testPayload, null));
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.

        exceptionText.Message.Should().Be("Signing key provider is not provided.");
    }

    #region Async Method Tests

    /// <summary>
    /// Tests CreateCoseSign1MessageAsync with byte array payload - should complete synchronously
    /// </summary>
    [Test]
    public async Task TestCreateCoseSign1MessageAsync_WithByteArray()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        byte[] testPayload = Encoding.ASCII.GetBytes("Async test payload!");
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider keyProvider = new X509Certificate2CoseSigningKeyProvider(chainBuilder, testCert);
        CoseSign1MessageFactory factory = new();

        // Act
        CoseSign1Message result = await factory.CreateCoseSign1MessageAsync(
            testPayload, keyProvider, embedPayload: false, cancellationToken: CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.ProtectedHeaders.Should().ContainKey(CoseHeaderLabel.Algorithm);
    }

    /// <summary>
    /// Tests CreateCoseSign1MessageAsync with stream payload - should use true async
    /// </summary>
    [Test]
    public async Task TestCreateCoseSign1MessageAsync_WithStream()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        byte[] testPayloadBytes = Encoding.ASCII.GetBytes("Async stream test!");
        MemoryStream payloadStream = new(testPayloadBytes);
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider keyProvider = new X509Certificate2CoseSigningKeyProvider(chainBuilder, testCert);
        CoseSign1MessageFactory factory = new();

        // Act
        CoseSign1Message result = await factory.CreateCoseSign1MessageAsync(
            payloadStream, keyProvider, embedPayload: false, cancellationToken: CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.ProtectedHeaders.Should().ContainKey(CoseHeaderLabel.Algorithm);
    }

    /// <summary>
    /// Tests CreateCoseSign1MessageBytesAsync with byte array payload
    /// </summary>
    [Test]
    public async Task TestCreateCoseSign1MessageBytesAsync_WithByteArray()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        byte[] testPayload = Encoding.ASCII.GetBytes("Async bytes test!");
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider keyProvider = new X509Certificate2CoseSigningKeyProvider(chainBuilder, testCert);
        CoseSign1MessageFactory factory = new();

        // Act
        ReadOnlyMemory<byte> result = await factory.CreateCoseSign1MessageBytesAsync(
            testPayload, keyProvider, embedPayload: false, cancellationToken: CancellationToken.None);

        // Assert
        result.Length.Should().BeGreaterThan(0);
        
        // Decode and verify
        CoseSign1Message message = CoseMessage.DecodeSign1(result.ToArray());
        message.Should().NotBeNull();
    }

    /// <summary>
    /// Tests CreateCoseSign1MessageBytesAsync with stream payload
    /// </summary>
    [Test]
    public async Task TestCreateCoseSign1MessageBytesAsync_WithStream()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        byte[] testPayloadBytes = Encoding.ASCII.GetBytes("Async stream bytes test!");
        MemoryStream payloadStream = new(testPayloadBytes);
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider keyProvider = new X509Certificate2CoseSigningKeyProvider(chainBuilder, testCert);
        CoseSign1MessageFactory factory = new();

        // Act
        ReadOnlyMemory<byte> result = await factory.CreateCoseSign1MessageBytesAsync(
            payloadStream, keyProvider, embedPayload: false, cancellationToken: CancellationToken.None);

        // Assert
        result.Length.Should().BeGreaterThan(0);
        
        // Decode and verify
        CoseSign1Message message = CoseMessage.DecodeSign1(result.ToArray());
        message.Should().NotBeNull();
    }

    /// <summary>
    /// Tests async methods with custom header extender
    /// </summary>
    [Test]
    public async Task TestCreateCoseSign1MessageAsync_WithHeaderExtender()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        byte[] testPayload = Encoding.ASCII.GetBytes("Test with header extender!");
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider keyProvider = new X509Certificate2CoseSigningKeyProvider(chainBuilder, testCert);
        CoseSign1MessageFactory factory = new();

        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        CoseHeaderLabel testLabel = new("custom-header");
        CoseHeaderMap testHeaders = new() { { testLabel, "custom-value" } };
        
        mockedHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(testHeaders);
        mockedHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(new CoseHeaderMap());

        // Act
        CoseSign1Message result = await factory.CreateCoseSign1MessageAsync(
            testPayload, keyProvider, embedPayload: false, headerExtender: mockedHeaderExtender.Object,
            cancellationToken: CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        mockedHeaderExtender.Verify(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>()), Times.Once);
    }

    /// <summary>
    /// Tests that async methods with embed=true work correctly
    /// </summary>
    [Test]
    public async Task TestCreateCoseSign1MessageAsync_WithEmbedPayload()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        byte[] testPayloadBytes = Encoding.ASCII.GetBytes("Embedded payload test!");
        MemoryStream payloadStream = new(testPayloadBytes);
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider keyProvider = new X509Certificate2CoseSigningKeyProvider(chainBuilder, testCert);
        CoseSign1MessageFactory factory = new();

        // Act
        CoseSign1Message result = await factory.CreateCoseSign1MessageAsync(
            payloadStream, keyProvider, embedPayload: true, cancellationToken: CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Content.Should().NotBeNull();
        result.Content!.Value.ToArray().Should().BeEquivalentTo(testPayloadBytes);
    }

    #endregion
}


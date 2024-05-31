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

        var response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object, true);

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

        var response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object, true);

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

        var response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSignerKeyProvider.Object, embedPayload: false);

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

        var exceptionText = Assert.Throws<CoseSigningException>(
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
        var bytesException = Assert.Throws<ArgumentOutOfRangeException>(() => coseSign1MessageFactory.CreateCoseSign1Message(bytesPayload, keyProvider));
        bytesException.Message.Should().Be("The payload to sign is empty.");

        Stream streamPayload = new MemoryStream();
        var streamException = Assert.Throws<ArgumentOutOfRangeException>(() => coseSign1MessageFactory.CreateCoseSign1Message(streamPayload, keyProvider));
        streamException.Message.Should().Be("The payload to sign is empty.");

#pragma warning disable CS8604 // Intentional null reference argument for testing.
        var nullException = Assert.Throws<ArgumentOutOfRangeException>(() => coseSign1MessageFactory.CreateCoseSign1Message(null as Stream, keyProvider));
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

        var exceptionText = Assert.Throws<CoseSigningException>(() =>
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
        var exceptionText = Assert.Throws<ArgumentNullException>(() => coseSign1MessageFactory.CreateCoseSign1Message(testPayload, null));
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.

        exceptionText.Message.Should().Be("Signing key provider is not provided.");
    }
}

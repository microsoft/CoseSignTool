// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests;

using CoseSign1.Abstractions;

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
        ICoseSigningKeyProvider mockedSigningKeyProvider = TestCertificateUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSigningKeyProvider, true);

        // TODO: do we want to check the signing certificate in the actual response to make sure it's RSA?
        response.Should().NotBeNull();
    }

    /// <summary>
    ///  Testing with ECDsa Signing Key and embed payload true.
    /// </summary>
    [Test]
    public void TestEmbedCoseSigningWithECDsaSuccess()
    {
        ICoseSigningKeyProvider mockedSigningKeyProvider = TestCertificateUtils.SetupMockSigningKeyProvider(keyType: CoseKeyType.ECDsa);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 selfSignedCertwithECDsA = TestCertificateUtils.CreateCertificate(useEcc: true);

        mockedHeaderExtender.Setup(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Verifiable();
        mockedHeaderExtender.Setup(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Verifiable();

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSigningKeyProvider, true, ContentTypeConstants.Cose, mockedHeaderExtender.Object);

        response.Should().NotBeNull();
        mockedHeaderExtender.Verify(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>()), Times.Once);
        mockedHeaderExtender.Verify(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>()), Times.Once);
    }

    /// <summary>
    ///  Testing with ECDsa Signing Key and embed payload true.
    /// </summary>
    [Test]
    public void TestEmbedCoseSigningWithMLDsaSuccess()
    {
        ICoseSigningKeyProvider mockedSigningKeyProvider = TestCertificateUtils.SetupMockSigningKeyProvider(keyType: CoseKeyType.MLDsa);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 selfSignedCertwithECDsA = TestCertificateUtils.CreateCertificate(useEcc: true);

        mockedHeaderExtender.Setup(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Verifiable();
        mockedHeaderExtender.Setup(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Verifiable();

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSigningKeyProvider, true, ContentTypeConstants.Cose, mockedHeaderExtender.Object);

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
        ICoseSigningKeyProvider mockedSigningKeyProvider = TestCertificateUtils.SetupMockSigningKeyProvider(keyType: CoseKeyType.ECDsa);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");

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

        mockedHeaderExtender.Setup(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(testProtectedHeaders2);
        mockedHeaderExtender.Setup(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns<CoseHeaderMap>(null);

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSigningKeyProvider, true, ContentTypeConstants.Cose, mockedHeaderExtender.Object);

        response.Should().NotBeNull();
        response.ProtectedHeaders.Count.Should().Be(3);
        response.ProtectedHeaders.First().Key.Should().Be(CoseHeaderLabel.Algorithm); // this is the algo header added by the CoseSigner
        response.ProtectedHeaders.ElementAt(1).Key.Should().Be(testProtectedHeaders2.Keys.First());
        response.ProtectedHeaders.Last().Key.Should().Be(testProtectedHeaders2.Keys.Last());
    }

    /// <summary>
    /// Testing for Detached CoseSign1Message
    /// </summary>
    [Test]
    public void TestDetachedCoseSigningSuccess()
    {
        ICoseSigningKeyProvider mockedSigningKeyProvider = TestCertificateUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new();
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");

        CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(testPayload, mockedSigningKeyProvider, embedPayload: false);

        // TODO: do we want to check the signing certificate in the actual response to make sure it's RSA?
        //mockedSignerKeyProvider.Object.IsRSA.Should().BeTrue();
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
        mockedSignerKeyProvider.Setup(x => x.GetCoseKey()).Returns<CoseKey>(null);

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
}

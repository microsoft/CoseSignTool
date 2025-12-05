// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests;

/// <summary>
/// Class for Testing Methods of <see cref="CoseSign1MessageBuilder"/>
/// </summary>
public class CoseSign1MessageBuilderTests
{
    /// <summary>
    /// Setup method
    /// </summary>
    [SetUp]
    public void Setup()
    {
    }

    /// <summary>
    /// Test Happy Path for CoseSign1MessageBuilder Constructor
    /// </summary>
    [Test]
    public void TestConstructorsSuccess()
    {
        // arrange
        Mock<ICoseSigningKeyProvider> keyProvider = new(MockBehavior.Strict);
        Mock<ICoseSign1MessageFactory> factoryObj = new();

        List<Action> constructorTests =
        [
            new Action(() => _= new CoseSign1MessageBuilder(keyProvider.Object, factoryObj.Object)),
            new Action(() => _= new CoseSign1MessageBuilder(keyProvider.Object))
        ];

        // test validate
        foreach (Action test in constructorTests)
        {
            // Actions should not throw.
            test();
        }
    }

    /// <summary>
    /// /// <summary>
    /// Test Failure Paths for CoseSign1MessageBuilder Constructor
    /// </summary>
    /// </summary>
    [Test]
    public void TestConstructorsFailure()
    {
        // arrange
        Mock<ICoseSign1MessageFactory> factoryObj = new();
        Mock<ICoseSigningKeyProvider> mockedSigningKeyPovider = new(MockBehavior.Strict);

        List<Action> constructorTests =
        [
            new Action(() => _ = new CoseSign1MessageBuilder(null, factoryObj.Object)),
            new Action(() => _ = new CoseSign1MessageBuilder(null)),
        ];

        // test validate
        foreach (Action test in constructorTests)
        {
            Assert.Throws<ArgumentNullException>(() => test());
        }

    }

    /// <summary>
    /// Testing Setter methods and Build() method
    /// Verifying if CreateCoseSign1Message() getting called on Build()
    /// </summary>
    [Test]
    public void TestSettersWithFactoryObject()
    {
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        Mock<ICoseSigningKeyProvider> mockedSigningKeyPovider = new(MockBehavior.Strict);
        Mock<ICoseSign1MessageFactory> mockedCoseSignFactoryObject = new();

        CoseSign1MessageBuilder testCosesign1Builder = new(mockedSigningKeyPovider.Object, mockedCoseSignFactoryObject.Object);

        mockedSigningKeyPovider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSigningKeyPovider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSigningKeyPovider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSigningKeyPovider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSigningKeyPovider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(testCert.GetRSAPrivateKey());
        mockedSigningKeyPovider.Setup(x => x.IsRSA).Returns(true);

        CoseSign1Message response = testCosesign1Builder.SetPayloadBytes(testPayload).SetEmbedPayload(true).Build();

        mockedCoseSignFactoryObject.Verify(v => v.CreateCoseSign1Message(It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<ICoseSigningKeyProvider>(),
               It.IsAny<bool>(), It.IsAny<string>(),It.IsAny<ICoseHeaderExtender>()), Times.Once);

        testCosesign1Builder.EmbedPayload.Should().BeTrue();
        testCosesign1Builder.HeaderExtender.Should().BeNull();
        testCosesign1Builder.SigningKeyProvider.Should().NotBeNull();
        testCosesign1Builder.PayloadBytes.Should().NotBeNull();
    }

    /// <summary>
    /// Testing Setting HeaderExtenders and Testing Build()
    /// </summary>
    [Test]
    public void TestSettingHeaderExtender()
    {
        //arrange
        byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();

        Mock<ICoseSigningKeyProvider> mockedSigningKeyPovider = new(MockBehavior.Strict);
        Mock<ICoseHeaderExtender> mockedHeaderExtender = new(MockBehavior.Strict);

        CoseSign1MessageBuilder testCoseSign1Builder = new(mockedSigningKeyPovider.Object);

        mockedSigningKeyPovider.Setup(x => x.GetProtectedHeaders()).Returns([]);
        mockedSigningKeyPovider.Setup(x => x.GetUnProtectedHeaders()).Returns([]);
        mockedSigningKeyPovider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSigningKeyPovider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSigningKeyPovider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(testCert.GetRSAPrivateKey());
        mockedSigningKeyPovider.Setup(x => x.IsRSA).Returns(true);

        CoseHeaderLabel testHeaderLabel = new("test-header-label");
        CoseHeaderLabel testHeaderLabel2 = new("test-header-label2");
        CoseHeaderMap testProtectedHeaders = new()
        {
            { testHeaderLabel, "test-header-value" }
        };

        CoseHeaderMap testUnProtectedHeaders = new()
        {
            { testHeaderLabel2, "test-header-value2" }
        };

        mockedHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(testProtectedHeaders);
        mockedHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(testUnProtectedHeaders);

        //test
        CoseSign1Message response = testCoseSign1Builder.SetPayloadBytes(testPayload)
                                           .SetContentType(ContentTypeConstants.Cose)
                                           .ExtendCoseHeader(mockedHeaderExtender.Object).Build();

        //verify
        testCoseSign1Builder.EmbedPayload.Should().BeFalse();
        testCoseSign1Builder.HeaderExtender.Should().NotBeNull();
    }

    /// <summary>
    /// Tests BuildAsync with a stream payload
    /// </summary>
    [Test]
    public async Task TestBuildAsyncSuccess()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        byte[] testPayloadBytes = Encoding.ASCII.GetBytes("Test async payload!");
        MemoryStream payloadStream = new(testPayloadBytes);

        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testCert);

        CoseSign1MessageBuilder builder = new(testSigningKeyProvider);
        builder.SetContentType(ContentTypeConstants.Cose).SetEmbedPayload(false);

        // Act
        CoseSign1Message response = await builder.BuildAsync(payloadStream);

        // Assert
        response.Should().NotBeNull();
        response.Should().BeOfType<CoseSign1Message>();
        response.ProtectedHeaders.Should().NotBeNull();
        response.ProtectedHeaders.Should().ContainKey(CoseHeaderLabel.Algorithm);
    }

    /// <summary>
    /// Tests BuildAsync with an empty stream throws exception
    /// </summary>
    [Test]
    public async Task TestBuildAsyncWithEmptyStream_ThrowsException()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        MemoryStream emptyStream = new(Array.Empty<byte>());

        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testCert);

        CoseSign1MessageBuilder builder = new(testSigningKeyProvider);

        // Act & Assert
        await builder.Invoking(async b => await b.BuildAsync(emptyStream))
            .Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    /// <summary>
    /// Tests BuildAsync with custom header extender
    /// </summary>
    [Test]
    public async Task TestBuildAsyncWithCustomHeaderExtender()
    {
        // Arrange
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        byte[] testPayloadBytes = Encoding.ASCII.GetBytes("Test payload with custom header!");
        MemoryStream payloadStream = new(testPayloadBytes);

        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testCert);

        Mock<ICoseHeaderExtender> mockedHeaderExtender = new(MockBehavior.Strict);
        CoseHeaderLabel testHeaderLabel = new("test-header");
        CoseHeaderMap testProtectedHeaders = new()
        {
            { testHeaderLabel, "test-value" }
        };

        mockedHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(testProtectedHeaders);
        mockedHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(new CoseHeaderMap());

        CoseSign1MessageBuilder builder = new(testSigningKeyProvider);
        builder.SetContentType(ContentTypeConstants.Cose)
               .SetEmbedPayload(false)
               .ExtendCoseHeader(mockedHeaderExtender.Object);

        // Act
        CoseSign1Message response = await builder.BuildAsync(payloadStream);

        // Assert
        response.Should().NotBeNull();
        response.ProtectedHeaders.Should().NotBeNull();
        mockedHeaderExtender.Verify(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>()), Times.Once);
    }
}


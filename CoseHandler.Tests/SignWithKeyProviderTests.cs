// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

/// <summary>
/// Class to test for SignInternal <see cref="CoseHandler"/> with SigningKeyProvider <see cref="ICoseSigningKeyProvider"/>
/// </summary>
[TestClass]
public class SignWithKeyProviderTests
{
    [TestMethod]
    public void TestSignSuccess()
    {

        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 testCertRSA = TestCertificateUtils.CreateCertificate();
        var testChain = TestCertificateUtils.CreateTestChain();

        string signedFile = Path.GetTempFileName();
        Mock<ICertificateChainBuilder> testChainBuilder = new();
        testChainBuilder.Setup(x => x.ChainElements).Returns(new List<X509Certificate2>(testChain));
        testChainBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);

        var mockedSignerKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder.Object, testCertRSA);

        CoseHandler.Sign(testPayload.ToArray(), mockedSignerKeyProvider, false, new FileInfo(signedFile));
    }

    //Testing Exception Path for SignInternal with KeyProvider
    [TestMethod]
    public void TestSignWithNoSigningKey()
    {
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("testPayload!");
        var signedFile = Path.GetTempFileName();

        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns<RSA>(null);
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(false);

        var exceptionText = Assert.ThrowsException<CoseSigningException>(() => CoseHandler.Sign(testPayload.ToArray(), mockedSignerKeyProvider.Object, false, new FileInfo(signedFile)));
        exceptionText.Message.Should().Be("Unsupported certificate type for COSE signing.");
    }

    /// <summary>
    /// Testing When No testPayload is Provided
    /// </summary>
    [TestMethod]
    public void TestSignWithEmptyPayload()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        X509Certificate2 selfSignedCertwithRSA = TestCertificateUtils.CreateCertificate();
        ReadOnlyMemory<byte> testPayload = ReadOnlyMemory<byte>.Empty;

        var signedFile = Path.GetTempFileName();

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(selfSignedCertwithRSA.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        bool isRSA = mockedSignerKeyProvider.Object.IsRSA;

        mockedSignerKeyProvider.Object.IsRSA.Should().BeTrue();

        var exceptionText = Assert.ThrowsException<ArgumentException>(() => CoseHandler.Sign(testPayload.ToArray(), mockedSignerKeyProvider.Object, false, new FileInfo(signedFile)));

        exceptionText.Message.Should().Be("Payload not provided.");
    }
}





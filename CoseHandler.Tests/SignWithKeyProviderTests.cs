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
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();

        string signedFile = Path.GetTempFileName();
        Mock<ICertificateChainBuilder> testChainBuilder = new();
        testChainBuilder.Setup(x => x.ChainElements).Returns(new List<X509Certificate2>(testChain));
        testChainBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);

        X509Certificate2CoseSigningKeyProvider mockedSignerKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder.Object, testCertRSA);

        CoseHandler.Sign(testPayload.ToArray(), mockedSignerKeyProvider, false, new FileInfo(signedFile));
    }

    /// <summary>
    /// Verifies per-operation hash and RSA padding options flow through the shared signing facade.
    /// </summary>
    [TestMethod]
    public async Task SignAsync_WithSigningOptions_UsesRequestedAlgorithm()
    {
        using X509Certificate2 certificate = TestCertificateUtils.CreateCertificate();
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        Mock<ICertificateChainBuilder> chainBuilder = new();
        chainBuilder.Setup(x => x.ChainElements).Returns(new List<X509Certificate2>(testChain));
        chainBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);
        X509Certificate2CoseSigningKeyProvider signingKeyProvider = new(chainBuilder.Object, certificate);
        using MemoryStream payload = new(Encoding.ASCII.GetBytes("testPayload!"));

        ReadOnlyMemory<byte> signedBytes = await CoseHandler.SignAsync(
            payload,
            signingKeyProvider,
            embedSign: true,
            contentType: "application/octet-stream",
            headerExtender: null,
            HashAlgorithmName.SHA384,
            RSASignaturePadding.Pkcs1);

        CoseSign1Message message = CoseMessage.DecodeSign1(signedBytes.ToArray());
        message.ProtectedHeaders[CoseHeaderLabel.Algorithm].GetValueAsInt32().Should().Be(-258);
    }

    //Testing Exception Path for SignInternal with KeyProvider
    [TestMethod]
    public void TestSignWithNoSigningKey()
    {
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("testPayload!");
        string signedFile = Path.GetTempFileName();

        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns<RSA>(null);
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(false);
        
        // Setup KeyChain property to return empty list since no keys are available
        mockedSignerKeyProvider.Setup(x => x.KeyChain).Returns(new List<AsymmetricAlgorithm>().AsReadOnly());

        CoseSigningException exceptionText = Assert.ThrowsException<CoseSigningException>(() => CoseHandler.Sign(testPayload.ToArray(), mockedSignerKeyProvider.Object, false, new FileInfo(signedFile)));
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

        string signedFile = Path.GetTempFileName();

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(selfSignedCertwithRSA.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        // Setup KeyChain property
        RSA? publicKey = selfSignedCertwithRSA.GetRSAPublicKey();
        System.Collections.ObjectModel.ReadOnlyCollection<AsymmetricAlgorithm> keyChain = publicKey != null ? new List<AsymmetricAlgorithm> { publicKey }.AsReadOnly() : new List<AsymmetricAlgorithm>().AsReadOnly();
        mockedSignerKeyProvider.Setup(x => x.KeyChain).Returns(keyChain);

        bool isRSA = mockedSignerKeyProvider.Object.IsRSA;

        mockedSignerKeyProvider.Object.IsRSA.Should().BeTrue();

        ArgumentException exceptionText = Assert.ThrowsException<ArgumentException>(() => CoseHandler.Sign(testPayload.ToArray(), mockedSignerKeyProvider.Object, false, new FileInfo(signedFile)));

        exceptionText.Message.Should().Be("Payload not provided.");
    }
}



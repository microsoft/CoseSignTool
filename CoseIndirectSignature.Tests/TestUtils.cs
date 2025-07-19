// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature.Tests;

/// <summary>
/// Test utility methods.
/// </summary>
public static class TestUtils
{
    /// <summary>
    /// Sets up a mock signing key provider for testing purposes.
    /// </summary>
    /// <param name="testName">The name of the test, defaults to the calling member.</param>
    /// <returns>A <see cref="Mock{ICoseSigningKeyProvider}"/> which uses a self-signed certificate for signing operations.</returns>
    public static ICoseSigningKeyProvider SetupMockSigningKeyProvider([CallerMemberName] string testName = "none")
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        X509Certificate2 selfSignedCertWithRSA = TestCertificateUtils.CreateCertificate(testName);

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(selfSignedCertWithRSA.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        // Setup KeyChain property to return the public key from the certificate
        RSA? publicKey = selfSignedCertWithRSA.GetRSAPublicKey();
        System.Collections.ObjectModel.ReadOnlyCollection<AsymmetricAlgorithm> keyChain = publicKey != null ? new List<AsymmetricAlgorithm> { publicKey }.AsReadOnly() : new List<AsymmetricAlgorithm>().AsReadOnly();
        mockedSignerKeyProvider.Setup(x => x.KeyChain).Returns(keyChain);

        return mockedSignerKeyProvider.Object;
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Class for testing methods of <see cref="X509Certificate2CoseSigningKeyProvider"/>
/// </summary>
public class X509Certificate2SigningKeyProviderTests
{
    /// <summary>
    /// Setup Method
    /// </summary>
    [SetUp]
    public void Setup() { }

    /// <summary>
    /// Testing Constructors Happy Path
    /// </summary>
    [Test]
    public void TestConstructorsSuccess()
    {
        // arrange
        Mock<ICertificateChainBuilder> testChainBuilder = new(MockBehavior.Strict);
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();

        List<Action> constructorTests =
        [
            new Action(() => _= new X509Certificate2CoseSigningKeyProvider(testChainBuilder.Object, testCert)),
            new Action(() => _= new X509Certificate2CoseSigningKeyProvider(testCert)),
            new Action(() => _= new X509Certificate2CoseSigningKeyProvider(testCert, HashAlgorithmName.SHA256)),
            new Action(() => _= new X509Certificate2CoseSigningKeyProvider(testCert, HashAlgorithmName.SHA512)),
        ];

        // test validate
        foreach (Action test in constructorTests)
        {
            // Actions should not throw.
            test();
        }
    }

    /// <summary>
    /// Testing Exception Path for Constructors
    /// </summary>
    [Test]
    public void TestConstructorsFailure()
    {
        // arrange
        Mock<ICertificateChainBuilder> testChainBuilder = new();

        // assert
        Assert.Throws<ArgumentNullException>(() => new X509Certificate2CoseSigningKeyProvider(testChainBuilder.Object, null));
        Assert.Throws<ArgumentNullException>(() => new X509Certificate2CoseSigningKeyProvider(null, HashAlgorithmName.SHA512));
    }

    /// <summary>
    /// Testing methods for getting signing key
    /// </summary>
    [Test]
    public void GetKeyProvidersShouldReturnProperProviders()
    {
        // arrange
        X509Certificate2 testCertRsa = TestCertificateUtils.CreateCertificate();
        X509Certificate2 testCertEcc = TestCertificateUtils.CreateCertificate(useEcc: true);

        // test
        X509Certificate2CoseSigningKeyProvider testObjRsa = new(testCertRsa);
        X509Certificate2CoseSigningKeyProvider testObjEcc = new(testCertEcc);

        // validate
        testObjEcc.GetECDsaKey().Should().NotBeNull();
        testObjEcc.GetRSAKey().Should().BeNull();

        testObjRsa.GetECDsaKey().Should().BeNull();
        testObjRsa.GetRSAKey().Should().NotBeNull();
    }

    /// <summary>
    /// Testing GetSigningCertificate method
    /// </summary>
    [Test]
    public void GetSigningCertificateShouldReturnCertificate()
    {
        // setup
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        TestX509Certificate2SigningKeyProvider testObj = new(testCert);

        // test and verify
        testObj.TestGetSigningCertificate().Should().NotBeNull();
        testObj.TestGetSigningCertificate().Should().Be(testCert);
    }

    /// <summary>
    /// Testing GetCertificateChain method with custom sort order
    /// </summary>
    [Test]
    public void GetCertificateChainShouldReturnProperSortOrder()
    {
        // setup
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        mockBuilder.Setup(m => m.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(m => m.ChainElements).Returns([.. testChain]);
        TestX509Certificate2SigningKeyProvider testObj = new(mockBuilder.Object, testChain.Last());

        // test
        IEnumerable<X509Certificate2> result = testObj.TestGetCertificateChain(X509ChainSortOrder.RootFirst);

        // validate
        result.Should().NotBeNull();
        result.Count().Should().Be(3);
        result.First().Should().Be(testChain[0]);
        result.ElementAt(1).Should().Be(testChain[1]);
        result.Last().Should().Be(testChain[2]);

        // test 2
        result = testObj.TestGetCertificateChain(X509ChainSortOrder.LeafFirst);

        // validate2
        result.Should().NotBeNull();
        result.Count().Should().Be(3);
        result.First().Should().Be(testChain[2]);
        result.ElementAt(1).Should().Be(testChain[1]);
        result.Last().Should().Be(testChain[0]);
    }

    /// <summary>
    /// Testing exception path for GetCertificateChain
    /// </summary>
    [Test]
    public void GetCertificateChainShouldReturnException()
    {
        // Setup
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509ChainPolicy policy = new();
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        mockBuilder.Setup(m => m.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockBuilder.Setup(m => m.ChainElements).Returns([.. testChain]);
        mockBuilder.Setup(m => m.ChainPolicy).Returns(policy);
        mockBuilder.Setup(m => m.ChainStatus).Returns([new X509ChainStatus()]);
        TestX509Certificate2SigningKeyProvider testObj = new(mockBuilder.Object, testChain.Last());

        // Test
        CoseSign1CertificateException? exceptionText = Assert.Throws<CoseSign1CertificateException>(() => testObj.TestGetCertificateChain(X509ChainSortOrder.RootFirst));

        // Validate
        exceptionText.Message.Should().MatchRegex(":Build is not successful for the provided SigningCertificate:");
    }

    /// <summary>
    /// Testing KeyChain property with self-signed certificate
    /// </summary>
    [Test]
    public void KeyChainShouldReturnSingleKeyForSelfSignedCert()
    {
        // Setup
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        X509Certificate2CoseSigningKeyProvider testObj = new(testCert);

        // Test
        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.KeyChain;

        // Validate
        keyChain.Should().NotBeNull();
        keyChain.Count.Should().Be(1);
        keyChain[0].Should().BeAssignableTo<RSA>();
    }

    /// <summary>
    /// Testing KeyChain property with certificate chain
    /// </summary>
    [Test]
    public void KeyChainShouldReturnAllKeysInChain()
    {
        // Setup
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        Mock<ICertificateChainBuilder> testChainBuilder = new();
        testChainBuilder.Setup(x => x.ChainElements).Returns(new List<X509Certificate2>(testChain));
        testChainBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);

        X509Certificate2CoseSigningKeyProvider testObj = new(testChainBuilder.Object, testChain[2]); // Use leaf certificate

        // Test
        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.KeyChain;

        // Validate
        keyChain.Should().NotBeNull();
        keyChain.Count.Should().Be(testChain.Count);
        
        // All keys should be RSA since test chain uses RSA certificates
        foreach (AsymmetricAlgorithm key in keyChain)
        {
            key.Should().BeAssignableTo<RSA>();
        }
    }

    /// <summary>
    /// Testing KeyChain property with ECC certificate
    /// </summary>
    [Test]
    public void KeyChainShouldReturnEccKeyForEccCert()
    {
        // Setup
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate(useEcc: true);
        X509Certificate2CoseSigningKeyProvider testObj = new(testCert);

        // Test
        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.KeyChain;

        // Validate
        keyChain.Should().NotBeNull();
        keyChain.Count.Should().Be(1);
        keyChain[0].Should().BeAssignableTo<ECDsa>();
    }

    /// <summary>
    /// Testing KeyChain property when chain building fails
    /// </summary>
    [Test]
    public void KeyChainShouldReturnEmptyListWhenChainBuildingFails()
    {
        // Setup
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        mockBuilder.Setup(m => m.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockBuilder.Setup(m => m.ChainElements).Returns([.. testChain]);
        mockBuilder.Setup(m => m.ChainPolicy).Returns(new X509ChainPolicy());
        mockBuilder.Setup(m => m.ChainStatus).Returns([new X509ChainStatus()]);
        
        X509Certificate2CoseSigningKeyProvider testObj = new(mockBuilder.Object, testChain.Last());

        // Test - KeyChain should handle the exception gracefully
        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.KeyChain;

        // Validate
        keyChain.Should().NotBeNull();
        keyChain.Should().BeEmpty();
    }

    /// <summary>
    /// Testing that KeyChain matches GetRSAKey result for RSA certificates
    /// </summary>
    [Test]
    public void KeyChainFirstElementShouldMatchGetRSAKeyForRsaCert()
    {
        // Setup
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        X509Certificate2CoseSigningKeyProvider testObj = new(testCert);

        // Test
        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.KeyChain;
        RSA? rsaKey = testObj.GetRSAKey(publicKey: true);

        // Validate
        keyChain.Should().NotBeNull();
        keyChain.Count.Should().Be(1);
        rsaKey.Should().NotBeNull();
        keyChain[0].Should().BeAssignableTo<RSA>();

        // Both should represent the same public key
        RSA chainRsaKey = (RSA)keyChain[0];
        chainRsaKey.KeySize.Should().Be(rsaKey!.KeySize);
    }

    /// <summary>
    /// Testing that KeyChain matches GetECDsaKey result for ECC certificates
    /// </summary>
    [Test]
    public void KeyChainFirstElementShouldMatchGetECDsaKeyForEccCert()
    {
        // Setup
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate(useEcc: true);
        X509Certificate2CoseSigningKeyProvider testObj = new(testCert);

        // Test
        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.KeyChain;
        ECDsa? ecdsaKey = testObj.GetECDsaKey(publicKey: true);

        // Validate
        keyChain.Should().NotBeNull();
        keyChain.Count.Should().Be(1);
        ecdsaKey.Should().NotBeNull();
        keyChain[0].Should().BeAssignableTo<ECDsa>();

        // Both should represent the same public key
        ECDsa chainEcdsaKey = (ECDsa)keyChain[0];
        chainEcdsaKey.KeySize.Should().Be(ecdsaKey!.KeySize);
    }
}
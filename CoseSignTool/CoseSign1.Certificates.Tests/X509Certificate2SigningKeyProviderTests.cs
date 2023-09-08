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
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate(nameof(TestConstructorsSuccess));

        List<Action> constructorTests = new()
        {
            new Action(() => new X509Certificate2CoseSigningKeyProvider(testChainBuilder.Object, testCert)),
            new Action(() => new X509Certificate2CoseSigningKeyProvider(testCert)),
            new Action(() => new X509Certificate2CoseSigningKeyProvider(testCert, HashAlgorithmName.SHA256)),
            new Action(() => new X509Certificate2CoseSigningKeyProvider(testCert, HashAlgorithmName.SHA512)),
            new Action(() => new X509Certificate2CoseSigningKeyProvider(testCert, HashAlgorithmName.SHA1)),
        };

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
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate(nameof(TestConstructorsFailure));


        List<Action> constructorTests = new()
        {
            new Action(() => new X509Certificate2CoseSigningKeyProvider(testChainBuilder.Object, null)),
            new Action(() => new X509Certificate2CoseSigningKeyProvider(null, HashAlgorithmName.SHA512)),
        };

        // test validate
        foreach (Action test in constructorTests)
        {
            // Actions should not throw.
            Assert.Throws<ArgumentNullException>(() => test());
        }
    }

    /// <summary>
    /// Testing methods for getting signing key
    /// </summary>
    [Test]
    public void GetKeyProvidersShouldReturnProperProviders()
    {
        // arrange
        X509Certificate2 testCertRsa = TestCertificateUtils.CreateCertificate(nameof(GetKeyProvidersShouldReturnProperProviders));
        X509Certificate2 testCertEcc = TestCertificateUtils.CreateCertificate(nameof(GetKeyProvidersShouldReturnProperProviders), useEcc: true);

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
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate(nameof(GetSigningCertificateShouldReturnCertificate));
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
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(nameof(GetCertificateChainShouldReturnProperSortOrder));
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        mockBuilder.Setup(m => m.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(m => m.ChainElements).Returns(testChain.ToList());
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
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(nameof(GetCertificateChainShouldReturnException));
        X509ChainPolicy policy = new();
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        mockBuilder.Setup(m => m.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockBuilder.Setup(m => m.ChainElements).Returns(testChain.ToList());
        mockBuilder.Setup(m => m.ChainPolicy).Returns(policy);
        mockBuilder.Setup(m => m.ChainStatus).Returns(new X509ChainStatus[] { new X509ChainStatus() });
        TestX509Certificate2SigningKeyProvider testObj = new(mockBuilder.Object, testChain.Last());

        // Test
        var exceptionText = Assert.Throws<CoseSign1CertificateException>(() => testObj.TestGetCertificateChain(X509ChainSortOrder.RootFirst));

        // Validate
        exceptionText.Message.Should().MatchRegex(":Build is not successful for the provided SigningCertificate:");
    }
}
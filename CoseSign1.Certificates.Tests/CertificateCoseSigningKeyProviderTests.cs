// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Class for Testing Methods Of <see cref="CertificateCoseSigningKeyProvider"/>
/// </summary>
public class CertificateCoseSigningKeyProviderTests
{
    /// <summary>
    /// Tests Constructor 
    /// </summary>
    [Test]
    public void TestConstructorsSuccess()
    {
        List<Action> constructorTests =
        [
            new Action(() => _= new TestCertificateCoseSigningKeyProvider()),
            new Action(() => _= new TestCertificateCoseSigningKeyProvider(HashAlgorithmName.SHA512))
        ];

        // test validate
        foreach (Action test in constructorTests)
        {
            // Actions should not throw.
            test();
        }
    }

    /// <summary>
    /// Testing HashAlgorithm Set to Default
    /// </summary>
    [Test]
    public void TestDefaultHashAlgorithm()
    {
        var testObj = new TestCertificateCoseSigningKeyProvider();
        testObj.HashAlgorithm.Should().Be(HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Tests Setting Custom HashAlgorithm
    /// </summary>
    [Test]
    public void TestSetCustomHashAlgorithm()
    {
        var testObj = new TestCertificateCoseSigningKeyProvider(HashAlgorithmName.SHA512);
        testObj.HashAlgorithm.Should().Be(HashAlgorithmName.SHA512);
    }

    // TODO: This class might not need to mock
    /// <summary>
    /// Testing GetRsaKey and IsRSA When RSA key is provided
    /// </summary>
    [Test]
    public void TestGetRSAKeyMethodWhenRSAExists()
    {
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<RSA>("ProvideRSAKey", ItExpr.IsAny<bool>())
            .Returns(testCert?.GetRSAPrivateKey() ?? throw new ArgumentNullException())
            .Verifiable();
        testObj.Object.GetRSAKey();

        testObj.Protected().Verify("ProvideRSAKey", Times.Once(), ItExpr.IsAny<bool>());
        testObj.Object.IsRSA.Should().BeTrue();
    }

    /// <summary>
    /// Testing GetRSAKey and IsRSA When RSA key is null
    /// </summary>
    [Test]
    public void TestWhenRSAIsNull()
    {
        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<RSA>("ProvideRSAKey", ItExpr.IsAny<bool>()).Returns<RSA>(null).Verifiable();
        testObj.Object.GetRSAKey();
        testObj.Object.IsRSA.Should().BeFalse();
    }

    /// <summary>
    /// Testing GetECDsaKey
    /// </summary>
    [Test]
    public void TestGetECDsaSigningKeyMethod()
    {
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate(useEcc: true);
        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<ECDsa>("ProvideECDsaKey", ItExpr.IsAny<bool>())
            .Returns(testCert?.GetECDsaPrivateKey() ?? throw new ArgumentNullException())
            .Verifiable();
        testObj.Object.GetECDsaKey();

        testObj.Protected().Verify("ProvideECDsaKey", Times.Once(), ItExpr.IsAny<bool>());
    }

    /// <summary>
    /// Testing Happy Path for GetProtectedHeaders
    /// </summary>
    [Test]
    public void TestGetProtectedHeadersSuccess()
    {
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        X509Certificate2 testCert = testChain[0];

        Mock <CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(testCert).Verifiable();
        testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", X509ChainSortOrder.LeafFirst)
               .Returns(testChain).Verifiable();

        var response = testObj.Object.GetProtectedHeaders();

        testObj.Protected().Verify("GetSigningCertificate", Times.AtLeastOnce());
        testObj.Protected().Verify("GetCertificateChain", Times.Once(), X509ChainSortOrder.LeafFirst);
        response.Should().NotBeNull();
        response.Count.Should().Be(2);
    }

    /// <summary>
    /// Testing Exception Path for GetProtectedHeaders
    /// </summary>
    [Test]
    public void TestGetProtectedHeadersException()
    {
        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns<X509Certificate2>(null);
        testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", X509ChainSortOrder.LeafFirst)
               .Returns<IEnumerable<X509Certificate2>>(null);

        var exceptionText = Assert.Throws<CoseSign1CertificateException>(() => testObj.Object.GetProtectedHeaders());

        exceptionText.Message.Should().Be("Signing Certificate Is Not Provided");
    }

    /// <summary>
    /// Testing GetUnProtectedHeaders
    /// </summary>
    [Test]
    public void TestGetUnProtectedHeaders()
    {
        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<CoseHeaderMap>("GetUnProtectedHeadersImplementation").Returns<CoseHeaderMap>(null);

        var response = testObj.Object.GetUnProtectedHeaders();

        testObj.Protected().Verify("GetUnProtectedHeadersImplementation", Times.AtLeastOnce());

        response.Should().BeNull();
    }

    /// <summary>
    /// Testing GetUnProtectedHeadersImplementation
    /// </summary>
    [Test]
    public void TestGetUnProtectedHeadersImplementation()
    {
        TestCertificateCoseSigningKeyProvider testMockObj = new();

        testMockObj.TestGetUnProtectedHeadersImplementation().Should().BeNull();
    }

}
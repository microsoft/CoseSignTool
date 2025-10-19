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


    // TODO: Do we need this?
    ///// <summary>
    ///// Testing HashAlgorithm Set to Default
    ///// </summary>
    //[Test]
    //public void TestDefaultHashAlgorithm()
    //{
    //    TestCertificateCoseSigningKeyProvider testObj = new TestCertificateCoseSigningKeyProvider();
    //    testObj.HashAlgorithm.Should().Be(HashAlgorithmName.SHA256);
    //}

    ///// <summary>
    ///// Tests Setting Custom HashAlgorithm
    ///// </summary>
    //[Test]
    //public void TestSetCustomHashAlgorithm()
    //{
    //    TestCertificateCoseSigningKeyProvider testObj = new TestCertificateCoseSigningKeyProvider(HashAlgorithmName.SHA512);
    //    testObj.HashAlgorithm.Should().Be(HashAlgorithmName.SHA512);
    //}

    // TODO: This class might not need to mock
    /// <summary>
    /// Testing GetRsaKey and IsRSA When RSA key is provided
    /// </summary>
    //[Test]
    //public void TestGetRSAKeyMethodWhenRSAExists()
    //{
    //    X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
    //    Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
    //    {
    //        CallBase = true
    //    };

    //    testObj.Protected().Setup<RSA>("ProvideRSAKey", ItExpr.IsAny<bool>())
    //        .Returns(testCert?.GetRSAPrivateKey() ?? throw new ArgumentNullException())
    //        .Verifiable();
    //    testObj.Object.GetRSAKey();

    //    testObj.Protected().Verify("ProvideRSAKey", Times.Once(), ItExpr.IsAny<bool>());
    //    testObj.Object.IsRSA.Should().BeTrue();
    //}

    ///// <summary>
    ///// Testing GetRSAKey and IsRSA When RSA key is null
    ///// </summary>
    //[Test]
    //public void TestWhenRSAIsNull()
    //{
    //    Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
    //    {
    //        CallBase = true
    //    };

    //    testObj.Protected().Setup<RSA>("ProvideRSAKey", ItExpr.IsAny<bool>()).Returns<RSA>(null).Verifiable();
    //    testObj.Object.GetRSAKey();
    //    testObj.Object.IsRSA.Should().BeFalse();
    //}

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

        CoseHeaderMap response = testObj.Object.GetProtectedHeaders();

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

        CoseSign1CertificateException? exceptionText = Assert.Throws<CoseSign1CertificateException>(() => testObj.Object.GetProtectedHeaders());

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

        CoseHeaderMap? response = testObj.Object.GetUnProtectedHeaders();

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

    ///// <summary>
    ///// Testing KeyChain property returns empty list when GetCertificateChain throws
    ///// </summary>
    //[Test]
    //public void TestKeyChainWhenCertificateChainThrows()
    //{
    //    TestCertificateCoseSigningKeyProvider testObj = new();

    //    // Since TestCertificateCoseSigningKeyProvider.GetCertificateChain throws NotImplementedException,
    //    // KeyChain should return empty list
    //    IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.KeyChain;

    //    keyChain.Should().NotBeNull();
    //    keyChain.Should().BeEmpty();
    //}

    /// <summary>
    /// Testing KeyChain property returns keys from certificate chain
    /// </summary>
    //[Test]
    //public void TestKeyChainWithValidCertificateChain()
    //{
    //    X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(leafFirst: true);
    //    X509Certificate2 testCert = testChain[0];

    //    Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
    //    {
    //        CallBase = true
    //    };

    //    testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(testCert);
    //    testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", ItExpr.IsAny<X509ChainSortOrder>())
    //           .Returns(testChain.Cast<X509Certificate2>());

    //    // Setup KeyChain property to avoid strict mock issues
    //    List<AsymmetricAlgorithm?> expectedKeys = testChain.Cast<X509Certificate2>()
    //        .Select(cert => cert.GetRSAPublicKey() as AsymmetricAlgorithm ?? cert.GetECDsaPublicKey())
    //        .Where(key => key != null)
    //        .ToList();
    //    testObj.SetupGet(x => x.KeyChain).Returns(expectedKeys!);

    //    IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.Object.KeyChain;

    //    keyChain.Should().NotBeNull();
    //    keyChain.Count.Should().Be(testChain.Count);
        
    //    // Verify that each key in the chain corresponds to a certificate
    //    for (int i = 0; i < testChain.Count; i++)
    //    {
    //        X509Certificate2 cert = testChain[i];
    //        AsymmetricAlgorithm? expectedKey = cert.GetRSAPublicKey() as AsymmetricAlgorithm ?? cert.GetECDsaPublicKey();
            
    //        keyChain[i].Should().NotBeNull();
    //        // Verify key type matches
    //        if (expectedKey is RSA)
    //        {
    //            keyChain[i].Should().BeAssignableTo<RSA>();
    //        }
    //        else if (expectedKey is ECDsa)
    //        {
    //            keyChain[i].Should().BeAssignableTo<ECDsa>();
    //        }
    //    }
    //}

    /// <summary>
    /// Testing KeyChain property with ECC certificates
    /// </summary>
    //[Test]
    //public void TestKeyChainWithEccCertificates()
    //{
    //    // Create ECC certificates
    //    X509Certificate2 leafCert = TestCertificateUtils.CreateCertificate("TestLeaf", useEcc: true);
    //    X509Certificate2 rootCert = TestCertificateUtils.CreateCertificate("TestRoot", useEcc: true);
        
    //    Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
    //    {
    //        CallBase = true
    //    };

    //    testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(leafCert);
    //    testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", ItExpr.IsAny<X509ChainSortOrder>())
    //           .Returns(new[] { leafCert, rootCert });

    //    // Setup KeyChain property to avoid strict mock issues
    //    AsymmetricAlgorithm[] expectedKeys = new AsymmetricAlgorithm[] { leafCert.GetECDsaPublicKey()!, rootCert.GetECDsaPublicKey()! };
    //    testObj.SetupGet(x => x.KeyChain).Returns(expectedKeys);

    //    IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.Object.KeyChain;

    //    keyChain.Should().NotBeNull();
    //    keyChain.Count.Should().Be(2);
    //    keyChain[0].Should().BeAssignableTo<ECDsa>();
    //    keyChain[1].Should().BeAssignableTo<ECDsa>();
    //}

    ///// <summary>
    ///// Testing KeyChain property with mixed RSA and ECC certificates
    ///// </summary>
    //[Test]
    //public void TestKeyChainWithMixedKeyTypes()
    //{
    //    // Create mixed certificate types
    //    X509Certificate2 rsaCert = TestCertificateUtils.CreateCertificate("TestRSA", useEcc: false);
    //    X509Certificate2 eccCert = TestCertificateUtils.CreateCertificate("TestECC", useEcc: true);
        
    //    Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
    //    {
    //        CallBase = true
    //    };

    //    testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(rsaCert);
    //    testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", ItExpr.IsAny<X509ChainSortOrder>())
    //           .Returns(new[] { rsaCert, eccCert });

    //    // Setup KeyChain property to avoid strict mock issues
    //    AsymmetricAlgorithm[] expectedKeys = new AsymmetricAlgorithm[] { rsaCert.GetRSAPublicKey()!, eccCert.GetECDsaPublicKey()! };
    //    testObj.SetupGet(x => x.KeyChain).Returns(expectedKeys);

    //    IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.Object.KeyChain;

    //    keyChain.Should().NotBeNull();
    //    keyChain.Count.Should().Be(2);
    //    keyChain[0].Should().BeAssignableTo<RSA>();
    //    keyChain[1].Should().BeAssignableTo<ECDsa>();
    //}

    ///// <summary>
    ///// Testing KeyChain property when certificate has no extractable public key
    ///// </summary>
    //[Test]
    //public void TestKeyChainWithCertificateWithoutExtractableKey()
    //{
    //    // Create a test class that returns empty certificate chain
    //    Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
    //    {
    //        CallBase = true
    //    };

    //    // Mock a certificate that doesn't have extractable keys by returning empty chain
    //    testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(TestCertificateUtils.CreateCertificate());
    //    testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", ItExpr.IsAny<X509ChainSortOrder>())
    //           .Returns(new X509Certificate2[0]); // Empty chain

    //    // Setup KeyChain property to return empty list for empty chain
    //    testObj.SetupGet(x => x.KeyChain).Returns(new List<AsymmetricAlgorithm>());

    //    IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.Object.KeyChain;

    //    keyChain.Should().NotBeNull();
    //    keyChain.Should().BeEmpty(); // No extractable keys from empty chain
    //}

    /// <summary>
    /// Testing GetKeyChain protected method directly
    /// </summary>
    //[Test]
    //public void TestGetKeyChainProtectedMethod()
    //{
    //    TestCertificateCoseSigningKeyProvider testObj = new();

    //    // This should return empty list since GetCertificateChain throws
    //    IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.TestGetKeyChain();

    //    keyChain.Should().NotBeNull();
    //    keyChain.Should().BeEmpty();
    //}

}
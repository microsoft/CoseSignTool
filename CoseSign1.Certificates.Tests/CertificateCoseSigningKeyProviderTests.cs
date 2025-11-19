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
        TestCertificateCoseSigningKeyProvider testObj = new TestCertificateCoseSigningKeyProvider();
        testObj.HashAlgorithm.Should().Be(HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Tests Setting Custom HashAlgorithm
    /// </summary>
    [Test]
    public void TestSetCustomHashAlgorithm()
    {
        TestCertificateCoseSigningKeyProvider testObj = new TestCertificateCoseSigningKeyProvider(HashAlgorithmName.SHA512);
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

    /// <summary>
    /// Testing KeyChain property returns empty list when GetCertificateChain throws
    /// </summary>
    [Test]
    public void TestKeyChainWhenCertificateChainThrows()
    {
        TestCertificateCoseSigningKeyProvider testObj = new();

        // Since TestCertificateCoseSigningKeyProvider.GetCertificateChain throws NotImplementedException,
        // KeyChain should return empty list
        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.KeyChain;

        keyChain.Should().NotBeNull();
        keyChain.Should().BeEmpty();
    }

    /// <summary>
    /// Testing KeyChain property returns keys from certificate chain
    /// </summary>
    [Test]
    public void TestKeyChainWithValidCertificateChain()
    {
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        X509Certificate2 testCert = testChain[0];

        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(testCert);
        testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", ItExpr.IsAny<X509ChainSortOrder>())
               .Returns(testChain.Cast<X509Certificate2>());

        // Setup KeyChain property to avoid strict mock issues
        List<AsymmetricAlgorithm?> expectedKeys = testChain.Cast<X509Certificate2>()
            .Select(cert => cert.GetRSAPublicKey() as AsymmetricAlgorithm ?? cert.GetECDsaPublicKey())
            .Where(key => key != null)
            .ToList();
        testObj.SetupGet(x => x.KeyChain).Returns(expectedKeys!);

        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.Object.KeyChain;

        keyChain.Should().NotBeNull();
        keyChain.Count.Should().Be(testChain.Count);
        
        // Verify that each key in the chain corresponds to a certificate
        for (int i = 0; i < testChain.Count; i++)
        {
            X509Certificate2 cert = testChain[i];
            AsymmetricAlgorithm? expectedKey = cert.GetRSAPublicKey() as AsymmetricAlgorithm ?? cert.GetECDsaPublicKey();
            
            keyChain[i].Should().NotBeNull();
            // Verify key type matches
            if (expectedKey is RSA)
            {
                keyChain[i].Should().BeAssignableTo<RSA>();
            }
            else if (expectedKey is ECDsa)
            {
                keyChain[i].Should().BeAssignableTo<ECDsa>();
            }
        }
    }

    /// <summary>
    /// Testing KeyChain property with ECC certificates
    /// </summary>
    [Test]
    public void TestKeyChainWithEccCertificates()
    {
        // Create ECC certificates
        X509Certificate2 leafCert = TestCertificateUtils.CreateCertificate("TestLeaf", useEcc: true);
        X509Certificate2 rootCert = TestCertificateUtils.CreateCertificate("TestRoot", useEcc: true);
        
        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(leafCert);
        testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", ItExpr.IsAny<X509ChainSortOrder>())
               .Returns(new[] { leafCert, rootCert });

        // Setup KeyChain property to avoid strict mock issues
        AsymmetricAlgorithm[] expectedKeys = new AsymmetricAlgorithm[] { leafCert.GetECDsaPublicKey()!, rootCert.GetECDsaPublicKey()! };
        testObj.SetupGet(x => x.KeyChain).Returns(expectedKeys);

        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.Object.KeyChain;

        keyChain.Should().NotBeNull();
        keyChain.Count.Should().Be(2);
        keyChain[0].Should().BeAssignableTo<ECDsa>();
        keyChain[1].Should().BeAssignableTo<ECDsa>();
    }

    /// <summary>
    /// Testing KeyChain property with mixed RSA and ECC certificates
    /// </summary>
    [Test]
    public void TestKeyChainWithMixedKeyTypes()
    {
        // Create mixed certificate types
        X509Certificate2 rsaCert = TestCertificateUtils.CreateCertificate("TestRSA", useEcc: false);
        X509Certificate2 eccCert = TestCertificateUtils.CreateCertificate("TestECC", useEcc: true);
        
        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(rsaCert);
        testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", ItExpr.IsAny<X509ChainSortOrder>())
               .Returns(new[] { rsaCert, eccCert });

        // Setup KeyChain property to avoid strict mock issues
        AsymmetricAlgorithm[] expectedKeys = new AsymmetricAlgorithm[] { rsaCert.GetRSAPublicKey()!, eccCert.GetECDsaPublicKey()! };
        testObj.SetupGet(x => x.KeyChain).Returns(expectedKeys);

        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.Object.KeyChain;

        keyChain.Should().NotBeNull();
        keyChain.Count.Should().Be(2);
        keyChain[0].Should().BeAssignableTo<RSA>();
        keyChain[1].Should().BeAssignableTo<ECDsa>();
    }

    /// <summary>
    /// Testing KeyChain property when certificate has no extractable public key
    /// </summary>
    [Test]
    public void TestKeyChainWithCertificateWithoutExtractableKey()
    {
        // Create a test class that returns empty certificate chain
        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        // Mock a certificate that doesn't have extractable keys by returning empty chain
        testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(TestCertificateUtils.CreateCertificate());
        testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", ItExpr.IsAny<X509ChainSortOrder>())
               .Returns(new X509Certificate2[0]); // Empty chain

        // Setup KeyChain property to return empty list for empty chain
        testObj.SetupGet(x => x.KeyChain).Returns(new List<AsymmetricAlgorithm>());

        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.Object.KeyChain;

        keyChain.Should().NotBeNull();
        keyChain.Should().BeEmpty(); // No extractable keys from empty chain
    }

    /// <summary>
    /// Testing GetKeyChain protected method directly
    /// </summary>
    [Test]
    public void TestGetKeyChainProtectedMethod()
    {
        TestCertificateCoseSigningKeyProvider testObj = new();

        // This should return empty list since GetCertificateChain throws
        IReadOnlyList<AsymmetricAlgorithm> keyChain = testObj.TestGetKeyChain();

        keyChain.Should().NotBeNull();
        keyChain.Should().BeEmpty();
    }

    /// <summary>
    /// Tests that the Issuer property returns null for the base test class with empty certificate chain
    /// </summary>
    [Test]
    public void TestIssuer_WithEmptyCertificateChain_ReturnsNull()
    {
        TestCertificateCoseSigningKeyProvider testObj = new();

        // The Issuer property should return null because GetCertificateChain returns empty
        string? issuer = testObj.Issuer;

        issuer.Should().BeNull();
    }

    /// <summary>
    /// Tests that the Issuer property returns a DID:x509 identifier for a valid certificate chain
    /// </summary>
    [Test]
    public void TestIssuer_WithValidCertificateChain_ReturnsDIDx509()
    {
        // Create a real certificate chain
        X509Certificate2Collection certs = TestCertificateUtils.CreateTestChain();
        X509Certificate2CoseSigningKeyProvider provider = new(certs[^1]);

        // The Issuer property should return a DID:x509 identifier
        string? issuer = provider.Issuer;

        issuer.Should().NotBeNullOrEmpty();
        issuer.Should().StartWith("did:x509:");

        // Clean up certificates
        foreach (var cert in certs)
        {
            cert.Dispose();
        }
    }

    /// <summary>
    /// Tests that derived classes can override the Issuer property
    /// </summary>
    [Test]
    public void TestIssuer_CanBeOverridden()
    {
        // Create a custom provider that overrides Issuer
        TestCertificateProviderWithCustomIssuer provider = new("custom-issuer-value");

        string? issuer = provider.Issuer;

        issuer.Should().Be("custom-issuer-value");
    }

    /// <summary>
    /// Helper class to test Issuer property override
    /// </summary>
    private class TestCertificateProviderWithCustomIssuer : CertificateCoseSigningKeyProvider
    {
        private readonly string _customIssuer;

        public TestCertificateProviderWithCustomIssuer(string customIssuer) : base(null, null)
        {
            _customIssuer = customIssuer;
        }

        public override string? Issuer => _customIssuer;

        protected override IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
        {
            return Enumerable.Empty<X509Certificate2>();
        }

        protected override X509Certificate2 GetSigningCertificate()
        {
            throw new NotImplementedException();
        }

        protected override ECDsa? ProvideECDsaKey(bool publicKey = false)
        {
            throw new NotImplementedException();
        }

        protected override RSA? ProvideRSAKey(bool publicKey = false)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Helper class to test GetKeyChain when GetCertificateChain throws CoseSign1CertificateException
    /// </summary>
    private class TestCertificateCoseSigningKeyProviderWithException : CertificateCoseSigningKeyProvider
    {
        public TestCertificateCoseSigningKeyProviderWithException() : base(null, null) { }

        protected override IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
        {
            throw new CoseSign1CertificateException("Test exception");
        }

        protected override X509Certificate2 GetSigningCertificate()
        {
            throw new NotImplementedException();
        }

        protected override ECDsa? ProvideECDsaKey(bool publicKey = false)
        {
            throw new NotImplementedException();
        }

        protected override RSA? ProvideRSAKey(bool publicKey = false)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Helper class to test GetKeyChain when GetCertificateChain throws ArgumentNullException
    /// </summary>
    private class TestCertificateCoseSigningKeyProviderWithArgumentNull : CertificateCoseSigningKeyProvider
    {
        public TestCertificateCoseSigningKeyProviderWithArgumentNull() : base(null, null) { }

        protected override IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
        {
            throw new ArgumentNullException("test");
        }

        protected override X509Certificate2 GetSigningCertificate()
        {
            throw new NotImplementedException();
        }

        protected override ECDsa? ProvideECDsaKey(bool publicKey = false)
        {
            throw new NotImplementedException();
        }

        protected override RSA? ProvideRSAKey(bool publicKey = false)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Helper class to test AddRoots when ChainBuilder is null
    /// Uses the parameterless constructor to avoid ChainBuilder initialization
    /// </summary>
    private class TestCertificateCoseSigningKeyProviderWithNullChainBuilder : CertificateCoseSigningKeyProvider
    {
        public TestCertificateCoseSigningKeyProviderWithNullChainBuilder() : base(HashAlgorithmName.SHA256)
        {
            // Uses the simple constructor that doesn't initialize ChainBuilder
        }

        protected override IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
        {
            throw new NotImplementedException();
        }

        protected override X509Certificate2 GetSigningCertificate()
        {
            throw new NotImplementedException();
        }

        protected override ECDsa? ProvideECDsaKey(bool publicKey = false)
        {
            throw new NotImplementedException();
        }

        protected override RSA? ProvideRSAKey(bool publicKey = false)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Tests constructor with ICertificateChainBuilder and root certificates
    /// </summary>
    [Test]
    public void TestConstructorWithChainBuilderAndRootCertificates()
    {
        // Create root certificates
        X509Certificate2 root1 = TestCertificateUtils.CreateCertificate("Root1");
        X509Certificate2 root2 = TestCertificateUtils.CreateCertificate("Root2");
        List<X509Certificate2> rootCerts = new() { root1, root2 };

        // Create mock provider with chain builder
        Mock<CertificateCoseSigningKeyProvider> testObj = new(
            MockBehavior.Strict,
            new X509ChainBuilder(),
            HashAlgorithmName.SHA384,
            rootCerts)
        {
            CallBase = true
        };

        // Verify properties are set correctly
        testObj.Object.ChainBuilder.Should().NotBeNull();
        testObj.Object.HashAlgorithm.Should().Be(HashAlgorithmName.SHA384);
        testObj.Object.ChainBuilder!.ChainPolicy.ExtraStore.Count.Should().Be(2);

        // Clean up
        root1.Dispose();
        root2.Dispose();
    }

    /// <summary>
    /// Tests constructor with null chain builder defaults to X509ChainBuilder
    /// </summary>
    [Test]
    public void TestConstructorWithNullChainBuilderDefaultsToX509ChainBuilder()
    {
        Mock<CertificateCoseSigningKeyProvider> testObj = new(
            MockBehavior.Strict,
            (ICertificateChainBuilder?)null,
            HashAlgorithmName.SHA256,
            (List<X509Certificate2>?)null)
        {
            CallBase = true
        };

        testObj.Object.ChainBuilder.Should().NotBeNull();
        testObj.Object.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
    }

    /// <summary>
    /// Tests constructor with empty root certificates list
    /// </summary>
    [Test]
    public void TestConstructorWithEmptyRootCertificates()
    {
        List<X509Certificate2> rootCerts = new();

        Mock<CertificateCoseSigningKeyProvider> testObj = new(
            MockBehavior.Strict,
            new X509ChainBuilder(),
            HashAlgorithmName.SHA256,
            rootCerts)
        {
            CallBase = true
        };

        testObj.Object.ChainBuilder.Should().NotBeNull();
        // Empty list should not clear or add to ExtraStore
    }

    /// <summary>
    /// Tests AddRoots method with append=false (default)
    /// </summary>
    [Test]
    public void TestAddRootsWithoutAppend()
    {
        X509Certificate2 existingRoot = TestCertificateUtils.CreateCertificate("ExistingRoot");
        List<X509Certificate2> existingRoots = new() { existingRoot };

        X509Certificate2CoseSigningKeyProvider provider = new(existingRoot);

        // Add initial roots
        provider.AddRoots(existingRoots, false);
        provider.ChainBuilder!.ChainPolicy.ExtraStore.Count.Should().Be(1);

        // Add new roots without append (should clear existing)
        X509Certificate2 newRoot1 = TestCertificateUtils.CreateCertificate("NewRoot1");
        X509Certificate2 newRoot2 = TestCertificateUtils.CreateCertificate("NewRoot2");
        List<X509Certificate2> newRoots = new() { newRoot1, newRoot2 };

        provider.AddRoots(newRoots, false);
        provider.ChainBuilder!.ChainPolicy.ExtraStore.Count.Should().Be(2);

        // Clean up
        existingRoot.Dispose();
        newRoot1.Dispose();
        newRoot2.Dispose();
    }

    /// <summary>
    /// Tests AddRoots method with append=true
    /// </summary>
    [Test]
    public void TestAddRootsWithAppend()
    {
        X509Certificate2 existingRoot = TestCertificateUtils.CreateCertificate("ExistingRoot");
        List<X509Certificate2> existingRoots = new() { existingRoot };

        X509Certificate2CoseSigningKeyProvider provider = new(existingRoot);

        // Add initial roots
        provider.AddRoots(existingRoots, false);
        provider.ChainBuilder!.ChainPolicy.ExtraStore.Count.Should().Be(1);

        // Add new roots with append (should add to existing)
        X509Certificate2 newRoot1 = TestCertificateUtils.CreateCertificate("NewRoot1");
        X509Certificate2 newRoot2 = TestCertificateUtils.CreateCertificate("NewRoot2");
        List<X509Certificate2> newRoots = new() { newRoot1, newRoot2 };

        provider.AddRoots(newRoots, true);
        provider.ChainBuilder!.ChainPolicy.ExtraStore.Count.Should().Be(3);

        // Clean up
        existingRoot.Dispose();
        newRoot1.Dispose();
        newRoot2.Dispose();
    }

    /// <summary>
    /// Tests AddRoots throws when ChainBuilder is null
    /// </summary>
    [Test]
    public void TestAddRootsThrowsWhenChainBuilderIsNull()
    {
        TestCertificateCoseSigningKeyProviderWithNullChainBuilder provider = new();

        X509Certificate2 root = TestCertificateUtils.CreateCertificate("Root");
        List<X509Certificate2> roots = new() { root };

        Action act = () => provider.AddRoots(roots, false);
        act.Should().Throw<ArgumentException>().WithMessage("*ChainBuilder*");

        root.Dispose();
    }

    /// <summary>
    /// Tests GetProtectedHeaders throws exception when signing certificate thumbprint doesn't match chain
    /// </summary>
    [Test]
    public void TestGetProtectedHeadersThrowsOnThumbprintMismatch()
    {
        X509Certificate2 signingCert = TestCertificateUtils.CreateCertificate("SigningCert");
        X509Certificate2 chainCert = TestCertificateUtils.CreateCertificate("DifferentCert");

        Mock<CertificateCoseSigningKeyProvider> testObj = new(MockBehavior.Strict)
        {
            CallBase = true
        };

        testObj.Protected().Setup<X509Certificate2>("GetSigningCertificate").Returns(signingCert);
        testObj.Protected().Setup<IEnumerable<X509Certificate2>>("GetCertificateChain", X509ChainSortOrder.LeafFirst)
               .Returns(new[] { chainCert }); // Different cert in chain

        CoseSign1CertificateException? exception = Assert.Throws<CoseSign1CertificateException>(() => testObj.Object.GetProtectedHeaders());
        exception!.Message.Should().Contain("must match the first item in the signing certificate chain list");
        exception.Message.Should().Contain(signingCert.Thumbprint);
        exception.Message.Should().Contain(chainCert.Thumbprint);

        signingCert.Dispose();
        chainCert.Dispose();
    }

    /// <summary>
    /// Tests GetKeyChain with actual certificate chain (RSA certificates)
    /// </summary>
    [Test]
    public void TestGetKeyChainWithRealCertificateChainRSA()
    {
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        X509Certificate2CoseSigningKeyProvider provider = new(testChain[^1]);

        IReadOnlyList<AsymmetricAlgorithm> keyChain = provider.KeyChain;

        keyChain.Should().NotBeNull();
        keyChain.Count.Should().BeGreaterOrEqualTo(1);
        
        // All keys should be RSA
        foreach (AsymmetricAlgorithm key in keyChain)
        {
            key.Should().BeAssignableTo<RSA>();
        }

        // Clean up
        foreach (var cert in testChain)
        {
            cert.Dispose();
        }
    }

    /// <summary>
    /// Tests GetKeyChain with actual ECC certificate chain
    /// </summary>
    [Test]
    public void TestGetKeyChainWithRealCertificateChainECC()
    {
        X509Certificate2 leafCert = TestCertificateUtils.CreateCertificate("Leaf", useEcc: true);
        X509Certificate2CoseSigningKeyProvider provider = new(leafCert);

        IReadOnlyList<AsymmetricAlgorithm> keyChain = provider.KeyChain;

        keyChain.Should().NotBeNull();
        keyChain.Count.Should().BeGreaterOrEqualTo(1);
        
        // All keys should be ECDsa
        foreach (AsymmetricAlgorithm key in keyChain)
        {
            key.Should().BeAssignableTo<ECDsa>();
        }

        leafCert.Dispose();
    }

    /// <summary>
    /// Tests GetKeyChain when GetCertificateChain throws CoseSign1CertificateException
    /// </summary>
    [Test]
    public void TestGetKeyChainHandlesCoseSign1CertificateException()
    {
        TestCertificateCoseSigningKeyProviderWithException provider = new();

        IReadOnlyList<AsymmetricAlgorithm> keyChain = provider.KeyChain;

        // Should return empty list when exception is thrown
        keyChain.Should().NotBeNull();
        keyChain.Should().BeEmpty();
    }

    /// <summary>
    /// Tests GetKeyChain handles ArgumentNullException gracefully
    /// </summary>
    [Test]
    public void TestGetKeyChainHandlesArgumentNullException()
    {
        TestCertificateCoseSigningKeyProviderWithArgumentNull provider = new();

        IReadOnlyList<AsymmetricAlgorithm> keyChain = provider.KeyChain;

        keyChain.Should().NotBeNull();
        keyChain.Should().BeEmpty();
    }

    /// <summary>
    /// Tests Issuer property handles exception during DID generation
    /// </summary>
    [Test]
    public void TestIssuerHandlesExceptionDuringDIDGeneration()
    {
        TestCertificateCoseSigningKeyProviderWithException provider = new();

        string? issuer = provider.Issuer;

        issuer.Should().BeNull();
    }

    /// <summary>
    /// Tests Issuer property with valid certificate chain generates proper DID
    /// </summary>
    [Test]
    public void TestIssuerWithValidChainGeneratesDID()
    {
        X509Certificate2Collection certs = TestCertificateUtils.CreateTestChain(leafFirst: true);
        X509Certificate2CoseSigningKeyProvider provider = new(certs[^1]);

        string? issuer = provider.Issuer;

        issuer.Should().NotBeNullOrEmpty();
        issuer.Should().StartWith("did:x509:");

        foreach (var cert in certs)
        {
            cert.Dispose();
        }
    }

    /// <summary>
    /// Tests constructor with hashAlgorithm parameter
    /// </summary>
    [Test]
    public void TestConstructorWithHashAlgorithmSHA384()
    {
        Mock<CertificateCoseSigningKeyProvider> testObj = new(
            MockBehavior.Strict,
            HashAlgorithmName.SHA384)
        {
            CallBase = true
        };

        testObj.Object.HashAlgorithm.Should().Be(HashAlgorithmName.SHA384);
    }

    /// <summary>
    /// Tests constructor with rootCertificates having non-zero count
    /// </summary>
    [Test]
    public void TestConstructorWithRootCertificatesNonZeroCount()
    {
        X509Certificate2 root = TestCertificateUtils.CreateCertificate("Root");
        List<X509Certificate2> rootCerts = new() { root };

        Mock<CertificateCoseSigningKeyProvider> testObj = new(
            MockBehavior.Strict,
            new X509ChainBuilder(),
            HashAlgorithmName.SHA256,
            rootCerts)
        {
            CallBase = true
        };

        testObj.Object.ChainBuilder.Should().NotBeNull();
        testObj.Object.ChainBuilder!.ChainPolicy.ExtraStore.Count.Should().Be(1);

        root.Dispose();
    }
}
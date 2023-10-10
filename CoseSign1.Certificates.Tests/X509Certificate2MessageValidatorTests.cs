// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Test class for <see cref="X509Certificate2MessageValidator"/>
/// </summary>
public class X509Certificate2MessageValidatorTests
{
    /// <summary>
    /// Setup method
    /// </summary>
    [SetUp]
    public void Setup()
    {
    }

    private class TestX509Certificate2MessageValidator : X509Certificate2MessageValidator
    {
        public TestX509Certificate2MessageValidator(bool allowUnprotected = false) : base(allowUnprotected)
        {
        }

        protected override CoseSign1ValidationResult ValidateCertificate(X509Certificate2 signingCertificate, List<X509Certificate2>? certChain, List<X509Certificate2>? extraCertificates)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Run through some basic validator tests.
    /// </summary>
    [Test]
    public void X509Certificate2MessageValidatorCtors()
    {
        List<Tuple<Func<X509Certificate2MessageValidator>, bool>> ctorTests = new()
        {
            Tuple.Create<Func<X509Certificate2MessageValidator>,bool>(() => new TestX509Certificate2MessageValidator(), false ),
            Tuple.Create<Func<X509Certificate2MessageValidator>,bool>(() => new TestX509Certificate2MessageValidator(false), false),
            Tuple.Create<Func<X509Certificate2MessageValidator>, bool>(() => new TestX509Certificate2MessageValidator(true), true)
        };
        foreach (Tuple<Func<X509Certificate2MessageValidator>, bool> ctor in ctorTests)
        {
            X509Certificate2MessageValidator testItem = null;
            Assert.DoesNotThrow(() => testItem = ctor.Item1());
            testItem.AllowUnprotected.Should().Be(ctor.Item2);
        }
    }

    /// <summary>
    /// Run through some basic validator tests.
    /// </summary>
    [Test]
    public void X509Certificate2MessageValidatorValidates()
    {
        // setup
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(nameof(X509Certificate2MessageValidatorValidates));
        Mock<X509Certificate2MessageValidator> mockValidator = new(MockBehavior.Strict)
        {
            CallBase = true
        };
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        ICoseSign1MessageFactory factory = new CoseSign1MessageFactory();
        X509Certificate2CoseSigningKeyProvider keyProvider = new(mockBuilder.Object, testChain.Last());
        byte[] testArray = new byte[] { 1, 2, 3, 4 };
        mockBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(x => x.ChainElements).Returns(testChain.ToList());
        X509Certificate2? invokedCert = null;
        List<X509Certificate2>? invokedCertChain = null;
        List<X509Certificate2>? invokedExtraCerts = null;
        List<CoseSign1ValidationResult>? validationResults = null;

        mockValidator.Setup(m => m.TryValidate(It.IsAny<CoseSign1Message>(), out validationResults)).CallBase();
        mockValidator.Setup(m => m.Validate(It.IsAny<CoseSign1Message>())).CallBase();
        mockValidator.Setup(m => m.NextElement).CallBase();
        mockValidator.Protected()
            .Setup<CoseSign1ValidationResult>(
                "ValidateMessage",
                ItExpr.IsAny<CoseSign1Message>())
            .CallBase();
        mockValidator.Protected()
            .Setup<CoseSign1ValidationResult>(
                "ValidateCertificate",
                ItExpr.IsAny<X509Certificate2>(),
                ItExpr.IsAny<List<X509Certificate2>>(),
                ItExpr.IsAny<List<X509Certificate2>>())
            .Callback<X509Certificate2, List<X509Certificate2>, List<X509Certificate2>>(
                (cert, certChain, extraCerts) =>
                {
                    invokedCert = cert;
                    invokedCertChain = certChain;
                    invokedExtraCerts = extraCerts;
                })
            .Returns(new CoseSign1ValidationResult(typeof(X509Certificate2MessageValidator)) { PassedValidation = true });

        CoseSign1Message message = factory.CreateCoseSign1Message(testArray, keyProvider, embedPayload: true, ContentTypeConstants.Cose);

        mockValidator.Object.TryValidate(message, out var results).Should().BeTrue(results.First().ResultMessage);
        results.Should().NotBeNull();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeTrue();
        invokedCert.Should().Be(testChain.Last());
        invokedCertChain.Count.Should().Be(3);
        // CertChain in the CoseSign1Message object is per RFC leaf first, so reverse the test chain for compare.
        invokedCertChain.Select(c => c.Thumbprint).SequenceEqual(testChain.Reverse().Select(c => c.Thumbprint)).Should().BeTrue();
        invokedExtraCerts.Should().BeNull();
    }

    /// <summary>
    /// Run through some basic validator tests.
    /// </summary>
    [Test]
    public void X509Certificate2MessageValidatorFailsWhenCertFailsToBeFound()
    {
        // setup
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(nameof(X509Certificate2MessageValidatorValidates));
        Mock<X509Certificate2MessageValidator> mockValidator = new(MockBehavior.Strict)
        {
            CallBase = true
        };
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        ICoseSign1MessageFactory factory = new CoseSign1MessageFactory();
        X509Certificate2CoseSigningKeyProvider keyProvider = new(mockBuilder.Object, testChain.Last());
        byte[] testArray = new byte[] { 1, 2, 3, 4 };
        mockBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(x => x.ChainElements).Returns<List<X509Certificate2>>(null);
        X509Certificate2? invokedCert = null;
        List<X509Certificate2>? invokedCertChain = null;
        List<X509Certificate2>? invokedExtraCerts = null;
        List<CoseSign1ValidationResult>? validationResults = null;

        mockValidator.Setup(m => m.TryValidate(It.IsAny<CoseSign1Message>(), out validationResults)).CallBase();
        mockValidator.Setup(m => m.Validate(It.IsAny<CoseSign1Message>())).CallBase();
        mockValidator.Setup(m => m.NextElement).CallBase();
        mockValidator.Protected()
            .Setup<CoseSign1ValidationResult>(
                "ValidateMessage",
                ItExpr.IsAny<CoseSign1Message>())
            .CallBase();
        mockValidator.Protected()
            .Setup<CoseSign1ValidationResult>(
                "ValidateCertificate",
                ItExpr.IsAny<X509Certificate2>(),
                ItExpr.IsAny<List<X509Certificate2>>(),
                ItExpr.IsAny<List<X509Certificate2>>())
            .Callback<X509Certificate2, List<X509Certificate2>, List<X509Certificate2>>(
                (cert, certChain, extraCerts) =>
                {
                    invokedCert = cert;
                    invokedCertChain = certChain;
                    invokedExtraCerts = extraCerts;
                })
            .Returns(new CoseSign1ValidationResult(typeof(X509Certificate2MessageValidator)) { PassedValidation = true });

        CoseSign1Message message = factory.CreateCoseSign1Message(testArray, keyProvider, embedPayload: true, ContentTypeConstants.Cose);

        mockValidator.Object.TryValidate(message, out var results).Should().BeFalse();
        results.Should().NotBeNull();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeFalse();
        mockValidator.Protected()
            .Verify<CoseSign1ValidationResult>(
                "ValidateCertificate",
                Times.Never(),
                ItExpr.IsAny<X509Certificate2>(),
                ItExpr.IsAny<List<X509Certificate2>>(),
                ItExpr.IsAny<List<X509Certificate2>>());

        invokedCert.Should().BeNull();
        invokedCertChain.Should().BeNull();
        invokedExtraCerts.Should().BeNull();
    }
}

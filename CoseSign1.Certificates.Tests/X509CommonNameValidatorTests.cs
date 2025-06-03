// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Test class for <see cref="X509CommonNameValidator"/>
/// </summary>
public class X509CommonNameValidatorTests
{
    /// <summary>
    /// Setup method
    /// </summary>
    [SetUp]
    public void Setup()
    {
    }

    private static IEnumerable<Tuple<Func<X509CommonNameValidator>, Action<X509CommonNameValidator>>> X509CommonNameValidatorCtorsTestData()
    {
        yield return Tuple.Create<Func<X509CommonNameValidator>, Action<X509CommonNameValidator>>(
            () => new X509CommonNameValidator("testCommonName"),
            (trustValidator) => trustValidator.AllowUnprotected.Should().BeFalse());
        yield return Tuple.Create<Func<X509CommonNameValidator>, Action<X509CommonNameValidator>>(
            () => new X509CommonNameValidator("testCommonName", true),
            (trustValidator) => trustValidator.AllowUnprotected.Should().BeTrue());
    }

    [Test]
    public void ValidateCommonName()
    {
        string subjectName = "Test Certificate, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        X509Certificate2 selfSignedRoot = TestCertificateUtils.CreateCertificate(subjectName);
        X509CommonNameValidator.ValidateCommonName(selfSignedRoot, $"CN={subjectName}");
    }

    [Test]
    public void ValidateBadlyFormedCommonNameFail()
    {
        X509Certificate2 selfSignedRoot = TestCertificateUtils.CreateCertificate();
        Exception e = Assert.Throws<CoseValidationException>(() => X509CommonNameValidator.ValidateCommonName(selfSignedRoot, "epic fail"));
        e.Message.Should().Contain("Invalid common name format");
    }

    [Test]
    public void ValidateIncorrectCommonNameFail()
    {
        X509Certificate2 selfSignedRoot = TestCertificateUtils.CreateCertificate();
        Exception e = Assert.Throws<CoseValidationException>(() => X509CommonNameValidator.ValidateCommonName(selfSignedRoot, "CN=epic fail"));
        e.Message.Should().Contain("does not match required name");
    }

    /// <summary>
    /// Testing Constructors Success
    /// </summary>
    /// <param name="inputCase"></param>
    [Test,
     TestCaseSource(nameof(X509CommonNameValidatorCtorsTestData))]
    public void X509CommonNameValidatorCtors(Tuple<Func<X509CommonNameValidator>, Action<X509CommonNameValidator>> inputCase)
    {
        X509CommonNameValidator testItem = null;
        Assert.DoesNotThrow(() => testItem = inputCase.Item1());
        Assert.DoesNotThrow(() => inputCase.Item2(testItem));
    }

    /// <summary>
    /// Testing Constructors Exception Path
    /// </summary>
    /// <param name="inputCase"></param>
    [Test]
    public void X509CommonNameValidatorCtorsException()
    {
        List<Action> constructorTests =
        [
            new Action(() => _= new X509CommonNameValidator("")),
            new Action(() => _= new X509CommonNameValidator(" ")),
        ];

        // test validate
        foreach (Action test in constructorTests)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => test());
        }
    }

    /// <summary>
    /// Run through some basic validator tests.
    /// </summary>
    [Test]
    public void X509CommonNameValidatorValidates()
    {
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        CoseSign1MessageFactory factory = new();
        byte[] testArray = [1, 2, 3, 4];
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        X509Certificate2CoseSigningKeyProvider keyProvider = new(mockBuilder.Object, testChain.Last());

        // test
        mockBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(x => x.ChainElements).Returns([.. testChain]);

        X509CommonNameValidator testNameValidator = new(testChain.Last().Subject);
        CoseSign1Message message = factory.CreateCoseSign1Message(testArray, keyProvider, embedPayload: true, ContentTypeConstants.Cose);

        testNameValidator.TryValidate(message, out List<CoseSign1ValidationResult>? validationResults).Should().BeTrue();
        validationResults[0].ResultMessage.Should().NotBeNull();
        validationResults.Count.Should().Be(1);
        validationResults[0].PassedValidation.Should().BeTrue();
    }

    /// <summary>
    /// Run through validator tests for error cases.
    /// </summary>
    [Test]
    public void X509CommonNameValidatorValidatesErrorPath()
    {
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        CoseSign1MessageFactory factory = new();
        X509Certificate2CoseSigningKeyProvider keyProvider = new(mockBuilder.Object, testChain.Last());
        byte[] testArray = [1, 2, 3, 4];

        // test
        mockBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(x => x.ChainElements).Returns([.. testChain]);

        X509CommonNameValidator testNameValidator = new("testCertName");

        CoseSign1Message message = factory.CreateCoseSign1Message(testArray, keyProvider, embedPayload: true, ContentTypeConstants.Cose);

        testNameValidator.TryValidate(message, out List<CoseSign1ValidationResult>? validationResults).Should().BeFalse();
        validationResults[0].ResultMessage.Should().NotBeNullOrWhiteSpace();
        validationResults.Count.Should().Be(1);
        validationResults[0].PassedValidation.Should().BeFalse();
    }

    /// <summary>
    /// validates when certificate provided is null
    /// </summary>
    [Test]
    public void X509TrustValidatorValidatesNullCertificate()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 testCertRSA = TestCertificateUtils.CreateCertificate();

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns([]);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns([]);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(testCertRSA.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        CoseSign1MessageBuilder coseSign1MessageBuilder = new(mockedSignerKeyProvider.Object);
        CoseSign1Message message = coseSign1MessageBuilder
                                  .SetPayloadBytes(testPayload)
                                  .SetContentType(ContentTypeConstants.Cose).Build();

        X509CommonNameValidator testNameValidator = new("testCertName");
        testNameValidator.TryValidate(message, out List<CoseSign1ValidationResult>? validationResults).Should().BeFalse();
        validationResults[0].ResultMessage.Should().NotBeNull();
        validationResults.Count.Should().Be(1);
        validationResults[0].PassedValidation.Should().BeFalse();
    }
}

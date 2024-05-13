// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Test class for <see cref="CoseSign1MessageValidator"/>
/// </summary>
public class CoseSign1MessageValidatorTests
{
    /// <summary>
    /// Setup method
    /// </summary>
    [SetUp]
    public void Setup()
    {
    }

    /// <summary>
    /// Just verify the shim for <see cref="X509Chain"/> functions properly.
    /// </summary>
    [Test]
    public void TestChainingValidators()
    {

        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        mockBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(x => x.ChainElements).Returns([.. testChain]);
        ICoseSign1MessageFactory factory = new CoseSign1MessageFactory();
        X509Certificate2CoseSigningKeyProvider keyProvider = new(mockBuilder.Object, testChain.Last());

        Mock<CoseSign1MessageValidator> mockValidator = new()
        {
            CallBase = true
        };

        Mock<CoseSign1MessageValidator> mockValidator2 = new()
        {
            CallBase = true
        };

        List<CoseSign1ValidationResult> list1 = [];
        mockValidator.Protected()
            .Setup<CoseSign1ValidationResult>(
                "ValidateMessage",
                ItExpr.IsAny<CoseSign1Message>())
            .Returns(new CoseSign1ValidationResult(typeof(CoseSign1ValidationResult)) { PassedValidation = true, ResultMessage = "Passed" });
        mockValidator.Setup(m => m.TryValidate(It.IsAny<CoseSign1Message>(), out list1)).CallBase();
        mockValidator.Setup(m => m.Validate(It.IsAny<CoseSign1Message>())).CallBase();
        mockValidator.Setup(m => m.NextElement).CallBase();

        mockValidator2.Protected()
            .Setup<CoseSign1ValidationResult>(
                "ValidateMessage",
                ItExpr.IsAny<CoseSign1Message>())
            .Returns(new CoseSign1ValidationResult(typeof(CoseSign1ValidationResult)) { PassedValidation = true, ResultMessage = "Passed" });
        mockValidator2.Setup(m => m.TryValidate(It.IsAny<CoseSign1Message>(), out list1)).CallBase();
        mockValidator2.Setup(m => m.Validate(It.IsAny<CoseSign1Message>())).CallBase();
        mockValidator2.Setup(m => m.NextElement).CallBase();

        byte[] testArray = [1, 2, 3, 4];
        CoseSign1Message message = factory.CreateCoseSign1Message(testArray, keyProvider, embedPayload: true, ContentTypeConstants.Cose);

        mockValidator.Object.NextElement = mockValidator2.Object;

        mockValidator.Object.TryValidate(message, out _).Should().BeTrue();
    }

    /// <summary>
    /// Just verify the shim for <see cref="X509Chain"/> functions properly.
    /// </summary>
    [Test]
    public void TestChainingValidatorsThatWouldCauseLoop()
    {

        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        mockBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(x => x.ChainElements).Returns([.. testChain]);
        ICoseSign1MessageFactory factory = new CoseSign1MessageFactory();
        X509Certificate2CoseSigningKeyProvider keyProvider = new(mockBuilder.Object, testChain.Last());

        Mock<CoseSign1MessageValidator> mockValidator = new()
        {
            CallBase = true
        };

        List<CoseSign1ValidationResult> list1 = [];
        mockValidator.Protected()
            .Setup<CoseSign1ValidationResult>(
                "ValidateMessage",
                ItExpr.IsAny<CoseSign1Message>())
            .Returns(new CoseSign1ValidationResult(typeof(CoseSign1ValidationResult)) { PassedValidation = true, ResultMessage = "Passed" });
        mockValidator.Setup(m => m.TryValidate(It.IsAny<CoseSign1Message>(), out list1)).CallBase();
        mockValidator.Setup(m => m.Validate(It.IsAny<CoseSign1Message>())).CallBase();
        mockValidator.Setup(m => m.NextElement).CallBase();

        CoseSign1MessageValidator realObject = mockValidator.Object;
        Assert.Throws<ArgumentOutOfRangeException>(() => realObject.NextElement = realObject);
    }
}

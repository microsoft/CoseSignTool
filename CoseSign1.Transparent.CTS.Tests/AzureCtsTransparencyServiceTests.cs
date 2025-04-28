// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.Tests;

using System;
using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Interfaces;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.CTS;
using CoseSign1.Transparent.Extensions;
using Moq;

/// <summary>
/// Unit tests for the <see cref="AzureCtsTransparencyService"/> class.
/// </summary>
[TestFixture]
public class AzureCtsTransparencyServiceTests
{
    private CoseSign1MessageFactory? messageFactory;
    private ICoseSigningKeyProvider? signingKeyProvider;

    [SetUp]
    public void Setup()
    {
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate();

        //create object of custom ChainBuilder
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();

        //create coseSignKeyProvider with custom chainbuilder and local cert
        //if no chainbuilder is specified, it will default to X509ChainBuilder, but that can't be used for integration tests
        signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);

        messageFactory = new();
    }

    /// <summary>
    /// Tests the constructor of <see cref="AzureCtsTransparencyService"/> for null arguments.
    /// </summary>
    [Test]
    public void Constructor_ThrowsArgumentNullException_WhenTransparencyClientIsNull()
    {
        // Act & Assert
        Assert.That(
            () => new AzureCtsTransparencyService(null),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("transparencyClient"));
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.MakeTransparentAsync"/> method for null arguments.
    /// </summary>
    [Test]
    public void MakeTransparentAsync_ThrowsArgumentNullException_WhenMessageIsNull()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient);

        // Act & Assert
        Assert.That(
            () => service.MakeTransparentAsync(null),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("message"));
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.MakeTransparentAsync"/> method for a failed operation.
    /// </summary>
    [Test]
    public void MakeTransparentAsync_ThrowsInvalidOperationException_WhenOperationFails()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        mockClient
            .Setup(client => client.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockFailedOperation());

        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient.Object);
        CoseSign1Message message = CreateMockCoseSign1Message();

        // Act & Assert
        Assert.That(
            async () => await service.MakeTransparentAsync(message),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("CreateEntryAsync failed to return a response"));
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.MakeTransparentAsync"/> method for a failed operation with an invalid entry Id.
    /// </summary>
    [Test]
    public void MakeTransparentAsync_ThrowsInvalidOperationException_WhenOperationFails_WithInvalidEntryId()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        mockClient
            .Setup(client => client.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockSuccessfulOperationWithInvalidResponse());

        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient.Object);
        CoseSign1Message message = CreateMockCoseSign1Message();

        // Act & Assert
        Assert.That(
            async () => await service.MakeTransparentAsync(message),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("The transparency operation failed, content was not a valid CBOR-encoded entryId."));
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.MakeTransparentAsync"/> method for a successful operation.
    /// </summary>
    [Test]
    public async Task MakeTransparentAsync_ReturnsExpectedResult_WhenOperationSucceeds()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMockCoseSign1Message();
        message.AddReceipts(new List<byte[]>() { new byte[] { 1, 2, 3 } });
        BinaryData mockEntryStatement = BinaryData.FromBytes(message.Encode());
        mockClient
            .Setup(client => client.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockSuccessfulOperation());
        mockClient
            .Setup(client => client.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(mockEntryStatement, Mock.Of<Response>()));

        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient.Object);

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(message);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.VerifyTransparencyAsync(CoseSign1Message, CancellationToken)"/> method for null arguments.
    /// </summary>
    [Test]
    public void VerifyTransparencyAsync_ThrowsArgumentNullException_WhenMessageIsNull()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient);

        // Act & Assert
        Assert.That(
            () => service.VerifyTransparencyAsync(null),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("message"));
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.VerifyTransparencyAsync(CoseSign1Message, CancellationToken)"/> method for a message without a transparency header.
    /// </summary>
    [Test]
    public void VerifyTransparencyAsync_ThrowsInvalidOperationException_WhenMessageLacksTransparencyHeader()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient);
        CoseSign1Message message = CreateMockCoseSign1Message();

        // Act & Assert
        Assert.That(
            () => service.VerifyTransparencyAsync(message),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("does not contain a transparency header"));
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.VerifyTransparencyAsync(CoseSign1Message, CancellationToken)"/> method for a successful verification.
    /// </summary>
    [Test]
    [Ignore("This test is ignored because RunTransparentStatementVerification is not virtual and cannot be mocked. This has been escalated to the package owners.")]
    public async Task VerifyTransparencyAsync_ReturnsTrue_WhenVerificationSucceeds()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        mockClient
            .Setup(client => client.RunTransparentStatementVerification(It.IsAny<byte[]>()))
            .Verifiable();

        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient.Object);
        CoseSign1Message message = CreateMessageWithTransparencyHeader();

        // Act
        bool result = await service.VerifyTransparencyAsync(message);

        // Assert
        Assert.That(result, Is.True);
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.VerifyTransparencyAsync(CoseSign1Message, byte[], CancellationToken)"/> method for null arguments.
    /// </summary>
    [Test]
    public void VerifyTransparencyAsync_WithReceipt_ThrowsArgumentNullException_WhenArgumentsAreNull()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient);

        // Act & Assert
        Assert.That(
            () => service.VerifyTransparencyAsync(null, new byte[] { 1, 2, 3 }),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("message"));

        Assert.That(
            () => service.VerifyTransparencyAsync(CreateMockCoseSign1Message(), null),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("receipt"));
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyService.VerifyTransparencyAsync(CoseSign1Message, byte[], CancellationToken)"/> method for an empty receipt.
    /// </summary>
    [Test]
    public void VerifyTransparencyAsync_WithReceipt_ThrowsArgumentOutOfRangeException_WhenReceiptIsEmpty()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        AzureCtsTransparencyService service = new AzureCtsTransparencyService(mockClient);
        CoseSign1Message message = CreateMockCoseSign1Message();

        // Act & Assert
        Assert.That(
            () => service.VerifyTransparencyAsync(message, Array.Empty<byte>()),
            Throws.TypeOf<ArgumentOutOfRangeException>().With.Property("ParamName").EqualTo("receipt"));
    }

    /// <summary>
    /// Helper method to create a mock failed operation.
    /// </summary>
    /// <returns>A mock failed operation.</returns>
    private static Operation<BinaryData> MockFailedOperation()
    {
        Mock<Operation<BinaryData>> mockOperation = new Mock<Operation<BinaryData>>();
        mockOperation.Setup(op => op.HasValue).Returns(false);
        mockOperation.Setup(op => op.GetRawResponse()).Returns(Mock.Of<Response>());
        return mockOperation.Object;
    }

    /// <summary>
    /// Helper method to create a mock successful operation but with an invalid Operati9onId.
    /// </summary>
    /// <returns>A mock successful operation.</returns>
    private static Operation<BinaryData> MockSuccessfulOperationWithInvalidResponse()
    {
        Mock<Operation<BinaryData>> mockOperation = new Mock<Operation<BinaryData>>();
        mockOperation.Setup(op => op.HasValue).Returns(true);
        CborWriter cborWriter = new CborWriter();
        cborWriter.WriteStartMap(1);
        cborWriter.WriteTextString("fooBar");
        cborWriter.WriteTextString("12345");
        cborWriter.WriteEndMap();
        mockOperation.Setup(op => op.Value).Returns(BinaryData.FromBytes(cborWriter.Encode()));
        return mockOperation.Object;
    }

    /// <summary>
    /// Helper method to create a mock successful operation.
    /// </summary>
    /// <returns>A mock successful operation.</returns>
    private static Operation<BinaryData> MockSuccessfulOperation()
    {
        Mock<Operation<BinaryData>> mockOperation = new Mock<Operation<BinaryData>>();
        mockOperation.Setup(op => op.HasValue).Returns(true);
        CborWriter cborWriter = new CborWriter();
        cborWriter.WriteStartMap(1);
        cborWriter.WriteTextString("EntryId");
        cborWriter.WriteTextString("12345");
        cborWriter.WriteEndMap();
        mockOperation.Setup(op => op.Value).Returns(BinaryData.FromBytes(cborWriter.Encode()));
        return mockOperation.Object;
    }

    /// <summary>
    /// Helper method to create a <see cref="CoseSign1Message"/> with a transparency header.
    /// </summary>
    /// <returns>A <see cref="CoseSign1Message"/> with a transparency header.</returns>
    private CoseSign1Message CreateMessageWithTransparencyHeader()
    {
        CoseSign1Message message = CreateMockCoseSign1Message();
        message.AddReceipts(new List<byte[]>() { new byte[] { 1, 2, 3 } });
        return message;
    }

    private CoseSign1Message CreateMockCoseSign1Message()
    {
        byte[] testPayload = Encoding.ASCII.GetBytes("Payload1!");
        return messageFactory!.CreateCoseSign1Message(testPayload, signingKeyProvider!, embedPayload: false);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.Tests;

using System;
using System.Collections.Generic;
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
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Transparent.Extensions;
using Moq;

/// <summary>
/// Unit tests for logging behavior in <see cref="MstTransparencyService"/> class.
/// </summary>
[TestFixture]
public class MstTransparencyServiceLoggingTests
{
    private CoseSign1MessageFactory? messageFactory;
    private ICoseSigningKeyProvider? signingKeyProvider;

    [SetUp]
    public void Setup()
    {
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();
        signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);
        messageFactory = new();
    }

    [Test]
    public async Task MakeTransparentAsync_WithLogging_LogsVerboseMessages()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMockCoseSign1Message();
        var logMessages = new List<string>();
        
        Action<string> logVerbose = msg => logMessages.Add($"VERBOSE: {msg}");
        Action<string> logError = msg => logMessages.Add($"ERROR: {msg}");
        
        mockClient
            .Setup(client => client.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockSuccessfulOperation());

        mockClient
            .Setup(client => client.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(BinaryData.FromBytes(message.Encode()), Mock.Of<Response>()));

        MstTransparencyService service = new MstTransparencyService(
            mockClient.Object, null, null, logVerbose, null, logError);

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(message);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Starting MakeTransparentAsync")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Encoded message size")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Calling CreateEntryAsync")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("CreateEntryAsync completed successfully")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Entry ID:")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Retrieving entry statement")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Entry statement size")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Decoding transparent statement")));
    }

    [Test]
    public void MakeTransparentAsync_WithOperationFailure_LogsError()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMockCoseSign1Message();
        var errorMessages = new List<string>();
        
        Action<string> logError = msg => errorMessages.Add($"ERROR: {msg}");
        
        mockClient
            .Setup(client => client.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockFailedOperation());

        MstTransparencyService service = new MstTransparencyService(
            mockClient.Object, null, null, null, null, logError);

        // Act & Assert
        Assert.That(
            async () => await service.MakeTransparentAsync(message),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("CreateEntryAsync failed"));
        
        Assert.That(errorMessages, Has.Some.Matches<string>(m => m.Contains("CreateEntryAsync failed")));
    }

    [Test]
    public void MakeTransparentAsync_WithInvalidEntryId_LogsError()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMockCoseSign1Message();
        var errorMessages = new List<string>();
        
        Action<string> logError = msg => errorMessages.Add($"ERROR: {msg}");
        
        mockClient
            .Setup(client => client.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MockSuccessfulOperationWithInvalidResponse());

        MstTransparencyService service = new MstTransparencyService(
            mockClient.Object, null, null, null, null, logError);

        // Act & Assert
        Assert.That(
            async () => await service.MakeTransparentAsync(message),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("not a valid CBOR-encoded entryId"));
        
        Assert.That(errorMessages, Has.Some.Matches<string>(m => m.Contains("not a valid CBOR-encoded entryId")));
    }

    [Test]
    public async Task VerifyTransparencyAsync_WithLogging_LogsVerboseMessages()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMessageWithTransparencyHeader();
        var logMessages = new List<string>();
        
        Action<string> logVerbose = msg => logMessages.Add($"VERBOSE: {msg}");
        
        var verificationOptions = new CodeTransparencyVerificationOptions
        {
            AuthorizedDomains = new List<string> { "example.com", "test.com" },
            AuthorizedReceiptBehavior = AuthorizedReceiptBehavior.RequireAll,
            UnauthorizedReceiptBehavior = UnauthorizedReceiptBehavior.FailIfPresent
        };

        MstTransparencyService service = new MstTransparencyService(
            mockClient.Object, verificationOptions, null, logVerbose, null, null);

        // Act
        try
        {
            await service.VerifyTransparencyAsync(message);
        }
        catch
        {
            // Expected to fail since we're using mock data
        }

        // Assert
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Starting transparency verification")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Transparency header found")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Authorized domains: example.com, test.com")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Authorized receipt behavior: RequireAll")));
        Assert.That(logMessages, Has.Some.Matches<string>(m => m.Contains("Unauthorized receipt behavior: FailIfPresent")));
    }

    [Test]
    public void VerifyTransparencyAsync_WithoutTransparencyHeader_LogsError()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMockCoseSign1Message(); // No transparency header
        var errorMessages = new List<string>();
        
        Action<string> logError = msg => errorMessages.Add($"ERROR: {msg}");

        MstTransparencyService service = new MstTransparencyService(
            mockClient.Object, null, null, null, null, logError);

        // Act & Assert
        Assert.That(
            async () => await service.VerifyTransparencyAsync(message),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("does not contain a transparency header"));
        
        Assert.That(errorMessages, Has.Some.Matches<string>(m => m.Contains("does not contain a transparency header")));
    }

    [Test]
    public async Task VerifyTransparencyAsync_WithInvalidOperationException_LogsErrorAndReturnsFalse()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMessageWithTransparencyHeader();
        var errorMessages = new List<string>();
        var verboseMessages = new List<string>();
        
        Action<string> logVerbose = msg => verboseMessages.Add($"VERBOSE: {msg}");
        Action<string> logError = msg => errorMessages.Add($"ERROR: {msg}");

        MstTransparencyService service = new MstTransparencyService(
            mockClient.Object, null, null, logVerbose, null, logError);

        // Act
        bool result = await service.VerifyTransparencyAsync(message);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errorMessages, Is.Not.Empty, "Should log at least one error message");
    }

    [Test]
    public async Task VerifyTransparencyAsync_WithInvalidReceipt_LogsErrorAndReturnsFalse()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();
        
        // Create a message with invalid CBOR in transparency header
        byte[] payload = Encoding.ASCII.GetBytes("TestPayload");
        CoseSign1Message message = messageFactory!.CreateCoseSign1Message(payload, signingKeyProvider!, embedPayload: false);
        
        // Add invalid receipt (will cause verification failure)
        message.AddReceipts(new List<byte[]> { new byte[] { 0xFF, 0xFF, 0xFF } });
        
        var errorMessages = new List<string>();
        var verboseMessages = new List<string>();
        
        Action<string> logVerbose = msg => verboseMessages.Add($"VERBOSE: {msg}");
        Action<string> logError = msg => errorMessages.Add($"ERROR: {msg}");

        MstTransparencyService service = new MstTransparencyService(
            mockClient.Object, null, null, logVerbose, null, logError);

        // Act
        bool result = await service.VerifyTransparencyAsync(message);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errorMessages, Is.Not.Empty, "Should log error about verification failure");
    }

    [Test]
    public void ToCoseSign1TransparencyService_WithLogging_CreatesServiceWithLogging()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        var logMessages = new List<string>();
        
        Action<string> logVerbose = msg => logMessages.Add($"VERBOSE: {msg}");
        Action<string> logWarning = msg => logMessages.Add($"WARNING: {msg}");
        Action<string> logError = msg => logMessages.Add($"ERROR: {msg}");

        // Act
        var service = mockClient.ToCoseSign1TransparencyService(logVerbose, logWarning, logError);

        // Assert
        Assert.That(service, Is.Not.Null);
        Assert.That(service, Is.InstanceOf<MstTransparencyService>());
    }

    [Test]
    public void ToCoseSign1TransparencyService_WithoutLogging_CreatesService()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();

        // Act
        var service = mockClient.ToCoseSign1TransparencyService();

        // Assert
        Assert.That(service, Is.Not.Null);
        Assert.That(service, Is.InstanceOf<MstTransparencyService>());
    }

    [Test]
    public void ToCoseSign1TransparencyService_WithNullClient_ThrowsArgumentNullException()
    {
        // Arrange
        CodeTransparencyClient? mockClient = null;

        // Act & Assert
        Assert.That(
            () => mockClient!.ToCoseSign1TransparencyService(),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("client"));
    }

    [Test]
    public void ToCoseSign1TransparencyService_WithLoggingAndNullClient_ThrowsArgumentNullException()
    {
        // Arrange
        CodeTransparencyClient? mockClient = null;
        Action<string> logVerbose = msg => { };

        // Act & Assert
        Assert.That(
            () => mockClient!.ToCoseSign1TransparencyService(logVerbose, null, null),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("client"));
    }

    // Helper methods

    private CoseSign1Message CreateMockCoseSign1Message()
    {
        byte[] testPayload = Encoding.ASCII.GetBytes("TestPayload");
        return messageFactory!.CreateCoseSign1Message(testPayload, signingKeyProvider!, embedPayload: false);
    }

    private CoseSign1Message CreateMessageWithTransparencyHeader()
    {
        CoseSign1Message message = CreateMockCoseSign1Message();
        message.AddReceipts(new List<byte[]> { new byte[] { 1, 2, 3 } });
        return message;
    }

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

    private static Operation<BinaryData> MockFailedOperation()
    {
        Mock<Operation<BinaryData>> mockOperation = new Mock<Operation<BinaryData>>();
        mockOperation.Setup(op => op.HasValue).Returns(false);
        mockOperation.Setup(op => op.GetRawResponse()).Returns(Mock.Of<Response>());
        return mockOperation.Object;
    }

    private static Operation<BinaryData> MockSuccessfulOperationWithInvalidResponse()
    {
        Mock<Operation<BinaryData>> mockOperation = new Mock<Operation<BinaryData>>();
        mockOperation.Setup(op => op.HasValue).Returns(true);
        
        CborWriter cborWriter = new CborWriter();
        cborWriter.WriteStartMap(1);
        cborWriter.WriteTextString("InvalidKey");
        cborWriter.WriteTextString("12345");
        cborWriter.WriteEndMap();
        
        mockOperation.Setup(op => op.Value).Returns(BinaryData.FromBytes(cborWriter.Encode()));
        return mockOperation.Object;
    }
}


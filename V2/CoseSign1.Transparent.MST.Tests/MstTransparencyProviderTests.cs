// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST.Extensions;
using Moq;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class MstTransparencyProviderTests
{
    private Mock<CodeTransparencyClient> MockClient = null!;
    private Mock<ICodeTransparencyVerifier> MockVerifier = null!;
    private X509Certificate2 TestCert = null!;

    [SetUp]
    public void Setup()
    {
        MockClient = new Mock<CodeTransparencyClient>();
        MockVerifier = new Mock<ICodeTransparencyVerifier>();
        TestCert = TestCertificateUtils.CreateCertificate("MstTestCert", useEcc: true);
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithClient_CreatesProvider()
    {
        // Act
        var provider = new MstTransparencyProvider(MockClient.Object);

        // Assert
        Assert.That(provider, Is.Not.Null);
        Assert.That(provider.ProviderName, Is.EqualTo("Microsoft Signing Transparency"));
    }

    [Test]
    public void Constructor_WithNullClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new MstTransparencyProvider(null!));
    }

    [Test]
    public void Constructor_WithClientAndOptions_CreatesProvider()
    {
        // Arrange
        var verificationOptions = new CodeTransparencyVerificationOptions();
        var clientOptions = new CodeTransparencyClientOptions();

        // Act
        var provider = new MstTransparencyProvider(MockClient.Object, verificationOptions, clientOptions);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithLogging_CreatesProvider()
    {
        // Arrange
        var logs = new List<string>();
        Action<string> logVerbose = msg => logs.Add($"VERBOSE: {msg}");
        Action<string> logError = msg => logs.Add($"ERROR: {msg}");

        // Act
        var provider = new MstTransparencyProvider(
            MockClient.Object,
            null,
            null,
            logVerbose,
            logError);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithVerifier_CreatesProvider()
    {
        // Act
        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null,
            null,
            null,
            null);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullVerifier_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new MstTransparencyProvider(
                MockClient.Object,
                null!,  // verifier
                null,
                null,
                null,
                null));
    }

    #endregion

    #region ProviderName Tests

    [Test]
    public void ProviderName_ReturnsExpectedValue()
    {
        // Arrange
        var provider = new MstTransparencyProvider(MockClient.Object);

        // Act & Assert
        Assert.That(provider.ProviderName, Is.EqualTo("Microsoft Signing Transparency"));
    }

    #endregion

    #region AddTransparencyProofAsync Tests

    [Test]
    public void AddTransparencyProofAsync_WithNullMessage_ThrowsArgumentNullException()
    {
        // Arrange
        var provider = new MstTransparencyProvider(MockClient.Object);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await provider.AddTransparencyProofAsync(null!));
    }

    [Test]
    public async Task AddTransparencyProofAsync_WithValidMessage_SubmitsToService()
    {
        // Arrange
        var testMessage = CreateTestSignedMessage("test payload");

        // Create CBOR-encoded entry ID response (as MST returns)
        var entryIdResponse = CreateCborEntryIdResponse("1.234");
        var transparentStatementBytes = testMessage.Encode();

        var mockOperation = CreateMockOperation(true, entryIdResponse);
        var mockStatementResponse = CreateMockResponse(transparentStatementBytes);

        MockClient
            .Setup(c => c.CreateEntryAsync(
                It.IsAny<WaitUntil>(),
                It.IsAny<BinaryData>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);

        MockClient
            .Setup(c => c.GetEntryStatementAsync(
                "1.234",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockStatementResponse);

        var provider = new MstTransparencyProvider(MockClient.Object);

        // Act
        var result = await provider.AddTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(result, Is.Not.Null);
        MockClient.Verify(c => c.CreateEntryAsync(
            WaitUntil.Completed,
            It.IsAny<BinaryData>(),
            It.IsAny<CancellationToken>()), Times.Once);
        MockClient.Verify(c => c.GetEntryStatementAsync(
            "1.234",
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task AddTransparencyProofAsync_WhenOperationFails_ThrowsInvalidOperationException()
    {
        // Arrange
        var testMessage = CreateTestSignedMessage("test payload");

        var mockOperation = CreateMockOperation(false, null);
        var mockResponse = new Mock<Response>();
        mockResponse.Setup(r => r.ReasonPhrase).Returns("Service unavailable");
        mockOperation.Setup(o => o.GetRawResponse()).Returns(mockResponse.Object);

        MockClient
            .Setup(c => c.CreateEntryAsync(
                It.IsAny<WaitUntil>(),
                It.IsAny<BinaryData>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);

        var provider = new MstTransparencyProvider(MockClient.Object);

        // Act & Assert
        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.AddTransparencyProofAsync(testMessage));

        Assert.That(ex!.Message, Does.Contain("MST transparency submission failed"));
    }

    [Test]
    public async Task AddTransparencyProofAsync_WhenEntryIdMissing_ThrowsInvalidOperationException()
    {
        // Arrange
        var testMessage = CreateTestSignedMessage("test payload");

        // Create an invalid response without proper CBOR entryId
        var invalidResponse = BinaryData.FromBytes(new byte[] { 0x00 });
        var mockOperation = CreateMockOperation(true, invalidResponse);

        MockClient
            .Setup(c => c.CreateEntryAsync(
                It.IsAny<WaitUntil>(),
                It.IsAny<BinaryData>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);

        var provider = new MstTransparencyProvider(MockClient.Object);

        // Act & Assert
        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.AddTransparencyProofAsync(testMessage));

        Assert.That(ex!.Message, Does.Contain("entryId"));
    }

    [Test]
    public async Task AddTransparencyProofAsync_LogsProgress()
    {
        // Arrange
        var logs = new List<string>();
        var testMessage = CreateTestSignedMessage("test payload");

        var entryIdResponse = CreateCborEntryIdResponse("1.234");
        var transparentStatementBytes = testMessage.Encode();

        var mockOperation = CreateMockOperation(true, entryIdResponse);
        var mockStatementResponse = CreateMockResponse(transparentStatementBytes);

        MockClient
            .Setup(c => c.CreateEntryAsync(
                It.IsAny<WaitUntil>(),
                It.IsAny<BinaryData>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);

        MockClient
            .Setup(c => c.GetEntryStatementAsync(
                "1.234",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockStatementResponse);

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            null,
            null,
            msg => logs.Add(msg),
            null);

        // Act
        await provider.AddTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(logs, Has.Count.GreaterThan(0));
        Assert.That(logs.Any(l => l.Contains("Starting transparency proof")), Is.True);
        Assert.That(logs.Any(l => l.Contains("Entry ID: 1.234")), Is.True);
    }

    #endregion

    #region VerifyTransparencyProofAsync Tests

    [Test]
    public void VerifyTransparencyProofAsync_WithNullMessage_ThrowsArgumentNullException()
    {
        // Arrange
        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await provider.VerifyTransparencyProofAsync(null!));
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_WithoutMstReceipt_ReturnsFailure()
    {
        // Arrange
        var testMessage = CreateTestSignedMessage("test payload");
        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act
        var result = await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ProviderName, Is.EqualTo("Microsoft Signing Transparency"));
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("MST receipt"));
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_WithValidReceipt_ReturnsSuccess()
    {
        // Arrange
        var testMessage = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()));

        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act
        var result = await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ProviderName, Is.EqualTo("Microsoft Signing Transparency"));
        MockVerifier.Verify(v => v.VerifyTransparentStatement(
            It.IsAny<byte[]>(),
            null,
            null), Times.Once);
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_WithVerificationOptions_PassesOptionsToVerifier()
    {
        // Arrange
        var testMessage = CreateMessageWithMstReceipt();
        var verificationOptions = new CodeTransparencyVerificationOptions
        {
            AuthorizedDomains = new List<string> { "example.com" }
        };
        var clientOptions = new CodeTransparencyClientOptions();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                verificationOptions,
                clientOptions));

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            verificationOptions,
            clientOptions,
            null,
            null);

        // Act
        await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        MockVerifier.Verify(v => v.VerifyTransparentStatement(
            It.IsAny<byte[]>(),
            verificationOptions,
            clientOptions), Times.Once);
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_WhenVerificationFails_ReturnsFailure()
    {
        // Arrange
        var testMessage = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new InvalidOperationException("Receipt signature invalid"));

        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act
        var result = await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("Receipt signature invalid"));
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_WhenCryptographicExceptionThrown_ReturnsFailure()
    {
        // Arrange
        var testMessage = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new CryptographicException("Key verification failed"));

        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act
        var result = await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors[0], Does.Contain("Cryptographic error"));
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_WhenCborExceptionThrown_ReturnsFailure()
    {
        // Arrange
        var testMessage = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new CborContentException("Invalid CBOR structure"));

        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act
        var result = await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors[0], Does.Contain("CBOR content error"));
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_WhenArgumentExceptionThrown_ReturnsFailure()
    {
        // Arrange
        var testMessage = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new ArgumentException("Invalid authorized domain"));

        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act
        var result = await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors[0], Does.Contain("Invalid argument"));
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_WhenAggregateExceptionThrown_ReturnsAllErrors()
    {
        // Arrange
        var testMessage = CreateMessageWithMstReceipt();

        var innerExceptions = new[]
        {
            new InvalidOperationException("Error 1"),
            new InvalidOperationException("Error 2")
        };

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new AggregateException(innerExceptions));

        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act
        var result = await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.EqualTo(2));
        Assert.That(result.Errors[0], Does.Contain("Error 1"));
        Assert.That(result.Errors[1], Does.Contain("Error 2"));
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_LogsVerificationProgress()
    {
        // Arrange
        var logs = new List<string>();
        var errors = new List<string>();
        var testMessage = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()));

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null,
            null,
            msg => logs.Add(msg),
            msg => errors.Add(msg));

        // Act
        await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(logs.Any(l => l.Contains("Starting transparency verification")), Is.True);
        Assert.That(logs.Any(l => l.Contains("MST receipt found")), Is.True);
        Assert.That(logs.Any(l => l.Contains("Verification succeeded")), Is.True);
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_LogsVerificationOptionsWhenConfigured()
    {
        // Arrange
        var logs = new List<string>();
        var testMessage = CreateMessageWithMstReceipt();
        var verificationOptions = new CodeTransparencyVerificationOptions
        {
            AuthorizedDomains = new List<string> { "test.example.com" }
        };

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()));

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            verificationOptions,
            null,
            msg => logs.Add(msg),
            null);

        // Act
        await provider.VerifyTransparencyProofAsync(testMessage);

        // Assert
        Assert.That(logs.Any(l => l.Contains("test.example.com")), Is.True);
        Assert.That(logs.Any(l => l.Contains("Authorized receipt behavior")), Is.True);
        Assert.That(logs.Any(l => l.Contains("Unauthorized receipt behavior")), Is.True);
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_RespectsCanncellationToken()
    {
        // Arrange
        var testMessage = CreateMessageWithMstReceipt();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var provider = new MstTransparencyProvider(MockClient.Object, MockVerifier.Object, null, null, null, null);

        // Act & Assert
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await provider.VerifyTransparencyProofAsync(testMessage, cts.Token));
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Creates a test COSE Sign1 message with the given payload.
    /// </summary>
    private CoseSign1Message CreateTestSignedMessage(string payload)
    {
        using var key = TestCert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
        var signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    /// <summary>
    /// Creates a CBOR-encoded response containing an EntryId field (as MST returns).
    /// </summary>
    private static BinaryData CreateCborEntryIdResponse(string entryId)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteTextString("EntryId");
        writer.WriteTextString(entryId);
        writer.WriteEndMap();
        return BinaryData.FromBytes(writer.Encode());
    }

    /// <summary>
    /// Creates a mock Operation for CreateEntryAsync.
    /// </summary>
    private static Mock<Operation<BinaryData>> CreateMockOperation(bool hasValue, BinaryData? value)
    {
        var mock = new Mock<Operation<BinaryData>>();
        mock.Setup(o => o.HasValue).Returns(hasValue);
        if (value != null)
        {
            mock.Setup(o => o.Value).Returns(value);
        }
        return mock;
    }

    /// <summary>
    /// Creates a mock Response containing BinaryData.
    /// </summary>
    private static Response<BinaryData> CreateMockResponse(byte[] content)
    {
        var mockResponse = new Mock<Response>();
        return Response.FromValue(BinaryData.FromBytes(content), mockResponse.Object);
    }

    /// <summary>
    /// Creates a CoseSign1Message with an MST receipt in unprotected headers.
    /// </summary>
    private CoseSign1Message CreateMessageWithMstReceipt()
    {
        // Create a minimal MST receipt (COSE_Sign1 structure for label 394)
        var receiptWriter = new CborWriter();
        receiptWriter.WriteStartArray(4);  // COSE_Sign1: [protected, unprotected, payload, signature]
        receiptWriter.WriteByteString(new byte[] { 0xA0 });  // Empty protected header map
        receiptWriter.WriteStartMap(0);  // Empty unprotected headers
        receiptWriter.WriteEndMap();
        receiptWriter.WriteNull();  // No payload
        receiptWriter.WriteByteString(new byte[64]);  // Dummy signature
        receiptWriter.WriteEndArray();
        var receiptBytes = receiptWriter.Encode();

        // Build the message with the receipt in unprotected headers
        // Protected header with algorithm
        var protectedWriter = new CborWriter();
        protectedWriter.WriteStartMap(1);
        protectedWriter.WriteInt32(1);  // alg label
        protectedWriter.WriteInt32(-7); // ES256
        protectedWriter.WriteEndMap();
        var protectedBytes = protectedWriter.Encode();

        // Unprotected headers with receipt at label 394
        var unprotectedWriter = new CborWriter();
        unprotectedWriter.WriteStartMap(1);
        unprotectedWriter.WriteInt32(394);  // Receipt label
        unprotectedWriter.WriteByteString(receiptBytes);
        unprotectedWriter.WriteEndMap();

        // Payload
        var payload = System.Text.Encoding.UTF8.GetBytes("test payload");

        // Create signature
        using var key = TestCert.GetECDsaPrivateKey()!;
        var toBeSigned = CreateToBeSigned(protectedBytes, payload);
        var signature = key.SignData(toBeSigned, HashAlgorithmName.SHA256);

        // Build the complete COSE_Sign1 structure
        var messageWriter = new CborWriter();
        messageWriter.WriteTag(CoseSign1Tag);
        messageWriter.WriteStartArray(4);
        messageWriter.WriteByteString(protectedBytes);
        
        // Write unprotected headers map directly
        messageWriter.WriteStartMap(1);
        messageWriter.WriteInt32(394);
        messageWriter.WriteByteString(receiptBytes);
        messageWriter.WriteEndMap();
        
        messageWriter.WriteByteString(payload);
        messageWriter.WriteByteString(signature);
        messageWriter.WriteEndArray();

        return CoseMessage.DecodeSign1(messageWriter.Encode());
    }

    private const CborTag CoseSign1Tag = (CborTag)18;

    private static byte[] CreateToBeSigned(byte[] protectedHeaders, byte[] payload)
    {
        var writer = new CborWriter();
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeaders);
        writer.WriteByteString(Array.Empty<byte>()); // external_aad
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        return writer.Encode();
    }

    #endregion
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST.Validation;
using Moq;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class MstReceiptValidatorTests
{
    private Mock<CodeTransparencyClient> MockClient = null!;
    private Mock<MstTransparencyProvider> MockProvider = null!;
    private Mock<ICodeTransparencyVerifier> MockVerifier = null!;
    private X509Certificate2 TestCert = null!;

    [SetUp]
    public void Setup()
    {
        MockClient = new Mock<CodeTransparencyClient>();
        MockVerifier = new Mock<ICodeTransparencyVerifier>();
        MockProvider = new Mock<MstTransparencyProvider>(
            MockClient.Object,
            MockVerifier.Object,
            null, null, null, null);
        TestCert = TestCertificateUtils.CreateCertificate("MstValidatorTestCert", useEcc: true);
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithClient_CreatesValidator()
    {
        // Arrange & Act
        var validator = new MstReceiptValidator(MockClient.Object);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullClient_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        Assert.Throws<ArgumentNullException>(() => new MstReceiptValidator((CodeTransparencyClient)null!));
    }

    [Test]
    public void Constructor_WithClientAndOptions_CreatesValidator()
    {
        // Arrange
        var verificationOptions = new CodeTransparencyVerificationOptions();

        // Act
        var validator = new MstReceiptValidator(MockClient.Object, verificationOptions);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithClientAndNullVerificationOptions_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new MstReceiptValidator(MockClient.Object, null!));
    }

    [Test]
    public void Constructor_WithClientOptionsAndClientOptions_CreatesValidator()
    {
        // Arrange
        var verificationOptions = new CodeTransparencyVerificationOptions();
        var clientOptions = new CodeTransparencyClientOptions();

        // Act
        var validator = new MstReceiptValidator(MockClient.Object, verificationOptions, clientOptions);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithProvider_CreatesValidator()
    {
        // Arrange & Act
        var validator = new MstReceiptValidator(MockProvider.Object);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullProvider_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        Assert.Throws<ArgumentNullException>(() => new MstReceiptValidator((MstTransparencyProvider)null!));
    }

    #endregion

    #region ValidateAsync Tests

    [Test]
    public async Task ValidateAsync_WithNullMessage_ReturnsFailure()
    {
        // Arrange
        var validator = new MstReceiptValidator(MockClient.Object);

        // Act
        var result = await validator.ValidateAsync(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_NULL_INPUT"));
    }

    [Test]
    public async Task ValidateAsync_WithoutMstReceipt_ReturnsFailure()
    {
        // Arrange
        var message = CreateTestMessage("test payload");
        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_NO_RECEIPT"));
    }

    [Test]
    public async Task ValidateAsync_WithValidReceipt_ReturnsSuccess()
    {
        // Arrange
        var message = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()));

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata, Contains.Key("ProviderName"));
    }

    [Test]
    public async Task ValidateAsync_WhenVerificationFails_ReturnsFailure()
    {
        // Arrange
        var message = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new InvalidOperationException("Verification failed"));

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.GreaterThan(0));
    }

    [Test]
    public async Task ValidateAsync_WhenExceptionThrown_ReturnsFailureWithException()
    {
        // Arrange
        var message = CreateMessageWithMstReceipt();
        var expectedException = new Exception("Unexpected error");

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(expectedException);

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_VERIFICATION_EXCEPTION"));
    }

    [Test]
    public async Task ValidateAsync_WithCancellation_ReturnsFailure()
    {
        // Arrange
        var message = CreateMessageWithMstReceipt();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // The exception is caught and converted to a failure result
        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new OperationCanceledException());

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message, cts.Token);

        // Assert - Cancellation is caught and returned as failure
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_VERIFICATION_EXCEPTION"));
    }

    #endregion

    #region Validate (Synchronous) Tests

    [Test]
    public void Validate_WithNullMessage_ReturnsFailure()
    {
        // Arrange
        var validator = new MstReceiptValidator(MockClient.Object);

        // Act
        var result = validator.Validate(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_NULL_INPUT"));
    }

    [Test]
    public void Validate_WithoutMstReceipt_ReturnsFailure()
    {
        // Arrange
        var message = CreateTestMessage("test payload");
        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_NO_RECEIPT"));
    }

    [Test]
    public void Validate_WithValidReceipt_ReturnsSuccess()
    {
        // Arrange
        var message = CreateMessageWithMstReceipt();

        MockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()));

        var provider = new MstTransparencyProvider(
            MockClient.Object,
            MockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    #endregion

    #region Helper Methods

    private CoseSign1Message CreateTestMessage(string payload)
    {
        using var key = TestCert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
        var signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private CoseSign1Message CreateMessageWithMstReceipt()
    {
        // Create a minimal MST receipt (COSE_Sign1 structure for label 394)
        var receiptWriter = new CborWriter();
        receiptWriter.WriteStartArray(4);
        receiptWriter.WriteByteString(new byte[] { 0xA0 });
        receiptWriter.WriteStartMap(0);
        receiptWriter.WriteEndMap();
        receiptWriter.WriteNull();
        receiptWriter.WriteByteString(new byte[64]);
        receiptWriter.WriteEndArray();
        var receiptBytes = receiptWriter.Encode();

        // Wrap in CBOR array
        var arrayWriter = new CborWriter();
        arrayWriter.WriteStartArray(1);
        arrayWriter.WriteByteString(receiptBytes);
        arrayWriter.WriteEndArray();
        var receiptsArrayBytes = arrayWriter.Encode();

        // Build protected headers with algorithm
        var protectedWriter = new CborWriter();
        protectedWriter.WriteStartMap(1);
        protectedWriter.WriteInt32(1);
        protectedWriter.WriteInt32(-7);
        protectedWriter.WriteEndMap();
        var protectedBytes = protectedWriter.Encode();

        // Payload
        var payload = System.Text.Encoding.UTF8.GetBytes("test payload");

        // Create signature
        using var key = TestCert.GetECDsaPrivateKey()!;
        var toBeSigned = CreateToBeSigned(protectedBytes, payload);
        var signature = key.SignData(toBeSigned, HashAlgorithmName.SHA256);

        // Build COSE_Sign1 with receipt in unprotected header
        var messageWriter = new CborWriter();
        messageWriter.WriteTag((CborTag)18);
        messageWriter.WriteStartArray(4);
        messageWriter.WriteByteString(protectedBytes);

        messageWriter.WriteStartMap(1);
        messageWriter.WriteInt32(394);
        messageWriter.WriteEncodedValue(receiptsArrayBytes);
        messageWriter.WriteEndMap();

        messageWriter.WriteByteString(payload);
        messageWriter.WriteByteString(signature);
        messageWriter.WriteEndArray();

        return CoseMessage.DecodeSign1(messageWriter.Encode());
    }

    private static byte[] CreateToBeSigned(byte[] protectedHeaders, byte[] payload)
    {
        var writer = new CborWriter();
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeaders);
        writer.WriteByteString(Array.Empty<byte>());
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        return writer.Encode();
    }

    #endregion
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.CodeTransparency;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;
using Moq;

[TestFixture]
public class MstReceiptValidatorTests
{
    private static X509Certificate2 CreateTestCert() =>
        TestCertificateUtils.CreateCertificate("MstValidatorTestCert", useEcc: true);

    private static Mock<CodeTransparencyClient> CreateMockClient() => new();

    private static Mock<ICodeTransparencyVerifier> CreateMockVerifier() => new();

    private static Mock<MstTransparencyProvider> CreateMockProvider(
        Mock<CodeTransparencyClient> mockClient,
        Mock<ICodeTransparencyVerifier> mockVerifier) =>
        new(mockClient.Object, mockVerifier.Object, null, null, null, null);

    #region Constructor Tests

    [Test]
    public void Constructor_WithClient_CreatesValidator()
    {
        // Arrange & Act
        var mockClient = CreateMockClient();
        var validator = new MstReceiptValidator(mockClient.Object);

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
        var mockClient = CreateMockClient();
        var verificationOptions = new CodeTransparencyVerificationOptions();

        // Act
        var validator = new MstReceiptValidator(mockClient.Object, verificationOptions);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithClientAndNullVerificationOptions_ThrowsArgumentNullException()
    {
        // Act & Assert
        var mockClient = CreateMockClient();
        Assert.Throws<ArgumentNullException>(() =>
            new MstReceiptValidator(mockClient.Object, null!));
    }

    [Test]
    public void Constructor_WithClientOptionsAndClientOptions_CreatesValidator()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var verificationOptions = new CodeTransparencyVerificationOptions();
        var clientOptions = new CodeTransparencyClientOptions();

        // Act
        var validator = new MstReceiptValidator(mockClient.Object, verificationOptions, clientOptions);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithProvider_CreatesValidator()
    {
        // Arrange & Act
        var mockClient = CreateMockClient();
        var mockVerifier = CreateMockVerifier();
        var mockProvider = CreateMockProvider(mockClient, mockVerifier);
        var validator = new MstReceiptValidator(mockProvider.Object);

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
        var mockClient = CreateMockClient();
        var validator = new MstReceiptValidator(mockClient.Object);

        // Act
        var result = await validator.ValidateAsync(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_NULL_INPUT"));
    }

    [Test]
    public async Task ValidateAsync_WhenStageIsNotKeyMaterialTrust_ReturnsNotApplicable()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var validator = new MstReceiptValidator(mockClient.Object);

        // Act
        var result = await validator.ValidateAsync(null!, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsNotApplicable, Is.True);
        Assert.That(result.IsFailure, Is.False);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public async Task ValidateAsync_WithoutMstReceipt_ReturnsSuccessWithNegativeTrustAssertions()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = CreateMockVerifier();
        using var cert = CreateTestCert();
        var message = CreateTestMessage(cert, "test payload");
        var provider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptPresent && a.Satisfied == false));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptTrusted && a.Satisfied == false && a.Details == "NoReceipt"));
    }

    [Test]
    public async Task ValidateAsync_WithValidReceipt_ReturnsSuccess()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = CreateMockVerifier();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        mockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()));

        var provider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));
        Assert.That(result.Metadata, Contains.Key("ProviderName"));

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptPresent && a.Satisfied));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptTrusted && a.Satisfied));
    }

    [Test]
    public async Task ValidateAsync_WhenVerificationFails_ReturnsSuccessWithNegativeTrustedAssertion()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = CreateMockVerifier();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        mockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new InvalidOperationException("Verification failed"));

        var provider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));
        Assert.That(result.Metadata, Contains.Key("ProviderName"));
        Assert.That(result.Metadata, Contains.Key("Errors"));

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptPresent && a.Satisfied));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptTrusted && a.Satisfied == false && a.Details == "VerificationFailed"));
    }

    [Test]
    public async Task ValidateAsync_WhenExceptionThrown_ReturnsSuccessWithExceptionMetadata()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = CreateMockVerifier();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);
        var expectedException = new Exception("Unexpected error");

        mockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(expectedException);

        var provider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));
        Assert.That(result.Metadata, Contains.Key("ExceptionType"));
        Assert.That(result.Metadata, Contains.Key("ExceptionMessage"));

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptPresent && a.Satisfied));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptTrusted && a.Satisfied == false && a.Details == "Exception"));
    }

    [Test]
    public async Task ValidateAsync_WithCancellation_ReturnsSuccessWithNegativeTrustedAssertion()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = CreateMockVerifier();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // The exception is caught and converted to a failure result
        mockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new OperationCanceledException());

        var provider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust, cts.Token);

        // Assert - Cancellation is treated as an exception and modeled as a negative trust claim.
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptPresent && a.Satisfied));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptTrusted && a.Satisfied == false && a.Details == "Exception"));
    }

    #endregion

    #region Validate (Synchronous) Tests

    [Test]
    public void Validate_WithNullMessage_ReturnsFailure()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var validator = new MstReceiptValidator(mockClient.Object);

        // Act
        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_NULL_INPUT"));
    }

    [Test]
    public void Validate_WhenStageIsNotKeyMaterialTrust_ReturnsNotApplicable()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var validator = new MstReceiptValidator(mockClient.Object);

        // Act
        var result = validator.Validate(null!, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsNotApplicable, Is.True);
        Assert.That(result.IsFailure, Is.False);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public void Validate_WithoutMstReceipt_ReturnsSuccessWithNegativeTrustAssertions()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = CreateMockVerifier();
        using var cert = CreateTestCert();
        var message = CreateTestMessage(cert, "test payload");
        var provider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptPresent && a.Satisfied == false));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptTrusted && a.Satisfied == false && a.Details == "NoReceipt"));
    }

    [Test]
    public void Validate_WithValidReceipt_ReturnsSuccess()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = CreateMockVerifier();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        mockVerifier
            .Setup(v => v.VerifyTransparentStatement(
                It.IsAny<byte[]>(),
                It.IsAny<CodeTransparencyVerificationOptions?>(),
                It.IsAny<CodeTransparencyClientOptions?>()));

        var provider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null, null, null, null);
        var validator = new MstReceiptValidator(provider);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.KeyMaterialTrust));

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptPresent && a.Satisfied));
        Assert.That(assertions, Has.One.Matches<TrustAssertion>(a => a.ClaimId == MstTrustClaims.ReceiptTrusted && a.Satisfied));
    }

    #endregion

    #region IsApplicable Tests

    [Test]
    public void IsApplicable_WithNullInput_ReturnsFalse()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var validator = new MstReceiptValidator(mockClient.Object);

        // Act
        var isApplicable = validator.IsApplicable(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(isApplicable, Is.False);
    }

    [Test]
    public void IsApplicable_WhenStageIsNotKeyMaterialTrust_ReturnsFalse()
    {
        // Arrange
        var mockClient = CreateMockClient();
        using var cert = CreateTestCert();
        var validator = new MstReceiptValidator(mockClient.Object);
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var isApplicable = validator.IsApplicable(message, ValidationStage.Signature);

        // Assert
        Assert.That(isApplicable, Is.False);
    }

    [Test]
    public void IsApplicable_WithoutMstReceipt_ReturnsFalse()
    {
        // Arrange
        var mockClient = CreateMockClient();
        using var cert = CreateTestCert();
        var validator = new MstReceiptValidator(mockClient.Object);
        var message = CreateTestMessage(cert, "test payload");

        // Act
        var isApplicable = validator.IsApplicable(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(isApplicable, Is.False);
    }

    [Test]
    public void IsApplicable_WithMstReceipt_ReturnsTrue()
    {
        // Arrange
        var mockClient = CreateMockClient();
        using var cert = CreateTestCert();
        var validator = new MstReceiptValidator(mockClient.Object);
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var isApplicable = validator.IsApplicable(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(isApplicable, Is.True);
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateTestMessage(X509Certificate2 cert, string payload)
    {
        using var key = cert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
        var signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateMessageWithMstReceipt(X509Certificate2 cert)
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
        using var key = cert.GetECDsaPrivateKey()!;
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
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using CoseSign1.Validation;
using CoseSignTool.MST.Plugin;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the MstReceiptPresenceValidator class.
/// </summary>
[TestFixture]
public class MstReceiptPresenceValidatorTests
{
    private MstReceiptPresenceValidator Validator = null!;
    private CoseSign1Message? ValidMessageWithoutReceipt;
    private X509Certificate2? TestCert;

    [SetUp]
#pragma warning disable CA2252 // Preview features
    public void Setup()
    {
        Validator = new MstReceiptPresenceValidator();

        // Create a test certificate
        var certFactory = new EphemeralCertificateFactory();
        TestCert = certFactory.CreateCertificate(opts =>
        {
            opts.WithSubjectName("CN=MstReceiptPresenceValidatorTest")
                .WithKeyAlgorithm(KeyAlgorithm.RSA)
                .WithKeySize(2048)
                .ForTlsAuthentication();
        });

        // Create a valid COSE message without MST receipt
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        ValidMessageWithoutReceipt = CoseSign1Message.DecodeSign1(messageBytes);
    }
#pragma warning restore CA2252

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        // Act
        var result = Validator.Validate(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        // Act
        var result = await Validator.ValidateAsync(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public void Validate_WithMessageWithoutReceipt_ReturnsFailure()
    {
        // Act
        var result = Validator.Validate(ValidMessageWithoutReceipt!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_RECEIPT_NOT_FOUND"));
    }

    [Test]
    public async Task ValidateAsync_WithMessageWithoutReceipt_ReturnsFailure()
    {
        // Act
        var result = await Validator.ValidateAsync(ValidMessageWithoutReceipt!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_RECEIPT_NOT_FOUND"));
    }

    [Test]
    public void Validator_ImplementsIValidator()
    {
        // Assert
        Assert.That(Validator, Is.AssignableTo<IValidator<CoseSign1Message>>());
    }

    [Test]
    public async Task ValidateAsync_ReturnsSameResultAsValidate()
    {
        // Act
        var syncResult = Validator.Validate(ValidMessageWithoutReceipt!);
        var asyncResult = await Validator.ValidateAsync(ValidMessageWithoutReceipt!);

        // Assert - both should return same failure for message without receipt
        Assert.That(syncResult.IsValid, Is.EqualTo(asyncResult.IsValid));
        Assert.That(syncResult.Failures[0].ErrorCode, Is.EqualTo(asyncResult.Failures[0].ErrorCode));
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_Completes()
    {
        // Arrange
        using var cts = new CancellationTokenSource();

        // Act
        var result = await Validator.ValidateAsync(ValidMessageWithoutReceipt!, cts.Token);

        // Assert - should complete without throwing
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_RECEIPT_NOT_FOUND"));
    }

    [Test]
    public void Validate_WithValidReceipt_ReturnsSuccess()
    {
        // Arrange
        var messageWithReceipt = CreateMessageWithValidMstReceipt();

        // Act
        var result = Validator.Validate(messageWithReceipt);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata, Contains.Key("ReceiptCount"));
        Assert.That(result.Metadata["ReceiptCount"], Is.EqualTo(1));
        Assert.That(result.Metadata, Contains.Key("ReceiptSizes"));
    }

    [Test]
    public async Task ValidateAsync_WithValidReceipt_ReturnsSuccess()
    {
        // Arrange
        var messageWithReceipt = CreateMessageWithValidMstReceipt();

        // Act
        var result = await Validator.ValidateAsync(messageWithReceipt);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["ReceiptCount"], Is.EqualTo(1));
    }

    [Test]
    public void Validate_WithMultipleReceipts_ReturnsSuccessWithCorrectCount()
    {
        // Arrange
        var messageWithReceipts = CreateMessageWithMultipleReceipts(3);

        // Act
        var result = Validator.Validate(messageWithReceipts);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["ReceiptCount"], Is.EqualTo(3));
        var receiptSizes = result.Metadata["ReceiptSizes"] as int[];
        Assert.That(receiptSizes, Is.Not.Null);
        Assert.That(receiptSizes, Has.Length.EqualTo(3));
    }

    #region Helper Methods

    private CoseSign1Message CreateMessageWithValidMstReceipt()
    {
        return CreateMessageWithMultipleReceipts(1);
    }

    private CoseSign1Message CreateMessageWithMultipleReceipts(int count)
    {
        // Create minimal valid COSE_Sign1 receipts
        var arrayWriter = new CborWriter();
        arrayWriter.WriteStartArray(count);

        for (int i = 0; i < count; i++)
        {
            var receiptWriter = new CborWriter();
            receiptWriter.WriteStartArray(4);
            receiptWriter.WriteByteString(new byte[] { 0xA0 });
            receiptWriter.WriteStartMap(0);
            receiptWriter.WriteEndMap();
            receiptWriter.WriteNull();
            receiptWriter.WriteByteString(new byte[64]);
            receiptWriter.WriteEndArray();
            arrayWriter.WriteByteString(receiptWriter.Encode());
        }

        arrayWriter.WriteEndArray();
        var receiptsArrayBytes = arrayWriter.Encode();

        return CreateMessageWithReceiptHeader(receiptsArrayBytes);
    }

    private CoseSign1Message CreateMessageWithReceiptHeader(byte[] receiptsArrayBytes)
    {
        // Build protected headers with algorithm
        var protectedWriter = new CborWriter();
        protectedWriter.WriteStartMap(1);
        protectedWriter.WriteInt32(1);  // alg label
        protectedWriter.WriteInt32(-7); // ES256
        protectedWriter.WriteEndMap();
        var protectedBytes = protectedWriter.Encode();

        // Payload
        var payload = System.Text.Encoding.UTF8.GetBytes("test payload");

        // Create signature using the test certificate
        using var key = TestCert!.GetRSAPrivateKey()!;
        var toBeSigned = CreateToBeSigned(protectedBytes, payload);
        var signature = key.SignData(toBeSigned, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Build COSE_Sign1 with receipt in unprotected header
        var messageWriter = new CborWriter();
        messageWriter.WriteTag((CborTag)18);
        messageWriter.WriteStartArray(4);
        messageWriter.WriteByteString(protectedBytes);

        messageWriter.WriteStartMap(1);
        messageWriter.WriteInt32(394);  // Receipt label
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
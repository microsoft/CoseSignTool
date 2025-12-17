// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Azure;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST.Extensions;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class CoseSign1MessageExtensionsTests
{
    private X509Certificate2 TestCert = null!;

    [SetUp]
    public void Setup()
    {
        TestCert = TestCertificateUtils.CreateCertificate("ExtensionTestCert", useEcc: true);
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    #region HasMstReceipt Tests

    [Test]
    public void HasMstReceipt_WithNullMessage_ReturnsFalse()
    {
        // Act
        CoseSign1Message? message = null;
        var result = message.HasMstReceipt();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void HasMstReceipt_WithoutReceiptHeader_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage("test payload");

        // Act
        var result = message.HasMstReceipt();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void HasMstReceipt_WithReceiptHeader_ReturnsTrue()
    {
        // Arrange
        var message = CreateMessageWithMstReceipt();

        // Act
        var result = message.HasMstReceipt();

        // Assert
        Assert.That(result, Is.True);
    }

    #endregion

    #region GetMstReceiptBytes Tests

    [Test]
    public void GetMstReceiptBytes_WithNullMessage_ReturnsEmptyList()
    {
        // Act
        CoseSign1Message? message = null;
        var result = message.GetMstReceiptBytes();

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void GetMstReceiptBytes_WithoutReceiptHeader_ReturnsEmptyList()
    {
        // Arrange
        var message = CreateTestMessage("test payload");

        // Act
        var result = message.GetMstReceiptBytes();

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void GetMstReceiptBytes_WithReceiptHeader_ReturnsReceipts()
    {
        // Arrange
        var message = CreateMessageWithMstReceipt();

        // Act
        var result = message.GetMstReceiptBytes();

        // Assert
        Assert.That(result, Has.Count.EqualTo(1));
        Assert.That(result[0], Is.Not.Null);
        Assert.That(result[0].Length, Is.GreaterThan(0));
    }

    [Test]
    public void GetMstReceiptBytes_WithInvalidCborStructure_ReturnsEmptyList()
    {
        // Arrange - create a message with a header value that isn't properly structured
        // The header value is an integer instead of a CBOR array of byte strings
        var message = CreateMessageWithNonArrayReceipt();

        // Act
        var result = message.GetMstReceiptBytes();

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void GetMstReceiptBytes_WithNonArrayCbor_ReturnsEmptyList()
    {
        // Arrange - create a message where the receipt header is not a CBOR array
        var message = CreateMessageWithNonArrayReceipt();

        // Act
        var result = message.GetMstReceiptBytes();

        // Assert
        Assert.That(result, Is.Empty);
    }

    #endregion

    #region GetMstReceipts Tests

    [Test]
    public void GetMstReceipts_WithNullMessage_ReturnsEmptyList()
    {
        // Act
        CoseSign1Message? message = null;
        var result = message.GetMstReceipts();

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void GetMstReceipts_WithoutReceiptHeader_ReturnsEmptyList()
    {
        // Arrange
        var message = CreateTestMessage("test payload");

        // Act
        var result = message.GetMstReceipts();

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void GetMstReceipts_WithValidReceipt_ReturnsDecodedReceipt()
    {
        // Arrange
        var message = CreateMessageWithMstReceipt();

        // Act
        var result = message.GetMstReceipts();

        // Assert
        Assert.That(result, Has.Count.EqualTo(1));
        Assert.That(result[0], Is.Not.Null);
    }

    [Test]
    public void GetMstReceipts_WithInvalidReceiptBytes_SkipsInvalidReceipt()
    {
        // Arrange - create message with receipt bytes that fail COSE decoding
        var message = CreateMessageWithInvalidReceiptBytes();

        // Act
        var result = message.GetMstReceipts();

        // Assert - invalid receipts are skipped
        Assert.That(result, Is.Empty);
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
        // Create a minimal valid COSE_Sign1 structure for the receipt
        var receiptWriter = new CborWriter();
        receiptWriter.WriteStartArray(4);  // COSE_Sign1: [protected, unprotected, payload, signature]
        receiptWriter.WriteByteString(new byte[] { 0xA0 });  // Empty protected header map
        receiptWriter.WriteStartMap(0);  // Empty unprotected headers
        receiptWriter.WriteEndMap();
        receiptWriter.WriteNull();  // No payload
        receiptWriter.WriteByteString(new byte[64]);  // Dummy signature
        receiptWriter.WriteEndArray();
        var receiptBytes = receiptWriter.Encode();

        // Wrap receipts in CBOR array
        var arrayWriter = new CborWriter();
        arrayWriter.WriteStartArray(1);
        arrayWriter.WriteByteString(receiptBytes);
        arrayWriter.WriteEndArray();
        var receiptsArrayBytes = arrayWriter.Encode();

        return CreateMessageWithHeaderValue(394, receiptsArrayBytes);
    }


    private CoseSign1Message CreateMessageWithNonArrayReceipt()
    {
        // Create CBOR that's not an array (an integer instead)
        var writer = new CborWriter();
        writer.WriteInt32(12345);
        var nonArrayBytes = writer.Encode();

        return CreateMessageWithHeaderValue(394, nonArrayBytes);
    }

    private CoseSign1Message CreateMessageWithInvalidReceiptBytes()
    {
        // Create array with invalid COSE_Sign1 bytes
        var arrayWriter = new CborWriter();
        arrayWriter.WriteStartArray(1);
        arrayWriter.WriteByteString(new byte[] { 0x00, 0x01, 0x02 });  // Invalid COSE
        arrayWriter.WriteEndArray();
        var receiptsArrayBytes = arrayWriter.Encode();

        return CreateMessageWithHeaderValue(394, receiptsArrayBytes);
    }

    private CoseSign1Message CreateMessageWithHeaderValue(int headerLabel, byte[] headerValue)
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

        // Create signature
        using var key = TestCert.GetECDsaPrivateKey()!;
        var toBeSigned = CreateToBeSigned(protectedBytes, payload);
        var signature = key.SignData(toBeSigned, HashAlgorithmName.SHA256);

        // Build the complete COSE_Sign1 structure with unprotected header
        var messageWriter = new CborWriter();
        messageWriter.WriteTag((CborTag)18);  // COSE_Sign1 tag
        messageWriter.WriteStartArray(4);
        messageWriter.WriteByteString(protectedBytes);

        // Write unprotected headers map with receipt
        messageWriter.WriteStartMap(1);
        messageWriter.WriteInt32(headerLabel);
        messageWriter.WriteEncodedValue(headerValue);
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
        writer.WriteByteString(Array.Empty<byte>()); // external_aad
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        return writer.Encode();
    }

    #endregion
}

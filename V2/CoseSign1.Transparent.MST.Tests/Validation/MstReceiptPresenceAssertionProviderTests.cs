// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="MstReceiptPresenceAssertionProvider"/>.
/// </summary>
[TestFixture]
[Category("MST")]
[Category("Validation")]
public class MstReceiptPresenceAssertionProviderTests
{
    private static X509Certificate2 CreateTestCert() =>
        TestCertificateUtils.CreateCertificate("MstPresenceTestCert", useEcc: true);

    #region Constructor and Basic Properties

    [Test]
    public void Constructor_CreatesValidInstance()
    {
        // Act
        var provider = new MstReceiptPresenceAssertionProvider();

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void ComponentName_ReturnsCorrectName()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();

        // Assert
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(MstReceiptPresenceAssertionProvider)));
    }

    [Test]
    public void Provider_ImplementsISigningKeyAssertionProvider()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();

        // Assert
        Assert.That(provider, Is.InstanceOf<ISigningKeyAssertionProvider>());
    }

    [Test]
    public void Provider_ImplementsIValidationComponent()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();

        // Assert
        Assert.That(provider, Is.InstanceOf<IValidationComponent>());
    }

    #endregion

    #region ExtractAssertions Tests

    [Test]
    public void ExtractAssertions_WithNullMessage_ReturnsEmptyList()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey.Object, null!);

        // Assert
        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public void ExtractAssertions_WithMessageWithoutReceipt_ReturnsTwoAssertions()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey.Object, message);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(2));
    }

    [Test]
    public void ExtractAssertions_WithMessageWithoutReceipt_ReturnsReceiptNotPresentAssertion()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey.Object, message);

        // Assert
        var presentAssertion = assertions.OfType<MstReceiptPresentAssertion>().FirstOrDefault();
        Assert.That(presentAssertion, Is.Not.Null);
        Assert.That(presentAssertion!.IsPresent, Is.False);
    }

    [Test]
    public void ExtractAssertions_WithMessageWithoutReceipt_ReturnsTrustNotVerifiedAssertion()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey.Object, message);

        // Assert
        var trustedAssertion = assertions.OfType<MstReceiptTrustedAssertion>().FirstOrDefault();
        Assert.That(trustedAssertion, Is.Not.Null);
        Assert.That(trustedAssertion!.IsTrusted, Is.False);
        Assert.That(trustedAssertion.Details, Is.EqualTo("NoReceipt"));
    }

    [Test]
    public void ExtractAssertions_WithMessageWithReceipt_ReturnsReceiptPresentAssertion()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey.Object, message);

        // Assert
        var presentAssertion = assertions.OfType<MstReceiptPresentAssertion>().FirstOrDefault();
        Assert.That(presentAssertion, Is.Not.Null);
        Assert.That(presentAssertion!.IsPresent, Is.True);
    }

    [Test]
    public void ExtractAssertions_WithMessageWithReceipt_ReturnsTrustNotVerifiedAssertion()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey.Object, message);

        // Assert
        var trustedAssertion = assertions.OfType<MstReceiptTrustedAssertion>().FirstOrDefault();
        Assert.That(trustedAssertion, Is.Not.Null);
        Assert.That(trustedAssertion!.IsTrusted, Is.False);
        Assert.That(trustedAssertion.Details, Is.EqualTo("NotVerified"));
    }

    [Test]
    public void ExtractAssertions_WithNullOptions_DoesNotThrow()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act & Assert
        Assert.DoesNotThrow(() => provider.ExtractAssertions(mockSigningKey.Object, message, null));
    }

    [Test]
    public void ExtractAssertions_WithOptions_DoesNotThrow()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");
        var options = new CoseSign1ValidationOptions();

        // Act & Assert
        Assert.DoesNotThrow(() => provider.ExtractAssertions(mockSigningKey.Object, message, options));
    }

    #endregion

    #region ExtractAssertionsAsync Tests

    [Test]
    public async Task ExtractAssertionsAsync_WithNullMessage_ReturnsEmptyList()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, null!);

        // Assert
        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithMessageWithoutReceipt_ReturnsTwoAssertions()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(2));
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithMessageWithReceipt_ReturnsCorrectAssertions()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions.OfType<MstReceiptPresentAssertion>().First().IsPresent, Is.True);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithCancellationToken_ReturnsAssertions()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");
        using var cts = new CancellationTokenSource();

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message, null, cts.Token);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(2));
    }

    [Test]
    public async Task ExtractAssertionsAsync_ResultsMatchSyncVersion()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var syncAssertions = provider.ExtractAssertions(mockSigningKey.Object, message);
        var asyncAssertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message);

        // Assert
        Assert.That(asyncAssertions.Count, Is.EqualTo(syncAssertions.Count));
        Assert.That(asyncAssertions.OfType<MstReceiptPresentAssertion>().First().IsPresent,
            Is.EqualTo(syncAssertions.OfType<MstReceiptPresentAssertion>().First().IsPresent));
    }

    #endregion

    #region IsApplicableTo Tests

    [Test]
    public void IsApplicableTo_WithNonNullMessage_ReturnsTrue()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var isApplicable = provider.IsApplicableTo(message);

        // Assert
        Assert.That(isApplicable, Is.True);
    }

    [Test]
    public void IsApplicableTo_WithMessageWithReceipt_ReturnsTrue()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var isApplicable = provider.IsApplicableTo(message);

        // Assert
        Assert.That(isApplicable, Is.True);
    }

    [Test]
    public void IsApplicableTo_WithNullMessage_ReturnsFalse()
    {
        // Arrange
        var provider = new MstReceiptPresenceAssertionProvider();

        // Act
        var isApplicable = provider.IsApplicableTo(null!);

        // Assert
        Assert.That(isApplicable, Is.False);
    }

    #endregion

    #region Helper Methods

    private const CborTag CoseSign1Tag = (CborTag)18;

    /// <summary>
    /// Creates a basic CoseSign1Message without MST receipt.
    /// </summary>
    private static CoseSign1Message CreateTestSignedMessage(X509Certificate2 cert, string payload)
    {
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
        using var key = cert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    /// <summary>
    /// Creates a CoseSign1Message with an MST receipt in unprotected headers.
    /// </summary>
    private static CoseSign1Message CreateMessageWithMstReceipt(X509Certificate2 cert)
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

        // Payload
        var payload = System.Text.Encoding.UTF8.GetBytes("test payload");

        // Create signature
        using var key = cert.GetECDsaPrivateKey()!;
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

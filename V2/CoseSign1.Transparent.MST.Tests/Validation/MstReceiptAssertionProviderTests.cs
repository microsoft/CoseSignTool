// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Tests.Common;
using CoseSign1.Validation.Interfaces;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="MstReceiptAssertionProvider"/>.
/// </summary>
[TestFixture]
[Category("MST")]
[Category("Validation")]
public class MstReceiptAssertionProviderTests
{
    private static X509Certificate2 CreateTestCert() =>
        TestCertificateUtils.CreateCertificate("MstReceiptProviderTestCert", useEcc: true);

    private static Mock<CodeTransparencyClient> CreateMockClient() => new();

    #region Constructor Tests

    [Test]
    public void Constructor_WithClient_CreatesInstance()
    {
        // Arrange
        var mockClient = CreateMockClient();

        // Act
        var provider = new MstReceiptAssertionProvider(mockClient.Object);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new MstReceiptAssertionProvider((CodeTransparencyClient)null!));
    }

    [Test]
    public void Constructor_WithClientAndOptions_CreatesInstance()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var verificationOptions = new CodeTransparencyVerificationOptions();

        // Act
        var provider = new MstReceiptAssertionProvider(mockClient.Object, verificationOptions);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullClientAndOptions_ThrowsArgumentNullException()
    {
        // Arrange
        var verificationOptions = new CodeTransparencyVerificationOptions();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new MstReceiptAssertionProvider(null!, verificationOptions));
        Assert.That(ex!.ParamName, Is.EqualTo("client"));
    }

    [Test]
    public void Constructor_WithClientAndNullOptions_ThrowsArgumentNullException()
    {
        // Arrange
        var mockClient = CreateMockClient();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new MstReceiptAssertionProvider(mockClient.Object, null!));
        Assert.That(ex!.ParamName, Is.EqualTo("verificationOptions"));
    }

    [Test]
    public void Constructor_WithClientOptionsAndClientOptions_CreatesInstance()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var verificationOptions = new CodeTransparencyVerificationOptions();
        var clientOptions = new CodeTransparencyClientOptions();

        // Act
        var provider = new MstReceiptAssertionProvider(mockClient.Object, verificationOptions, clientOptions);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithProvider_CreatesInstance()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var transparencyProvider = new MstTransparencyProvider(mockClient.Object);

        // Act
        var provider = new MstReceiptAssertionProvider(transparencyProvider);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullProvider_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new MstReceiptAssertionProvider((MstTransparencyProvider)null!));
    }

    #endregion

    #region ComponentName Tests

    [Test]
    public void ComponentName_ReturnsCorrectName()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);

        // Assert
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(MstReceiptAssertionProvider)));
    }

    #endregion

    #region Interface Implementation Tests

    [Test]
    public void Provider_ImplementsISigningKeyAssertionProvider()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);

        // Assert
        Assert.That(provider, Is.InstanceOf<ISigningKeyAssertionProvider>());
    }

    [Test]
    public void Provider_ImplementsIValidationComponent()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);

        // Assert
        Assert.That(provider, Is.InstanceOf<IValidationComponent>());
    }

    [Test]
    public void Provider_ExtendsMstValidationComponentBase()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);

        // Assert
        Assert.That(provider, Is.InstanceOf<MstValidationComponentBase>());
    }

    #endregion

    #region ExtractAssertions Tests

    [Test]
    public void ExtractAssertions_WithNullMessage_ReturnsEmptyList()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
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
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
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
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
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
    public void ExtractAssertions_WithMessageWithoutReceipt_ReturnsTrustNoReceiptAssertion()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
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
    public void ExtractAssertions_WithNullOptions_DoesNotThrow()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act & Assert
        Assert.DoesNotThrow(() => provider.ExtractAssertions(mockSigningKey.Object, message, null));
    }

    #endregion

    #region ExtractAssertionsAsync Tests

    [Test]
    public async Task ExtractAssertionsAsync_WithNullMessage_ReturnsEmptyList()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
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
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(2));
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithCancellationToken_DoesNotThrow()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");
        using var cts = new CancellationTokenSource();

        // Act & Assert
        Assert.DoesNotThrowAsync(async () =>
            await provider.ExtractAssertionsAsync(mockSigningKey.Object, message, null, cts.Token));
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithMessageWithReceipt_VerifiesReceipt()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = new Mock<ICodeTransparencyVerifier>();
        mockVerifier.Setup(v => v.VerifyTransparentStatement(
            It.IsAny<byte[]>(),
            It.IsAny<CodeTransparencyVerificationOptions?>(),
            It.IsAny<CodeTransparencyClientOptions?>()));

        var transparencyProvider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null,
            null,
            null,
            null);
        var provider = new MstReceiptAssertionProvider(transparencyProvider);
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(2));
        var presentAssertion = assertions.OfType<MstReceiptPresentAssertion>().FirstOrDefault();
        Assert.That(presentAssertion, Is.Not.Null);
        Assert.That(presentAssertion!.IsPresent, Is.True);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithValidReceipt_ReturnsTrustedAssertion()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = new Mock<ICodeTransparencyVerifier>();
        mockVerifier.Setup(v => v.VerifyTransparentStatement(
            It.IsAny<byte[]>(),
            It.IsAny<CodeTransparencyVerificationOptions?>(),
            It.IsAny<CodeTransparencyClientOptions?>()));

        var transparencyProvider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null,
            null,
            null,
            null);
        var provider = new MstReceiptAssertionProvider(transparencyProvider);
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message);

        // Assert
        var trustedAssertion = assertions.OfType<MstReceiptTrustedAssertion>().FirstOrDefault();
        Assert.That(trustedAssertion, Is.Not.Null);
        Assert.That(trustedAssertion!.IsTrusted, Is.True);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithInvalidReceipt_ReturnsVerificationFailedAssertion()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = new Mock<ICodeTransparencyVerifier>();
        mockVerifier.Setup(v => v.VerifyTransparentStatement(
            It.IsAny<byte[]>(),
            It.IsAny<CodeTransparencyVerificationOptions?>(),
            It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new CryptographicException("Invalid signature"));

        var transparencyProvider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null,
            null,
            null,
            null);
        var provider = new MstReceiptAssertionProvider(transparencyProvider);
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message);

        // Assert
        var trustedAssertion = assertions.OfType<MstReceiptTrustedAssertion>().FirstOrDefault();
        Assert.That(trustedAssertion, Is.Not.Null);
        Assert.That(trustedAssertion!.IsTrusted, Is.False);
        Assert.That(trustedAssertion.Details, Is.EqualTo("VerificationFailed"));
    }

    [Test]
    public async Task ExtractAssertionsAsync_WhenVerificationThrowsException_ReturnsExceptionAssertion()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var mockVerifier = new Mock<ICodeTransparencyVerifier>();
        mockVerifier.Setup(v => v.VerifyTransparentStatement(
            It.IsAny<byte[]>(),
            It.IsAny<CodeTransparencyVerificationOptions?>(),
            It.IsAny<CodeTransparencyClientOptions?>()))
            .Throws(new InvalidOperationException("Test exception"));

        var transparencyProvider = new MstTransparencyProvider(
            mockClient.Object,
            mockVerifier.Object,
            null,
            null,
            null,
            null);
        var provider = new MstReceiptAssertionProvider(transparencyProvider);
        var mockSigningKey = new Mock<ISigningKey>();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(mockSigningKey.Object, message);

        // Assert
        var trustedAssertion = assertions.OfType<MstReceiptTrustedAssertion>().FirstOrDefault();
        Assert.That(trustedAssertion, Is.Not.Null);
        Assert.That(trustedAssertion!.IsTrusted, Is.False);
        Assert.That(trustedAssertion.Details, Is.EqualTo("VerificationFailed"));
    }

    #endregion

    #region IsApplicableTo Tests

    [Test]
    public void IsApplicableTo_WithNonNullMessage_ReturnsTrue()
    {
        // Arrange
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
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
        var mockClient = CreateMockClient();
        var provider = new MstReceiptAssertionProvider(mockClient.Object);
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var isApplicable = provider.IsApplicableTo(message);

        // Assert
        Assert.That(isApplicable, Is.True);
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

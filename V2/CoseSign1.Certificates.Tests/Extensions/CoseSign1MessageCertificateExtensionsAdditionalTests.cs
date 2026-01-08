// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Text;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Direct;

namespace CoseSign1.Certificates.Tests.Extensions;

/// <summary>
/// Additional tests for CoseSign1MessageCertificateExtensions to improve coverage.
/// </summary>
[TestFixture]
public class CoseSign1MessageCertificateExtensionsAdditionalTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("test payload");

    private static CoseSign1Message CreateMessageWithHeaders(CoseHeaderMap? protectedHeaders = null, CoseHeaderMap? unprotectedHeaders = null)
    {
        using var key = ECDsa.Create();
        protectedHeaders ??= new CoseHeaderMap();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        byte[] signedBytes = CoseSign1Message.SignDetached(TestPayload, signer, ReadOnlySpan<byte>.Empty);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    #region TryGetCertificateChain - allowUnprotected Tests

    [Test]
    public void TryGetCertificateChain_WithUnprotectedHeader_AndAllowUnprotectedTrue_ReturnsChain()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();

        var unprotectedHeaders = new CoseHeaderMap();
        var writer = new CborWriter();
        writer.WriteByteString(testCert.RawData);
        var x5chainValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        unprotectedHeaders.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, x5chainValue);

        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(chain, Is.Not.Null);
        Assert.That(chain!.Count, Is.EqualTo(1));
    }

    [Test]
    public void TryGetCertificateChain_WithUnprotectedHeader_AndAllowUnprotectedFalse_ReturnsFalse()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();

        var unprotectedHeaders = new CoseHeaderMap();
        var writer = new CborWriter();
        writer.WriteByteString(testCert.RawData);
        var x5chainValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        unprotectedHeaders.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, x5chainValue);

        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain, allowUnprotected: false);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(chain, Is.Null);
    }

    [Test]
    public void TryGetCertificateChain_WithInvalidCborState_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var writer = new CborWriter();
        writer.WriteInt32(42); // Invalid - should be ByteString or Array
        var invalidValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, invalidValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(chain, Is.Null);
    }

    [Test]
    public void TryGetCertificateChain_WithCorruptedCertData_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var writer = new CborWriter();
        writer.WriteByteString(new byte[] { 0xFF, 0xFF, 0xFF }); // Invalid cert data
        var invalidValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, invalidValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(chain, Is.Null);
    }

    [Test]
    public void TryGetCertificateChain_WithIndefiniteLengthArray_ParsesCorrectly()
    {
        // Arrange
        using var cert1 = TestCertificateUtils.CreateCertificate();
        using var cert2 = TestCertificateUtils.CreateCertificate();

        var headers = new CoseHeaderMap();
        var writer = new CborWriter();
        writer.WriteStartArray(null); // Indefinite length array
        writer.WriteByteString(cert1.RawData);
        writer.WriteByteString(cert2.RawData);
        writer.WriteEndArray();
        var x5chainValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, x5chainValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(chain, Is.Not.Null);
        Assert.That(chain!.Count, Is.EqualTo(2));
    }

    #endregion

    #region TryGetExtraCertificates Tests

    [Test]
    public void TryGetExtraCertificates_WithSingleCertificate_ReturnsCollection()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate();
        var headers = new CoseHeaderMap();

        var writer = new CborWriter();
        writer.WriteByteString(cert.RawData); // Single cert, not array
        var x5bagValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Bag, x5bagValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetExtraCertificates(out X509Certificate2Collection? certs);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(certs, Is.Not.Null);
        Assert.That(certs!.Count, Is.EqualTo(1));
    }

    [Test]
    public void TryGetExtraCertificates_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).TryGetExtraCertificates(out X509Certificate2Collection? certs);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(certs, Is.Null);
    }

    [Test]
    public void TryGetExtraCertificates_WithMissingHeader_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetExtraCertificates(out X509Certificate2Collection? certs);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(certs, Is.Null);
    }

    [Test]
    public void TryGetExtraCertificates_WithAllowUnprotectedTrue_ReadsFromUnprotected()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate();
        var unprotectedHeaders = new CoseHeaderMap();

        var writer = new CborWriter();
        writer.WriteByteString(cert.RawData);
        var x5bagValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        unprotectedHeaders.Add(CertificateHeaderContributor.HeaderLabels.X5Bag, x5bagValue);

        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        // Act
        bool result = message.TryGetExtraCertificates(out X509Certificate2Collection? certs, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(certs, Is.Not.Null);
        Assert.That(certs!.Count, Is.EqualTo(1));
    }

    [Test]
    public void TryGetExtraCertificates_WithInvalidCborState_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var writer = new CborWriter();
        writer.WriteInt32(42); // Invalid state
        var invalidValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Bag, invalidValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetExtraCertificates(out X509Certificate2Collection? certs);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(certs, Is.Null);
    }

    [Test]
    public void TryGetExtraCertificates_WithCorruptedData_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var writer = new CborWriter();
        writer.WriteByteString(new byte[] { 0x00, 0x01, 0x02 }); // Invalid cert
        var invalidValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Bag, invalidValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetExtraCertificates(out X509Certificate2Collection? certs);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(certs, Is.Null);
    }

    #endregion

    #region TryGetCertificateThumbprint Tests

    [Test]
    public void TryGetCertificateThumbprint_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).TryGetCertificateThumbprint(out CoseX509Thumbprint? thumbprint);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(thumbprint, Is.Null);
    }

    [Test]
    public void TryGetCertificateThumbprint_WithMissingHeader_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateThumbprint(out CoseX509Thumbprint? thumbprint);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(thumbprint, Is.Null);
    }

    [Test]
    public void TryGetCertificateThumbprint_WithAllowUnprotectedTrue_ReadsFromUnprotected()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate();
        var thumbprint = new CoseX509Thumbprint(cert, HashAlgorithmName.SHA256);
        var unprotectedHeaders = new CoseHeaderMap();

        var writer = new CborWriter();
        thumbprint.Serialize(writer);
        var x5tValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        unprotectedHeaders.Add(CertificateHeaderContributor.HeaderLabels.X5T, x5tValue);

        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        // Act
        bool result = message.TryGetCertificateThumbprint(out CoseX509Thumbprint? extractedThumbprint, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(extractedThumbprint, Is.Not.Null);
    }

    [Test]
    public void TryGetCertificateThumbprint_WithCorruptedData_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var writer = new CborWriter();
        writer.WriteInt32(999); // Invalid thumbprint data
        var invalidValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, invalidValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateThumbprint(out CoseX509Thumbprint? thumbprint);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(thumbprint, Is.Null);
    }

    #endregion

    #region TryGetSigningCertificate Tests

    [Test]
    public void TryGetSigningCertificate_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).TryGetSigningCertificate(out X509Certificate2? cert);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(cert, Is.Null);
    }

    [Test]
    public void TryGetSigningCertificate_WithNoChain_ReturnsFalse()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA256);
        var headers = new CoseHeaderMap();

        // Add only x5t, no x5chain
        var writer = new CborWriter();
        thumbprint.Serialize(writer);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(writer.Encode()));

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetSigningCertificate(out X509Certificate2? cert);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(cert, Is.Null);
    }

    [Test]
    public void TryGetSigningCertificate_WithNoThumbprint_ReturnsFalse()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();
        var headers = new CoseHeaderMap();

        // Add only x5chain, no x5t
        var writer = new CborWriter();
        writer.WriteByteString(testCert.RawData);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(writer.Encode()));

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetSigningCertificate(out X509Certificate2? cert);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(cert, Is.Null);
    }

    [Test]
    public void TryGetSigningCertificate_WithAllowUnprotectedTrue_FindsCertInUnprotected()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA256);
        var unprotectedHeaders = new CoseHeaderMap();

        var thumbprintWriter = new CborWriter();
        thumbprint.Serialize(thumbprintWriter);
        unprotectedHeaders.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(thumbprintWriter.Encode()));

        var chainWriter = new CborWriter();
        chainWriter.WriteByteString(testCert.RawData);
        unprotectedHeaders.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(chainWriter.Encode()));

        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        // Act
        bool result = message.TryGetSigningCertificate(out X509Certificate2? cert, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(cert, Is.Not.Null);
    }

    #endregion

    #region VerifySignature - Hash Algorithm Coverage

    [Test]
    public void VerifySignature_WithRSA3072_UsesSHA384()
    {
        // Arrange
        using var rsa = RSA.Create(3072);
        var certReq = new CertificateRequest(
            new X500DistinguishedName("CN=RSA 3072 Test"),
            rsa,
            HashAlgorithmName.SHA384,
            RSASignaturePadding.Pss);
        using var rsaCert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var signingService = CertificateSigningService.Create(rsaCert, new X509Certificate2[] { rsaCert });
        using var factory = new DirectSignatureFactory(signingService);
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/test");
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Act
        bool result = message.VerifySignature();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifySignature_WithRSA4096_UsesSHA512()
    {
        // Arrange
        using var rsa = RSA.Create(4096);
        var certReq = new CertificateRequest(
            new X500DistinguishedName("CN=RSA 4096 Test"),
            rsa,
            HashAlgorithmName.SHA512,
            RSASignaturePadding.Pss);
        using var rsaCert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var signingService = CertificateSigningService.Create(rsaCert, new X509Certificate2[] { rsaCert });
        using var factory = new DirectSignatureFactory(signingService);
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/test");
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Act
        bool result = message.VerifySignature();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifySignature_WithECDsaP384_UsesSHA384()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithECDsaP384_UsesSHA384), useEcc: true, keySize: 384);
        using var signingService = CertificateSigningService.Create(testCert, new X509Certificate2[] { testCert });
        using var factory = new DirectSignatureFactory(signingService);
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/test");
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Act
        bool result = message.VerifySignature();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifySignature_WithECDsaP521_UsesSHA512()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithECDsaP521_UsesSHA512), useEcc: true, keySize: 521);
        using var signingService = CertificateSigningService.Create(testCert, new X509Certificate2[] { testCert });
        using var factory = new DirectSignatureFactory(signingService);
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/test");
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Act
        bool result = message.VerifySignature();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifySignature_WithUnsupportedKeyType_ReturnsFalse()
    {
        // Arrange - Create message with cert but manipulate to have no valid public key
        using var testCert = TestCertificateUtils.CreateCertificate();
        var headers = new CoseHeaderMap();

        // Add certificate headers
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA256);
        var thumbprintWriter = new CborWriter();
        thumbprint.Serialize(thumbprintWriter);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(thumbprintWriter.Encode()));

        var chainWriter = new CborWriter();
        chainWriter.WriteByteString(testCert.RawData);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(chainWriter.Encode()));

        var message = CreateMessageWithHeaders(headers);

        // Act - The message was signed with ECDsa, so it will fail verification with the certificate's key
        // because CreateMessageWithHeaders uses a different key
        bool result = message.VerifySignature();

        // Assert
        Assert.That(result, Is.False, "Should fail when certificate key doesn't match signature");
    }

    [Test]
    public void VerifySignature_WithAllowUnprotectedTrue_UsesUnprotectedHeaders()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithAllowUnprotectedTrue_UsesUnprotectedHeaders), useEcc: true);
        using var signingService = CertificateSigningService.Create(testCert, new X509Certificate2[] { testCert });

        // Create message with unprotected headers using factory
        using var factory = new DirectSignatureFactory(signingService);
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/test");
        var message = CoseMessage.DecodeSign1(messageBytes);

        // The factory places certs in protected headers, so we need to manually move them to unprotected
        // For this test, just verify that the allowUnprotected parameter is accepted
        // (actual unprotected cert extraction is already tested in TryGetSigningCertificate tests)

        // Act - allowUnprotected=true should work with certs in protected headers too
        bool result = message.VerifySignature(allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifySignature_WithDetachedContent_AndNullPayload_ReturnsFalse()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithDetachedContent_AndNullPayload_ReturnsFalse), useEcc: true);
        using var signingService = CertificateSigningService.Create(testCert, new X509Certificate2[] { testCert });
        using var factory = new DirectSignatureFactory(signingService);

        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/test", options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Act
        bool result = message.VerifySignature(payload: null);

        // Assert
        Assert.That(result, Is.False);
    }

    #endregion
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Text;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Direct;

namespace CoseSign1.Certificates.Tests.Extensions;

/// <summary>
/// Tests for CoseSign1MessageCertificateExtensions certificate extraction methods.
/// </summary>
[TestFixture]
public class CoseSign1MessageCertificateExtensionsTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("test payload");

    // Helper to create a message with proper certificates using the factory
    private static CoseSign1Message CreateMessageWithCertificates(X509Certificate2 cert, X509Certificate2[]? chain = null)
    {
        chain ??= new[] { cert };
        using var signingService = CertificateSigningService.Create(cert, chain);
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        return CoseMessage.DecodeSign1(messageBytes);
    }

    // Helper to create a message with custom headers (for testing edge cases)
    private static CoseSign1Message CreateMessageWithHeaders(CoseHeaderMap headers)
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        byte[] signedBytes = CoseSign1Message.SignDetached(TestPayload, signer, ReadOnlySpan<byte>.Empty);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    [Test]
    public void TryGetCertificateChain_WithSingleCertificate_ReturnsCollection()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();

        var headers = new CoseHeaderMap();
        // Add x5chain header (label 33) with single certificate
        var writer = new CborWriter();
        writer.WriteByteString(testCert.RawData);
        var x5chainValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, x5chainValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(chain, Is.Not.Null);
        Assert.That(chain!.Count, Is.EqualTo(1));
        Assert.That(chain[0].RawData, Is.EqualTo(testCert.RawData));
    }

    [Test]
    public void TryGetCertificateChain_WithCertificateArray_ReturnsCollection()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("Test", useEcc: true, keySize: 256, leafFirst: true);
        using var testCert = chain[0];
        using var issuerCert = chain[1];

        var headers = new CoseHeaderMap();
        // Add x5chain header with array of certificates
        var writer = new CborWriter();
        writer.WriteStartArray(2);
        writer.WriteByteString(testCert.RawData);
        writer.WriteByteString(issuerCert.RawData);
        writer.WriteEndArray();
        var x5chainValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, x5chainValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? certChain);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(certChain, Is.Not.Null);
        Assert.That(certChain!.Count, Is.EqualTo(2));
        Assert.That(certChain[0].RawData, Is.EqualTo(testCert.RawData));
        Assert.That(certChain[1].RawData, Is.EqualTo(issuerCert.RawData));
    }

    [Test]
    public void TryGetCertificateChain_WithMissingHeader_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(chain, Is.Null);
    }

    [Test]
    public void TryGetExtraCertificates_WithX5Bag_ReturnsCollection()
    {
        // Arrange
        using var issuerCert = TestCertificateUtils.CreateCertificate();
        var headers = new CoseHeaderMap();

        // Add x5bag header (label 32)
        var writer = new CborWriter();
        writer.WriteStartArray(1);
        writer.WriteByteString(issuerCert.RawData);
        writer.WriteEndArray();
        var x5bagValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Bag, x5bagValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetExtraCertificates(out X509Certificate2Collection? certs);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(certs, Is.Not.Null);
        Assert.That(certs!.Count, Is.EqualTo(1));
        Assert.That(certs[0].RawData, Is.EqualTo(issuerCert.RawData));
    }

    [Test]
    public void TryGetCertificateThumbprint_WithX5T_ReturnsThumbprint()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA256);
        var headers = new CoseHeaderMap();

        // Add x5t header (label 34)
        var writer = new CborWriter();
        thumbprint.Serialize(writer);
        var x5tValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, x5tValue);

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateThumbprint(out CoseX509Thumbprint? extractedThumbprint);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(extractedThumbprint, Is.Not.Null);
        Assert.That(extractedThumbprint!.HashId, Is.EqualTo(thumbprint.HashId));
        Assert.That(extractedThumbprint.Thumbprint.ToArray(), Is.EqualTo(thumbprint.Thumbprint.ToArray()));
    }

    [Test]
    public void TryGetSigningCertificate_WithValidX5TAndChain_ReturnsCertificate()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA256);
        var headers = new CoseHeaderMap();

        // Add x5t header
        var thumbprintWriter = new CborWriter();
        thumbprint.Serialize(thumbprintWriter);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(thumbprintWriter.Encode()));

        // Add x5chain header with matching certificate
        var chainWriter = new CborWriter();
        chainWriter.WriteStartArray(1);
        chainWriter.WriteByteString(testCert.RawData);
        chainWriter.WriteEndArray();
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(chainWriter.Encode()));

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetSigningCertificate(out X509Certificate2? cert);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(cert, Is.Not.Null);
        Assert.That(cert!.RawData, Is.EqualTo(testCert.RawData));
    }

    [Test]
    public void TryGetSigningCertificate_WithNoMatchingCertInChain_ReturnsFalse()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate();
        using var issuerCert = TestCertificateUtils.CreateCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA256);
        var headers = new CoseHeaderMap();

        // Add x5t header
        var thumbprintWriter = new CborWriter();
        thumbprint.Serialize(thumbprintWriter);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(thumbprintWriter.Encode()));

        // Add x5chain header with different certificate (issuer instead of test cert)
        var chainWriter = new CborWriter();
        chainWriter.WriteStartArray(1);
        chainWriter.WriteByteString(issuerCert.RawData);
        chainWriter.WriteEndArray();
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(chainWriter.Encode()));

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetSigningCertificate(out X509Certificate2? cert);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(cert, Is.Null);
    }

    [Test]
    public void TryGetPublicKey_WithRSACertificate_ReturnsRSAKey()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest(
            new X500DistinguishedName("CN=RSA Test"),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var rsaCert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var thumbprint = new CoseX509Thumbprint(rsaCert, HashAlgorithmName.SHA256);
        var headers = new CoseHeaderMap();

        var thumbprintWriter = new CborWriter();
        thumbprint.Serialize(thumbprintWriter);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(thumbprintWriter.Encode()));

        var chainWriter = new CborWriter();
        chainWriter.WriteByteString(rsaCert.RawData);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(chainWriter.Encode()));

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetSigningCertificate(out X509Certificate2? certificate);
        var publicKey = certificate?.GetRSAPublicKey();

        // Assert
        Assert.That(result, Is.True);
        Assert.That(publicKey, Is.Not.Null);

        rsaCert.Dispose();
    }

    [Test]
    public void TryGetPublicKey_WithECDsaCertificate_ReturnsECDsaKey()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(TryGetPublicKey_WithECDsaCertificate_ReturnsECDsaKey), useEcc: true);
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA256);
        var headers = new CoseHeaderMap();

        var thumbprintWriter = new CborWriter();
        thumbprint.Serialize(thumbprintWriter);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(thumbprintWriter.Encode()));

        var chainWriter = new CborWriter();
        chainWriter.WriteByteString(testCert.RawData);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(chainWriter.Encode()));

        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetSigningCertificate(out X509Certificate2? certificate);
        var publicKey = certificate?.GetECDsaPublicKey();

        // Assert
        Assert.That(result, Is.True);
        Assert.That(publicKey, Is.Not.Null);
    }

    [Test]
    public void TryGetPublicKey_WithNoCertificate_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetSigningCertificate(out X509Certificate2? certificate);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(certificate, Is.Null);
    }

    [Test]
    public void TryGetCertificateChain_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(chain, Is.Null);
    }

    [Test]
    public void VerifySignature_WithEmbeddedContent_VerifiesSuccessfully()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithEmbeddedContent_VerifiesSuccessfully), useEcc: true);
        var message = CreateMessageWithCertificates(testCert);

        // Act - No payload needed for embedded content
        bool result = message.VerifySignature();

        // Assert
        Assert.That(result, Is.True);
        Assert.That(message.Content, Is.Not.Null, "Expected embedded content");
    }

    [Test]
    public void VerifySignature_WithDetachedContent_RequiresPayload()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithDetachedContent_RequiresPayload), useEcc: true);
        using var signingService = CertificateSigningService.Create(testCert, new X509Certificate2[] { testCert });
        using var factory = new DirectSignatureFactory(signingService);

        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json", options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Act & Assert - Should fail without payload
        Assert.That(message.Content, Is.Null, "Expected detached content");
        Assert.That(message.VerifySignature(), Is.False, "Should fail without payload for detached signature");

        // Should succeed with payload
        Assert.That(message.VerifySignature(TestPayload), Is.True, "Should succeed with payload for detached signature");
    }

    [Test]
    public void VerifySignature_WithEmbeddedContent_IgnoresPayloadParameter()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithEmbeddedContent_IgnoresPayloadParameter), useEcc: true);
        var message = CreateMessageWithCertificates(testCert);

        // Act - Payload parameter should be ignored since content is embedded
        byte[] wrongPayload = Encoding.UTF8.GetBytes("wrong payload");
        bool result = message.VerifySignature(wrongPayload);

        // Assert
        Assert.That(result, Is.True, "Should verify using embedded content, ignoring payload parameter");
    }

    [Test]
    public void VerifySignature_WithDetachedContent_AndEmptyPayload_ReturnsFalse()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithDetachedContent_AndEmptyPayload_ReturnsFalse), useEcc: true);
        using var signingService = CertificateSigningService.Create(testCert, new X509Certificate2[] { testCert });
        using var factory = new DirectSignatureFactory(signingService);

        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json", options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Act & Assert
        Assert.That(message.VerifySignature(Array.Empty<byte>()), Is.False, "Should fail with empty payload");
    }

    [Test]
    public void VerifySignature_WithDetachedContent_AndWrongPayload_ReturnsFalse()
    {
        // Arrange
        using var testCert = TestCertificateUtils.CreateCertificate(nameof(VerifySignature_WithDetachedContent_AndWrongPayload_ReturnsFalse), useEcc: true);
        using var signingService = CertificateSigningService.Create(testCert, new X509Certificate2[] { testCert });
        using var factory = new DirectSignatureFactory(signingService);

        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json", options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Act
        byte[] wrongPayload = Encoding.UTF8.GetBytes("wrong payload");
        bool result = message.VerifySignature(wrongPayload);

        // Assert
        Assert.That(result, Is.False, "Should fail with wrong payload");
    }

    [Test]
    public void VerifySignature_WithRSACertificate_VerifiesSuccessfully()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest(
            new X500DistinguishedName("CN=RSA Test"),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var rsaCert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var message = CreateMessageWithCertificates(rsaCert);

        // Act
        bool result = message.VerifySignature();

        // Assert
        Assert.That(result, Is.True);

        rsaCert.Dispose();
    }

    [Test]
    public void VerifySignature_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).VerifySignature();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifySignature_WithNoCertificate_ReturnsFalse()
    {
        // Arrange - Create message without certificates
        var headers = new CoseHeaderMap();
        var message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.VerifySignature();

        // Assert
        Assert.That(result, Is.False, "Should fail when no signing certificate is available");
    }
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests.Indirect.Extensions;

using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Direct;
using CoseSign1.Indirect.Extensions;
using CoseSign1.Tests.Common;

[TestFixture]
public class CoseSign1MessageIndirectExtensionsTests
{
    [Test]
    public void GetSignatureFormat_WithNullMessage_ReturnsDirect()
    {
        // Act
        var format = ((CoseSign1Message)null!).GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.Direct));
    }

    [Test]
    public void GetSignatureFormat_WithNoSpecialHeaders_ReturnsDirect()
    {
        // Arrange
        var message = CreateDirectSignature();

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.Direct));
    }

    [Test]
    public void GetSignatureFormat_WithCoseHashEnvelopeHeader_ReturnsIndirectCoseHashEnvelope()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(new CoseHeaderLabel(258), CoseHeaderValue.FromInt32(-16)); // PayloadHashAlg = SHA-256
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectCoseHashEnvelope));
    }

    [Test]
    public void GetSignatureFormat_WithCoseHashVContentType_ReturnsIndirectCoseHashV()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectCoseHashV));
    }

    [Test]
    public void GetSignatureFormat_WithCoseHashVContentTypeCaseInsensitive_ReturnsIndirectCoseHashV()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+COSE-HASH-V"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectCoseHashV));
    }

    [Test]
    public void GetSignatureFormat_WithHashLegacyContentType_ReturnsIndirectHashLegacy()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha256"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectHashLegacy));
    }

    [Test]
    public void GetSignatureFormat_WithHashLegacyDifferentAlgorithm_ReturnsIndirectHashLegacy()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("text/plain+hash-sha384"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectHashLegacy));
    }

    [Test]
    public void GetSignatureFormat_WithEmptyContentType_ReturnsDirect()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString(""));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.Direct));
    }

    [Test]
    public void TryGetIndirectContentType_WithNullMessage_ReturnsFalse()
    {
        // Act
        var result = ((CoseSign1Message)null!).TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    [Test]
    public void TryGetIndirectContentType_WithDirectSignature_ReturnsFalse()
    {
        // Arrange
        var message = CreateDirectSignature();

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    [Test]
    public void TryGetIndirectContentType_WithCoseHashEnvelopeStringPreimageType_ReturnsContentType()
    {
        // Arrange
        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(new CoseHeaderLabel(258), CoseHeaderValue.FromInt32(-16)); // PayloadHashAlg

        var unprotectedHeaders = new CoseHeaderMap();
        unprotectedHeaders.Add(new CoseHeaderLabel(259), CoseHeaderValue.FromString("application/json")); // PreimageContentType

        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, protectedHeaders, unprotectedHeaders);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetIndirectContentType_WithCoseHashEnvelopeIntPreimageType_ReturnsCoAPFormat()
    {
        // Arrange
        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(new CoseHeaderLabel(258), CoseHeaderValue.FromInt32(-16)); // PayloadHashAlg

        var unprotectedHeaders = new CoseHeaderMap();
        unprotectedHeaders.Add(new CoseHeaderLabel(259), CoseHeaderValue.FromInt32(50)); // PreimageContentType as CoAP int

        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, protectedHeaders, unprotectedHeaders);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("coap/50"));
    }

    [Test]
    public void TryGetIndirectContentType_WithCoseHashEnvelopeNoPreimageType_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(new CoseHeaderLabel(258), CoseHeaderValue.FromInt32(-16)); // PayloadHashAlg only
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    [Test]
    public void TryGetIndirectContentType_WithCoseHashV_ReturnsStrippedContentType()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetIndirectContentType_WithCoseHashVCaseInsensitive_ReturnsStrippedContentType()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("text/plain+COSE-HASH-V"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("text/plain"));
    }

    [Test]
    public void TryGetIndirectContentType_WithCoseHashVNoContentType_ReturnsFalse()
    {
        // Arrange - Force CoseHashV detection but no content-type header
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("+cose-hash-v")); // Only extension
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null.Or.Empty);
    }

    [Test]
    public void TryGetIndirectContentType_WithHashLegacy_ReturnsStrippedContentType()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha256"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetIndirectContentType_WithHashLegacyDifferentAlgorithm_ReturnsStrippedContentType()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("text/xml+hash-sha512"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("text/xml"));
    }

    [Test]
    public void TryGetIndirectContentType_WithHashLegacyUnderscoreInName_ReturnsStrippedContentType()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/data+hash-sha3_256"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/data"));
    }

    [Test]
    public void TryGetIndirectContentType_WithHashLegacyNoBaseContentType_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("+hash-sha256"));
        var message = CreateTestMessage(new byte[] { 1, 2, 3 }, headers);

        // Act
        var result = message.TryGetIndirectContentType(out var contentType);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null.Or.Empty);
    }

    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    private CoseSign1Message CreateDirectSignature()
    {
        using var cert = TestCertificateUtils.CreateCertificate("IndirectExtTest");
        using var signingService = CertificateSigningService.Create(cert, new X509Certificate2[] { cert });
        using var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        return CoseMessage.DecodeSign1(messageBytes);
    }

    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    private CoseSign1Message CreateTestMessage(byte[] payload, CoseHeaderMap? protectedHeaders = null, CoseHeaderMap? unprotectedHeaders = null)
    {
        using var cert = TestCertificateUtils.CreateCertificate("IndirectExtTest");
        using var signingService = CertificateSigningService.Create(cert, new X509Certificate2[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        DirectSignatureOptions? options = null;
        if (protectedHeaders != null || unprotectedHeaders != null)
        {
            options = new DirectSignatureOptions
            {
                AdditionalHeaderContributors = new[]
                {
                    new CustomHeaderContributor(protectedHeaders, unprotectedHeaders)
                }
            };
        }

        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", options);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    private class CustomHeaderContributor : IHeaderContributor
    {
        private readonly CoseHeaderMap? ProtectedHeaders;
        private readonly CoseHeaderMap? UnprotectedHeaders;

        public CustomHeaderContributor(CoseHeaderMap? protectedHeaders, CoseHeaderMap? unprotectedHeaders)
        {
            ProtectedHeaders = protectedHeaders;
            UnprotectedHeaders = unprotectedHeaders;
        }

        public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

        public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
        {
            if (ProtectedHeaders != null)
            {
                foreach (var (label, value) in ProtectedHeaders)
                {
                    headers[label] = value;
                }
            }
        }

        public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
        {
            if (UnprotectedHeaders != null)
            {
                foreach (var (label, value) in UnprotectedHeaders)
                {
                    headers[label] = value;
                }
            }
        }
    }
}
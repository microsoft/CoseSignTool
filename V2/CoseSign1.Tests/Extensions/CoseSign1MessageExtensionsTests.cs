// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using CoseSign1.Extensions;
using CoseSign1.Indirect.Extensions;
using CoseSign1.Tests.Common;

namespace CoseSign1.Tests.Extensions;

/// <summary>
/// Tests for CoseSign1MessageExtensions core header extraction methods.
/// </summary>
[TestFixture]
public class CoseSign1MessageExtensionsTests
{
    private static readonly byte[] TestPayload = "test"u8.ToArray();

    /// <summary>
    /// Creates a test COSE Sign1 message using proper signing infrastructure.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="headers">Optional headers to include.</param>
    /// <returns>A properly signed CoseSign1Message.</returns>
    private static CoseSign1Message CreateTestMessage(byte[] payload, CoseHeaderMap? headers = null)
    {
        using X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        using LocalCertificateSigningService signingService = new(cert, new[] { cert });
        using DirectSignatureFactory factory = new(signingService);

        DirectSignatureOptions? options = headers != null
            ? new DirectSignatureOptions { AdditionalHeaderContributors = [new CustomHeaderContributor(headers)] }
            : null;

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/json", options);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    /// <summary>
    /// Custom header contributor to add arbitrary headers for testing.
    /// </summary>
    private class CustomHeaderContributor : IHeaderContributor
    {
        private readonly CoseHeaderMap _headers;

        public CustomHeaderContributor(CoseHeaderMap headers)
        {
            _headers = headers;
        }

        public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

        public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
        {
            foreach (var (label, value) in _headers)
            {
                headers[label] = value;
            }
        }

        public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
        {
            // Not used in these tests
        }
    }

    [Test]
    public void TryGetContentType_WithDirectSignature_ReturnsHeaderThree()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithIndirectHashLegacy_StripsPlusHashExtension()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha256"));
        var message = CreateTestMessage("hash"u8.ToArray(), headers);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithCoseHashV_StripsPlusCoseHashV()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v"));
        var message = CreateTestMessage("hash"u8.ToArray(), headers);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithCoseHashEnvelope_ReturnsPreimageContentType()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(new CoseHeaderLabel(258), CoseHeaderValue.FromInt32(-16)); // PayloadHashAlg
        headers.Add(new CoseHeaderLabel(259), CoseHeaderValue.FromString("application/octet-stream")); // PreimageContentType
        var message = CreateTestMessage("hash"u8.ToArray(), headers);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/octet-stream"));
    }

    [Test]
    public void TryGetContentType_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    [Test]
    public void GetSignatureFormat_WithDirectSignature_ReturnsDirect()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.Direct));
    }

    [Test]
    public void GetSignatureFormat_WithHashLegacy_ReturnsIndirectHashLegacy()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha384"));
        var message = CreateTestMessage("hash"u8.ToArray(), headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectHashLegacy));
    }

    [Test]
    public void GetSignatureFormat_WithCoseHashV_ReturnsIndirectCoseHashV()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/vnd.example+cose-hash-v"));
        var message = CreateTestMessage("hash"u8.ToArray(), headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectCoseHashV));
    }

    [Test]
    public void GetSignatureFormat_WithCoseHashEnvelope_ReturnsIndirectCoseHashEnvelope()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(new CoseHeaderLabel(258), CoseHeaderValue.FromInt32(-16)); // PayloadHashAlg
        var message = CreateTestMessage("hash"u8.ToArray(), headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectCoseHashEnvelope));
    }

    [Test]
    public void TryGetHeader_String_WithProtectedHeader_ReturnsValue()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("text/plain"));
        var message = CreateTestMessage(TestPayload, headers);

        // Act
        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out string? value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo("text/plain"));
    }

    [Test]
    public void TryGetHeader_Int_WithProtectedHeader_ReturnsValue()
    {
        // Arrange - Use a custom label that doesn't conflict with signing
        var customLabel = new CoseHeaderLabel(1234); // Custom label
        var headers = new CoseHeaderMap();
        headers.Add(customLabel, CoseHeaderValue.FromInt32(42));
        var message = CreateTestMessage(TestPayload, headers);

        // Act
        bool result = message.TryGetHeader(customLabel, out int value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo(42));
    }

    [Test]
    public void TryGetHeader_Bytes_WithProtectedHeader_ReturnsValue()
    {
        // Arrange
        var testBytes = new byte[] { 1, 2, 3, 4 };
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(testBytes));
        var message = CreateTestMessage(TestPayload, headers);

        // Act
        bool result = message.TryGetHeader(CoseHeaderLabel.KeyIdentifier, out ReadOnlyMemory<byte> value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value.ToArray(), Is.EqualTo(testBytes));
    }

    [Test]
    public void TryGetHeader_WithMissingHeader_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);

        // Act
        bool result = message.TryGetHeader(new CoseHeaderLabel(999), out string? value);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void TryGetHeader_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).TryGetHeader(CoseHeaderLabel.ContentType, out string? value);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void HasHeader_WithExistingProtectedHeader_ReturnsTrue()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);

        // Act
        bool result = message.HasHeader(CoseHeaderLabel.ContentType);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void HasHeader_WithMissingHeader_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);

        // Act
        bool result = message.HasHeader(new CoseHeaderLabel(999));

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void HasHeader_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).HasHeader(CoseHeaderLabel.ContentType);

        // Assert
        Assert.That(result, Is.False);
    }
}

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

    #region Unprotected Header Tests

    [Test]
    public void TryGetHeader_String_WithUnprotectedHeader_AllowedTrue_ReturnsValue()
    {
        // Arrange - Create a message and manually add unprotected header
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5000);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromString("unprotected-value"));

        // Act
        bool result = message.TryGetHeader(testLabel, out string? value, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo("unprotected-value"));
    }

    [Test]
    public void TryGetHeader_String_WithUnprotectedHeader_AllowedFalse_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5001);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromString("unprotected-value"));

        // Act
        bool result = message.TryGetHeader(testLabel, out string? value, allowUnprotected: false);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void TryGetHeader_Int_WithUnprotectedHeader_AllowedTrue_ReturnsValue()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5002);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromInt32(99));

        // Act
        bool result = message.TryGetHeader(testLabel, out int value, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo(99));
    }

    [Test]
    public void TryGetHeader_Int_WithUnprotectedHeader_AllowedFalse_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5003);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromInt32(99));

        // Act
        bool result = message.TryGetHeader(testLabel, out int value, allowUnprotected: false);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.EqualTo(0));
    }

    [Test]
    public void TryGetHeader_Bytes_WithUnprotectedHeader_AllowedTrue_ReturnsValue()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5004);
        var testBytes = new byte[] { 0xAA, 0xBB, 0xCC };
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromBytes(testBytes));

        // Act
        bool result = message.TryGetHeader(testLabel, out ReadOnlyMemory<byte> value, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value.ToArray(), Is.EqualTo(testBytes));
    }

    [Test]
    public void TryGetHeader_Bytes_WithUnprotectedHeader_AllowedFalse_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5005);
        var testBytes = new byte[] { 0xDD, 0xEE, 0xFF };
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromBytes(testBytes));

        // Act
        bool result = message.TryGetHeader(testLabel, out ReadOnlyMemory<byte> value, allowUnprotected: false);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value.Length, Is.EqualTo(0));
    }

    [Test]
    public void HasHeader_WithUnprotectedHeader_AllowedTrue_ReturnsTrue()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5006);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromString("test"));

        // Act
        bool result = message.HasHeader(testLabel, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void HasHeader_WithUnprotectedHeader_AllowedFalse_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5007);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromString("test"));

        // Act
        bool result = message.HasHeader(testLabel, allowUnprotected: false);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void TryGetHeader_ProtectedTakesPrecedenceOverUnprotected()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5008);

        // Add to both protected (via creation) and unprotected
        var headers = new CoseHeaderMap();
        headers.Add(testLabel, CoseHeaderValue.FromString("protected-value"));
        message = CreateTestMessage(TestPayload, headers);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromString("unprotected-value"));

        // Act
        bool result = message.TryGetHeader(testLabel, out string? value, allowUnprotected: true);

        // Assert - Should return protected value
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo("protected-value"));
    }

    #endregion

    #region Type Conversion Error Tests

    [Test]
    public void TryGetHeader_String_WithIntValue_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var testLabel = new CoseHeaderLabel(5100);
        headers.Add(testLabel, CoseHeaderValue.FromInt32(42));
        var message = CreateTestMessage(TestPayload, headers);

        // Act - Try to get as string
        bool result = message.TryGetHeader(testLabel, out string? value);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void TryGetHeader_Int_WithStringValue_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var testLabel = new CoseHeaderLabel(5101);
        headers.Add(testLabel, CoseHeaderValue.FromString("not-a-number"));
        var message = CreateTestMessage(TestPayload, headers);

        // Act - Try to get as int
        bool result = message.TryGetHeader(testLabel, out int value);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.EqualTo(0));
    }

    [Test]
    public void TryGetHeader_Bytes_WithStringValue_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var testLabel = new CoseHeaderLabel(5102);
        headers.Add(testLabel, CoseHeaderValue.FromString("not-bytes"));
        var message = CreateTestMessage(TestPayload, headers);

        // Act - Try to get as bytes
        bool result = message.TryGetHeader(testLabel, out ReadOnlyMemory<byte> value);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value.Length, Is.EqualTo(0));
    }

    [Test]
    public void TryGetHeader_String_WithIntValue_FromUnprotected_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5103);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromInt32(123));

        // Act - Try to get as string from unprotected
        bool result = message.TryGetHeader(testLabel, out string? value, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void TryGetHeader_Int_WithBytesValue_FromUnprotected_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5104);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromBytes(new byte[] { 1, 2, 3 }));

        // Act - Try to get as int from unprotected
        bool result = message.TryGetHeader(testLabel, out int value, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.EqualTo(0));
    }

    [Test]
    public void TryGetHeader_Bytes_WithIntValue_FromUnprotected_ReturnsFalse()
    {
        // Arrange
        var message = CreateTestMessage(TestPayload);
        var testLabel = new CoseHeaderLabel(5105);
        message.UnprotectedHeaders.Add(testLabel, CoseHeaderValue.FromInt32(456));

        // Act - Try to get as bytes from unprotected
        bool result = message.TryGetHeader(testLabel, out ReadOnlyMemory<byte> value, allowUnprotected: true);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value.Length, Is.EqualTo(0));
    }

    #endregion

    #region Additional Edge Cases

    [Test]
    public void TryGetHeader_String_WithEmptyString_ReturnsTrue()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var testLabel = new CoseHeaderLabel(5200);
        headers.Add(testLabel, CoseHeaderValue.FromString(string.Empty));
        var message = CreateTestMessage(TestPayload, headers);

        // Act
        bool result = message.TryGetHeader(testLabel, out string? value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TryGetHeader_Bytes_WithEmptyBytes_ReturnsTrue()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var testLabel = new CoseHeaderLabel(5201);
        headers.Add(testLabel, CoseHeaderValue.FromBytes(Array.Empty<byte>()));
        var message = CreateTestMessage(TestPayload, headers);

        // Act
        bool result = message.TryGetHeader(testLabel, out ReadOnlyMemory<byte> value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value.Length, Is.EqualTo(0));
    }

    [Test]
    public void TryGetHeader_Int_WithZero_ReturnsTrue()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var testLabel = new CoseHeaderLabel(5202);
        headers.Add(testLabel, CoseHeaderValue.FromInt32(0));
        var message = CreateTestMessage(TestPayload, headers);

        // Act
        bool result = message.TryGetHeader(testLabel, out int value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo(0));
    }

    [Test]
    public void TryGetHeader_Int_WithNegativeValue_ReturnsTrue()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var testLabel = new CoseHeaderLabel(5203);
        headers.Add(testLabel, CoseHeaderValue.FromInt32(-42));
        var message = CreateTestMessage(TestPayload, headers);

        // Act
        bool result = message.TryGetHeader(testLabel, out int value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo(-42));
    }

    [Test]
    public void TryGetContentType_WithMissingContentTypeHeader_ReturnsFalse()
    {
        // Arrange - Create a minimalist message without content type
        var testMessage = new byte[] { 0xd2, 0x84, 0x40, 0xa0, 0x40, 0x40 }; // Minimal COSE_Sign1 without content type
        var message = CoseMessage.DecodeSign1(testMessage);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    #endregion
}
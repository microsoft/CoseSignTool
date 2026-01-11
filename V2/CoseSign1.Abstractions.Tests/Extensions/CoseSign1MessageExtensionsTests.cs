// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Tests.Extensions;

using System.Security.Cryptography.Cose;
using System.Text;

/// <summary>
/// Tests for <see cref="CoseSign1MessageExtensions"/>.
/// </summary>
[TestFixture]
public class CoseSign1MessageExtensionsTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("test payload");

    #region Helper Methods

    private static CoseSign1Message CreateMessageWithHeaders(
        CoseHeaderMap? protectedHeaders = null,
        CoseHeaderMap? unprotectedHeaders = null)
    {
        using var key = ECDsa.Create();
        protectedHeaders ??= new CoseHeaderMap();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        byte[] signedBytes = CoseSign1Message.SignDetached(TestPayload, signer, ReadOnlySpan<byte>.Empty);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    #endregion

    #region IsIndirectSignature Tests

    [Test]
    public void IsIndirectSignature_WithDirectSignature_ReturnsFalse()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.IsIndirectSignature(), Is.False);
    }

    [Test]
    public void IsIndirectSignature_WithHashLegacyContentType_ReturnsTrue()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha256") }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.IsIndirectSignature(), Is.True);
    }

    [Test]
    public void IsIndirectSignature_WithCoseHashVContentType_ReturnsTrue()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v") }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.IsIndirectSignature(), Is.True);
    }

    [Test]
    public void IsIndirectSignature_WithPayloadHashAlgHeader_ReturnsTrue()
    {
        var headers = new CoseHeaderMap
        {
            { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16) } // SHA-256
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.IsIndirectSignature(), Is.True);
    }

    #endregion

    #region GetSignatureFormat Tests

    [Test]
    public void GetSignatureFormat_WithNoIndirectMarkers_ReturnsDirect()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.GetSignatureFormat(), Is.EqualTo(SignatureFormat.Direct));
    }

    [Test]
    public void GetSignatureFormat_WithPayloadHashAlgHeader_ReturnsCoseHashEnvelope()
    {
        var headers = new CoseHeaderMap
        {
            { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16) }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.GetSignatureFormat(), Is.EqualTo(SignatureFormat.IndirectCoseHashEnvelope));
    }

    [Test]
    public void GetSignatureFormat_WithCoseHashVContentType_ReturnsCoseHashV()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v") }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.GetSignatureFormat(), Is.EqualTo(SignatureFormat.IndirectCoseHashV));
    }

    [Test]
    public void GetSignatureFormat_WithHashLegacyContentType_ReturnsHashLegacy()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha256") }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.GetSignatureFormat(), Is.EqualTo(SignatureFormat.IndirectHashLegacy));
    }

    [Test]
    public void GetSignatureFormat_WithNullMessage_ReturnsDirect()
    {
        CoseSign1Message? message = null;

        Assert.That(message!.GetSignatureFormat(), Is.EqualTo(SignatureFormat.Direct));
    }

    [TestCase("application/test+hash-sha384")]
    [TestCase("text/plain+hash-SHA512")]
    [TestCase("application/octet-stream+hash-sha_256")]
    public void GetSignatureFormat_WithVariousHashLegacyFormats_ReturnsHashLegacy(string contentType)
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString(contentType) }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.GetSignatureFormat(), Is.EqualTo(SignatureFormat.IndirectHashLegacy));
    }

    #endregion

    #region TryGetContentType Tests

    [Test]
    public void TryGetContentType_WithDirectSignature_ReturnsContentType()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithHashLegacy_ReturnsStrippedContentType()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha256") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithCoseHashV_ReturnsStrippedContentType()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithCoseHashEnvelope_ReturnsPreimageContentType()
    {
        var headers = new CoseHeaderMap
        {
            { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16) },
            { IndirectSignatureHeaderLabels.PreimageContentType, CoseHeaderValue.FromString("application/xml") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/xml"));
    }

    [Test]
    public void TryGetContentType_WithNullMessage_ReturnsFalse()
    {
        CoseSign1Message? message = null;

        bool result = message!.TryGetContentType(out string? contentType);

        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    [Test]
    public void TryGetContentType_WithNoContentType_ReturnsFalse()
    {
        var message = CreateMessageWithHeaders(new CoseHeaderMap());

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    #endregion

    #region TryGetPayloadLocation Tests

    [Test]
    public void TryGetPayloadLocation_WithCoseHashEnvelopeAndLocation_ReturnsLocation()
    {
        var headers = new CoseHeaderMap
        {
            { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16) },
            { IndirectSignatureHeaderLabels.PayloadLocation, CoseHeaderValue.FromString("https://example.com/payload") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetPayloadLocation(out string? location);

        Assert.That(result, Is.True);
        Assert.That(location, Is.EqualTo("https://example.com/payload"));
    }

    [Test]
    public void TryGetPayloadLocation_WithDirectSignature_ReturnsFalse()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetPayloadLocation(out string? location);

        Assert.That(result, Is.False);
        Assert.That(location, Is.Null);
    }

    [Test]
    public void TryGetPayloadLocation_WithCoseHashEnvelopeButNoLocation_ReturnsFalse()
    {
        var headers = new CoseHeaderMap
        {
            { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16) }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetPayloadLocation(out string? location);

        Assert.That(result, Is.False);
        Assert.That(location, Is.Null);
    }

    [Test]
    public void TryGetPayloadLocation_WithNullMessage_ReturnsFalse()
    {
        CoseSign1Message? message = null;

        bool result = message!.TryGetPayloadLocation(out string? location);

        Assert.That(result, Is.False);
        Assert.That(location, Is.Null);
    }

    #endregion

    #region TryGetHeader (String) Tests

    [Test]
    public void TryGetHeader_String_WithProtectedHeader_ReturnsValue()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out string? value);

        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetHeader_String_WithUnprotectedHeader_AndProtectedLocation_ReturnsFalse()
    {
        var unprotectedHeaders = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out string? value, CoseHeaderLocation.Protected);

        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void TryGetHeader_String_WithUnprotectedHeader_AndAnyLocation_ReturnsValue()
    {
        var unprotectedHeaders = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out string? value, CoseHeaderLocation.Any);

        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetHeader_String_WithNullMessage_ReturnsFalse()
    {
        CoseSign1Message? message = null;

        bool result = message!.TryGetHeader(CoseHeaderLabel.ContentType, out string? value);

        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void TryGetHeader_String_WithMissingHeader_ReturnsFalse()
    {
        var message = CreateMessageWithHeaders(new CoseHeaderMap());

        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out string? value);

        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    #endregion

    #region TryGetHeader (Int) Tests

    [Test]
    public void TryGetHeader_Int_WithProtectedHeader_ReturnsValue()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.Algorithm, CoseHeaderValue.FromInt32(-7) } // ES256
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetHeader(CoseHeaderLabel.Algorithm, out int value);

        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo(-7));
    }

    [Test]
    public void TryGetHeader_Int_WithNullMessage_ReturnsFalse()
    {
        CoseSign1Message? message = null;

        bool result = message!.TryGetHeader(CoseHeaderLabel.Algorithm, out int value);

        Assert.That(result, Is.False);
        Assert.That(value, Is.EqualTo(default(int)));
    }

    #endregion

    #region TryGetHeader (Bytes) Tests

    [Test]
    public void TryGetHeader_Bytes_WithProtectedHeader_ReturnsValue()
    {
        var testBytes = new byte[] { 1, 2, 3, 4, 5 };
        var keyIdLabel = new CoseHeaderLabel(4); // kid header
        var headers = new CoseHeaderMap
        {
            { keyIdLabel, CoseHeaderValue.FromBytes(testBytes) }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetHeader(keyIdLabel, out ReadOnlyMemory<byte> value);

        Assert.That(result, Is.True);
        Assert.That(value.ToArray(), Is.EqualTo(testBytes));
    }

    [Test]
    public void TryGetHeader_Bytes_WithNullMessage_ReturnsFalse()
    {
        CoseSign1Message? message = null;
        var keyIdLabel = new CoseHeaderLabel(4); // kid header

        bool result = message!.TryGetHeader(keyIdLabel, out ReadOnlyMemory<byte> value);

        Assert.That(result, Is.False);
        Assert.That(value.IsEmpty, Is.True);
    }

    #endregion

    #region HasHeader Tests

    [Test]
    public void HasHeader_WithExistingProtectedHeader_ReturnsTrue()
    {
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(headers);

        Assert.That(message.HasHeader(CoseHeaderLabel.ContentType), Is.True);
    }

    [Test]
    public void HasHeader_WithMissingHeader_ReturnsFalse()
    {
        var message = CreateMessageWithHeaders(new CoseHeaderMap());

        Assert.That(message.HasHeader(CoseHeaderLabel.ContentType), Is.False);
    }

    [Test]
    public void HasHeader_WithUnprotectedHeader_AndProtectedLocation_ReturnsFalse()
    {
        var unprotectedHeaders = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        Assert.That(message.HasHeader(CoseHeaderLabel.ContentType, CoseHeaderLocation.Protected), Is.False);
    }

    [Test]
    public void HasHeader_WithUnprotectedHeader_AndAnyLocation_ReturnsTrue()
    {
        var unprotectedHeaders = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        Assert.That(message.HasHeader(CoseHeaderLabel.ContentType, CoseHeaderLocation.Any), Is.True);
    }

    [Test]
    public void HasHeader_WithNullMessage_ReturnsFalse()
    {
        CoseSign1Message? message = null;

        Assert.That(message!.HasHeader(CoseHeaderLabel.ContentType), Is.False);
    }

    [Test]
    public void HasHeader_WithUnprotectedHeader_AndUnprotectedLocation_ReturnsTrue()
    {
        var unprotectedHeaders = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        Assert.That(message.HasHeader(CoseHeaderLabel.ContentType, CoseHeaderLocation.Unprotected), Is.True);
    }

    #endregion

    #region TryGetHeader Type Conversion Edge Cases

    [Test]
    public void TryGetHeader_String_WithIntHeader_ReturnsFalse()
    {
        // Try to read an int header as string - should fail conversion
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.Algorithm, CoseHeaderValue.FromInt32(-7) }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetHeader(CoseHeaderLabel.Algorithm, out string? value);

        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void TryGetHeader_Int_WithStringHeader_ReturnsFalse()
    {
        // Try to read a string header as int - should fail conversion
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out int value);

        Assert.That(result, Is.False);
        Assert.That(value, Is.EqualTo(default(int)));
    }

    [Test]
    public void TryGetHeader_Bytes_WithStringHeader_ReturnsFalse()
    {
        // Try to read a string header as bytes - should fail conversion
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out ReadOnlyMemory<byte> value);

        Assert.That(result, Is.False);
        Assert.That(value.IsEmpty, Is.True);
    }

    [Test]
    public void TryGetHeader_Int_WithMissingHeader_ReturnsFalse()
    {
        var message = CreateMessageWithHeaders(new CoseHeaderMap());

        bool result = message.TryGetHeader(CoseHeaderLabel.Algorithm, out int value);

        Assert.That(result, Is.False);
        Assert.That(value, Is.EqualTo(default(int)));
    }

    [Test]
    public void TryGetHeader_Bytes_WithMissingHeader_ReturnsFalse()
    {
        var message = CreateMessageWithHeaders(new CoseHeaderMap());
        var keyIdLabel = new CoseHeaderLabel(4);

        bool result = message.TryGetHeader(keyIdLabel, out ReadOnlyMemory<byte> value);

        Assert.That(result, Is.False);
        Assert.That(value.IsEmpty, Is.True);
    }

    #endregion

    #region TryGetHeader with Unprotected Headers

    [Test]
    public void TryGetHeader_Int_WithUnprotectedHeader_AndAnyLocation_ReturnsValue()
    {
        var unprotectedHeaders = new CoseHeaderMap
        {
            { CoseHeaderLabel.Algorithm, CoseHeaderValue.FromInt32(-7) }
        };
        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        bool result = message.TryGetHeader(CoseHeaderLabel.Algorithm, out int value, CoseHeaderLocation.Any);

        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo(-7));
    }

    [Test]
    public void TryGetHeader_Bytes_WithUnprotectedHeader_AndAnyLocation_ReturnsValue()
    {
        var testBytes = new byte[] { 1, 2, 3 };
        var keyIdLabel = new CoseHeaderLabel(4);
        var unprotectedHeaders = new CoseHeaderMap
        {
            { keyIdLabel, CoseHeaderValue.FromBytes(testBytes) }
        };
        var message = CreateMessageWithHeaders(null, unprotectedHeaders);

        bool result = message.TryGetHeader(keyIdLabel, out ReadOnlyMemory<byte> value, CoseHeaderLocation.Any);

        Assert.That(result, Is.True);
        Assert.That(value.ToArray(), Is.EqualTo(testBytes));
    }

    #endregion

    #region TryGetIndirectContentType Edge Cases

    [Test]
    public void TryGetContentType_WithCoseHashVAndOnlySuffix_ReturnsFalse()
    {
        // Content type that is only the suffix, stripping it leaves empty
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("+cose-hash-v") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null.Or.Empty);
    }

    [Test]
    public void TryGetContentType_WithHashLegacyAndOnlySuffix_ReturnsFalse()
    {
        // Content type that is only the suffix, stripping it leaves empty
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("+hash-sha256") }
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null.Or.Empty);
    }

    [Test]
    public void TryGetContentType_WithCoseHashEnvelopeAndCoAPIntContentType_ReturnsFormattedContentType()
    {
        // Test CoAP int content type format (header 259 as int)
        var headers = new CoseHeaderMap
        {
            { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16) },
            { IndirectSignatureHeaderLabels.PreimageContentType, CoseHeaderValue.FromInt32(50) } // CoAP content format
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("coap/50"));
    }

    [Test]
    public void TryGetContentType_WithCoseHashEnvelopeAndNoPreimageContentType_ReturnsFalse()
    {
        var headers = new CoseHeaderMap
        {
            { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16) }
            // No PreimageContentType header
        };
        var message = CreateMessageWithHeaders(headers);

        bool result = message.TryGetContentType(out string? contentType);

        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    #endregion
}

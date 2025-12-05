// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Tests;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using NUnit.Framework;

/// <summary>
/// Tests for the CWTClaimsHeaderExtender class.
/// </summary>
[TestFixture]
public class CWTClaimsHeaderExtenderTests
{
    private static byte[] ConvertDictionaryToCborBytes(Dictionary<int, object> dictionary)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(dictionary.Count);
        
        foreach (var kvp in dictionary)
        {
            writer.WriteInt32(kvp.Key);
            
            switch (kvp.Value)
            {
                case string str:
                    writer.WriteTextString(str);
                    break;
                case long l:
                    writer.WriteInt64(l);
                    break;
                case int i:
                    writer.WriteInt32(i);
                    break;
                case byte[] bytes:
                    writer.WriteByteString(bytes);
                    break;
                case bool b:
                    writer.WriteBoolean(b);
                    break;
                case double d:
                    writer.WriteDouble(d);
                    break;
                default:
                    throw new NotSupportedException($"Type {kvp.Value.GetType()} is not supported");
            }
        }
        
        writer.WriteEndMap();
        return writer.Encode();
    }
    [Test]
    public void Constructor_CreatesEmptyClaimsCollection()
    {
        // Arrange & Act
        var extender = new CWTClaimsHeaderExtender();

        // Assert
        Assert.That(extender, Is.Not.Null);
        Assert.That(extender.CustomClaims.Count, Is.EqualTo(0));
        Assert.That(extender.Issuer, Is.Null);
        Assert.That(extender.Subject, Is.EqualTo("unknown.intent")); // Default subject
        Assert.That(extender.Audience, Is.Null);
        Assert.That(extender.ExpirationTime, Is.Null);
        Assert.That(extender.NotBefore, Is.Null);
        Assert.That(extender.IssuedAt, Is.Null);
        Assert.That(extender.CWTID, Is.Null);
    }

    [Test]
    public void Constructor_WithDictionary_InitializesWithClaims()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.Issuer, "test-issuer" },
            { CWTClaimsHeaderLabels.Subject, "test-subject" },
            { CWTClaimsHeaderLabels.ExpirationTime, 1234567890L }
        };

        // Act
        var cwtClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claims));
        var extender = new CWTClaimsHeaderExtender(cwtClaims);

        // Assert
        Assert.That(extender.CustomClaims.Count, Is.EqualTo(0));
        Assert.That(extender.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(extender.Subject, Is.EqualTo("test-subject"));
        Assert.That(extender.ExpirationTime!.Value.ToUnixTimeSeconds(), Is.EqualTo(1234567890L));
    }

    [Test]
    public void Properties_WithNonStringIssuer_ThrowsWhenParsing()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.Issuer, 123 } // Wrong type
        };

        // Act & Assert - CwtClaims.FromCborBytes will throw when encountering wrong type
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claims)));
    }

    [Test]
    public void Properties_WithNonStringSubject_ThrowsWhenParsing()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.Subject, 123 } // Wrong type
        };

        // Act & Assert - CwtClaims.FromCborBytes will throw when encountering wrong type
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claims)));
    }

    [Test]
    public void Properties_WithNonStringAudience_ThrowsWhenParsing()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.Audience, 123 } // Wrong type
        };

        // Act & Assert - CwtClaims.FromCborBytes will throw when encountering wrong type
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claims)));
    }

    [Test]
    public void Properties_WithNonLongExpirationTime_ThrowsWhenParsing()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.ExpirationTime, "not a long" } // Wrong type
        };

        // Act & Assert - CwtClaims.FromCborBytes will throw when encountering wrong type
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claims)));
    }

    [Test]
    public void Properties_WithNonLongNotBefore_ThrowsWhenParsing()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.NotBefore, "not a long" } // Wrong type
        };

        // Act & Assert - CwtClaims.FromCborBytes will throw when encountering wrong type
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claims)));
    }

    [Test]
    public void Properties_WithNonLongIssuedAt_ThrowsWhenParsing()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.IssuedAt, "not a long" } // Wrong type
        };

        // Act & Assert - CwtClaims.FromCborBytes will throw when encountering wrong type
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claims)));
    }

    [Test]
    public void Properties_WithNonByteArrayCWTID_ThrowsWhenParsing()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.CWTID, "not a byte array" } // Wrong type
        };

        // Act & Assert - CwtClaims.FromCborBytes will throw when encountering wrong type
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claims)));
    }

    [Test]
    public void CustomClaims_ReturnsReadOnlyDictionary()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetCustomClaim(100, "custom-value-1");
        extender.SetCustomClaim(101, "custom-value-2");

        // Act
        var customClaims = extender.CustomClaims;

        // Assert
        Assert.That(customClaims, Is.InstanceOf<IReadOnlyDictionary<int, object>>());
        Assert.That(customClaims.Count, Is.EqualTo(2));
        Assert.That(customClaims[100], Is.EqualTo("custom-value-1"));
        Assert.That(customClaims[101], Is.EqualTo("custom-value-2"));
    }

    [Test]
    public void Constructor_WithNullDictionary_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        Assert.Throws<ArgumentNullException>(() => new CWTClaimsHeaderExtender(null!));
    }

    [Test]
    public void SetIssuer_WithValidIssuer_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        const string issuer = "https://example.com";

        // Act
        var result = extender.SetIssuer(issuer);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.Issuer, Is.EqualTo(issuer));
    }

    [Test]
    public void SetIssuer_WithNullIssuer_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetIssuer(null!));
        Assert.That(ex!.ParamName, Is.EqualTo("issuer"));
    }

    [Test]
    public void SetIssuer_WithEmptyIssuer_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetIssuer(""));
        Assert.That(ex!.ParamName, Is.EqualTo("issuer"));
    }

    [Test]
    public void SetIssuer_WithWhitespaceIssuer_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetIssuer("   "));
        Assert.That(ex!.ParamName, Is.EqualTo("issuer"));
    }

    [Test]
    public void SetSubject_WithValidSubject_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        const string subject = "test-subject";

        // Act
        var result = extender.SetSubject(subject);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.Subject, Is.EqualTo(subject));
    }

    [Test]
    public void SetSubject_WithNullSubject_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetSubject(null!));
        Assert.That(ex!.ParamName, Is.EqualTo("subject"));
    }

    [Test]
    public void SetSubject_WithEmptySubject_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetSubject(""));
        Assert.That(ex!.ParamName, Is.EqualTo("subject"));
    }

    [Test]
    public void SetAudience_WithValidAudience_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        const string audience = "https://audience.com";

        // Act
        var result = extender.SetAudience(audience);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.Audience, Is.EqualTo(audience));
    }

    [Test]
    public void SetAudience_WithNullAudience_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetAudience(null!));
        Assert.That(ex!.ParamName, Is.EqualTo("audience"));
    }

    [Test]
    public void SetAudience_WithEmptyAudience_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetAudience(""));
        Assert.That(ex!.ParamName, Is.EqualTo("audience"));
    }

    [Test]
    public void SetExpirationTime_WithValidTimestamp_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        long expiration = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();

        // Act
        var result = extender.SetExpirationTime(expiration);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.ExpirationTime!.Value.ToUnixTimeSeconds(), Is.EqualTo(expiration));
    }

    [Test]
    public void SetExpirationTime_WithDateTimeOffset_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        var expiration = DateTimeOffset.UtcNow.AddHours(1);

        // Act
        var result = extender.SetExpirationTime(expiration);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.ExpirationTime!.Value.ToUnixTimeSeconds(), Is.EqualTo(expiration.ToUnixTimeSeconds()));
    }

    [Test]
    public void SetNotBefore_WithValidTimestamp_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        long notBefore = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Act
        var result = extender.SetNotBefore(notBefore);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.NotBefore!.Value.ToUnixTimeSeconds(), Is.EqualTo(notBefore));
    }

    [Test]
    public void SetNotBefore_WithDateTimeOffset_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        var notBefore = DateTimeOffset.UtcNow;

        // Act
        var result = extender.SetNotBefore(notBefore);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.NotBefore!.Value.ToUnixTimeSeconds(), Is.EqualTo(notBefore.ToUnixTimeSeconds()));
    }

    [Test]
    public void SetIssuedAt_WithValidTimestamp_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        long issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Act
        var result = extender.SetIssuedAt(issuedAt);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.IssuedAt!.Value.ToUnixTimeSeconds(), Is.EqualTo(issuedAt));
    }

    [Test]
    public void SetIssuedAt_WithDateTimeOffset_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        var issuedAt = DateTimeOffset.UtcNow;

        // Act
        var result = extender.SetIssuedAt(issuedAt);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.IssuedAt!.Value.ToUnixTimeSeconds(), Is.EqualTo(issuedAt.ToUnixTimeSeconds()));
    }

    [Test]
    public void SetCWTID_WithValidId_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        byte[] cwtId = new byte[] { 1, 2, 3, 4 };

        // Act
        var result = extender.SetCWTID(cwtId);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.CWTID, Is.EqualTo(cwtId));
    }

    [Test]
    public void SetCWTID_WithNullId_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetCWTID(null!));
        Assert.That(ex!.ParamName, Is.EqualTo("cwtId"));
    }

    [Test]
    public void SetCWTID_WithEmptyArray_ThrowsArgumentException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => extender.SetCWTID(Array.Empty<byte>()));
        Assert.That(ex!.ParamName, Is.EqualTo("cwtId"));
    }

    [Test]
    public void SetCustomClaim_WithValidLabelAndValue_ReturnsSelf()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        const int customLabel = 100;
        const string customValue = "custom-value";

        // Act
        var result = extender.SetCustomClaim(customLabel, customValue);

        // Assert
        Assert.That(result, Is.SameAs(extender));
        Assert.That(extender.CustomClaims[customLabel], Is.EqualTo(customValue));
    }

    [Test]
    public void SetCustomClaim_WithNullValue_ThrowsArgumentNullException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => extender.SetCustomClaim(100, null!));
        Assert.That(ex!.ParamName, Is.EqualTo("value"));
    }

    [Test]
    public void SetCustomClaim_WithIntValue_StoresCorrectly()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        const int customLabel = 100;
        const int customValue = 42;

        // Act
        extender.SetCustomClaim(customLabel, customValue);

        // Assert
        Assert.That(extender.CustomClaims[customLabel], Is.EqualTo(customValue));
    }

    [Test]
    public void RemoveClaim_WithExistingCustomClaim_ReturnsTrue()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetCustomClaim(100, "custom-value");

        // Act
        bool result = extender.RemoveClaim(100);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(extender.CustomClaims.ContainsKey(100), Is.False);
    }

    [Test]
    public void RemoveClaim_WithNonExistingClaim_ReturnsFalse()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();

        // Act
        bool result = extender.RemoveClaim(CWTClaimsHeaderLabels.Issuer);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void ExtendProtectedHeaders_WithNullHeaders_ThrowsArgumentNullException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("issuer");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => extender.ExtendProtectedHeaders(null!));
    }

    [Test]
    public void ExtendProtectedHeaders_WithNoClaims_DoesNotAddHeaders()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert - With only default subject (no real claims), headers should not be added
        Assert.That(headers.Count, Is.EqualTo(0));
        Assert.That(headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.False);
    }

    [Test]
    public void ExtendProtectedHeaders_WithIssuerClaim_AddsEncodedHeader()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("https://example.com");
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(1));
        Assert.That(headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.True);
        
        // Verify the CBOR encoding contains the issuer claim and auto-populated iat/nbf
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        Assert.That(reader.PeekState(), Is.EqualTo(CborReaderState.StartMap));
        reader.ReadStartMap();
        
        var claimsRead = new Dictionary<int, object>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == CWTClaimsHeaderLabels.Issuer)
            {
                claimsRead[label] = reader.ReadTextString();
            }
            else if (label == CWTClaimsHeaderLabels.IssuedAt || label == CWTClaimsHeaderLabels.NotBefore)
            {
                claimsRead[label] = reader.ReadInt64();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();
        
        // Verify expected claims
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.Issuer), Is.True);
        Assert.That(claimsRead[CWTClaimsHeaderLabels.Issuer], Is.EqualTo("https://example.com"));
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.IssuedAt), Is.True, "iat should be auto-populated");
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.NotBefore), Is.True, "nbf should be auto-populated");
    }

    [Test]
    public void ExtendProtectedHeaders_WithMultipleClaims_EncodesCorrectly()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("issuer");
        extender.SetSubject("subject");
        extender.SetAudience("audience");
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(1));
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        var claimsRead = new Dictionary<int, object>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == CWTClaimsHeaderLabels.Issuer || label == CWTClaimsHeaderLabels.Subject || label == CWTClaimsHeaderLabels.Audience)
            {
                claimsRead[label] = reader.ReadTextString();
            }
            else if (label == CWTClaimsHeaderLabels.IssuedAt || label == CWTClaimsHeaderLabels.NotBefore)
            {
                claimsRead[label] = reader.ReadInt64();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();

        
        Assert.That(claimsRead.Count, Is.EqualTo(5), "Should have 3 explicit claims + iat + nbf");
        Assert.That(claimsRead[CWTClaimsHeaderLabels.Issuer], Is.EqualTo("issuer"));
        Assert.That(claimsRead[CWTClaimsHeaderLabels.Subject], Is.EqualTo("subject"));
        Assert.That(claimsRead[CWTClaimsHeaderLabels.Audience], Is.EqualTo("audience"));
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.IssuedAt), Is.True, "iat should be auto-populated");
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.NotBefore), Is.True, "nbf should be auto-populated");
    }    [Test]
    public void ExtendProtectedHeaders_WithIntClaim_EncodesCorrectly()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        long expiration = 1234567890;
        extender.SetExpirationTime(expiration);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        var claimsRead = new Dictionary<int, object>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            var state = reader.PeekState();
            if (state == CborReaderState.TextString)
            {
                claimsRead[label] = reader.ReadTextString();
            }
            else
            {
                claimsRead[label] = reader.ReadInt64();
            }
        }
        reader.ReadEndMap();
        
        // Verify the explicitly set claim plus default subject and auto-populated iat/nbf
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.ExpirationTime), Is.True);
        Assert.That(claimsRead[CWTClaimsHeaderLabels.ExpirationTime], Is.EqualTo(expiration));
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.Subject), Is.True, "Default subject should be present");
    }

    [Test]
    public void ExtendProtectedHeaders_WithByteArrayClaim_EncodesCorrectly()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        byte[] cwtId = new byte[] { 1, 2, 3, 4, 5 };
        extender.SetCWTID(cwtId);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        byte[]? readCwtId = null;
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == CWTClaimsHeaderLabels.CWTID)
            {
                readCwtId = reader.ReadByteString();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();
        
        Assert.That(readCwtId, Is.Not.Null);
        Assert.That(readCwtId, Is.EqualTo(cwtId));
    }

    [Test]
    public void ExtendProtectedHeaders_WithCustomIntClaim_EncodesCorrectly()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        const int customLabel = 102;
        const int customValue = 123;
        extender.SetCustomClaim(customLabel, customValue);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        int? readCustomValue = null;
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == customLabel)
            {
                readCustomValue = reader.ReadInt32();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();
        
        Assert.That(readCustomValue, Is.Not.Null);
        Assert.That(readCustomValue, Is.EqualTo(customValue));
    }

    [Test]
    [Ignore("Unsupported types are now handled during CBOR parsing, not during ExtendProtectedHeaders")]
    public void ExtendProtectedHeaders_WithUnsupportedClaimType_ThrowsInvalidOperationException()
    {
        // This test is no longer applicable with the new CwtClaims API
        // as unsupported types would cause issues during ConvertDictionaryToCborBytes
        // or CwtClaims.FromCborBytes, not during ExtendProtectedHeaders
    }

    [Test]
    public void ExtendProtectedHeaders_WithCustomBooleanClaim_EncodesCorrectly()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        const int customLabel = 100;
        extender.SetCustomClaim(customLabel, true);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        bool? readCustomValue = null;
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == customLabel)
            {
                readCustomValue = reader.ReadBoolean();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();
        
        Assert.That(readCustomValue, Is.Not.Null);
        Assert.That(readCustomValue, Is.True);
    }

    [Test]
    public void ExtendProtectedHeaders_WithCustomDoubleClaim_EncodesCorrectly()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        const int customLabel = 101;
        const double customValue = 3.14159;
        extender.SetCustomClaim(customLabel, customValue);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        double? readCustomValue = null;
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == customLabel)
            {
                readCustomValue = reader.ReadDouble();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();
        
        Assert.That(readCustomValue, Is.Not.Null);
        Assert.That(readCustomValue, Is.EqualTo(customValue).Within(0.001));
    }

    [Test]
    public void ExtendUnProtectedHeaders_DoesNotModifyHeaders()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("issuer");
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendUnProtectedHeaders(headers);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(0));
    }

    [Test]
    public void ExtendUnProtectedHeaders_WithNullHeaders_ReturnsNewMap()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("issuer");

        // Act
        var result = extender.ExtendUnProtectedHeaders(null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(0));
    }

    [Test]
    public void FluentChaining_SupportsMultipleOperations()
    {
        // Arrange & Act
        var extender = new CWTClaimsHeaderExtender()
            .SetIssuer("issuer")
            .SetSubject("subject")
            .SetAudience("audience")
            .SetExpirationTime(1234567890)
            .SetNotBefore(1234567880)
            .SetIssuedAt(1234567880)
            .SetCustomClaim(100, "custom");

        var headers = new CoseHeaderMap();
        extender.ExtendProtectedHeaders(headers);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(1));
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        int claimCount = 0;
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            reader.ReadInt32(); // label
            reader.SkipValue(); // value
            claimCount++;
        }
        reader.ReadEndMap();

        Assert.That(claimCount, Is.EqualTo(7));
    }

    [Test]
    public void RemoveClaim_AfterSetClaim_RemovesFromEncoding()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("issuer");
        extender.SetSubject("subject");
        extender.RemoveClaim(CWTClaimsHeaderLabels.Subject);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        var claimsRead = new Dictionary<int, object>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == CWTClaimsHeaderLabels.Issuer)
            {
                claimsRead[label] = reader.ReadTextString();
            }
            else if (label == CWTClaimsHeaderLabels.IssuedAt || label == CWTClaimsHeaderLabels.NotBefore)
            {
                claimsRead[label] = reader.ReadInt64();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();

        // Verify only issuer remains (subject was removed) plus auto-populated iat/nbf
        Assert.That(claimsRead.Count, Is.EqualTo(3), "Should have issuer + iat + nbf");
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.Issuer), Is.True);
        Assert.That(claimsRead[CWTClaimsHeaderLabels.Issuer], Is.EqualTo("issuer"));
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.Subject), Is.False);
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.IssuedAt), Is.True, "iat should be auto-populated");
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.NotBefore), Is.True, "nbf should be auto-populated");
    }

    #region SCITT Schema Validation Tests

    /// <summary>
    /// Validates that the CWT Claims encoding complies with the SCITT CDDL schema.
    /// Schema: https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture/blob/main/signed_statement.cddl
    /// 
    /// Per the SCITT specification:
    /// CWT_Claims = {
    ///   &(iss: 1) => tstr     ; REQUIRED: Issuer
    ///   &(sub: 2) => tstr     ; REQUIRED: Subject
    ///   * label => any        ; Additional claims allowed
    /// }
    /// </summary>
    [Test]
    public void CWTClaims_ComplyWithScittSchema_RequiredFields()
    {
        // Arrange - Create extender with required SCITT fields
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("did:x509:test-issuer");
        extender.SetSubject("test-subject");
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert - Validate the encoded CWT Claims against SCITT schema
        Assert.That(headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.True, 
            "Protected header must contain CWT_Claims at label 15");

        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        // Validate CBOR structure
        Assert.That(reader.PeekState(), Is.EqualTo(CborReaderState.StartMap), 
            "CWT_Claims must be a CBOR map");
        
        reader.ReadStartMap();
        var claims = new Dictionary<int, object>();
        
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            
            // Read based on expected type per SCITT/RFC 8392
            if (label == CWTClaimsHeaderLabels.Issuer || label == CWTClaimsHeaderLabels.Subject)
            {
                // iss and sub must be text strings
                claims[label] = reader.ReadTextString();
            }
            else if (label == CWTClaimsHeaderLabels.IssuedAt || label == CWTClaimsHeaderLabels.NotBefore)
            {
                // iat and nbf are NumericDate (integer or floating-point per RFC 8392)
                claims[label] = reader.ReadInt64();
            }
            else
            {
                // Additional claims allowed
                reader.SkipValue();
            }
        }
        
        reader.ReadEndMap();

        // Validate REQUIRED fields per SCITT schema
        Assert.That(claims.ContainsKey(CWTClaimsHeaderLabels.Issuer), Is.True, 
            "SCITT requires 'iss' (label 1) claim");
        Assert.That(claims.ContainsKey(CWTClaimsHeaderLabels.Subject), Is.True, 
            "SCITT requires 'sub' (label 2) claim");
        
        // Validate types
        Assert.That(claims[CWTClaimsHeaderLabels.Issuer], Is.TypeOf<string>(), 
            "iss must be a text string (tstr)");
        Assert.That(claims[CWTClaimsHeaderLabels.Subject], Is.TypeOf<string>(), 
            "sub must be a text string (tstr)");
        
        // Validate values
        Assert.That(claims[CWTClaimsHeaderLabels.Issuer], Is.EqualTo("did:x509:test-issuer"));
        Assert.That(claims[CWTClaimsHeaderLabels.Subject], Is.EqualTo("test-subject"));
    }

    [Test]
    public void CWTClaims_ComplyWithScittSchema_WithAdditionalClaims()
    {
        // Arrange - Create extender with required + optional fields
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("did:x509:test-issuer");
        extender.SetSubject("test-subject");
        extender.SetAudience("test-audience");
        extender.SetExpirationTime(DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());
        extender.SetCustomClaim(100, "custom-value");
        extender.SetCustomClaim(-260, "hcert-data"); // Health Certificate claim
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        var issuerFound = false;
        var subjectFound = false;
        var claimCount = 0;
        
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            claimCount++;
            
            if (label == CWTClaimsHeaderLabels.Issuer)
            {
                issuerFound = true;
                Assert.That(reader.ReadTextString(), Is.EqualTo("did:x509:test-issuer"));
            }
            else if (label == CWTClaimsHeaderLabels.Subject)
            {
                subjectFound = true;
                Assert.That(reader.ReadTextString(), Is.EqualTo("test-subject"));
            }
            else
            {
                // Additional claims allowed by SCITT schema (* label => any)
                reader.SkipValue();
            }
        }
        
        reader.ReadEndMap();

        // Validate SCITT required fields are present
        Assert.That(issuerFound, Is.True, "SCITT requires 'iss' claim");
        Assert.That(subjectFound, Is.True, "SCITT requires 'sub' claim");
        
        // Verify additional claims were encoded (should have iss, sub, aud, exp, custom, hcert, iat, nbf)
        Assert.That(claimCount, Is.GreaterThanOrEqualTo(8), 
            "Should have required claims + additional claims + auto-populated iat/nbf");
    }

    [Test]
    public void CWTClaims_ComplyWithScittSchema_NegativeLabelsAllowed()
    {
        // Arrange - Test negative label support per IANA registry
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("did:x509:test-issuer");
        extender.SetSubject("test-subject");
        
        // Add negative labels (valid per IANA registry)
        extender.SetCustomClaim(-260, "hcert-data");  // Health Certificate
        extender.SetCustomClaim(-259, "nonce-data");  // EUPHNonce
        extender.SetCustomClaim(-1, "private-use");   // Unassigned range
        
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert - Verify negative labels are encoded
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        reader.ReadStartMap();
        var negativeLabelCount = 0;
        
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            
            if (label < 0)
            {
                negativeLabelCount++;
            }
            
            reader.SkipValue();
        }
        
        reader.ReadEndMap();

        // Verify negative labels were encoded (SCITT schema allows * label => any)
        Assert.That(negativeLabelCount, Is.EqualTo(3), 
            "All negative labels should be encoded per IANA registry");
    }

    #endregion

    #region PreventMerge Tests

    [Test]
    public void Constructor_WithPreventMergeTrue_StoresFlag()
    {
        // Arrange & Act
        var extender = new CWTClaimsHeaderExtender(preventMerge: true);

        // Assert
        Assert.That(extender, Is.Not.Null);
    }

    [Test]
    public void ExtendProtectedHeaders_WithPreventMergeFalse_MergesSuccessfully()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var existingClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "existing-issuer" } };
        var existingClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(existingClaimsDict));
        headers.SetCwtClaims(existingClaims);

        var extender = new CWTClaimsHeaderExtender(preventMerge: false);
        extender.SetSubject("new-subject");

        // Act
        var result = extender.ExtendProtectedHeaders(headers);

        // Assert
        result.TryGetCwtClaims(out CwtClaims? finalClaims);
        Assert.That(finalClaims, Is.Not.Null);
        Assert.That(finalClaims!.Issuer, Is.EqualTo("existing-issuer"));
        Assert.That(finalClaims.Subject, Is.EqualTo("new-subject"));
    }

    [Test]
    public void ExtendProtectedHeaders_WithPreventMergeTrueAndExistingClaims_ThrowsException()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var existingClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "existing-issuer" } };
        var existingClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(existingClaimsDict));
        headers.SetCwtClaims(existingClaims);

        var extender = new CWTClaimsHeaderExtender(preventMerge: true);
        extender.SetIssuer("new-issuer");

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => 
            extender.ExtendProtectedHeaders(headers));
        Assert.That(ex!.Message, Does.Contain("CWT claims already exist"));
        Assert.That(ex.Message, Does.Contain("preventMerge"));
    }

    [Test]
    public void ExtendProtectedHeaders_WithPreventMergeTrueAndNoClaims_Succeeds()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var extender = new CWTClaimsHeaderExtender(preventMerge: true);
        extender.SetIssuer("new-issuer");
        extender.SetSubject("new-subject");

        // Act
        var result = extender.ExtendProtectedHeaders(headers);

        // Assert
        result.TryGetCwtClaims(out CwtClaims? finalClaims);
        Assert.That(finalClaims, Is.Not.Null);
        Assert.That(finalClaims!.Issuer, Is.EqualTo("new-issuer"));
        Assert.That(finalClaims.Subject, Is.EqualTo("new-subject"));
    }

    [Test]
    public void ExtendUnProtectedHeaders_WithPreventMergeTrueAndExistingClaims_ThrowsException()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var existingClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "existing-issuer" } };
        var existingClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(existingClaimsDict));
        headers.SetCwtClaims(existingClaims);

        var extender = new CWTClaimsHeaderExtender(preventMerge: true, headerPlacement: CwtClaimsHeaderPlacement.UnprotectedOnly);
        extender.SetIssuer("new-issuer");

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => 
            extender.ExtendUnProtectedHeaders(headers));
        Assert.That(ex!.Message, Does.Contain("CWT claims already exist"));
        Assert.That(ex.Message, Does.Contain("preventMerge"));
    }

    #endregion

    #region HeaderPlacement Tests

    [Test]
    public void Constructor_WithProtectedOnlyPlacement_UsesDefault()
    {
        // Arrange & Act
        var extender = new CWTClaimsHeaderExtender(headerPlacement: CwtClaimsHeaderPlacement.ProtectedOnly);
        extender.SetIssuer("test-issuer");

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        extender.ExtendProtectedHeaders(protectedHeaders);
        extender.ExtendUnProtectedHeaders(unprotectedHeaders);

        // Assert
        Assert.That(protectedHeaders.TryGetCwtClaims(out CwtClaims? protectedClaims), Is.True);
        Assert.That(protectedClaims!.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(unprotectedHeaders.TryGetCwtClaims(out _), Is.False);
    }

    [Test]
    public void Constructor_WithUnprotectedOnlyPlacement_AddsToUnprotectedOnly()
    {
        // Arrange & Act
        var extender = new CWTClaimsHeaderExtender(headerPlacement: CwtClaimsHeaderPlacement.UnprotectedOnly);
        extender.SetIssuer("test-issuer");

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        extender.ExtendProtectedHeaders(protectedHeaders);
        extender.ExtendUnProtectedHeaders(unprotectedHeaders);

        // Assert
        Assert.That(protectedHeaders.TryGetCwtClaims(out _), Is.False);
        Assert.That(unprotectedHeaders.TryGetCwtClaims(out CwtClaims? unprotectedClaims), Is.True);
        Assert.That(unprotectedClaims!.Issuer, Is.EqualTo("test-issuer"));
    }

    [Test]
    public void Constructor_WithBothPlacement_AddsToBothHeaders()
    {
        // Arrange & Act
        var extender = new CWTClaimsHeaderExtender(headerPlacement: CwtClaimsHeaderPlacement.Both);
        extender.SetIssuer("test-issuer");
        extender.SetSubject("test-subject");

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        extender.ExtendProtectedHeaders(protectedHeaders);
        extender.ExtendUnProtectedHeaders(unprotectedHeaders);

        // Assert
        Assert.That(protectedHeaders.TryGetCwtClaims(out CwtClaims? protectedClaims), Is.True);
        Assert.That(protectedClaims!.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(protectedClaims.Subject, Is.EqualTo("test-subject"));
        
        Assert.That(unprotectedHeaders.TryGetCwtClaims(out CwtClaims? unprotectedClaims), Is.True);
        Assert.That(unprotectedClaims!.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(unprotectedClaims.Subject, Is.EqualTo("test-subject"));
    }

    [Test]
    public void Constructor_WithCwtClaimsAndPreventMerge_StoresBothOptions()
    {
        // Arrange
        var claimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "initial-issuer" } };
        var claims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claimsDict));

        // Act
        var extender = new CWTClaimsHeaderExtender(claims, preventMerge: true, headerPlacement: CwtClaimsHeaderPlacement.UnprotectedOnly);
        var headers = new CoseHeaderMap();
        extender.ExtendUnProtectedHeaders(headers);

        // Assert
        Assert.That(headers.TryGetCwtClaims(out CwtClaims? result), Is.True);
        Assert.That(result!.Issuer, Is.EqualTo("initial-issuer"));
    }

    [Test]
    public void HeaderPlacement_BothWithPreventMerge_EnforcesOnBothHeaders()
    {
        // Arrange
        var protectedHeaders = new CoseHeaderMap();
        var existingProtectedClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "protected-issuer" } };
        var existingProtectedClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(existingProtectedClaimsDict));
        protectedHeaders.SetCwtClaims(existingProtectedClaims);

        var unprotectedHeaders = new CoseHeaderMap();

        var extender = new CWTClaimsHeaderExtender(preventMerge: true, headerPlacement: CwtClaimsHeaderPlacement.Both);
        extender.SetSubject("new-subject");

        // Act & Assert - Should throw on protected headers
        Assert.Throws<InvalidOperationException>(() => 
            extender.ExtendProtectedHeaders(protectedHeaders));
    }

    [Test]
    public void HeaderPlacement_BothWithPreventMerge_EnforcesOnUnprotectedToo()
    {
        // Arrange
        var protectedHeaders = new CoseHeaderMap();

        var unprotectedHeaders = new CoseHeaderMap();
        var existingUnprotectedClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "unprotected-issuer" } };
        var existingUnprotectedClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(existingUnprotectedClaimsDict));
        unprotectedHeaders.SetCwtClaims(existingUnprotectedClaims);

        var extender = new CWTClaimsHeaderExtender(preventMerge: true, headerPlacement: CwtClaimsHeaderPlacement.Both);
        extender.SetSubject("new-subject");

        // Act
        extender.ExtendProtectedHeaders(protectedHeaders); // Should succeed (no existing claims)

        // Assert - Should throw on unprotected headers
        Assert.Throws<InvalidOperationException>(() => 
            extender.ExtendUnProtectedHeaders(unprotectedHeaders));
    }

    [Test]
    public void HeaderPlacement_UnprotectedOnlyWithMerge_MergesInUnprotectedHeaders()
    {
        // Arrange
        var unprotectedHeaders = new CoseHeaderMap();
        var existingClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "existing-issuer" } };
        var existingClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(existingClaimsDict));
        unprotectedHeaders.SetCwtClaims(existingClaims);

        var extender = new CWTClaimsHeaderExtender(preventMerge: false, headerPlacement: CwtClaimsHeaderPlacement.UnprotectedOnly);
        extender.SetSubject("new-subject");

        // Act
        var result = extender.ExtendUnProtectedHeaders(unprotectedHeaders);

        // Assert
        result.TryGetCwtClaims(out CwtClaims? finalClaims);
        Assert.That(finalClaims, Is.Not.Null);
        Assert.That(finalClaims!.Issuer, Is.EqualTo("existing-issuer"));
        Assert.That(finalClaims.Subject, Is.EqualTo("new-subject"));
    }

    #endregion

    #region CustomHeaderLabel Tests

    [Test]
    public void Constructor_WithCustomHeaderLabel_UsesCustomLabel()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(999);
        var extender = new CWTClaimsHeaderExtender(customHeaderLabel: customLabel);
        extender.SetIssuer("test-issuer");

        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert - Should be at custom label, not default
        Assert.That(headers.TryGetValue(customLabel, out _), Is.True);
        Assert.That(headers.TryGetValue(CWTClaimsHeaderLabels.CWTClaims, out _), Is.False);
        Assert.That(headers.TryGetCwtClaims(out CwtClaims? claims, customLabel), Is.True);
        Assert.That(claims!.Issuer, Is.EqualTo("test-issuer"));
    }

    [Test]
    public void SetCwtClaims_WithCustomLabel_StoresAtCustomLabel()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(888);
        var claimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "custom-issuer" } };
        var claims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claimsDict));
        var headers = new CoseHeaderMap();

        // Act
        headers.SetCwtClaims(claims, customLabel);

        // Assert
        Assert.That(headers.TryGetValue(customLabel, out _), Is.True);
        Assert.That(headers.TryGetCwtClaims(out CwtClaims? retrievedClaims, customLabel), Is.True);
        Assert.That(retrievedClaims!.Issuer, Is.EqualTo("custom-issuer"));
    }

    [Test]
    public void TryGetCwtClaims_WithCustomLabel_RetrievesFromCustomLabel()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(777);
        var claimsDict = new Dictionary<int, object> 
        { 
            { CWTClaimsHeaderLabels.Issuer, "custom-issuer" },
            { CWTClaimsHeaderLabels.Subject, "custom-subject" }
        };
        var claims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claimsDict));
        var headers = new CoseHeaderMap();
        headers.SetCwtClaims(claims, customLabel);

        // Act
        bool result = headers.TryGetCwtClaims(out CwtClaims? retrievedClaims, customLabel);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(retrievedClaims, Is.Not.Null);
        Assert.That(retrievedClaims!.Issuer, Is.EqualTo("custom-issuer"));
        Assert.That(retrievedClaims.Subject, Is.EqualTo("custom-subject"));
    }

    [Test]
    public void TryGetCwtClaims_WithWrongLabel_ReturnsFalse()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(666);
        var wrongLabel = new CoseHeaderLabel(555);
        var claimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "test-issuer" } };
        var claims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(claimsDict));
        var headers = new CoseHeaderMap();
        headers.SetCwtClaims(claims, customLabel);

        // Act
        bool result = headers.TryGetCwtClaims(out CwtClaims? retrievedClaims, wrongLabel);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(retrievedClaims, Is.Null);
    }

    [Test]
    public void ExtendProtectedHeaders_WithCustomLabel_PreventsMergeAtCustomLabel()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(444);
        var headers = new CoseHeaderMap();
        var existingClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "existing-issuer" } };
        var existingClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(existingClaimsDict));
        headers.SetCwtClaims(existingClaims, customLabel);

        var extender = new CWTClaimsHeaderExtender(preventMerge: true, customHeaderLabel: customLabel);
        extender.SetIssuer("new-issuer");

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => 
            extender.ExtendProtectedHeaders(headers));
        Assert.That(ex!.Message, Does.Contain("CWT claims already exist"));
    }

    [Test]
    public void MergeCwtClaims_WithCustomLabel_MergesAtCustomLabel()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(333);
        var headers = new CoseHeaderMap();
        var existingClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Issuer, "existing-issuer" } };
        var existingClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(existingClaimsDict));
        headers.SetCwtClaims(existingClaims, customLabel);

        var newClaimsDict = new Dictionary<int, object> { { CWTClaimsHeaderLabels.Subject, "new-subject" } };
        var newClaims = CwtClaims.FromCborBytes(ConvertDictionaryToCborBytes(newClaimsDict));

        // Act
        headers.MergeCwtClaims(newClaims, logOverrides: false, headerLabel: customLabel);

        // Assert
        headers.TryGetCwtClaims(out CwtClaims? mergedClaims, customLabel);
        Assert.That(mergedClaims, Is.Not.Null);
        Assert.That(mergedClaims!.Issuer, Is.EqualTo("existing-issuer"));
        Assert.That(mergedClaims.Subject, Is.EqualTo("new-subject"));
    }

    [Test]
    public void CustomHeaderLabel_UnprotectedHeaders_WorksCorrectly()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(222);
        var extender = new CWTClaimsHeaderExtender(
            headerPlacement: CwtClaimsHeaderPlacement.UnprotectedOnly, 
            customHeaderLabel: customLabel);
        extender.SetIssuer("unprotected-issuer");

        var unprotectedHeaders = new CoseHeaderMap();

        // Act
        extender.ExtendUnProtectedHeaders(unprotectedHeaders);

        // Assert
        Assert.That(unprotectedHeaders.TryGetCwtClaims(out CwtClaims? claims, customLabel), Is.True);
        Assert.That(claims!.Issuer, Is.EqualTo("unprotected-issuer"));
    }

    #endregion
}


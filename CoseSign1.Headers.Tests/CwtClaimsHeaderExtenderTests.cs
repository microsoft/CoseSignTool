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
    [Test]
    public void Constructor_CreatesEmptyClaimsCollection()
    {
        // Arrange & Act
        var extender = new CWTClaimsHeaderExtender();

        // Assert
        Assert.That(extender, Is.Not.Null);
        Assert.That(extender.AllClaims.Count, Is.EqualTo(0));
        Assert.That(extender.Issuer, Is.Null);
        Assert.That(extender.Subject, Is.Null);
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
        var extender = new CWTClaimsHeaderExtender(claims);

        // Assert
        Assert.That(extender.AllClaims.Count, Is.EqualTo(3));
        Assert.That(extender.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(extender.Subject, Is.EqualTo("test-subject"));
        Assert.That(extender.ExpirationTime, Is.EqualTo(1234567890L));
    }

    [Test]
    public void Properties_WithNonStringIssuer_ReturnsNull()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.Issuer, 123 } // Wrong type
        };
        var extender = new CWTClaimsHeaderExtender(claims);

        // Act & Assert
        Assert.That(extender.Issuer, Is.Null);
    }

    [Test]
    public void Properties_WithNonStringSubject_ReturnsNull()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.Subject, 123 } // Wrong type
        };
        var extender = new CWTClaimsHeaderExtender(claims);

        // Act & Assert
        Assert.That(extender.Subject, Is.Null);
    }

    [Test]
    public void Properties_WithNonStringAudience_ReturnsNull()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.Audience, 123 } // Wrong type
        };
        var extender = new CWTClaimsHeaderExtender(claims);

        // Act & Assert
        Assert.That(extender.Audience, Is.Null);
    }

    [Test]
    public void Properties_WithNonLongExpirationTime_ReturnsNull()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.ExpirationTime, "not a long" } // Wrong type
        };
        var extender = new CWTClaimsHeaderExtender(claims);

        // Act & Assert
        Assert.That(extender.ExpirationTime, Is.Null);
    }

    [Test]
    public void Properties_WithNonLongNotBefore_ReturnsNull()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.NotBefore, "not a long" } // Wrong type
        };
        var extender = new CWTClaimsHeaderExtender(claims);

        // Act & Assert
        Assert.That(extender.NotBefore, Is.Null);
    }

    [Test]
    public void Properties_WithNonLongIssuedAt_ReturnsNull()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.IssuedAt, "not a long" } // Wrong type
        };
        var extender = new CWTClaimsHeaderExtender(claims);

        // Act & Assert
        Assert.That(extender.IssuedAt, Is.Null);
    }

    [Test]
    public void Properties_WithNonByteArrayCWTID_ReturnsNull()
    {
        // Arrange
        var claims = new Dictionary<int, object>
        {
            { CWTClaimsHeaderLabels.CWTID, "not a byte array" } // Wrong type
        };
        var extender = new CWTClaimsHeaderExtender(claims);

        // Act & Assert
        Assert.That(extender.CWTID, Is.Null);
    }

    [Test]
    public void AllClaims_ReturnsReadOnlyDictionary()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("test-issuer");
        extender.SetSubject("test-subject");

        // Act
        var allClaims = extender.AllClaims;

        // Assert
        Assert.That(allClaims, Is.InstanceOf<IReadOnlyDictionary<int, object>>());
        Assert.That(allClaims.Count, Is.EqualTo(2));
        Assert.That(allClaims[CWTClaimsHeaderLabels.Issuer], Is.EqualTo("test-issuer"));
        Assert.That(allClaims[CWTClaimsHeaderLabels.Subject], Is.EqualTo("test-subject"));
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
        Assert.That(extender.AllClaims[CWTClaimsHeaderLabels.Issuer], Is.EqualTo(issuer));
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
        Assert.That(extender.ExpirationTime, Is.EqualTo(expiration));
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
        Assert.That(extender.ExpirationTime, Is.EqualTo(expiration.ToUnixTimeSeconds()));
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
        Assert.That(extender.NotBefore, Is.EqualTo(notBefore));
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
        Assert.That(extender.NotBefore, Is.EqualTo(notBefore.ToUnixTimeSeconds()));
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
        Assert.That(extender.IssuedAt, Is.EqualTo(issuedAt));
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
        Assert.That(extender.IssuedAt, Is.EqualTo(issuedAt.ToUnixTimeSeconds()));
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
        Assert.That(extender.AllClaims[customLabel], Is.EqualTo(customValue));
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
        Assert.That(extender.AllClaims[customLabel], Is.EqualTo(customValue));
    }

    [Test]
    public void RemoveClaim_WithExistingClaim_ReturnsTrue()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        extender.SetIssuer("issuer");

        // Act
        bool result = extender.RemoveClaim(CWTClaimsHeaderLabels.Issuer);

        // Assert
        Assert.That(result, Is.True);
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
    public void ExtendProtectedHeaders_WithNoClaims_DoesNotAddHeader()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(0));
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
        var claimsRead = new Dictionary<int, long>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            claimsRead[label] = reader.ReadInt64();
        }
        reader.ReadEndMap();
        
        // Verify the explicitly set claim - no iat/nbf since no issuer/subject
        Assert.That(claimsRead.Count, Is.EqualTo(1), "Should only have exp, no auto-populated claims without issuer/subject");
        Assert.That(claimsRead[CWTClaimsHeaderLabels.ExpirationTime], Is.EqualTo(expiration));
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
    public void ExtendProtectedHeaders_WithUnsupportedClaimType_ThrowsInvalidOperationException()
    {
        // Arrange
        var extender = new CWTClaimsHeaderExtender();
        var unsupportedValue = new object(); // Plain object is not supported
        var claims = new Dictionary<int, object>
        {
            { 100, unsupportedValue }
        };
        extender = new CWTClaimsHeaderExtender(claims);
        var headers = new CoseHeaderMap();

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => extender.ExtendProtectedHeaders(headers));
        Assert.That(ex!.Message, Does.Contain("Unsupported claim value type"));
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
}

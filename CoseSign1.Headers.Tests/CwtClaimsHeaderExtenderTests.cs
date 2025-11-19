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
        
        // Verify the CBOR encoding contains the issuer claim
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new CborReader(encodedClaims);
        
        Assert.That(reader.PeekState(), Is.EqualTo(CborReaderState.StartMap));
        reader.ReadStartMap();
        Assert.That(reader.ReadInt32(), Is.EqualTo(CWTClaimsHeaderLabels.Issuer));
        Assert.That(reader.ReadTextString(), Is.EqualTo("https://example.com"));
        reader.ReadEndMap();
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
        var claimsRead = new Dictionary<int, string>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            string value = reader.ReadTextString();
            claimsRead[label] = value;
        }
        reader.ReadEndMap();

        Assert.That(claimsRead.Count, Is.EqualTo(3));
        Assert.That(claimsRead[CWTClaimsHeaderLabels.Issuer], Is.EqualTo("issuer"));
        Assert.That(claimsRead[CWTClaimsHeaderLabels.Subject], Is.EqualTo("subject"));
        Assert.That(claimsRead[CWTClaimsHeaderLabels.Audience], Is.EqualTo("audience"));
    }

    [Test]
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
        Assert.That(reader.ReadInt32(), Is.EqualTo(CWTClaimsHeaderLabels.ExpirationTime));
        Assert.That(reader.ReadInt64(), Is.EqualTo(expiration));
        reader.ReadEndMap();
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
        Assert.That(reader.ReadInt32(), Is.EqualTo(CWTClaimsHeaderLabels.CWTID));
        byte[] readBytes = reader.ReadByteString();
        Assert.That(readBytes, Is.EqualTo(cwtId));
        reader.ReadEndMap();
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
        Assert.That(reader.ReadInt32(), Is.EqualTo(customLabel));
        Assert.That(reader.ReadInt32(), Is.EqualTo(customValue));
        reader.ReadEndMap();
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
        Assert.That(reader.ReadInt32(), Is.EqualTo(customLabel));
        Assert.That(reader.ReadBoolean(), Is.True);
        reader.ReadEndMap();
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
        Assert.That(reader.ReadInt32(), Is.EqualTo(customLabel));
        Assert.That(reader.ReadDouble(), Is.EqualTo(customValue).Within(0.00001));
        reader.ReadEndMap();
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
        var claimsRead = new Dictionary<int, string>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            string value = reader.ReadTextString();
            claimsRead[label] = value;
        }
        reader.ReadEndMap();

        Assert.That(claimsRead.Count, Is.EqualTo(1));
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.Issuer), Is.True);
        Assert.That(claimsRead.ContainsKey(CWTClaimsHeaderLabels.Subject), Is.False);
    }
}

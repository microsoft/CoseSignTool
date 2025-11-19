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

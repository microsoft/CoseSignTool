// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using CoseSign1.Headers;

namespace CoseSign1.Headers.Tests;

[TestFixture]
public class CwtClaimsAdditionalTests
{
    [Test]
    public void IsDefault_WithDefaultInstance_ReturnsTrue()
    {
        // Arrange
        var claims = new CwtClaims();

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsDefault_WithIssuerSet_ReturnsFalse()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test" };

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsDefault_WithSubjectSet_ReturnsFalse()
    {
        // Arrange
        var claims = new CwtClaims { Subject = "test" };

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsDefault_WithAudienceSet_ReturnsFalse()
    {
        // Arrange
        var claims = new CwtClaims { Audience = "test" };

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsDefault_WithExpirationTimeSet_ReturnsFalse()
    {
        // Arrange
        var claims = new CwtClaims { ExpirationTime = DateTimeOffset.UtcNow };

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsDefault_WithNotBeforeSet_ReturnsFalse()
    {
        // Arrange
        var claims = new CwtClaims { NotBefore = DateTimeOffset.UtcNow };

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsDefault_WithIssuedAtSet_ReturnsFalse()
    {
        // Arrange
        var claims = new CwtClaims { IssuedAt = DateTimeOffset.UtcNow };

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsDefault_WithCwtIdSet_ReturnsFalse()
    {
        // Arrange
        var claims = new CwtClaims { CwtId = new byte[] { 1, 2, 3 } };

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsDefault_WithCustomClaimSet_ReturnsFalse()
    {
        // Arrange
        var claims = new CwtClaims();
        claims.CustomClaims[100] = "test";

        // Act
        var result = claims.IsDefault();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void Merge_WithNull_ReturnsDeepCopy()
    {
        // Arrange
        var original = new CwtClaims
        {
            Issuer = "issuer",
            Subject = "subject",
            CwtId = new byte[] { 1, 2, 3 }
        };
        original.CustomClaims[100] = "test";

        // Act
        var merged = original.Merge(null);

        // Assert
        Assert.That(merged, Is.Not.SameAs(original));
        Assert.That(merged.Issuer, Is.EqualTo(original.Issuer));
        Assert.That(merged.Subject, Is.EqualTo(original.Subject));
        Assert.That(merged.CwtId, Is.EqualTo(original.CwtId));
        Assert.That(merged.CwtId, Is.Not.SameAs(original.CwtId));
        Assert.That(merged.CustomClaims, Is.Not.SameAs(original.CustomClaims));
        Assert.That(merged.CustomClaims[100], Is.EqualTo("test"));
    }

    [Test]
    public void Merge_WithOther_OverwritesValues()
    {
        // Arrange
        var baseClaims = new CwtClaims
        {
            Issuer = "original-issuer",
            Subject = "original-subject",
            Audience = "original-audience"
        };
        baseClaims.CustomClaims[100] = "original-value";

        var otherClaims = new CwtClaims
        {
            Issuer = "new-issuer",
            ExpirationTime = DateTimeOffset.UtcNow.AddHours(1)
        };
        otherClaims.CustomClaims[100] = "new-value";
        otherClaims.CustomClaims[200] = "additional-value";

        // Act
        var merged = baseClaims.Merge(otherClaims);

        // Assert
        Assert.That(merged.Issuer, Is.EqualTo("new-issuer")); // Overwritten
        Assert.That(merged.Subject, Is.EqualTo("original-subject")); // Preserved
        Assert.That(merged.Audience, Is.EqualTo("original-audience")); // Preserved
        Assert.That(merged.ExpirationTime, Is.EqualTo(otherClaims.ExpirationTime)); // Added
        Assert.That(merged.CustomClaims[100], Is.EqualTo("new-value")); // Overwritten
        Assert.That(merged.CustomClaims[200], Is.EqualTo("additional-value")); // Added
    }

    [Test]
    public void Merge_WithAllProperties_MergesCorrectly()
    {
        // Arrange
        var baseClaims = new CwtClaims
        {
            Issuer = "base-issuer"
        };

        var otherClaims = new CwtClaims
        {
            Subject = "new-subject",
            Audience = "new-audience",
            ExpirationTime = new DateTimeOffset(2025, 12, 31, 12, 0, 0, TimeSpan.Zero),
            NotBefore = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            IssuedAt = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero),
            CwtId = new byte[] { 1, 2, 3 }
        };

        // Act
        var merged = baseClaims.Merge(otherClaims);

        // Assert
        Assert.That(merged.Issuer, Is.EqualTo("base-issuer"));
        Assert.That(merged.Subject, Is.EqualTo("new-subject"));
        Assert.That(merged.Audience, Is.EqualTo("new-audience"));
        Assert.That(merged.ExpirationTime, Is.EqualTo(otherClaims.ExpirationTime));
        Assert.That(merged.NotBefore, Is.EqualTo(otherClaims.NotBefore));
        Assert.That(merged.IssuedAt, Is.EqualTo(otherClaims.IssuedAt));
        Assert.That(merged.CwtId, Is.EqualTo(otherClaims.CwtId));
        Assert.That(merged.CwtId, Is.Not.SameAs(otherClaims.CwtId));
    }

    [Test]
    public void ToString_WithDefaultInstance_ReturnsEmptyString()
    {
        // Arrange
        var claims = new CwtClaims();

        // Act
        var result = claims.ToString();

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void ToString_WithAllProperties_IncludesAllFields()
    {
        // Arrange
        var claims = new CwtClaims
        {
            Issuer = "test-issuer",
            Subject = "test-subject",
            Audience = "test-audience",
            ExpirationTime = new DateTimeOffset(2025, 12, 31, 12, 0, 0, TimeSpan.Zero),
            NotBefore = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            IssuedAt = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero),
            CwtId = new byte[] { 0xAA, 0xBB, 0xCC }
        };
        claims.CustomClaims[100] = "custom-value";
        claims.CustomClaims[200] = new byte[] { 1, 2 };

        // Act
        var result = claims.ToString();

        // Assert
        Assert.That(result, Does.Contain("Issuer: test-issuer"));
        Assert.That(result, Does.Contain("Subject: test-subject"));
        Assert.That(result, Does.Contain("Audience: test-audience"));
        Assert.That(result, Does.Contain("Expires:"));
        Assert.That(result, Does.Contain("Not Before:"));
        Assert.That(result, Does.Contain("Issued At:"));
        Assert.That(result, Does.Contain("CWT ID: AA-BB-CC"));
        Assert.That(result, Does.Contain("Custom Claims: 2"));
        Assert.That(result, Does.Contain("[100]: custom-value"));
        Assert.That(result, Does.Contain("[200]: [2 bytes]"));
    }

    [Test]
    public void FromCborBytes_WithNegativeInteger_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteInt32(100); // Custom claim
        writer.WriteInt64(-123); // Negative integer
        writer.WriteEndMap();
        var cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims[100], Is.EqualTo(-123L));
    }

    [Test]
    public void FromCborBytes_WithDouble_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteInt32(100); // Custom claim
        writer.WriteDouble(3.14159);
        writer.WriteEndMap();
        var cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims[100], Is.EqualTo(3.14159).Within(0.00001));
    }

    [Test]
    public void FromCborBytes_WithByteString_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteInt32(100); // Custom claim
        writer.WriteByteString(new byte[] { 1, 2, 3, 4, 5 });
        writer.WriteEndMap();
        var cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims[100], Is.EqualTo(new byte[] { 1, 2, 3, 4, 5 }));
    }

    [Test]
    public void FromCborBytes_WithBoolean_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(100);
        writer.WriteBoolean(true);
        writer.WriteInt32(200);
        writer.WriteBoolean(false);
        writer.WriteEndMap();
        var cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims[100], Is.True);
        Assert.That(claims.CustomClaims[200], Is.False);
    }

    [Test]
    public void FromCborBytes_WithComplexType_StoresAsRawCbor()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteInt32(100); // Custom claim
        writer.WriteStartArray(3); // Complex type (array)
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteEndArray();
        writer.WriteEndMap();
        var cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims[100], Is.InstanceOf<byte[]>());
        var rawCbor = (byte[])claims.CustomClaims[100];
        Assert.That(rawCbor.Length, Is.GreaterThan(0));
    }

    [Test]
    public void ToCborBytes_WithIntCustomClaim_SerializesCorrectly()
    {
        // Arrange
        var claims = new CwtClaims();
        claims.CustomClaims[100] = 42; // int, not long

        // Act
        var cborBytes = claims.ToCborBytes();

        // Assert
        var parsed = CwtClaims.FromCborBytes(cborBytes);
        Assert.That(parsed.CustomClaims[100], Is.EqualTo(42L)); // Will be parsed as long
    }

    [Test]
    public void ToCborBytes_WithDoubleCustomClaim_SerializesCorrectly()
    {
        // Arrange
        var claims = new CwtClaims();
        claims.CustomClaims[100] = 3.14159;

        // Act
        var cborBytes = claims.ToCborBytes();

        // Assert
        var parsed = CwtClaims.FromCborBytes(cborBytes);
        Assert.That(parsed.CustomClaims[100], Is.EqualTo(3.14159).Within(0.00001));
    }

    [Test]
    public void ToCborBytes_WithByteArrayCustomClaim_SerializesCorrectly()
    {
        // Arrange
        var claims = new CwtClaims();
        claims.CustomClaims[100] = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };

        // Act
        var cborBytes = claims.ToCborBytes();

        // Assert
        var parsed = CwtClaims.FromCborBytes(cborBytes);
        Assert.That(parsed.CustomClaims[100], Is.EqualTo(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }));
    }

    [Test]
    public void ToCborBytes_WithUnsupportedType_ThrowsInvalidOperationException()
    {
        // Arrange
        var claims = new CwtClaims();
        claims.CustomClaims[100] = new object(); // Unsupported type

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => claims.ToCborBytes());
        Assert.That(ex!.Message, Does.Contain("Unsupported CWT claim value type"));
        Assert.That(ex.Message, Does.Contain("Object"));
    }

    [Test]
    public void ToCborBytes_WithEmptyClaims_CreatesEmptyMap()
    {
        // Arrange
        var claims = new CwtClaims();

        // Act
        var cborBytes = claims.ToCborBytes();

        // Assert
        var reader = new CborReader(cborBytes);
        var mapSize = reader.ReadStartMap();
        Assert.That(mapSize, Is.EqualTo(0));
    }

    [Test]
    public void FromCborBytes_WithAllStandardLabels_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(7);

        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");

        writer.WriteInt32(CWTClaimsHeaderLabels.Subject);
        writer.WriteTextString("subject");

        writer.WriteInt32(CWTClaimsHeaderLabels.Audience);
        writer.WriteTextString("audience");

        writer.WriteInt32(CWTClaimsHeaderLabels.ExpirationTime);
        writer.WriteInt64(1735689600); // 2025-01-01 00:00:00 UTC

        writer.WriteInt32(CWTClaimsHeaderLabels.NotBefore);
        writer.WriteInt64(1704067200); // 2024-01-01 00:00:00 UTC

        writer.WriteInt32(CWTClaimsHeaderLabels.IssuedAt);
        writer.WriteInt64(1719878400); // 2024-07-02 00:00:00 UTC

        writer.WriteInt32(CWTClaimsHeaderLabels.CWTID);
        writer.WriteByteString(new byte[] { 0x01, 0x02, 0x03, 0x04 });

        writer.WriteEndMap();
        var cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.Issuer, Is.EqualTo("issuer"));
        Assert.That(claims.Subject, Is.EqualTo("subject"));
        Assert.That(claims.Audience, Is.EqualTo("audience"));
        Assert.That(claims.ExpirationTime!.Value.ToUnixTimeSeconds(), Is.EqualTo(1735689600));
        Assert.That(claims.NotBefore!.Value.ToUnixTimeSeconds(), Is.EqualTo(1704067200));
        Assert.That(claims.IssuedAt!.Value.ToUnixTimeSeconds(), Is.EqualTo(1719878400));
        Assert.That(claims.CwtId, Is.EqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 }));
    }

    [Test]
    public void CopyConstructor_WithNullCwtId_HandlesCorrectly()
    {
        // Arrange
        var original = new CwtClaims
        {
            Issuer = "test",
            CwtId = null
        };

        // Act
        var copy = new CwtClaims(original);

        // Assert
        Assert.That(copy.CwtId, Is.Null);
    }
}
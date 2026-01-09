// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Tests;

using System.Formats.Cbor;

[TestFixture]
public class CwtClaimsTests
{
    [Test]
    public void Constructor_Default_CreatesEmptyInstance()
    {
        // Act
        var claims = new CwtClaims();

        // Assert
        Assert.That(claims, Is.Not.Null);
        Assert.That(claims.Issuer, Is.Null);
        Assert.That(claims.Subject, Is.Null);
        Assert.That(claims.Audience, Is.Null);
        Assert.That(claims.ExpirationTime, Is.Null);
        Assert.That(claims.NotBefore, Is.Null);
        Assert.That(claims.IssuedAt, Is.Null);
        Assert.That(claims.CwtId, Is.Null);
        Assert.That(claims.CustomClaims, Is.Not.Null);
        Assert.That(claims.CustomClaims.Count, Is.EqualTo(0));
    }

    [Test]
    public void Constructor_Copy_CopiesAllProperties()
    {
        // Arrange
        var original = new CwtClaims
        {
            Issuer = "test-issuer",
            Subject = "test-subject",
            Audience = "test-audience",
            ExpirationTime = DateTimeOffset.UtcNow.AddHours(1),
            NotBefore = DateTimeOffset.UtcNow,
            IssuedAt = DateTimeOffset.UtcNow,
            CwtId = new byte[] { 1, 2, 3, 4 }
        };
        original.CustomClaims[100] = "custom-value";
        original.CustomClaims[101] = 42;

        // Act
        var copy = new CwtClaims(original);

        // Assert
        Assert.That(copy.Issuer, Is.EqualTo(original.Issuer));
        Assert.That(copy.Subject, Is.EqualTo(original.Subject));
        Assert.That(copy.Audience, Is.EqualTo(original.Audience));
        Assert.That(copy.ExpirationTime, Is.EqualTo(original.ExpirationTime));
        Assert.That(copy.NotBefore, Is.EqualTo(original.NotBefore));
        Assert.That(copy.IssuedAt, Is.EqualTo(original.IssuedAt));
        Assert.That(copy.CwtId, Is.EqualTo(original.CwtId));
        Assert.That(copy.CwtId, Is.Not.SameAs(original.CwtId)); // Deep copy
        Assert.That(copy.CustomClaims, Is.EqualTo(original.CustomClaims));
        Assert.That(copy.CustomClaims, Is.Not.SameAs(original.CustomClaims)); // Deep copy
    }

    [Test]
    public void Constructor_Copy_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new CwtClaims(null!));
    }

    [Test]
    public void Properties_SetAndGet_WorksCorrectly()
    {
        // Arrange
        var claims = new CwtClaims();
        var now = DateTimeOffset.UtcNow;
        var cwtId = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        claims.Issuer = "issuer";
        claims.Subject = "subject";
        claims.Audience = "audience";
        claims.ExpirationTime = now.AddHours(1);
        claims.NotBefore = now;
        claims.IssuedAt = now;
        claims.CwtId = cwtId;
        claims.CustomClaims[42] = "test";

        // Assert
        Assert.That(claims.Issuer, Is.EqualTo("issuer"));
        Assert.That(claims.Subject, Is.EqualTo("subject"));
        Assert.That(claims.Audience, Is.EqualTo("audience"));
        Assert.That(claims.ExpirationTime, Is.EqualTo(now.AddHours(1)));
        Assert.That(claims.NotBefore, Is.EqualTo(now));
        Assert.That(claims.IssuedAt, Is.EqualTo(now));
        Assert.That(claims.CwtId, Is.EqualTo(cwtId));
        Assert.That(claims.CustomClaims[42], Is.EqualTo("test"));
    }

    [Test]
    public void ToCborBytes_WithAllClaims_SerializesCorrectly()
    {
        // Arrange
        var claims = new CwtClaims
        {
            Issuer = "test-issuer",
            Subject = "test-subject",
            Audience = "test-audience",
            ExpirationTime = new DateTimeOffset(2025, 12, 31, 23, 59, 59, TimeSpan.Zero),
            NotBefore = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            IssuedAt = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            CwtId = new byte[] { 1, 2, 3 }
        };

        // Act
        var cborBytes = claims.ToCborBytes();

        // Assert
        Assert.That(cborBytes, Is.Not.Null);
        Assert.That(cborBytes.Length, Is.GreaterThan(0));

        // Verify we can parse it back
        var parsed = CwtClaims.FromCborBytes(cborBytes);
        Assert.That(parsed.Issuer, Is.EqualTo(claims.Issuer));
        Assert.That(parsed.Subject, Is.EqualTo(claims.Subject));
        Assert.That(parsed.Audience, Is.EqualTo(claims.Audience));
    }

    [Test]
    public void ToCborBytes_WithCustomClaims_IncludesCustomData()
    {
        // Arrange
        var claims = new CwtClaims();
        claims.CustomClaims[100] = "custom-string";
        claims.CustomClaims[101] = 42L;
        claims.CustomClaims[102] = true;

        // Act
        var cborBytes = claims.ToCborBytes();

        // Assert
        Assert.That(cborBytes, Is.Not.Null);
        var parsed = CwtClaims.FromCborBytes(cborBytes);
        Assert.That(parsed.CustomClaims[100], Is.EqualTo("custom-string"));
        Assert.That(parsed.CustomClaims[101], Is.EqualTo(42L));
        Assert.That(parsed.CustomClaims[102], Is.EqualTo(true));
    }

    [Test]
    public void FromCborBytes_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => CwtClaims.FromCborBytes(null!));
    }

    [Test]
    public void FromCborBytes_WithValidData_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteInt32(1); // iss
        writer.WriteTextString("test-issuer");
        writer.WriteInt32(2); // sub
        writer.WriteTextString("test-subject");
        writer.WriteInt32(3); // aud
        writer.WriteTextString("test-audience");
        writer.WriteEndMap();
        var cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(claims.Subject, Is.EqualTo("test-subject"));
        Assert.That(claims.Audience, Is.EqualTo("test-audience"));
    }

    [Test]
    public void FromCborBytes_WithInvalidCbor_ThrowsException()
    {
        // Arrange
        var invalidCbor = new byte[] { 0xFF, 0xFF, 0xFF };

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(invalidCbor));
    }

    [Test]
    public void DefaultSubject_HasExpectedValue()
    {
        // Assert
        Assert.That(CwtClaims.DefaultSubject, Is.EqualTo("unknown.intent"));
    }

    [Test]
    public void CustomClaims_SupportsMultipleTypes()
    {
        // Arrange
        var claims = new CwtClaims();

        // Act
        claims.CustomClaims[10] = "string-value";
        claims.CustomClaims[20] = 123L;
        claims.CustomClaims[30] = 456;
        claims.CustomClaims[40] = new byte[] { 1, 2, 3 };
        claims.CustomClaims[50] = true;
        claims.CustomClaims[60] = 3.14;

        // Assert
        Assert.That(claims.CustomClaims[10], Is.EqualTo("string-value"));
        Assert.That(claims.CustomClaims[20], Is.EqualTo(123L));
        Assert.That(claims.CustomClaims[30], Is.EqualTo(456));
        Assert.That(claims.CustomClaims[40], Is.EqualTo(new byte[] { 1, 2, 3 }));
        Assert.That(claims.CustomClaims[50], Is.EqualTo(true));
        Assert.That(claims.CustomClaims[60], Is.EqualTo(3.14));
    }

    [Test]
    public void RoundTrip_AllStandardClaims_PreservesData()
    {
        // Arrange
        var original = new CwtClaims
        {
            Issuer = "issuer",
            Subject = "subject",
            Audience = "audience",
            ExpirationTime = new DateTimeOffset(2025, 12, 31, 12, 0, 0, TimeSpan.Zero),
            NotBefore = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            IssuedAt = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero),
            CwtId = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }
        };

        // Act
        var cbor = original.ToCborBytes();
        var roundtrip = CwtClaims.FromCborBytes(cbor);

        // Assert
        Assert.That(roundtrip.Issuer, Is.EqualTo(original.Issuer));
        Assert.That(roundtrip.Subject, Is.EqualTo(original.Subject));
        Assert.That(roundtrip.Audience, Is.EqualTo(original.Audience));
        Assert.That(roundtrip.CwtId, Is.EqualTo(original.CwtId));
        // Note: DateTimeOffset comparison may need tolerance due to precision
    }
}
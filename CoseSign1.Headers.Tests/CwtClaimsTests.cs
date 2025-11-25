using System;
using System.Formats.Cbor;
using CoseSign1.Headers;
using NUnit.Framework;

namespace CoseSign1.Headers.Tests;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class CwtClaimsTests
{
    [Test]
    public void FromCborBytes_WithAllStandardClaims_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(7);
        
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("did:example:issuer");
        
        writer.WriteInt32(CWTClaimsHeaderLabels.Subject);
        writer.WriteTextString("test.subject");
        
        writer.WriteInt32(CWTClaimsHeaderLabels.Audience);
        writer.WriteTextString("test-audience");
        
        writer.WriteInt32(CWTClaimsHeaderLabels.ExpirationTime);
        writer.WriteInt64(1735689599); // 2024-12-31T23:59:59Z
        
        writer.WriteInt32(CWTClaimsHeaderLabels.NotBefore);
        writer.WriteInt64(1704067200); // 2024-01-01T00:00:00Z
        
        writer.WriteInt32(CWTClaimsHeaderLabels.IssuedAt);
        writer.WriteInt64(1732008000); // 2024-11-19T10:00:00Z
        
        writer.WriteInt32(CWTClaimsHeaderLabels.CWTID);
        writer.WriteByteString(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.Issuer, Is.EqualTo("did:example:issuer"));
        Assert.That(claims.Subject, Is.EqualTo("test.subject"));
        Assert.That(claims.Audience, Is.EqualTo("test-audience"));
        Assert.That(claims.ExpirationTime!.Value.ToUnixTimeSeconds(), Is.EqualTo(1735689599));
        Assert.That(claims.NotBefore!.Value.ToUnixTimeSeconds(), Is.EqualTo(1704067200));
        Assert.That(claims.IssuedAt!.Value.ToUnixTimeSeconds(), Is.EqualTo(1732008000));
        Assert.That(claims.CwtId, Is.EqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 }));
    }

    [Test]
    public void FromCborBytes_WithCustomStringClaim_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(100);
        writer.WriteTextString("custom-value");
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims.ContainsKey(100), Is.True);
        Assert.That(claims.CustomClaims[100], Is.EqualTo("custom-value"));
    }

    [Test]
    public void FromCborBytes_WithCustomIntegerClaim_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(101);
        writer.WriteInt64(42);
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims.ContainsKey(101), Is.True);
        Assert.That(claims.CustomClaims[101], Is.EqualTo(42L));
    }

    [Test]
    public void FromCborBytes_WithCustomByteStringClaim_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(102);
        writer.WriteByteString(new byte[] { 0xAA, 0xBB, 0xCC });
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims.ContainsKey(102), Is.True);
        Assert.That(claims.CustomClaims[102], Is.EqualTo(new byte[] { 0xAA, 0xBB, 0xCC }));
    }

    [Test]
    public void FromCborBytes_WithCustomBooleanClaim_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(103);
        writer.WriteBoolean(true);
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims.ContainsKey(103), Is.True);
        Assert.That(claims.CustomClaims[103], Is.EqualTo(true));
    }

    [Test]
    public void FromCborBytes_WithCustomMapClaim_StoresAsRawCborBytes()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(200); // Custom label
        writer.WriteStartMap(2);
        writer.WriteTextString("nested");
        writer.WriteTextString("value");
        writer.WriteTextString("count");
        writer.WriteInt32(5);
        writer.WriteEndMap();
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims.ContainsKey(200), Is.True);
        Assert.That(claims.CustomClaims[200], Is.InstanceOf<byte[]>());
        
        // Verify we can decode the raw CBOR bytes
        var rawCbor = (byte[])claims.CustomClaims[200];
        var reader = new CborReader(rawCbor);
        reader.ReadStartMap();
        Assert.That(reader.ReadTextString(), Is.EqualTo("nested"));
        Assert.That(reader.ReadTextString(), Is.EqualTo("value"));
        Assert.That(reader.ReadTextString(), Is.EqualTo("count"));
        Assert.That(reader.ReadInt32(), Is.EqualTo(5));
        reader.ReadEndMap();
    }

    [Test]
    public void FromCborBytes_WithCustomArrayClaim_StoresAsRawCborBytes()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(201); // Custom label
        writer.WriteStartArray(3);
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteEndArray();
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims.ContainsKey(201), Is.True);
        Assert.That(claims.CustomClaims[201], Is.InstanceOf<byte[]>());
        
        // Verify we can decode the raw CBOR bytes
        var rawCbor = (byte[])claims.CustomClaims[201];
        var reader = new CborReader(rawCbor);
        int? arrayLength = reader.ReadStartArray();
        Assert.That(arrayLength, Is.EqualTo(3));
        Assert.That(reader.ReadInt32(), Is.EqualTo(1));
        Assert.That(reader.ReadInt32(), Is.EqualTo(2));
        Assert.That(reader.ReadInt32(), Is.EqualTo(3));
        reader.ReadEndArray();
    }

    [Test]
    public void FromCborBytes_WithMultipleCustomClaims_ParsesAllCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(4);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(100);
        writer.WriteTextString("string-value");
        writer.WriteInt32(101);
        writer.WriteInt64(123);
        writer.WriteInt32(102);
        writer.WriteByteString(new byte[] { 0x01, 0x02 });
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims.Count, Is.EqualTo(3));
        Assert.That(claims.CustomClaims[100], Is.EqualTo("string-value"));
        Assert.That(claims.CustomClaims[101], Is.EqualTo(123L));
        Assert.That(claims.CustomClaims[102], Is.EqualTo(new byte[] { 0x01, 0x02 }));
    }

    [Test]
    public void FromCborBytes_WithNullBytes_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => CwtClaims.FromCborBytes(null!));
    }

    [Test]
    public void FromCborBytes_WithInvalidCbor_ThrowsInvalidOperationException()
    {
        // Arrange
        byte[] invalidCbor = new byte[] { 0xFF, 0xFF, 0xFF };

        // Act & Assert - ReadStartMap throws InvalidOperationException for invalid CBOR major type
        Assert.Throws<InvalidOperationException>(() => CwtClaims.FromCborBytes(invalidCbor));
    }

    [Test]
    public void ToString_WithAllStandardClaims_FormatsCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(7);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("did:example:issuer");
        writer.WriteInt32(CWTClaimsHeaderLabels.Subject);
        writer.WriteTextString("test.subject");
        writer.WriteInt32(CWTClaimsHeaderLabels.Audience);
        writer.WriteTextString("test-audience");
        writer.WriteInt32(CWTClaimsHeaderLabels.ExpirationTime);
        writer.WriteInt64(1735689599);
        writer.WriteInt32(CWTClaimsHeaderLabels.NotBefore);
        writer.WriteInt64(1704067200);
        writer.WriteInt32(CWTClaimsHeaderLabels.IssuedAt);
        writer.WriteInt64(1732008000);
        writer.WriteInt32(CWTClaimsHeaderLabels.CWTID);
        writer.WriteByteString(new byte[] { 0x01, 0x02 });
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Act
        string result = claims.ToString();

        // Assert
        Assert.That(result, Does.Contain("Issuer: did:example:issuer"));
        Assert.That(result, Does.Contain("Subject: test.subject"));
        Assert.That(result, Does.Contain("Audience: test-audience"));
        Assert.That(result, Does.Contain("Expires:"));
        Assert.That(result, Does.Contain("Not Before:"));
        Assert.That(result, Does.Contain("Issued At:"));
        Assert.That(result, Does.Contain("CWT ID: 01-02"));
    }

    [Test]
    public void ToString_WithCustomClaims_IncludesCustomClaimsCount()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(4);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(100);
        writer.WriteTextString("string-value");
        writer.WriteInt32(101);
        writer.WriteInt64(123);
        writer.WriteInt32(102);
        writer.WriteByteString(new byte[] { 0x01, 0x02 });
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Act
        string result = claims.ToString();

        // Assert
        Assert.That(result, Does.Contain("Custom Claims: 3"));
        Assert.That(result, Does.Contain("[100]:"));
        Assert.That(result, Does.Contain("[101]:"));
        Assert.That(result, Does.Contain("[102]:"));
    }

    [Test]
    public void ToString_WithComplexCustomClaim_ShowsByteCount()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(200);
        writer.WriteStartMap(1);
        writer.WriteTextString("key");
        writer.WriteTextString("value");
        writer.WriteEndMap();
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Act
        string result = claims.ToString();

        // Assert
        Assert.That(result, Does.Contain("[200]:"));
        Assert.That(result, Does.Match(@"\[200\]: \[\d+ bytes\]"));
    }

    [Test]
    public void FromCborBytes_WithEmptyMap_CreatesClaimsWithNoData()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.Issuer, Is.Null);
        Assert.That(claims.Subject, Is.Null);
        Assert.That(claims.Audience, Is.Null);
        Assert.That(claims.ExpirationTime, Is.Null);
        Assert.That(claims.NotBefore, Is.Null);
        Assert.That(claims.IssuedAt, Is.Null);
        Assert.That(claims.CwtId, Is.Null);
        Assert.That(claims.CustomClaims.Count, Is.EqualTo(0));
    }

    [Test]
    public void FromCborBytes_WithNegativeIntegerClaim_ParsesCorrectly()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
        writer.WriteTextString("issuer");
        writer.WriteInt32(110);
        writer.WriteInt64(-42);
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Act
        var claims = CwtClaims.FromCborBytes(cborBytes);

        // Assert
        Assert.That(claims.CustomClaims.ContainsKey(110), Is.True);
        Assert.That(claims.CustomClaims[110], Is.EqualTo(-42L));
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Tests.Extensions;

using System;
using System.Security.Cryptography.Cose;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;

[TestFixture]
public class CoseHeaderMapCwtClaimsExtensionsTests
{
    #region TryGetCwtClaims Tests

    [Test]
    public void TryGetCwtClaims_WithNullHeaderMap_ReturnsFalse()
    {
        // Arrange
        CoseHeaderMap? nullHeaderMap = null;

        // Act
        bool result = nullHeaderMap!.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(claims, Is.Null);
    }

    [Test]
    public void TryGetCwtClaims_WithEmptyHeaderMap_ReturnsFalse()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();

        // Act
        bool result = headerMap.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(claims, Is.Null);
    }

    [Test]
    public void TryGetCwtClaims_WithValidClaims_ReturnsTrue()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var originalClaims = new CwtClaims
        {
            Subject = "testSubject",
            Issuer = "testIssuer"
        };
        headerMap.SetCwtClaims(originalClaims);

        // Act
        bool result = headerMap.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);
        Assert.That(claims!.Subject, Is.EqualTo("testSubject"));
        Assert.That(claims.Issuer, Is.EqualTo("testIssuer"));
    }

    [Test]
    public void TryGetCwtClaims_WithComplexClaims_ReturnsAllProperties()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var expirationTime = DateTimeOffset.UtcNow.AddHours(1);
        var notBefore = DateTimeOffset.UtcNow;
        var issuedAt = DateTimeOffset.UtcNow.AddMinutes(-5);
        var cwtId = new byte[] { 1, 2, 3, 4, 5 };

        var originalClaims = new CwtClaims
        {
            Subject = "testSubject",
            Issuer = "testIssuer",
            Audience = "testAudience",
            ExpirationTime = expirationTime,
            NotBefore = notBefore,
            IssuedAt = issuedAt,
            CwtId = cwtId
        };
        originalClaims.CustomClaims[100] = "customValue";
        originalClaims.CustomClaims[101] = 42L;

        headerMap.SetCwtClaims(originalClaims);

        // Act
        bool result = headerMap.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);
        Assert.That(claims!.Subject, Is.EqualTo("testSubject"));
        Assert.That(claims.Issuer, Is.EqualTo("testIssuer"));
        Assert.That(claims.Audience, Is.EqualTo("testAudience"));
        Assert.That(claims.ExpirationTime?.ToUnixTimeSeconds(), Is.EqualTo(expirationTime.ToUnixTimeSeconds()));
        Assert.That(claims.NotBefore?.ToUnixTimeSeconds(), Is.EqualTo(notBefore.ToUnixTimeSeconds()));
        Assert.That(claims.IssuedAt?.ToUnixTimeSeconds(), Is.EqualTo(issuedAt.ToUnixTimeSeconds()));
        Assert.That(claims.CwtId, Is.EqualTo(cwtId));
        Assert.That(claims.CustomClaims[100], Is.EqualTo("customValue"));
        Assert.That(claims.CustomClaims[101], Is.EqualTo(42L));
    }

    [Test]
    public void TryGetCwtClaims_WithCustomHeaderLabel_ReturnsClaimsFromCustomLabel()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var customLabel = new CoseHeaderLabel(999);
        var claims = new CwtClaims { Subject = "customLabelSubject" };

        headerMap.SetCwtClaims(claims, customLabel);

        // Act
        bool result = headerMap.TryGetCwtClaims(out CwtClaims? retrievedClaims, customLabel);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(retrievedClaims, Is.Not.Null);
        Assert.That(retrievedClaims!.Subject, Is.EqualTo("customLabelSubject"));
    }

    [Test]
    public void TryGetCwtClaims_WithCustomHeaderLabel_DoesNotReturnDefaultLabel()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var customLabel = new CoseHeaderLabel(999);
        var claims = new CwtClaims { Subject = "customLabelSubject" };

        headerMap.SetCwtClaims(claims, customLabel);

        // Act - Try to get with default label
        bool result = headerMap.TryGetCwtClaims(out CwtClaims? retrievedClaims);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(retrievedClaims, Is.Null);
    }

    [Test]
    public void TryGetCwtClaims_WithNonMapCborData_ReturnsFalse()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        // Create CBOR data that's valid but not a CWT claims map (just a text string)
        var writer = new System.Formats.Cbor.CborWriter();
        writer.WriteTextString("notAMap");
        var invalidBytes = writer.Encode();
        var value = CoseHeaderValue.FromEncodedValue(invalidBytes);
        headerMap[CWTClaimsHeaderLabels.CWTClaims] = value;

        // Act
        bool result = headerMap.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(claims, Is.Null);
    }

    #endregion

    #region SetCwtClaims Tests

    [Test]
    public void SetCwtClaims_WithNullHeaderMap_ThrowsArgumentNullException()
    {
        // Arrange
        CoseHeaderMap? nullHeaderMap = null;
        var claims = new CwtClaims { Subject = "test" };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => nullHeaderMap!.SetCwtClaims(claims));
    }

    [Test]
    public void SetCwtClaims_WithNullClaims_ThrowsArgumentNullException()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        CwtClaims? nullClaims = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => headerMap.SetCwtClaims(nullClaims!));
    }

    [Test]
    public void SetCwtClaims_WithValidClaims_SetsClaimsInDefaultLabel()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var claims = new CwtClaims
        {
            Subject = "testSubject",
            Issuer = "testIssuer"
        };

        // Act
        headerMap.SetCwtClaims(claims);

        // Assert
        Assert.That(headerMap.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.True);
        bool retrieved = headerMap.TryGetCwtClaims(out CwtClaims? retrievedClaims);
        Assert.That(retrieved, Is.True);
        Assert.That(retrievedClaims!.Subject, Is.EqualTo("testSubject"));
        Assert.That(retrievedClaims.Issuer, Is.EqualTo("testIssuer"));
    }

    [Test]
    public void SetCwtClaims_WithCustomHeaderLabel_SetsClaimsInCustomLabel()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var customLabel = new CoseHeaderLabel(888);
        var claims = new CwtClaims { Subject = "customSubject" };

        // Act
        headerMap.SetCwtClaims(claims, customLabel);

        // Assert
        Assert.That(headerMap.ContainsKey(customLabel), Is.True);
        Assert.That(headerMap.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.False);
        bool retrieved = headerMap.TryGetCwtClaims(out CwtClaims? retrievedClaims, customLabel);
        Assert.That(retrieved, Is.True);
        Assert.That(retrievedClaims!.Subject, Is.EqualTo("customSubject"));
    }

    [Test]
    public void SetCwtClaims_OverwritesExistingClaims()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var originalClaims = new CwtClaims { Subject = "original" };
        var newClaims = new CwtClaims { Subject = "updated", Issuer = "newIssuer" };

        // Act
        headerMap.SetCwtClaims(originalClaims);
        headerMap.SetCwtClaims(newClaims);

        // Assert
        bool retrieved = headerMap.TryGetCwtClaims(out CwtClaims? retrievedClaims);
        Assert.That(retrieved, Is.True);
        Assert.That(retrievedClaims!.Subject, Is.EqualTo("updated"));
        Assert.That(retrievedClaims.Issuer, Is.EqualTo("newIssuer"));
    }

    [Test]
    public void SetCwtClaims_WithEmptyClaims_SetsEmptyClaimsMap()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var emptyClaims = new CwtClaims();

        // Act
        headerMap.SetCwtClaims(emptyClaims);

        // Assert
        bool retrieved = headerMap.TryGetCwtClaims(out CwtClaims? retrievedClaims);
        Assert.That(retrieved, Is.True);
        Assert.That(retrievedClaims, Is.Not.Null);
        Assert.That(retrievedClaims!.Subject, Is.Null);
        Assert.That(retrievedClaims.Issuer, Is.Null);
    }

    [Test]
    public void SetCwtClaims_RoundTripPreservesAllData()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var expirationTime = new DateTimeOffset(2025, 12, 31, 23, 59, 59, TimeSpan.Zero);
        var notBefore = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var issuedAt = new DateTimeOffset(2025, 6, 15, 12, 30, 0, TimeSpan.Zero);
        var cwtId = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var originalClaims = new CwtClaims
        {
            Subject = "subject",
            Issuer = "issuer",
            Audience = "audience",
            ExpirationTime = expirationTime,
            NotBefore = notBefore,
            IssuedAt = issuedAt,
            CwtId = cwtId
        };
        originalClaims.CustomClaims[200] = "customString";
        originalClaims.CustomClaims[201] = 12345L;

        // Act
        headerMap.SetCwtClaims(originalClaims);
        bool retrieved = headerMap.TryGetCwtClaims(out CwtClaims? roundTrippedClaims);

        // Assert
        Assert.That(retrieved, Is.True);
        Assert.That(roundTrippedClaims, Is.Not.Null);
        Assert.That(roundTrippedClaims!.Subject, Is.EqualTo(originalClaims.Subject));
        Assert.That(roundTrippedClaims.Issuer, Is.EqualTo(originalClaims.Issuer));
        Assert.That(roundTrippedClaims.Audience, Is.EqualTo(originalClaims.Audience));
        Assert.That(roundTrippedClaims.ExpirationTime?.ToUnixTimeSeconds(), Is.EqualTo(expirationTime.ToUnixTimeSeconds()));
        Assert.That(roundTrippedClaims.NotBefore?.ToUnixTimeSeconds(), Is.EqualTo(notBefore.ToUnixTimeSeconds()));
        Assert.That(roundTrippedClaims.IssuedAt?.ToUnixTimeSeconds(), Is.EqualTo(issuedAt.ToUnixTimeSeconds()));
        Assert.That(roundTrippedClaims.CwtId, Is.EqualTo(cwtId));
        Assert.That(roundTrippedClaims.CustomClaims[200], Is.EqualTo("customString"));
        Assert.That(roundTrippedClaims.CustomClaims[201], Is.EqualTo(12345L));
    }

    #endregion

    #region RemoveCwtClaims Tests

    [Test]
    public void RemoveCwtClaims_WithNullHeaderMap_ReturnsFalse()
    {
        // Arrange
        CoseHeaderMap? nullHeaderMap = null;

        // Act
        bool result = nullHeaderMap!.RemoveCwtClaims();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void RemoveCwtClaims_WithEmptyHeaderMap_ReturnsFalse()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();

        // Act
        bool result = headerMap.RemoveCwtClaims();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void RemoveCwtClaims_WithExistingClaims_RemovesAndReturnsTrue()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var claims = new CwtClaims { Subject = "test" };
        headerMap.SetCwtClaims(claims);

        // Act
        bool result = headerMap.RemoveCwtClaims();

        // Assert
        Assert.That(result, Is.True);
        Assert.That(headerMap.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.False);
        bool tryGet = headerMap.TryGetCwtClaims(out CwtClaims? retrievedClaims);
        Assert.That(tryGet, Is.False);
        Assert.That(retrievedClaims, Is.Null);
    }

    [Test]
    public void RemoveCwtClaims_WithCustomHeaderLabel_RemovesFromCustomLabel()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var customLabel = new CoseHeaderLabel(777);
        var claims = new CwtClaims { Subject = "customTest" };
        headerMap.SetCwtClaims(claims, customLabel);

        // Act
        bool result = headerMap.RemoveCwtClaims(customLabel);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(headerMap.ContainsKey(customLabel), Is.False);
        bool tryGet = headerMap.TryGetCwtClaims(out CwtClaims? retrievedClaims, customLabel);
        Assert.That(tryGet, Is.False);
    }

    [Test]
    public void RemoveCwtClaims_WithCustomHeaderLabel_DoesNotRemoveDefaultLabel()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var customLabel = new CoseHeaderLabel(777);
        var defaultClaims = new CwtClaims { Subject = "default" };
        var customClaims = new CwtClaims { Subject = "custom" };

        headerMap.SetCwtClaims(defaultClaims);
        headerMap.SetCwtClaims(customClaims, customLabel);

        // Act - Remove only custom label
        bool result = headerMap.RemoveCwtClaims(customLabel);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(headerMap.ContainsKey(customLabel), Is.False);
        Assert.That(headerMap.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.True);
        bool tryGetDefault = headerMap.TryGetCwtClaims(out CwtClaims? defaultRetrieved);
        Assert.That(tryGetDefault, Is.True);
        Assert.That(defaultRetrieved!.Subject, Is.EqualTo("default"));
    }

    [Test]
    public void RemoveCwtClaims_CalledTwice_SecondReturnsFalse()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var claims = new CwtClaims { Subject = "test" };
        headerMap.SetCwtClaims(claims);

        // Act
        bool firstRemove = headerMap.RemoveCwtClaims();
        bool secondRemove = headerMap.RemoveCwtClaims();

        // Assert
        Assert.That(firstRemove, Is.True);
        Assert.That(secondRemove, Is.False);
    }

    [Test]
    public void RemoveCwtClaims_WithHeaderMapContainingOtherHeaders_OnlyRemovesClaims()
    {
        // Arrange
        var headerMap = new CoseHeaderMap();
        var claims = new CwtClaims { Subject = "test" };
        var otherLabel = new CoseHeaderLabel(999);
        var otherValue = CoseHeaderValue.FromInt32(42);

        headerMap.SetCwtClaims(claims);
        headerMap[otherLabel] = otherValue;

        // Act
        bool result = headerMap.RemoveCwtClaims();

        // Assert
        Assert.That(result, Is.True);
        Assert.That(headerMap.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.False);
        Assert.That(headerMap.ContainsKey(otherLabel), Is.True);
        Assert.That(headerMap[otherLabel].EncodedValue.ToArray(), Is.EqualTo(otherValue.EncodedValue.ToArray()));
    }

    #endregion
}
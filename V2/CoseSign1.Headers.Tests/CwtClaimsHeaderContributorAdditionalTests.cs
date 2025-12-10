// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;
using Moq;

namespace CoseSign1.Headers.Tests;

[TestFixture]
public class CwtClaimsHeaderContributorAdditionalTests
{
    private Mock<ISigningKey> _mockSigningKey = null!;
    private SigningContext _signingContext = null!;
    private HeaderContributorContext _context = null!;

    [SetUp]
    public void SetUp()
    {
        _mockSigningKey = new Mock<ISigningKey>();
        _signingContext = new SigningContext(new byte[] { 1, 2, 3 }, "application/test");
        _context = new HeaderContributorContext(_signingContext, _mockSigningKey.Object);
    }

    [Test]
    public void SetAudience_WithNullOrEmpty_ThrowsArgumentException()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => contributor.SetAudience(null!));
        Assert.Throws<ArgumentException>(() => contributor.SetAudience(""));
        Assert.Throws<ArgumentException>(() => contributor.SetAudience("  "));
    }

    [Test]
    public void SetCWTID_WithNullOrEmpty_ThrowsArgumentException()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => contributor.SetCWTID(null!));
        Assert.Throws<ArgumentException>(() => contributor.SetCWTID(Array.Empty<byte>()));
    }

    [Test]
    public void SetCustomClaim_WithNullValue_ThrowsArgumentNullException()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => contributor.SetCustomClaim(100, null!));
    }

    [Test]
    public void WithTimestamps_SetsAllTimestamps()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();
        var iat = DateTimeOffset.UtcNow;
        var nbf = DateTimeOffset.UtcNow.AddHours(-1);
        var exp = DateTimeOffset.UtcNow.AddHours(1);

        // Act
        var result = contributor.WithTimestamps(iat, nbf, exp);

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.IssuedAt, Is.EqualTo(iat));
        Assert.That(contributor.NotBefore, Is.EqualTo(nbf));
        Assert.That(contributor.ExpirationTime, Is.EqualTo(exp));
    }

    [Test]
    public void WithTimestamps_WithNullValues_DoesNotSet()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result = contributor.WithTimestamps(null, null, null);

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.IssuedAt, Is.Null);
        Assert.That(contributor.NotBefore, Is.Null);
        Assert.That(contributor.ExpirationTime, Is.Null);
    }

    [Test]
    public void WithAudience_WithNullOrEmpty_DoesNotSet()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result1 = contributor.WithAudience(null);
        var result2 = contributor.WithAudience("");
        var result3 = contributor.WithAudience("  ");

        // Assert
        Assert.That(result1, Is.SameAs(contributor));
        Assert.That(result2, Is.SameAs(contributor));
        Assert.That(result3, Is.SameAs(contributor));
        Assert.That(contributor.Audience, Is.Null);
    }

    [Test]
    public void WithAudience_WithValidValue_SetsAudience()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result = contributor.WithAudience("test-audience");

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.Audience, Is.EqualTo("test-audience"));
    }

    [Test]
    public void WithCwtId_WithNull_DoesNotSet()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result = contributor.WithCwtId(null);

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.CWTID, Is.Null);
    }

    [Test]
    public void WithCwtId_WithEmptyArray_DoesNotSet()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result = contributor.WithCwtId(Array.Empty<byte>());

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.CWTID, Is.Null);
    }

    [Test]
    public void WithCwtId_WithValidValue_SetsCwtId()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();
        var cwtId = new byte[] { 1, 2, 3, 4 };

        // Act
        var result = contributor.WithCwtId(cwtId);

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.CWTID, Is.EqualTo(cwtId));
    }

    [Test]
    public void UseProtectedHeaders_ReturnsNewInstanceWithCorrectPlacement()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test" };
        var contributor = new CwtClaimsHeaderContributor(claims, CwtClaimsHeaderPlacement.UnprotectedOnly);

        // Act
        var result = contributor.UseProtectedHeaders();

        // Assert
        Assert.That(result, Is.Not.SameAs(contributor));
        Assert.That(result.Issuer, Is.EqualTo("test"));
    }

    [Test]
    public void UseProtectedHeaders_WhenAlreadyProtected_ReturnsSameInstance()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor(CwtClaimsHeaderPlacement.ProtectedOnly);

        // Act
        var result = contributor.UseProtectedHeaders();

        // Assert
        Assert.That(result, Is.SameAs(contributor));
    }

    [Test]
    public void UseUnprotectedHeaders_ReturnsNewInstanceWithCorrectPlacement()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test" };
        var contributor = new CwtClaimsHeaderContributor(claims, CwtClaimsHeaderPlacement.ProtectedOnly);

        // Act
        var result = contributor.UseUnprotectedHeaders();

        // Assert
        Assert.That(result, Is.Not.SameAs(contributor));
        Assert.That(result.Issuer, Is.EqualTo("test"));
    }

    [Test]
    public void UseUnprotectedHeaders_WhenAlreadyUnprotected_ReturnsSameInstance()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor(CwtClaimsHeaderPlacement.UnprotectedOnly);

        // Act
        var result = contributor.UseUnprotectedHeaders();

        // Assert
        Assert.That(result, Is.SameAs(contributor));
    }

    [Test]
    public void UseBothHeaders_ReturnsNewInstanceWithCorrectPlacement()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test" };
        var contributor = new CwtClaimsHeaderContributor(claims, CwtClaimsHeaderPlacement.ProtectedOnly);

        // Act
        var result = contributor.UseBothHeaders();

        // Assert
        Assert.That(result, Is.Not.SameAs(contributor));
        Assert.That(result.Issuer, Is.EqualTo("test"));
    }

    [Test]
    public void UseBothHeaders_WhenAlreadyBoth_ReturnsSameInstance()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor(CwtClaimsHeaderPlacement.Both);

        // Act
        var result = contributor.UseBothHeaders();

        // Assert
        Assert.That(result, Is.SameAs(contributor));
    }

    [Test]
    public void ContributeProtectedHeaders_WithNullHeaders_ThrowsArgumentNullException()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => contributor.ContributeProtectedHeaders(null!, _context));
    }

    [Test]
    public void ContributeUnprotectedHeaders_WithNullHeaders_ThrowsArgumentNullException()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => contributor.ContributeUnprotectedHeaders(null!, _context));
    }

    [Test]
    public void ContributeProtectedHeaders_WithBothPlacement_AddsHeaders()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test-issuer", Subject = "test-subject" };
        var contributor = new CwtClaimsHeaderContributor(claims, CwtClaimsHeaderPlacement.Both);
        var headers = new CoseHeaderMap();

        // Act
        contributor.ContributeProtectedHeaders(headers, _context);

        // Assert
        Assert.That(headers.Count, Is.GreaterThan(0));
    }

    [Test]
    public void ContributeUnprotectedHeaders_WithBothPlacement_AddsHeaders()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test-issuer", Subject = "test-subject" };
        var contributor = new CwtClaimsHeaderContributor(claims, CwtClaimsHeaderPlacement.Both);
        var headers = new CoseHeaderMap();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, _context);

        // Assert
        Assert.That(headers.Count, Is.GreaterThan(0));
    }

    [Test]
    public void ContributeProtectedHeaders_WithAutoPopulateTimestamps_PopulatesTimestamps()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test-issuer" };
        var contributor = new CwtClaimsHeaderContributor(
            claims,
            CwtClaimsHeaderPlacement.ProtectedOnly,
            customHeaderLabel: null,
            autoPopulateTimestamps: true);
        var headers = new CoseHeaderMap();

        // Act
        contributor.ContributeProtectedHeaders(headers, _context);

        // Assert
        headers.TryGetCwtClaims(out var resultClaims);
        Assert.That(resultClaims, Is.Not.Null);
        Assert.That(resultClaims!.IssuedAt, Is.Not.Null);
        Assert.That(resultClaims.NotBefore, Is.Not.Null);
    }

    [Test]
    public void ContributeProtectedHeaders_WithoutAutoPopulateTimestamps_DoesNotPopulateTimestamps()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test-issuer" };
        var contributor = new CwtClaimsHeaderContributor(
            claims,
            CwtClaimsHeaderPlacement.ProtectedOnly,
            customHeaderLabel: null,
            autoPopulateTimestamps: false);
        var headers = new CoseHeaderMap();

        // Act
        contributor.ContributeProtectedHeaders(headers, _context);

        // Assert
        headers.TryGetCwtClaims(out var resultClaims);
        Assert.That(resultClaims, Is.Not.Null);
        Assert.That(resultClaims!.IssuedAt, Is.Null);
        Assert.That(resultClaims.NotBefore, Is.Null);
    }

    [Test]
    public void ContributeProtectedHeaders_WithExistingClaims_MergesClaims()
    {
        // Arrange
        var existingClaims = new CwtClaims { Audience = "existing-audience" };
        var headers = new CoseHeaderMap();
        headers.SetCwtClaims(existingClaims);

        var newClaims = new CwtClaims { Issuer = "new-issuer" };
        var contributor = new CwtClaimsHeaderContributor(
            newClaims,
            CwtClaimsHeaderPlacement.ProtectedOnly,
            customHeaderLabel: null,
            autoPopulateTimestamps: false);

        // Act
        contributor.ContributeProtectedHeaders(headers, _context);

        // Assert
        headers.TryGetCwtClaims(out var resultClaims);
        Assert.That(resultClaims, Is.Not.Null);
        Assert.That(resultClaims!.Issuer, Is.EqualTo("new-issuer"));
        Assert.That(resultClaims.Audience, Is.EqualTo("existing-audience"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithDefaultClaims_DoesNotAddHeaders()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor(
            CwtClaimsHeaderPlacement.ProtectedOnly,
            customHeaderLabel: null,
            autoPopulateTimestamps: false);
        var headers = new CoseHeaderMap();

        // Act
        contributor.ContributeProtectedHeaders(headers, _context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(0));
    }

    [Test]
    public void Constructor_WithCustomHeaderLabel_UsesCustomLabel()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(99);
        var claims = new CwtClaims { Issuer = "test" };
        var contributor = new CwtClaimsHeaderContributor(
            claims,
            CwtClaimsHeaderPlacement.ProtectedOnly,
            customHeaderLabel: customLabel,
            autoPopulateTimestamps: false);
        var headers = new CoseHeaderMap();

        // Act
        contributor.ContributeProtectedHeaders(headers, _context);

        // Assert
        headers.TryGetCwtClaims(out var resultClaims, customLabel);
        Assert.That(resultClaims, Is.Not.Null);
        Assert.That(resultClaims!.Issuer, Is.EqualTo("test"));
    }

    [Test]
    public void SetSubject_WithWhitespace_ThrowsArgumentException()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => contributor.SetSubject("  "));
    }

    [Test]
    public void AllProperties_ReturnCorrectValues()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var cwtId = new byte[] { 1, 2, 3 };
        var claims = new CwtClaims
        {
            Issuer = "issuer",
            Subject = "subject",
            Audience = "audience",
            ExpirationTime = now.AddHours(1),
            NotBefore = now.AddHours(-1),
            IssuedAt = now,
            CwtId = cwtId
        };
        var contributor = new CwtClaimsHeaderContributor(claims);

        // Act & Assert
        Assert.That(contributor.Issuer, Is.EqualTo("issuer"));
        Assert.That(contributor.Subject, Is.EqualTo("subject"));
        Assert.That(contributor.Audience, Is.EqualTo("audience"));
        Assert.That(contributor.ExpirationTime, Is.EqualTo(now.AddHours(1)));
        Assert.That(contributor.NotBefore, Is.EqualTo(now.AddHours(-1)));
        Assert.That(contributor.IssuedAt, Is.EqualTo(now));
        Assert.That(contributor.CWTID, Is.EqualTo(cwtId));
    }

    [Test]
    public void ContributeProtectedHeaders_WithAutoPopulateAndExistingTimestamps_KeepsExistingTimestamps()
    {
        // Arrange
        var specificTime = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var claims = new CwtClaims
        {
            Issuer = "test",
            IssuedAt = specificTime,
            NotBefore = specificTime
        };
        var contributor = new CwtClaimsHeaderContributor(
            claims,
            CwtClaimsHeaderPlacement.ProtectedOnly,
            customHeaderLabel: null,
            autoPopulateTimestamps: true); // Auto-populate is enabled but claims already have timestamps
        var headers = new CoseHeaderMap();

        // Act
        contributor.ContributeProtectedHeaders(headers, _context);

        // Assert
        headers.TryGetCwtClaims(out var resultClaims);
        Assert.That(resultClaims, Is.Not.Null);
        Assert.That(resultClaims!.IssuedAt, Is.EqualTo(specificTime));
        Assert.That(resultClaims.NotBefore, Is.EqualTo(specificTime));
    }
}

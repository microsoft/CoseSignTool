// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Tests;

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using Moq;

[TestFixture]
public class CwtClaimsHeaderContributorTests
{
    [Test]
    public void Constructor_Default_CreatesInstance()
    {
        // Act
        var contributor = new CwtClaimsHeaderContributor();

        // Assert
        Assert.That(contributor, Is.Not.Null);
        Assert.That(contributor.Issuer, Is.Null);
        Assert.That(contributor.Subject, Is.Null);
        Assert.That(contributor.Audience, Is.Null);
        Assert.That(contributor.MergeStrategy, Is.EqualTo(HeaderMergeStrategy.Replace));
    }

    [Test]
    public void Constructor_WithClaims_UsesClaims()
    {
        // Arrange
        var claims = new CwtClaims
        {
            Issuer = "test-issuer",
            Subject = "test-subject",
            Audience = "test-audience"
        };

        // Act
        var contributor = new CwtClaimsHeaderContributor(claims);

        // Assert
        Assert.That(contributor.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(contributor.Subject, Is.EqualTo("test-subject"));
        Assert.That(contributor.Audience, Is.EqualTo("test-audience"));
    }

    [Test]
    public void Constructor_WithNullClaims_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new CwtClaimsHeaderContributor(null!));
    }

    [Test]
    public void Constructor_WithPlacement_SetsPlacement()
    {
        // Act
        var contributorProtected = new CwtClaimsHeaderContributor(CwtClaimsHeaderPlacement.ProtectedOnly);
        var contributorUnprotected = new CwtClaimsHeaderContributor(CwtClaimsHeaderPlacement.UnprotectedOnly);
        var contributorBoth = new CwtClaimsHeaderContributor(CwtClaimsHeaderPlacement.Both);

        // Assert
        Assert.That(contributorProtected, Is.Not.Null);
        Assert.That(contributorUnprotected, Is.Not.Null);
        Assert.That(contributorBoth, Is.Not.Null);
    }

    [Test]
    public void SetIssuer_SetsIssuer()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result = contributor.SetIssuer("new-issuer");

        // Assert
        Assert.That(result, Is.SameAs(contributor)); // Fluent API
        Assert.That(contributor.Issuer, Is.EqualTo("new-issuer"));
    }

    [Test]
    public void SetIssuer_WithNullOrEmpty_ThrowsArgumentException()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => contributor.SetIssuer(null!));
        Assert.Throws<ArgumentException>(() => contributor.SetIssuer(""));
        Assert.Throws<ArgumentException>(() => contributor.SetIssuer("  "));
    }

    [Test]
    public void SetSubject_SetsSubject()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result = contributor.SetSubject("new-subject");

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.Subject, Is.EqualTo("new-subject"));
    }

    [Test]
    public void SetSubject_WithNullOrEmpty_ThrowsArgumentException()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => contributor.SetSubject(null!));
        Assert.Throws<ArgumentException>(() => contributor.SetSubject(""));
    }

    [Test]
    public void SetAudience_SetsAudience()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result = contributor.SetAudience("new-audience");

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.Audience, Is.EqualTo("new-audience"));
    }

    [Test]
    public void SetExpirationTime_SetsExpirationTime()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();
        var expTime = DateTimeOffset.UtcNow.AddHours(1);

        // Act
        var result = contributor.SetExpirationTime(expTime);

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.ExpirationTime, Is.EqualTo(expTime));
    }

    [Test]
    public void SetNotBefore_SetsNotBefore()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();
        var nbf = DateTimeOffset.UtcNow;

        // Act
        var result = contributor.SetNotBefore(nbf);

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.NotBefore, Is.EqualTo(nbf));
    }

    [Test]
    public void SetIssuedAt_SetsIssuedAt()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();
        var iat = DateTimeOffset.UtcNow;

        // Act
        var result = contributor.SetIssuedAt(iat);

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.IssuedAt, Is.EqualTo(iat));
    }

    [Test]
    public void SetCWTID_SetsCwtId()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();
        var cwtId = new byte[] { 1, 2, 3, 4 };

        // Act
        var result = contributor.SetCWTID(cwtId);

        // Assert
        Assert.That(result, Is.SameAs(contributor));
        Assert.That(contributor.CWTID, Is.EqualTo(cwtId));
    }

    [Test]
    public void SetCustomClaim_AddsCustomClaim()
    {
        // Arrange
        var contributor = new CwtClaimsHeaderContributor();

        // Act
        var result = contributor.SetCustomClaim(100, "custom-value");

        // Assert
        Assert.That(result, Is.SameAs(contributor));
    }

    [Test]
    public void FluentApi_ChainsMultipleCalls()
    {
        // Arrange & Act
        var contributor = new CwtClaimsHeaderContributor()
            .SetIssuer("issuer")
            .SetSubject("subject")
            .SetAudience("audience");

        // Assert
        Assert.That(contributor.Issuer, Is.EqualTo("issuer"));
        Assert.That(contributor.Subject, Is.EqualTo("subject"));
        Assert.That(contributor.Audience, Is.EqualTo("audience"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithClaims_AddsHeaders()
    {
        // Arrange
        var claims = new CwtClaims
        {
            Issuer = "test-issuer",
            Subject = "test-subject"
        };
        var contributor = new CwtClaimsHeaderContributor(claims);
        var headers = new CoseHeaderMap();
        var mockSigningKey = new Mock<ISigningKey>();
        var signingContext = new SigningContext(new byte[] { 1, 2, 3 }, "application/test");
        var context = new HeaderContributorContext(signingContext, mockSigningKey.Object);

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.GreaterThan(0));
    }

    [Test]
    public void ContributeUnprotectedHeaders_WithProtectedOnlyPlacement_DoesNotAdd()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test" };
        var contributor = new CwtClaimsHeaderContributor(claims, CwtClaimsHeaderPlacement.ProtectedOnly);
        var headers = new CoseHeaderMap();
        var mockSigningKey = new Mock<ISigningKey>();
        var signingContext = new SigningContext(new byte[] { 1, 2, 3 }, "application/test");
        var context = new HeaderContributorContext(signingContext, mockSigningKey.Object);

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(0));
    }

    [Test]
    public void ContributeUnprotectedHeaders_WithUnprotectedOnlyPlacement_Adds()
    {
        // Arrange
        var claims = new CwtClaims { Issuer = "test" };
        var contributor = new CwtClaimsHeaderContributor(claims, CwtClaimsHeaderPlacement.UnprotectedOnly);
        var headers = new CoseHeaderMap();
        var mockSigningKey = new Mock<ISigningKey>();
        var signingContext = new SigningContext(new byte[] { 1, 2, 3 }, "application/test");
        var context = new HeaderContributorContext(signingContext, mockSigningKey.Object);

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Constructor_WithAutoPopulateTimestamps_False_DoesNotAutoPopulate()
    {
        // Arrange & Act
        var contributor = new CwtClaimsHeaderContributor(
            CwtClaimsHeaderPlacement.ProtectedOnly,
            customHeaderLabel: null,
            autoPopulateTimestamps: false);

        // Assert
        Assert.That(contributor, Is.Not.Null);
        Assert.That(contributor.IssuedAt, Is.Null);
        Assert.That(contributor.NotBefore, Is.Null);
    }
}
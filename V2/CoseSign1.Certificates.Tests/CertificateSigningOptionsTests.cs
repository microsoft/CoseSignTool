// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates;
using CoseSign1.Headers;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests;

[TestFixture]
public class CertificateSigningOptionsTests
{
    [Test]
    public void Constructor_Default_InitializesWithDefaultValues()
    {
        // Act
        var options = new CertificateSigningOptions();

        // Assert
        Assert.That(options.EnableScittCompliance, Is.False, "EnableScittCompliance should default to false");
        Assert.That(options.CustomCwtClaims, Is.Null, "CustomCwtClaims should default to null");
    }

    [Test]
    public void EnableScittCompliance_SetToTrue_ReturnsTrue()
    {
        // Arrange
        var options = new CertificateSigningOptions();

        // Act
        options.EnableScittCompliance = true;

        // Assert
        Assert.That(options.EnableScittCompliance, Is.True);
    }

    [Test]
    public void EnableScittCompliance_SetToFalse_ReturnsFalse()
    {
        // Arrange
        var options = new CertificateSigningOptions
        {
            EnableScittCompliance = true
        };

        // Act
        options.EnableScittCompliance = false;

        // Assert
        Assert.That(options.EnableScittCompliance, Is.False);
    }

    [Test]
    public void CustomCwtClaims_SetValue_ReturnsSetValue()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        var claims = new CwtClaims
        {
            Issuer = "https://example.com",
            Subject = "pkg:npm/test@1.0.0",
            Audience = "https://transparency.example.com"
        };

        // Act
        options.CustomCwtClaims = claims;

        // Assert
        Assert.That(options.CustomCwtClaims, Is.SameAs(claims));
        Assert.That(options.CustomCwtClaims.Issuer, Is.EqualTo("https://example.com"));
        Assert.That(options.CustomCwtClaims.Subject, Is.EqualTo("pkg:npm/test@1.0.0"));
        Assert.That(options.CustomCwtClaims.Audience, Is.EqualTo("https://transparency.example.com"));
    }

    [Test]
    public void CustomCwtClaims_SetNull_ReturnsNull()
    {
        // Arrange
        var options = new CertificateSigningOptions
        {
            CustomCwtClaims = new CwtClaims { Issuer = "test" }
        };

        // Act
        options.CustomCwtClaims = null;

        // Assert
        Assert.That(options.CustomCwtClaims, Is.Null);
    }

    [Test]
    public void InheritsFrom_SigningOptions()
    {
        // Arrange & Act
        var options = new CertificateSigningOptions();

        // Assert
        Assert.That(options, Is.InstanceOf<CoseSign1.Abstractions.SigningOptions>());
    }

    [Test]
    public void ScittCompliance_And_CustomClaims_CanBothBeSet()
    {
        // Arrange
        var claims = new CwtClaims
        {
            Issuer = "did:x509:0:sha256:test",
            Subject = "test-subject"
        };

        // Act
        var options = new CertificateSigningOptions
        {
            EnableScittCompliance = true,
            CustomCwtClaims = claims
        };

        // Assert
        Assert.That(options.EnableScittCompliance, Is.True);
        Assert.That(options.CustomCwtClaims, Is.SameAs(claims));
    }
}
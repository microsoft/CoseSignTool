// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using DIDx509.Models;
using NUnit.Framework;

namespace DIDx509.Tests.Models;

[TestFixture]
public class CertificateExtensionsTests
{
    [Test]
    public void Constructor_WithAllParameters_SetsProperties()
    {
        // Arrange
        var ekus = new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" };
        var sans = new[] { new SubjectAlternativeName("dns", "example.com") };
        var fulcioIssuer = "https://fulcio.sigstore.dev";

        // Act
        var extensions = new CertificateExtensions(ekus, sans, fulcioIssuer);

        // Assert
        Assert.That(extensions.Eku, Is.EqualTo(ekus));
        Assert.That(extensions.San, Is.EqualTo(sans));
        Assert.That(extensions.FulcioIssuer, Is.EqualTo(fulcioIssuer));
    }

    [Test]
    public void Constructor_WithNullParameters_AllowsNulls()
    {
        // Act
        var extensions = new CertificateExtensions();

        // Assert
        Assert.That(extensions.Eku, Is.Null);
        Assert.That(extensions.San, Is.Null);
        Assert.That(extensions.FulcioIssuer, Is.Null);
    }

    [Test]
    public void HasEku_WithMatchingOid_ReturnsTrue()
    {
        // Arrange
        var ekus = new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3" };
        var extensions = new CertificateExtensions(eku: ekus);

        // Act & Assert
        Assert.That(extensions.HasEku("1.3.6.1.5.5.7.3.1"), Is.True);
        Assert.That(extensions.HasEku("1.3.6.1.5.5.7.3.2"), Is.True);
        Assert.That(extensions.HasEku("1.3.6.1.5.5.7.3.3"), Is.True);
    }

    [Test]
    public void HasEku_WithNonMatchingOid_ReturnsFalse()
    {
        // Arrange
        var ekus = new[] { "1.3.6.1.5.5.7.3.1" };
        var extensions = new CertificateExtensions(eku: ekus);

        // Act & Assert
        Assert.That(extensions.HasEku("1.3.6.1.5.5.7.3.9"), Is.False);
    }

    [Test]
    public void HasEku_WithNullEkuList_ReturnsFalse()
    {
        // Arrange
        var extensions = new CertificateExtensions(eku: null);

        // Act & Assert
        Assert.That(extensions.HasEku("1.3.6.1.5.5.7.3.1"), Is.False);
    }

    [Test]
    public void HasEku_WithEmptyOidParameter_ReturnsFalse()
    {
        // Arrange
        var ekus = new[] { "1.3.6.1.5.5.7.3.1" };
        var extensions = new CertificateExtensions(eku: ekus);

        // Act & Assert
        Assert.That(extensions.HasEku(""), Is.False);
        Assert.That(extensions.HasEku(null!), Is.False);
    }

    [Test]
    public void HasEku_IsCaseSensitive()
    {
        // Arrange
        var ekus = new[] { "1.3.6.1.5.5.7.3.1" };
        var extensions = new CertificateExtensions(eku: ekus);

        // Act & Assert - OIDs are case-sensitive
        Assert.That(extensions.HasEku("1.3.6.1.5.5.7.3.1"), Is.True);
    }

    [Test]
    public void HasSan_WithMatchingDnsSan_ReturnsTrue()
    {
        // Arrange
        var sans = new[]
        {
            new SubjectAlternativeName("dns", "example.com"),
            new SubjectAlternativeName("dns", "www.example.com")
        };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("dns", "example.com"), Is.True);
        Assert.That(extensions.HasSan("dns", "www.example.com"), Is.True);
    }

    [Test]
    public void HasSan_WithMatchingEmailSan_ReturnsTrue()
    {
        // Arrange
        var sans = new[] { new SubjectAlternativeName("email", "test@example.com") };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("email", "test@example.com"), Is.True);
    }

    [Test]
    public void HasSan_WithMatchingUriSan_ReturnsTrue()
    {
        // Arrange
        var sans = new[] { new SubjectAlternativeName("uri", "https://example.com") };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("uri", "https://example.com"), Is.True);
    }

    [Test]
    public void HasSan_WithNonMatchingValue_ReturnsFalse()
    {
        // Arrange
        var sans = new[] { new SubjectAlternativeName("dns", "example.com") };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("dns", "other.com"), Is.False);
    }

    [Test]
    public void HasSan_WithNonMatchingType_ReturnsFalse()
    {
        // Arrange
        var sans = new[] { new SubjectAlternativeName("dns", "example.com") };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("email", "example.com"), Is.False);
    }

    [Test]
    public void HasSan_TypeIsCaseInsensitive()
    {
        // Arrange
        var sans = new[] { new SubjectAlternativeName("dns", "example.com") };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("DNS", "example.com"), Is.True);
        Assert.That(extensions.HasSan("Dns", "example.com"), Is.True);
    }

    [Test]
    public void HasSan_ValueIsCaseSensitive()
    {
        // Arrange
        var sans = new[] { new SubjectAlternativeName("dns", "example.com") };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("dns", "Example.com"), Is.False);
        Assert.That(extensions.HasSan("dns", "EXAMPLE.COM"), Is.False);
    }

    [Test]
    public void HasSan_WithNullSanList_ReturnsFalse()
    {
        // Arrange
        var extensions = new CertificateExtensions(san: null);

        // Act & Assert
        Assert.That(extensions.HasSan("dns", "example.com"), Is.False);
    }

    [Test]
    public void HasSan_WithEmptyTypeParameter_ReturnsFalse()
    {
        // Arrange
        var sans = new[] { new SubjectAlternativeName("dns", "example.com") };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("", "example.com"), Is.False);
        Assert.That(extensions.HasSan(null!, "example.com"), Is.False);
    }

    [Test]
    public void HasSan_WithEmptyValueParameter_ReturnsFalse()
    {
        // Arrange
        var sans = new[] { new SubjectAlternativeName("dns", "example.com") };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("dns", ""), Is.False);
        Assert.That(extensions.HasSan("dns", null!), Is.False);
    }

    [Test]
    public void HasSan_WithDnTypeSan_ReturnsFalse()
    {
        // Arrange - DN type has X509Name value, not string, so ValueAsString is null
        var dnValue = new X509Name(new Dictionary<string, string> { ["CN"] = "Test" });
        var sans = new[] { new SubjectAlternativeName("dn", dnValue) };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert - DN type won't match because ValueAsString is null
        Assert.That(extensions.HasSan("dn", "Test"), Is.False);
    }

    [Test]
    public void HasSan_WithEmptyList_ReturnsFalse()
    {
        // Arrange
        var sans = Array.Empty<SubjectAlternativeName>();
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("dns", "example.com"), Is.False);
    }

    [Test]
    public void HasSan_WithMultipleSans_FindsCorrectOne()
    {
        // Arrange
        var sans = new[]
        {
            new SubjectAlternativeName("dns", "example.com"),
            new SubjectAlternativeName("email", "test@example.com"),
            new SubjectAlternativeName("uri", "https://example.com"),
            new SubjectAlternativeName("dns", "www.example.com")
        };
        var extensions = new CertificateExtensions(san: sans);

        // Act & Assert
        Assert.That(extensions.HasSan("dns", "example.com"), Is.True);
        Assert.That(extensions.HasSan("email", "test@example.com"), Is.True);
        Assert.That(extensions.HasSan("uri", "https://example.com"), Is.True);
        Assert.That(extensions.HasSan("dns", "www.example.com"), Is.True);
        Assert.That(extensions.HasSan("dns", "notfound.com"), Is.False);
    }
}
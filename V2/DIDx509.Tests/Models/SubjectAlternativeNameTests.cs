// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using DIDx509;
using DIDx509.Models;
using NUnit.Framework;

namespace DIDx509.Tests.Models;

[TestFixture]
public class SubjectAlternativeNameTests
{
    [Test]
    public void Constructor_WithDnsType_CreatesInstance()
    {
        // Act
        var san = new SubjectAlternativeName("dns", "example.com");

        // Assert
        Assert.That(san.Type, Is.EqualTo("dns"));
        Assert.That(san.Value, Is.EqualTo("example.com"));
        Assert.That(san.ValueAsString, Is.EqualTo("example.com"));
        Assert.That(san.ValueAsName, Is.Null);
    }

    [Test]
    public void Constructor_WithEmailType_CreatesInstance()
    {
        // Act
        var san = new SubjectAlternativeName("email", "test@example.com");

        // Assert
        Assert.That(san.Type, Is.EqualTo("email"));
        Assert.That(san.ValueAsString, Is.EqualTo("test@example.com"));
    }

    [Test]
    public void Constructor_WithUriType_CreatesInstance()
    {
        // Act
        var san = new SubjectAlternativeName("uri", "https://example.com");

        // Assert
        Assert.That(san.Type, Is.EqualTo("uri"));
        Assert.That(san.ValueAsString, Is.EqualTo("https://example.com"));
    }

    [Test]
    public void Constructor_WithDnType_CreatesInstance()
    {
        // Arrange
        var x509Name = new X509Name(new Dictionary<string, string> { ["CN"] = "Test User" });

        // Act
        var san = new SubjectAlternativeName("dn", x509Name);

        // Assert
        Assert.That(san.Type, Is.EqualTo("dn"));
        Assert.That(san.Value, Is.SameAs(x509Name));
        Assert.That(san.ValueAsName, Is.SameAs(x509Name));
        Assert.That(san.ValueAsString, Is.Null);
    }

    [Test]
    public void Constructor_WithNullType_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new SubjectAlternativeName(null!, "value"));
    }

    [Test]
    public void Constructor_WithNullValue_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new SubjectAlternativeName("dns", null!));
    }

    [Test]
    public void Constructor_WithDnsTypeAndNonStringValue_ThrowsArgumentException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => new SubjectAlternativeName("dns", 123));
        Assert.That(ex!.Message, Does.Contain("requires string value"));
    }

    [Test]
    public void Constructor_WithEmailTypeAndNonStringValue_ThrowsArgumentException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => new SubjectAlternativeName("email", 123));
        Assert.That(ex!.Message, Does.Contain("requires string value"));
    }

    [Test]
    public void Constructor_WithUriTypeAndNonStringValue_ThrowsArgumentException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => new SubjectAlternativeName("uri", 123));
        Assert.That(ex!.Message, Does.Contain("requires string value"));
    }

    [Test]
    public void Constructor_WithDnTypeAndStringValue_ThrowsArgumentException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => new SubjectAlternativeName("dn", "not an X509Name"));
        Assert.That(ex!.Message, Does.Contain("requires X509Name value"));
    }

    [Test]
    public void Constructor_WithUnknownType_ThrowsArgumentException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => new SubjectAlternativeName("unknown", "value"));
        Assert.That(ex!.Message, Does.Contain("Unknown SAN type"));
    }

    [Test]
    public void Constructor_TypeIsCaseInsensitive()
    {
        // Act & Assert - should accept case variations
        Assert.DoesNotThrow(() => new SubjectAlternativeName("DNS", "example.com"));
        Assert.DoesNotThrow(() => new SubjectAlternativeName("Email", "test@example.com"));
        Assert.DoesNotThrow(() => new SubjectAlternativeName("URI", "https://example.com"));

        var x509Name = new X509Name(new Dictionary<string, string> { ["CN"] = "Test" });
        Assert.DoesNotThrow(() => new SubjectAlternativeName("DN", x509Name));
    }

    [Test]
    public void Matches_WithSameTypeSameValue_ReturnsTrue()
    {
        // Arrange
        var san1 = new SubjectAlternativeName("dns", "example.com");
        var san2 = new SubjectAlternativeName("dns", "example.com");

        // Act & Assert
        Assert.That(san1.Matches(san2), Is.True);
        Assert.That(san2.Matches(san1), Is.True);
    }

    [Test]
    public void Matches_WithSameTypeDifferentValue_ReturnsFalse()
    {
        // Arrange
        var san1 = new SubjectAlternativeName("dns", "example.com");
        var san2 = new SubjectAlternativeName("dns", "other.com");

        // Act & Assert
        Assert.That(san1.Matches(san2), Is.False);
    }

    [Test]
    public void Matches_WithDifferentTypeSameValue_ReturnsFalse()
    {
        // Arrange
        var san1 = new SubjectAlternativeName("dns", "example.com");
        var san2 = new SubjectAlternativeName("email", "example.com");

        // Act & Assert
        Assert.That(san1.Matches(san2), Is.False);
    }

    [Test]
    public void Matches_TypeComparisonIsCaseInsensitive()
    {
        // Arrange
        var san1 = new SubjectAlternativeName("dns", "example.com");
        var san2 = new SubjectAlternativeName("DNS", "example.com");

        // Act & Assert
        Assert.That(san1.Matches(san2), Is.True);
    }

    [Test]
    public void Matches_ValueComparisonIsCaseSensitive()
    {
        // Arrange
        var san1 = new SubjectAlternativeName("dns", "example.com");
        var san2 = new SubjectAlternativeName("dns", "Example.com");

        // Act & Assert
        Assert.That(san1.Matches(san2), Is.False);
    }

    [Test]
    public void Matches_WithNullParameter_ReturnsFalse()
    {
        // Arrange
        var san = new SubjectAlternativeName("dns", "example.com");

        // Act & Assert
        Assert.That(san.Matches(null!), Is.False);
    }

    [Test]
    public void Matches_WithX509NameValues_UsesContainsAll()
    {
        // Arrange
        var name1 = new X509Name(new Dictionary<string, string> { ["CN"] = "Test", ["O"] = "Org" });
        var name2 = new X509Name(new Dictionary<string, string> { ["CN"] = "Test", ["O"] = "Org" });
        var san1 = new SubjectAlternativeName("dn", name1);
        var san2 = new SubjectAlternativeName("dn", name2);

        // Act & Assert
        Assert.That(san1.Matches(san2), Is.True);
    }

    [Test]
    public void Matches_WithX509NameValues_DifferentAttributes_ReturnsFalse()
    {
        // Arrange
        var name1 = new X509Name(new Dictionary<string, string> { ["CN"] = "Test1" });
        var name2 = new X509Name(new Dictionary<string, string> { ["CN"] = "Test2" });
        var san1 = new SubjectAlternativeName("dn", name1);
        var san2 = new SubjectAlternativeName("dn", name2);

        // Act & Assert
        Assert.That(san1.Matches(san2), Is.False);
    }

    [Test]
    public void ToString_WithStringValue_ReturnsFormattedString()
    {
        // Arrange
        var san = new SubjectAlternativeName("dns", "example.com");

        // Act
        var result = san.ToString();

        // Assert
        Assert.That(result, Is.EqualTo("dns:example.com"));
    }

    [Test]
    public void ToString_WithX509NameValue_ReturnsFormattedString()
    {
        // Arrange
        var name = new X509Name(new Dictionary<string, string> { ["CN"] = "Test" });
        var san = new SubjectAlternativeName("dn", name);

        // Act
        var result = san.ToString();

        // Assert
        Assert.That(result, Does.StartWith("dn:"));
    }

    [Test]
    public void Constructor_WithAllValidTypes_CreatesInstances()
    {
        // Arrange & Act & Assert
        Assert.DoesNotThrow(() => new SubjectAlternativeName(DidX509Constants.SanTypeEmail, "test@example.com"));
        Assert.DoesNotThrow(() => new SubjectAlternativeName(DidX509Constants.SanTypeDns, "example.com"));
        Assert.DoesNotThrow(() => new SubjectAlternativeName(DidX509Constants.SanTypeUri, "https://example.com"));

        var name = new X509Name(new Dictionary<string, string> { ["CN"] = "Test" });
        Assert.DoesNotThrow(() => new SubjectAlternativeName(DidX509Constants.SanTypeDn, name));
    }
}
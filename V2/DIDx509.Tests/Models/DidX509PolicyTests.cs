// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests.Models;

using DIDx509.Models;

[TestFixture]
public class DidX509PolicyTests
{
    [Test]
    public void Constructor_WithNameAndRawValue_CreatesInstance()
    {
        // Act
        var policy = new DidX509Policy("subject", "CN:Test User");

        // Assert
        Assert.That(policy.Name, Is.EqualTo("subject"));
        Assert.That(policy.RawValue, Is.EqualTo("CN:Test User"));
        Assert.That(policy.ParsedValue, Is.Null);
    }

    [Test]
    public void Constructor_WithParsedValue_SetsAllProperties()
    {
        // Arrange
        var parsedValue = new X509Name(new Dictionary<string, string> { ["CN"] = "Test" });

        // Act
        var policy = new DidX509Policy("subject", "CN:Test", parsedValue);

        // Assert
        Assert.That(policy.Name, Is.EqualTo("subject"));
        Assert.That(policy.RawValue, Is.EqualTo("CN:Test"));
        Assert.That(policy.ParsedValue, Is.SameAs(parsedValue));
    }

    [Test]
    public void Constructor_WithNullName_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new DidX509Policy(null!, "value"));
    }

    [Test]
    public void Constructor_WithNullRawValue_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new DidX509Policy("name", null!));
    }

    [Test]
    public void Constructor_WithNullParsedValue_AllowsNull()
    {
        // Act
        var policy = new DidX509Policy("subject", "CN:Test", null);

        // Assert
        Assert.That(policy.ParsedValue, Is.Null);
    }

    [Test]
    public void Constructor_WithVariousPolicyNames_CreatesInstances()
    {
        // Act & Assert
        Assert.DoesNotThrow(() => new DidX509Policy("subject", "CN:Test"));
        Assert.DoesNotThrow(() => new DidX509Policy("san", "dns:example.com"));
        Assert.DoesNotThrow(() => new DidX509Policy("eku", "1.3.6.1.5.5.7.3.1"));
        Assert.DoesNotThrow(() => new DidX509Policy("fulcio-issuer", "https://fulcio.sigstore.dev"));
    }

    [Test]
    public void ParsedValue_CanBeAnyType()
    {
        // Arrange & Act
        var policy1 = new DidX509Policy("test", "raw", "string value");
        var policy2 = new DidX509Policy("test", "raw", 123);
        var policy3 = new DidX509Policy("test", "raw", new[] { "a", "b" });

        // Assert
        Assert.That(policy1.ParsedValue, Is.EqualTo("string value"));
        Assert.That(policy2.ParsedValue, Is.EqualTo(123));
        Assert.That(policy3.ParsedValue, Is.EqualTo(new[] { "a", "b" }));
    }

    [Test]
    public void Constructor_WithEmptyStrings_CreatesInstance()
    {
        // Act
        var policy = new DidX509Policy("", "");

        // Assert
        Assert.That(policy.Name, Is.Empty);
        Assert.That(policy.RawValue, Is.Empty);
    }

    [Test]
    public void Constructor_PreservesExactValues()
    {
        // Arrange
        var name = "SubJeCt";
        var rawValue = "CN:Test User:O:Test Org";
        var parsedValue = new X509Name(new Dictionary<string, string> { ["CN"] = "Test User", ["O"] = "Test Org" });

        // Act
        var policy = new DidX509Policy(name, rawValue, parsedValue);

        // Assert
        Assert.That(policy.Name, Is.EqualTo("SubJeCt"));
        Assert.That(policy.RawValue, Is.EqualTo("CN:Test User:O:Test Org"));
        Assert.That(policy.ParsedValue, Is.SameAs(parsedValue));
    }
}
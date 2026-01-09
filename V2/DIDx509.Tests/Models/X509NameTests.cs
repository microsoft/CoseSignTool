// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests.Models;

using DIDx509.Models;

[TestFixture]
public class X509NameTests
{
    [Test]
    public void Constructor_WithAttributes_SetsProperties()
    {
        // Arrange
        var attributes = new Dictionary<string, string>
        {
            ["CN"] = "Test User",
            ["O"] = "Test Org",
            ["C"] = "US"
        };

        // Act
        var name = new X509Name(attributes);

        // Assert
        Assert.That(name.Attributes.Count, Is.EqualTo(3));
        Assert.That(name.Attributes["CN"], Is.EqualTo("Test User"));
        Assert.That(name.Attributes["O"], Is.EqualTo("Test Org"));
        Assert.That(name.Attributes["C"], Is.EqualTo("US"));
    }

    [Test]
    public void Constructor_WithNullAttributes_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new X509Name(null!));
    }

    [Test]
    public void Constructor_WithEmptyAttributes_CreatesInstance()
    {
        // Arrange
        var attributes = new Dictionary<string, string>();

        // Act
        var name = new X509Name(attributes);

        // Assert
        Assert.That(name.Attributes.Count, Is.EqualTo(0));
    }

    [Test]
    public void Constructor_AttributesAreCaseInsensitive()
    {
        // Arrange
        var attributes = new Dictionary<string, string>
        {
            ["cn"] = "Test User"
        };

        // Act
        var name = new X509Name(attributes);

        // Assert - can retrieve with different casing
        Assert.That(name.GetAttribute("CN"), Is.EqualTo("Test User"));
        Assert.That(name.GetAttribute("cn"), Is.EqualTo("Test User"));
        Assert.That(name.GetAttribute("Cn"), Is.EqualTo("Test User"));
    }

    [Test]
    public void GetAttribute_WithExistingKey_ReturnsValue()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { ["CN"] = "Test User" };
        var name = new X509Name(attributes);

        // Act
        var result = name.GetAttribute("CN");

        // Assert
        Assert.That(result, Is.EqualTo("Test User"));
    }

    [Test]
    public void GetAttribute_WithNonExistingKey_ReturnsNull()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { ["CN"] = "Test User" };
        var name = new X509Name(attributes);

        // Act
        var result = name.GetAttribute("O");

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void GetAttribute_IsCaseInsensitive()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { ["CN"] = "Test User" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.GetAttribute("CN"), Is.EqualTo("Test User"));
        Assert.That(name.GetAttribute("cn"), Is.EqualTo("Test User"));
        Assert.That(name.GetAttribute("Cn"), Is.EqualTo("Test User"));
    }

    [Test]
    public void ContainsAll_WithMatchingAttributes_ReturnsTrue()
    {
        // Arrange
        var name1 = new X509Name(new Dictionary<string, string>
        {
            ["CN"] = "Test User",
            ["O"] = "Test Org",
            ["C"] = "US"
        });
        var name2 = new X509Name(new Dictionary<string, string>
        {
            ["CN"] = "Test User",
            ["O"] = "Test Org"
        });

        // Act & Assert - name1 contains all attributes from name2
        Assert.That(name1.ContainsAll(name2), Is.True);
    }

    [Test]
    public void ContainsAll_WithMissingAttribute_ReturnsFalse()
    {
        // Arrange
        var name1 = new X509Name(new Dictionary<string, string>
        {
            ["CN"] = "Test User"
        });
        var name2 = new X509Name(new Dictionary<string, string>
        {
            ["CN"] = "Test User",
            ["O"] = "Test Org"
        });

        // Act & Assert - name1 does not contain "O" attribute
        Assert.That(name1.ContainsAll(name2), Is.False);
    }

    [Test]
    public void ContainsAll_WithDifferentValue_ReturnsFalse()
    {
        // Arrange
        var name1 = new X509Name(new Dictionary<string, string>
        {
            ["CN"] = "User1"
        });
        var name2 = new X509Name(new Dictionary<string, string>
        {
            ["CN"] = "User2"
        });

        // Act & Assert
        Assert.That(name1.ContainsAll(name2), Is.False);
    }

    [Test]
    public void ContainsAll_WithEmptyOther_ReturnsTrue()
    {
        // Arrange
        var name1 = new X509Name(new Dictionary<string, string> { ["CN"] = "Test" });
        var name2 = new X509Name(new Dictionary<string, string>());

        // Act & Assert - empty name is contained in any name
        Assert.That(name1.ContainsAll(name2), Is.True);
    }

    [Test]
    public void ContainsAll_WithNullParameter_ThrowsArgumentNullException()
    {
        // Arrange
        var name = new X509Name(new Dictionary<string, string> { ["CN"] = "Test" });

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => name.ContainsAll(null!));
    }

    [Test]
    public void ContainsAll_ValueComparisonIsCaseSensitive()
    {
        // Arrange
        var name1 = new X509Name(new Dictionary<string, string> { ["CN"] = "Test" });
        var name2 = new X509Name(new Dictionary<string, string> { ["CN"] = "test" });

        // Act & Assert
        Assert.That(name1.ContainsAll(name2), Is.False);
        Assert.That(name2.ContainsAll(name1), Is.False);
    }

    [Test]
    public void CN_Property_ReturnsCommonName()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { [DidX509Constants.AttributeCN] = "Test User" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.CN, Is.EqualTo("Test User"));
    }

    [Test]
    public void CN_Property_WhenNotPresent_ReturnsNull()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { ["O"] = "Test Org" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.CN, Is.Null);
    }

    [Test]
    public void L_Property_ReturnsLocality()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { [DidX509Constants.AttributeL] = "Seattle" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.L, Is.EqualTo("Seattle"));
    }

    [Test]
    public void ST_Property_ReturnsStateOrProvince()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { [DidX509Constants.AttributeST] = "Washington" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.ST, Is.EqualTo("Washington"));
    }

    [Test]
    public void O_Property_ReturnsOrganization()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { [DidX509Constants.AttributeO] = "Test Org" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.O, Is.EqualTo("Test Org"));
    }

    [Test]
    public void OU_Property_ReturnsOrganizationalUnit()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { [DidX509Constants.AttributeOU] = "Engineering" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.OU, Is.EqualTo("Engineering"));
    }

    [Test]
    public void C_Property_ReturnsCountry()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { [DidX509Constants.AttributeC] = "US" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.C, Is.EqualTo("US"));
    }

    [Test]
    public void STREET_Property_ReturnsStreetAddress()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { [DidX509Constants.AttributeSTREET] = "123 Main St" };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.STREET, Is.EqualTo("123 Main St"));
    }

    [Test]
    public void AllProperties_WhenNotPresent_ReturnNull()
    {
        // Arrange
        var attributes = new Dictionary<string, string>();
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.CN, Is.Null);
        Assert.That(name.L, Is.Null);
        Assert.That(name.ST, Is.Null);
        Assert.That(name.O, Is.Null);
        Assert.That(name.OU, Is.Null);
        Assert.That(name.C, Is.Null);
        Assert.That(name.STREET, Is.Null);
    }

    [Test]
    public void AllProperties_WithCompleteAttributes_ReturnValues()
    {
        // Arrange
        var attributes = new Dictionary<string, string>
        {
            [DidX509Constants.AttributeCN] = "Test User",
            [DidX509Constants.AttributeL] = "Seattle",
            [DidX509Constants.AttributeST] = "Washington",
            [DidX509Constants.AttributeO] = "Test Org",
            [DidX509Constants.AttributeOU] = "Engineering",
            [DidX509Constants.AttributeC] = "US",
            [DidX509Constants.AttributeSTREET] = "123 Main St"
        };
        var name = new X509Name(attributes);

        // Act & Assert
        Assert.That(name.CN, Is.EqualTo("Test User"));
        Assert.That(name.L, Is.EqualTo("Seattle"));
        Assert.That(name.ST, Is.EqualTo("Washington"));
        Assert.That(name.O, Is.EqualTo("Test Org"));
        Assert.That(name.OU, Is.EqualTo("Engineering"));
        Assert.That(name.C, Is.EqualTo("US"));
        Assert.That(name.STREET, Is.EqualTo("123 Main St"));
    }

    [Test]
    public void Attributes_IsReadOnly()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { ["CN"] = "Test" };
        var name = new X509Name(attributes);

        // Act & Assert - Attributes should be read-only
        Assert.That(name.Attributes, Is.InstanceOf<IReadOnlyDictionary<string, string>>());
    }

    [Test]
    public void Constructor_CopiesAttributes_DoesNotShareReference()
    {
        // Arrange
        var attributes = new Dictionary<string, string> { ["CN"] = "Original" };
        var name = new X509Name(attributes);

        // Act - modify original dictionary
        attributes["CN"] = "Modified";
        attributes["O"] = "New Org";

        // Assert - X509Name should not be affected
        Assert.That(name.GetAttribute("CN"), Is.EqualTo("Original"));
        Assert.That(name.GetAttribute("O"), Is.Null);
        Assert.That(name.Attributes.Count, Is.EqualTo(1));
    }
}
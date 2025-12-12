// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using NUnit.Framework;

namespace CoseSign1.Abstractions.Tests;

/// <summary>
/// Tests for SigningServiceMetadata class.
/// </summary>
[TestFixture]
public class SigningServiceMetadataTests
{
    [Test]
    public void Constructor_ShouldInitializeAllProperties()
    {
        // Arrange
        var serviceName = "Azure Key Vault Signing Service";
        var description = "Signs using keys stored in Azure Key Vault";
        var additionalData = new Dictionary<string, object>
        {
            { "SupportsHSM", true },
            { "MaxKeySize", 4096 }
        };

        // Act
        var metadata = new SigningServiceMetadata(serviceName, description, additionalData);

        // Assert
        Assert.That(metadata.ServiceName, Is.EqualTo(serviceName));
        Assert.That(metadata.Description, Is.EqualTo(description));
        Assert.That(metadata.AdditionalData, Is.EqualTo(additionalData));
        Assert.That(metadata.AdditionalData, Is.Not.SameAs(additionalData), "Should be a defensive copy");
    }

    [Test]
    public void Constructor_WithNullDescription_ShouldUseEmptyString()
    {
        // Arrange & Act
        var metadata = new SigningServiceMetadata("Service Name", null, null);

        // Assert
        Assert.That(metadata.Description, Is.EqualTo(string.Empty));
    }

    [Test]
    public void Constructor_WithNullAdditionalData_ShouldCreateEmptyDictionary()
    {
        // Arrange & Act
        var metadata = new SigningServiceMetadata("Service Name", "Description", null);

        // Assert
        Assert.That(metadata.AdditionalData, Is.Not.Null);
        Assert.That(metadata.AdditionalData, Is.Empty);
    }

    [Test]
    public void ToString_ShouldReturnMeaningfulRepresentation()
    {
        // Arrange
        var metadata = new SigningServiceMetadata("My Service", "Test Description", null);

        // Act
        var result = metadata.ToString();

        // Assert
        Assert.That(result, Does.Contain("My Service"));
    }
}
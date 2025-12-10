// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Abstractions;
using NUnit.Framework;

namespace CoseSign1.Abstractions.Tests;

[TestFixture]
public class SigningOptionsTests
{
    [Test]
    public void Constructor_InitializesWithDefaults()
    {
        // Act
        var options = new SigningOptions();

        // Assert
        Assert.That(options.AdditionalHeaderContributors, Is.Null);
        Assert.That(options.AdditionalContext, Is.Null);
        Assert.That(options.AdditionalData.Length, Is.EqualTo(0));
        Assert.That(options.DisableTransparency, Is.False);
        Assert.That(options.FailOnTransparencyError, Is.True);
    }

    [Test]
    public void AdditionalHeaderContributors_CanBeSet()
    {
        // Arrange
        var options = new SigningOptions();
        var contributors = new List<IHeaderContributor>().AsReadOnly();

        // Act
        options.AdditionalHeaderContributors = contributors;

        // Assert
        Assert.That(options.AdditionalHeaderContributors, Is.SameAs(contributors));
    }

    [Test]
    public void AdditionalContext_CanBeSet()
    {
        // Arrange
        var options = new SigningOptions();
        var context = new Dictionary<string, object> { ["key"] = "value" };

        // Act
        options.AdditionalContext = context;

        // Assert
        Assert.That(options.AdditionalContext, Is.SameAs(context));
        Assert.That(options.AdditionalContext["key"], Is.EqualTo("value"));
    }

    [Test]
    public void AdditionalData_CanBeSet()
    {
        // Arrange
        var options = new SigningOptions();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        options.AdditionalData = data;

        // Assert
        Assert.That(options.AdditionalData.Length, Is.EqualTo(5));
        Assert.That(options.AdditionalData.ToArray(), Is.EqualTo(data));
    }

    [Test]
    public void DisableTransparency_CanBeSet()
    {
        // Arrange
        var options = new SigningOptions();

        // Act
        options.DisableTransparency = true;

        // Assert
        Assert.That(options.DisableTransparency, Is.True);
    }

    [Test]
    public void FailOnTransparencyError_CanBeSet()
    {
        // Arrange
        var options = new SigningOptions();

        // Act
        options.FailOnTransparencyError = false;

        // Assert
        Assert.That(options.FailOnTransparencyError, Is.False);
    }

    [Test]
    public void AllProperties_CanBeSetTogether()
    {
        // Arrange & Act
        var options = new SigningOptions
        {
            AdditionalHeaderContributors = new List<IHeaderContributor>().AsReadOnly(),
            AdditionalContext = new Dictionary<string, object> { ["test"] = 123 },
            AdditionalData = new byte[] { 9, 8, 7 },
            DisableTransparency = true,
            FailOnTransparencyError = false
        };

        // Assert
        Assert.That(options.AdditionalHeaderContributors, Is.Not.Null);
        Assert.That(options.AdditionalContext, Is.Not.Null);
        Assert.That(options.AdditionalData.Length, Is.EqualTo(3));
        Assert.That(options.DisableTransparency, Is.True);
        Assert.That(options.FailOnTransparencyError, Is.False);
    }

    [Test]
    public void AdditionalData_DefaultIsEmpty()
    {
        // Arrange
        var options = new SigningOptions();

        // Assert
        Assert.That(options.AdditionalData.IsEmpty, Is.True);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.MST.Plugin;

namespace CoseSignTool.MST.Plugin.Tests;

/// <summary>
/// Tests for MstTransparencyProviderContributor.
/// </summary>
[TestFixture]
public class MstTransparencyProviderContributorTests
{
    [Test]
    public void ProviderName_ReturnsCorrectName()
    {
        // Arrange
        var contributor = new MstTransparencyProviderContributor();

        // Act
        var name = contributor.ProviderName;

        // Assert
        Assert.That(name, Is.EqualTo("Microsoft Signing Transparency"));
    }

    [Test]
    public void ProviderDescription_ReturnsDescription()
    {
        // Arrange
        var contributor = new MstTransparencyProviderContributor();

        // Act
        var description = contributor.ProviderDescription;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description, Does.Contain("MST"));
    }

    [Test]
    public async Task CreateTransparencyProviderAsync_WithDefaultEndpoint_ReturnsProvider()
    {
        // Arrange
        var contributor = new MstTransparencyProviderContributor();
        var options = new Dictionary<string, object?>();

        // Act
        var provider = await contributor.CreateTransparencyProviderAsync(options);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public async Task CreateTransparencyProviderAsync_WithCustomEndpoint_ReturnsProvider()
    {
        // Arrange
        var contributor = new MstTransparencyProviderContributor();
        var options = new Dictionary<string, object?>
        {
            ["mst-endpoint"] = "https://custom.codetransparency.azure.net"
        };

        // Act
        var provider = await contributor.CreateTransparencyProviderAsync(options);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void CreateTransparencyProviderAsync_WithInvalidEndpoint_ThrowsArgumentException()
    {
        // Arrange
        var contributor = new MstTransparencyProviderContributor();
        var options = new Dictionary<string, object?>
        {
            ["mst-endpoint"] = "not-a-valid-url"
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(
            () => contributor.CreateTransparencyProviderAsync(options));
    }

    [Test]
    public async Task CreateTransparencyProviderAsync_WithNullEndpoint_UsesDefault()
    {
        // Arrange
        var contributor = new MstTransparencyProviderContributor();
        var options = new Dictionary<string, object?>
        {
            ["mst-endpoint"] = null
        };

        // Act
        var provider = await contributor.CreateTransparencyProviderAsync(options);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public async Task CreateTransparencyProviderAsync_WithEmptyEndpoint_UsesDefault()
    {
        // Arrange
        var contributor = new MstTransparencyProviderContributor();
        var options = new Dictionary<string, object?>
        {
            ["mst-endpoint"] = ""
        };

        // Act
        var provider = await contributor.CreateTransparencyProviderAsync(options);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public async Task CreateTransparencyProviderAsync_WithCancellationToken_ReturnsProvider()
    {
        // Arrange
        var contributor = new MstTransparencyProviderContributor();
        var options = new Dictionary<string, object?>();
        var cancellationToken = new CancellationToken();

        // Act
        var provider = await contributor.CreateTransparencyProviderAsync(options, cancellationToken);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }
}

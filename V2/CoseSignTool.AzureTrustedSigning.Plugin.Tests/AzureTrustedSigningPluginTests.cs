// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.AzureTrustedSigning.Plugin;

namespace CoseSignTool.AzureTrustedSigning.Plugin.Tests;

/// <summary>
/// Tests for AzureTrustedSigningPlugin.
/// </summary>
[TestFixture]
public class AzureTrustedSigningPluginTests
{
    [Test]
    public void Name_ReturnsCorrectName()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var name = plugin.Name;

        // Assert
        Assert.That(name, Is.EqualTo("Azure Trusted Signing"));
    }

    [Test]
    public void Version_ReturnsVersion()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var version = plugin.Version;

        // Assert
        Assert.That(version, Is.Not.Null);
        Assert.That(version, Is.Not.Empty);
        Assert.That(version, Is.EqualTo("1.0.0"));
    }

    [Test]
    public void Description_ReturnsDescription()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var description = plugin.Description;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToLowerInvariant(), Does.Contain("azure"));
    }

    [Test]
    public async Task InitializeAsync_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act & Assert - should not throw
        await plugin.InitializeAsync();
    }

    [Test]
    public async Task InitializeAsync_WithConfiguration_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();
        var config = new Dictionary<string, string> { ["key"] = "value" };

        // Act & Assert - should not throw
        await plugin.InitializeAsync(config);
    }

    [Test]
    public void GetSigningCommandProviders_ReturnsAzureProvider()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var providers = plugin.GetSigningCommandProviders().ToList();

        // Assert
        Assert.That(providers, Is.Not.Null);
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers, Has.Some.Matches<CoseSignTool.Plugins.ISigningCommandProvider>(p => p.CommandName == "sign-azure"));
    }

    [Test]
    public void GetTransparencyProviderContributors_ReturnsEmpty()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var contributors = plugin.GetTransparencyProviderContributors().ToList();

        // Assert
        Assert.That(contributors, Is.Empty);
    }

    [Test]
    public void RegisterCommands_DoesNotThrow()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();
        var rootCommand = new System.CommandLine.RootCommand();

        // Act & Assert - should not throw
        plugin.RegisterCommands(rootCommand);
    }
}
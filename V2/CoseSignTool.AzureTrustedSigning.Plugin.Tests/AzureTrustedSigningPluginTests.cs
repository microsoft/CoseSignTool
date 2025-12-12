// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.AzureTrustedSigning.Plugin;

namespace CoseSignTool.AzureTrustedSigning.Plugin.Tests;

/// <summary>
/// Tests for AzureTrustedSigningPlugin.
/// </summary>
public class AzureTrustedSigningPluginTests
{
    [Fact]
    public void Name_ReturnsCorrectName()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var name = plugin.Name;

        // Assert
        Assert.Equal("Azure Trusted Signing", name);
    }

    [Fact]
    public void Version_ReturnsVersion()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var version = plugin.Version;

        // Assert
        Assert.NotNull(version);
        Assert.NotEmpty(version);
        Assert.Equal("1.0.0", version);
    }

    [Fact]
    public void Description_ReturnsDescription()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var description = plugin.Description;

        // Assert
        Assert.NotNull(description);
        Assert.NotEmpty(description);
        Assert.Contains("Azure", description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InitializeAsync_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act & Assert - should not throw
        await plugin.InitializeAsync();
    }

    [Fact]
    public async Task InitializeAsync_WithConfiguration_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();
        var config = new Dictionary<string, string> { ["key"] = "value" };

        // Act & Assert - should not throw
        await plugin.InitializeAsync(config);
    }

    [Fact]
    public void GetSigningCommandProviders_ReturnsAzureProvider()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var providers = plugin.GetSigningCommandProviders().ToList();

        // Assert
        Assert.NotNull(providers);
        Assert.Single(providers);
        Assert.Contains(providers, p => p.CommandName == "sign-azure");
    }

    [Fact]
    public void GetTransparencyProviderContributors_ReturnsEmpty()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();

        // Act
        var contributors = plugin.GetTransparencyProviderContributors().ToList();

        // Assert
        Assert.Empty(contributors);
    }

    [Fact]
    public void RegisterCommands_DoesNotThrow()
    {
        // Arrange
        var plugin = new AzureTrustedSigningPlugin();
        var rootCommand = new System.CommandLine.RootCommand();

        // Act & Assert - should not throw
        plugin.RegisterCommands(rootCommand);
    }
}

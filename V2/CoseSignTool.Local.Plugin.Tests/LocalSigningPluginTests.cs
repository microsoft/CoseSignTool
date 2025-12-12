// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Local.Plugin;

namespace CoseSignTool.Local.Plugin.Tests;

/// <summary>
/// Tests for LocalSigningPlugin.
/// </summary>
public class LocalSigningPluginTests
{
    [Fact]
    public void Name_ReturnsCorrectName()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var name = plugin.Name;

        // Assert
        Assert.Equal("Local Certificate Signing", name);
    }

    [Fact]
    public void Version_ReturnsVersion()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

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
        var plugin = new LocalSigningPlugin();

        // Act
        var description = plugin.Description;

        // Assert
        Assert.NotNull(description);
        Assert.NotEmpty(description);
        Assert.Contains("local", description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InitializeAsync_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act & Assert - should not throw
        await plugin.InitializeAsync();
    }

    [Fact]
    public async Task InitializeAsync_WithConfiguration_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();
        var config = new Dictionary<string, string> { ["key"] = "value" };

        // Act & Assert - should not throw
        await plugin.InitializeAsync(config);
    }

    [Fact]
    public void GetSigningCommandProviders_ReturnsProviders()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var providers = plugin.GetSigningCommandProviders().ToList();

        // Assert
        Assert.NotNull(providers);
        Assert.NotEmpty(providers);
        // Should always include PFX provider
        Assert.Contains(providers, p => p.CommandName == "sign-pfx");
    }

    [Fact]
    public void GetSigningCommandProviders_IncludesPlatformSpecificProviders()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var providers = plugin.GetSigningCommandProviders().ToList();

        // Assert
        Assert.NotNull(providers);
        // On Windows, should include certstore provider
        if (OperatingSystem.IsWindows())
        {
            Assert.Contains(providers, p => p.CommandName == "sign-certstore");
        }
    }

    [Fact]
    public void GetTransparencyProviderContributors_ReturnsEmpty()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var contributors = plugin.GetTransparencyProviderContributors().ToList();

        // Assert
        Assert.Empty(contributors);
    }

    [Fact]
    public void RegisterCommands_DoesNotThrow()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();
        var rootCommand = new System.CommandLine.RootCommand();

        // Act & Assert - should not throw
        plugin.RegisterCommands(rootCommand);
    }
}

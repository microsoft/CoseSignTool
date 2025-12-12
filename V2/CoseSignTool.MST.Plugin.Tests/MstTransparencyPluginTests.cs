// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.MST.Plugin;
using System.CommandLine;

namespace CoseSignTool.MST.Plugin.Tests;

/// <summary>
/// Tests for MstTransparencyPlugin.
/// </summary>
public class MstTransparencyPluginTests
{
    [Fact]
    public void Name_ReturnsCorrectName()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var name = plugin.Name;

        // Assert
        Assert.Equal("Microsoft Signing Transparency", name);
    }

    [Fact]
    public void Version_ReturnsVersion()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var version = plugin.Version;

        // Assert
        Assert.NotNull(version);
        Assert.Equal("1.0.0", version);
    }

    [Fact]
    public void Description_ReturnsDescription()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var description = plugin.Description;

        // Assert
        Assert.NotNull(description);
        Assert.NotEmpty(description);
        Assert.Contains("Microsoft Signing Transparency", description);
    }

    [Fact]
    public async Task InitializeAsync_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act & Assert - no exception should be thrown
        await plugin.InitializeAsync();
    }

    [Fact]
    public async Task InitializeAsync_WithConfiguration_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();
        var options = new Dictionary<string, string>
        {
            ["endpoint"] = "https://mst.example.com"
        };

        // Act & Assert - no exception should be thrown
        await plugin.InitializeAsync(options);
    }

    [Fact]
    public void GetSigningCommandProviders_ReturnsEmpty()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var providers = plugin.GetSigningCommandProviders().ToList();

        // Assert - MST plugin doesn't provide signing commands
        Assert.Empty(providers);
    }

    [Fact]
    public void GetTransparencyProviderContributors_ReturnsMstContributor()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var contributors = plugin.GetTransparencyProviderContributors().ToList();

        // Assert
        Assert.Single(contributors);
        Assert.IsType<MstTransparencyProviderContributor>(contributors[0]);
    }

    [Fact]
    public void RegisterCommands_AddsVerifyMstCommand()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();
        var rootCommand = new RootCommand("Test");

        // Act
        plugin.RegisterCommands(rootCommand);

        // Assert
        Assert.Contains(rootCommand.Subcommands, c => c.Name == "verify-mst");
    }

    [Fact]
    public void RegisterCommands_VerifyMstCommandHasSignatureArgument()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();
        var rootCommand = new RootCommand("Test");

        // Act
        plugin.RegisterCommands(rootCommand);

        // Assert
        var verifyMstCommand = rootCommand.Subcommands.First(c => c.Name == "verify-mst");
        Assert.Contains(verifyMstCommand.Arguments, a => a.Name == "signature");
    }

    [Fact]
    public void RegisterCommands_VerifyMstCommandHasEndpointOption()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();
        var rootCommand = new RootCommand("Test");

        // Act
        plugin.RegisterCommands(rootCommand);

        // Assert
        var verifyMstCommand = rootCommand.Subcommands.First(c => c.Name == "verify-mst");
        Assert.Contains(verifyMstCommand.Options, o => o.Name == "endpoint");
    }
}

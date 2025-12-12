// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.MST.Plugin;
using System.CommandLine;

namespace CoseSignTool.MST.Plugin.Tests;

/// <summary>
/// Tests for MstTransparencyPlugin.
/// </summary>
[TestFixture]
public class MstTransparencyPluginTests
{
    [Test]
    public void Name_ReturnsCorrectName()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var name = plugin.Name;

        // Assert
        Assert.That(name, Is.EqualTo("Microsoft Signing Transparency"));
    }

    [Test]
    public void Version_ReturnsVersion()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var version = plugin.Version;

        // Assert
        Assert.That(version, Is.Not.Null);
        Assert.That(version, Is.EqualTo("1.0.0"));
    }

    [Test]
    public void Description_ReturnsDescription()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var description = plugin.Description;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description, Does.Contain("Microsoft Signing Transparency"));
    }

    [Test]
    public async Task InitializeAsync_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act & Assert - no exception should be thrown
        await plugin.InitializeAsync();
    }

    [Test]
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

    [Test]
    public void GetSigningCommandProviders_ReturnsEmpty()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var providers = plugin.GetSigningCommandProviders().ToList();

        // Assert - MST plugin doesn't provide signing commands
        Assert.That(providers, Is.Empty);
    }

    [Test]
    public void GetTransparencyProviderContributors_ReturnsMstContributor()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var contributors = plugin.GetTransparencyProviderContributors().ToList();

        // Assert
        Assert.That(contributors, Has.Count.EqualTo(1));
        Assert.That(contributors[0], Is.InstanceOf<MstTransparencyProviderContributor>());
    }

    [Test]
    public void RegisterCommands_AddsVerifyMstCommand()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();
        var rootCommand = new RootCommand("Test");

        // Act
        plugin.RegisterCommands(rootCommand);

        // Assert
        Assert.That(rootCommand.Subcommands, Has.Some.Matches<Command>(c => c.Name == "verify-mst"));
    }

    [Test]
    public void RegisterCommands_VerifyMstCommandHasSignatureArgument()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();
        var rootCommand = new RootCommand("Test");

        // Act
        plugin.RegisterCommands(rootCommand);

        // Assert
        var verifyMstCommand = rootCommand.Subcommands.First(c => c.Name == "verify-mst");
        Assert.That(verifyMstCommand.Arguments, Has.Some.Matches<Argument>(a => a.Name == "signature"));
    }

    [Test]
    public void RegisterCommands_VerifyMstCommandHasEndpointOption()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();
        var rootCommand = new RootCommand("Test");

        // Act
        plugin.RegisterCommands(rootCommand);

        // Assert
        var verifyMstCommand = rootCommand.Subcommands.First(c => c.Name == "verify-mst");
        Assert.That(verifyMstCommand.Options, Has.Some.Matches<Option>(o => o.Name == "endpoint"));
    }
}

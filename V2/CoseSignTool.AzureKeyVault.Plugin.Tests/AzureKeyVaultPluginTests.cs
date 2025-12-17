// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

/// <summary>
/// Tests for <see cref="AzureKeyVaultPlugin"/>.
/// </summary>
[TestFixture]
public class AzureKeyVaultPluginTests
{
    [Test]
    public void Name_ReturnsCorrectName()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

        // Act
        var name = plugin.Name;

        // Assert
        Assert.That(name, Is.EqualTo("Azure Key Vault"));
    }

    [Test]
    public void Version_ReturnsVersion()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

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
        var plugin = new AzureKeyVaultPlugin();

        // Act
        var description = plugin.Description;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToLowerInvariant(), Does.Contain("key vault"));
    }

    [Test]
    public async Task InitializeAsync_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

        // Act & Assert - should not throw
        await plugin.InitializeAsync();
    }

    [Test]
    public async Task InitializeAsync_WithConfiguration_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();
        var config = new Dictionary<string, string> { ["key"] = "value" };

        // Act & Assert - should not throw
        await plugin.InitializeAsync(config);
    }

    [Test]
    public void GetExtensions_SigningCommandProviders_ReturnsTwoProviders()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.SigningCommandProviders.ToList();

        // Assert
        Assert.That(providers, Is.Not.Null);
        Assert.That(providers, Has.Count.EqualTo(2));
    }

    [Test]
    public void GetExtensions_SigningCommandProviders_IncludesCertificateProvider()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.SigningCommandProviders.ToList();

        // Assert
        Assert.That(providers, Has.Some.Matches<ISigningCommandProvider>(p => p.CommandName == "sign-akv-cert"));
    }

    [Test]
    public void GetExtensions_SigningCommandProviders_IncludesKeyProvider()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.SigningCommandProviders.ToList();

        // Assert
        Assert.That(providers, Has.Some.Matches<ISigningCommandProvider>(p => p.CommandName == "sign-akv-key"));
    }

    [Test]
    public void GetExtensions_VerificationProviders_ReturnsProvider()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.VerificationProviders.ToList();

        // Assert
        Assert.That(providers, Is.Not.Empty);
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0].ProviderName, Is.EqualTo("AzureKeyVault"));
    }

    [Test]
    public void GetExtensions_TransparencyProviders_ReturnsEmpty()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.TransparencyProviders.ToList();

        // Assert
        Assert.That(providers, Is.Empty);
    }

    [Test]
    public void RegisterCommands_DoesNotThrow()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();
        var rootCommand = new RootCommand();

        // Act & Assert - should not throw
        Assert.DoesNotThrow(() => plugin.RegisterCommands(rootCommand));
    }

    [Test]
    public void RegisterCommands_DoesNotAddAdditionalCommands()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();
        var rootCommand = new RootCommand();
        var initialCommandCount = rootCommand.Subcommands.Count;

        // Act
        plugin.RegisterCommands(rootCommand);

        // Assert - Plugin doesn't register additional commands, only signing providers
        Assert.That(rootCommand.Subcommands.Count, Is.EqualTo(initialCommandCount));
    }

    [Test]
    public void IPlugin_Interface_ImplementedCorrectly()
    {
        // Arrange
        var plugin = new AzureKeyVaultPlugin();

        // Assert - Plugin implements IPlugin interface
        Assert.That(plugin, Is.InstanceOf<IPlugin>());
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin.Tests;

using CoseSignTool.Abstractions;

/// <summary>
/// Tests for LocalSigningPlugin.
/// </summary>
[TestFixture]
public class LocalSigningPluginTests
{
    [Test]
    public void Name_ReturnsCorrectName()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var name = plugin.Name;

        // Assert
        Assert.That(name, Is.EqualTo("Local Certificate Signing"));
    }

    [Test]
    public void Version_ReturnsVersion()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

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
        var plugin = new LocalSigningPlugin();

        // Act
        var description = plugin.Description;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToLowerInvariant(), Does.Contain("local"));
    }

    [Test]
    public async Task InitializeAsync_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act & Assert - should not throw
        await plugin.InitializeAsync();
    }

    [Test]
    public async Task InitializeAsync_WithConfiguration_CompletesSuccessfully()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();
        var config = new Dictionary<string, string> { ["key"] = "value" };

        // Act & Assert - should not throw
        await plugin.InitializeAsync(config);
    }

    [Test]
    public void GetExtensions_SigningCommandProviders_ReturnsProviders()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.SigningCommandProviders.ToList();

        // Assert
        Assert.That(providers, Is.Not.Null);
        Assert.That(providers, Is.Not.Empty);
        // Should always include PFX provider
        Assert.That(providers, Has.Some.Matches<ISigningCommandProvider>(p => p.CommandName == "x509-pfx"));
    }

    [Test]
    public void GetExtensions_SigningCommandProviders_IncludesPlatformSpecificProviders()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.SigningCommandProviders.ToList();

        // Assert
        Assert.That(providers, Is.Not.Null);
        // On Windows, should include certstore provider
        if (OperatingSystem.IsWindows())
        {
            Assert.That(providers, Has.Some.Matches<ISigningCommandProvider>(p => p.CommandName == "x509-certstore"));
        }
    }

    [Test]
    public void GetExtensions_TransparencyProviders_ReturnsEmpty()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var contributors = extensions.TransparencyProviders.ToList();

        // Assert
        Assert.That(contributors, Is.Empty);
    }

    [Test]
    public void GetExtensions_VerificationProviders_ReturnsX509VerificationProvider()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.VerificationProviders.ToList();

        // Assert - Local plugin provides X509 verification provider
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<X509VerificationProvider>());
    }

    [Test]
    public void RegisterCommands_DoesNotThrow()
    {
        // Arrange
        var plugin = new LocalSigningPlugin();
        var rootCommand = new System.CommandLine.RootCommand();

        // Act & Assert - should not throw
        plugin.RegisterCommands(rootCommand);
    }
}
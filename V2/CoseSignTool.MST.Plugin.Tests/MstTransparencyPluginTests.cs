// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Validation;
using CoseSignTool.MST.Plugin;
using Moq;

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
    public void GetExtensions_SigningCommandProviders_ReturnsEmpty()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var extensions = plugin.GetExtensions();

        // Assert - MST plugin doesn't provide signing commands
        Assert.That(extensions.SigningCommandProviders, Is.Empty);
    }

    [Test]
    public void GetExtensions_TransparencyProviders_ReturnsMstContributor()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var contributors = extensions.TransparencyProviders.ToList();

        // Assert
        Assert.That(contributors, Has.Count.EqualTo(1));
        Assert.That(contributors[0], Is.InstanceOf<MstTransparencyProviderContributor>());
    }

    [Test]
    public void GetExtensions_VerificationProviders_ReturnsMstVerificationProvider()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();

        // Act
        var extensions = plugin.GetExtensions();
        var providers = extensions.VerificationProviders.ToList();

        // Assert - MST plugin provides verification provider
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<MstVerificationProvider>());
    }

    [Test]
    public void RegisterCommands_DoesNotAddCommands()
    {
        // Arrange
        var plugin = new MstTransparencyPlugin();
        var rootCommand = new RootCommand("Test");
        var initialCount = rootCommand.Subcommands.Count;

        // Act
        plugin.RegisterCommands(rootCommand);

        // Assert - MST plugin does not add commands (I/O is handled by main exe)
        Assert.That(rootCommand.Subcommands.Count, Is.EqualTo(initialCount));
    }

    [Test]
    public void AddMstValidator_WithVerifyReceiptClient_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        var client = new Mock<CodeTransparencyClient>().Object;

        var result = builder.AddMstValidator(b => b.VerifyReceipt(client));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddMstValidator_WithVerifyReceiptProvider_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        var client = new Mock<CodeTransparencyClient>().Object;
        var provider = new MstTransparencyProvider(client);

        var result = builder.AddMstValidator(b => b.VerifyReceipt(provider));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddMstValidator_WithNoValidatorsConfigured_ThrowsInvalidOperationException()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();

        var ex = Assert.Throws<InvalidOperationException>(() => builder.AddMstValidator(_ => { }));
        Assert.That(ex!.Message, Is.EqualTo("No MST validators configured"));
    }

    [Test]
    public void AddMstValidator_WithNullBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => MstValidationExtensions.AddMstValidator(null!, _ => { }));
    }

    [Test]
    public void AddMstValidator_WithNullConfigure_ThrowsArgumentNullException()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        Assert.Throws<ArgumentNullException>(() => builder.AddMstValidator(null!));
    }

    [Test]
    public void AddMstValidator_VerifyReceiptWithNullClient_ThrowsArgumentNullException()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        Assert.Throws<ArgumentNullException>(() => builder.AddMstValidator(b => b.VerifyReceipt((CodeTransparencyClient)null!)));
    }

    [Test]
    public void AddMstValidator_VerifyReceiptWithNullProvider_ThrowsArgumentNullException()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        Assert.Throws<ArgumentNullException>(() => builder.AddMstValidator(b => b.VerifyReceipt((MstTransparencyProvider)null!)));
    }
}
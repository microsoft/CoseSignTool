// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin.Tests;

using System.CommandLine;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation.Interfaces;
using Moq;

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
    public void ValidateMst_WithVerifyReceiptClient_AddsValidator()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        builder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(builder.Object);
        var client = new Mock<CodeTransparencyClient>().Object;

        var result = builder.Object.ValidateMst(b => b.VerifyReceipt(client));

        Assert.That(result, Is.SameAs(builder.Object));
    }

    [Test]
    public void ValidateMst_WithVerifyReceiptProvider_AddsValidator()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        builder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(builder.Object);
        var client = new Mock<CodeTransparencyClient>().Object;
        var provider = new MstTransparencyProvider(client);

        var result = builder.Object.ValidateMst(b => b.VerifyReceipt(provider));

        Assert.That(result, Is.SameAs(builder.Object));
    }

    [Test]
    public void ValidateMst_WithRequireReceiptPresence_AddsValidator()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        builder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(builder.Object);

        var result = builder.Object.ValidateMst(b => b.RequireReceiptPresence());

        Assert.That(result, Is.SameAs(builder.Object));
    }

    [Test]
    public void ValidateMst_WithVerifyReceiptOnline_AddsValidator()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        builder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(builder.Object);
        var client = new Mock<CodeTransparencyClient>().Object;

        var result = builder.Object.ValidateMst(b => b.VerifyReceiptOnline(client, "example.com"));

        Assert.That(result, Is.SameAs(builder.Object));
    }

    [Test]
    public void ValidateMst_WithNoValidatorsConfigured_ThrowsInvalidOperationException()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Object.ValidateMst(_ => { }));
        Assert.That(ex!.Message, Is.EqualTo("No MST validators configured"));
    }

    [Test]
    public void ValidateMst_WithNullBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => MstValidationExtensions.ValidateMst(null!, _ => { }));
    }

    [Test]
    public void ValidateMst_WithNullConfigure_ThrowsArgumentNullException()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        Assert.Throws<ArgumentNullException>(() => builder.Object.ValidateMst(null!));
    }

    [Test]
    public void ValidateMst_VerifyReceiptWithNullClient_ThrowsArgumentNullException()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        Assert.Throws<ArgumentNullException>(() => builder.Object.ValidateMst(b => b.VerifyReceipt((CodeTransparencyClient)null!)));
    }

    [Test]
    public void ValidateMst_VerifyReceiptWithNullProvider_ThrowsArgumentNullException()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        Assert.Throws<ArgumentNullException>(() => builder.Object.ValidateMst(b => b.VerifyReceipt((MstTransparencyProvider)null!)));
    }

    [Test]
    public void ValidateMst_VerifyReceiptOnlineWithNullClient_ThrowsArgumentNullException()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        Assert.Throws<ArgumentNullException>(() => builder.Object.ValidateMst(b => b.VerifyReceiptOnline(null!, "example.com")));
    }

    [Test]
    public void ValidateMst_VerifyReceiptOnlineWithNullIssuerHost_ThrowsArgumentNullException()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        var client = new Mock<CodeTransparencyClient>().Object;
        Assert.Throws<ArgumentNullException>(() => builder.Object.ValidateMst(b => b.VerifyReceiptOnline(client, null!)));
    }

    [Test]
    public void ValidateMst_VerifyReceiptOnlineWithEmptyIssuerHost_ThrowsArgumentNullException()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        var client = new Mock<CodeTransparencyClient>().Object;
        Assert.Throws<ArgumentNullException>(() => builder.Object.ValidateMst(b => b.VerifyReceiptOnline(client, "")));
    }

    #region Legacy API Tests

#pragma warning disable CS0618 // Type or member is obsolete - testing legacy API
    [Test]
    public void AddMstValidator_WithVerifyReceiptClient_AddsValidator()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();
        builder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(builder.Object);
        var client = new Mock<CodeTransparencyClient>().Object;

        var result = builder.Object.AddMstValidator(b => b.VerifyReceipt(client));

        Assert.That(result, Is.SameAs(builder.Object));
    }

    [Test]
    public void AddMstValidator_WithNullBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => MstValidationExtensions.AddMstValidator(null!, _ => { }));
    }
#pragma warning restore CS0618

    #endregion
}
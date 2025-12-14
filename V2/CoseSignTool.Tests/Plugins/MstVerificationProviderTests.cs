// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;
using CoseSignTool.MST.Plugin;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the MstVerificationProvider class.
/// </summary>
[TestFixture]
public class MstVerificationProviderTests
{
    private MstVerificationProvider Provider = null!;
    private Command Command = null!;
    private Parser Parser = null!;

    [SetUp]
    public void Setup()
    {
        Provider = new MstVerificationProvider();
        Command = new Command("verify", "Test verify command");
        Provider.AddVerificationOptions(Command);
        Parser = new Parser(Command);
    }

    [Test]
    public void ProviderName_ReturnsMST()
    {
        // Assert
        Assert.That(Provider.ProviderName, Is.EqualTo("MST"));
    }

    [Test]
    public void Description_ReturnsExpectedDescription()
    {
        // Assert
        Assert.That(Provider.Description, Does.Contain("Microsoft Signing Transparency"));
    }

    [Test]
    public void Priority_Returns100()
    {
        // Assert - MST should run after signature and chain validation
        Assert.That(Provider.Priority, Is.EqualTo(100));
    }

    [Test]
    public void AddVerificationOptions_AddsAllRequiredOptions()
    {
        // Assert
        Assert.That(Command.Options.Any(o => o.Name == "require-receipt"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "mst-endpoint"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "verify-receipt"), Is.True);
    }

    [Test]
    public void IsActivated_WithDefaultOptions_ReturnsFalse()
    {
        // Arrange - no MST options specified
        var parseResult = Parser.Parse("");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.False, "MST provider should not be activated by default");
    }

    [Test]
    public void IsActivated_WithRequireReceipt_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--require-receipt");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "provider should activate when receipt is required");
    }

    [Test]
    public void IsActivated_WithMstEndpoint_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--mst-endpoint https://example.com");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "provider should activate when endpoint is provided");
    }

    [Test]
    public void CreateValidators_WithNoOptions_ReturnsEmpty()
    {
        // Arrange
        var parseResult = Parser.Parse("");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Is.Empty, "no validators when no MST options specified");
    }

    [Test]
    public void CreateValidators_WithRequireReceipt_IncludesPresenceValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--require-receipt");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.TypeOf<MstReceiptPresenceValidator>());
    }

    [Test]
    public void CreateValidators_WithEndpoint_IncludesReceiptValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--mst-endpoint https://example.codetransparency.azure.net");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.TypeOf<CoseSign1.Transparent.MST.Validation.MstReceiptValidator>());
    }

    [Test]
    public void CreateValidators_WithEndpointAndNoVerify_ReturnsEmpty()
    {
        // Arrange - endpoint but verify-receipt set to false
        var parseResult = Parser.Parse("--mst-endpoint https://example.com --verify-receipt false");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Is.Empty, "no receipt validator when verify-receipt is false");
    }

    [Test]
    public void CreateValidators_WithBothOptions_IncludesBothValidators()
    {
        // Arrange
        var parseResult = Parser.Parse("--require-receipt --mst-endpoint https://example.codetransparency.azure.net");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators.Any(v => v is MstReceiptPresenceValidator), Is.True);
        Assert.That(validators.Any(v => v.GetType().Name == "MstReceiptValidator"), Is.True);
    }

    [Test]
    public void GetVerificationMetadata_WithNoOptions_ShowsNotRequired()
    {
        // Arrange
        var parseResult = Parser.Parse("");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Receipt Required"));
        Assert.That(metadata["Receipt Required"], Is.EqualTo("No"));
    }

    [Test]
    public void GetVerificationMetadata_WithRequireReceipt_ShowsRequired()
    {
        // Arrange
        var parseResult = Parser.Parse("--require-receipt");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Receipt Required"));
        Assert.That(metadata["Receipt Required"], Is.EqualTo("Yes"));
    }

    [Test]
    public void GetVerificationMetadata_WithEndpoint_IncludesEndpointInfo()
    {
        // Arrange
        var parseResult = Parser.Parse("--mst-endpoint https://myservice.codetransparency.azure.net");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("MST Endpoint"));
        Assert.That(metadata["MST Endpoint"], Is.EqualTo("https://myservice.codetransparency.azure.net"));
        Assert.That(metadata, Does.ContainKey("Verify Receipt"));
        Assert.That(metadata["Verify Receipt"], Is.EqualTo("Yes"));
    }

    [Test]
    public void GetVerificationMetadata_WithEndpointNoVerify_ShowsNoVerify()
    {
        // Arrange
        var parseResult = Parser.Parse("--mst-endpoint https://example.com --verify-receipt false");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Verify Receipt"));
        Assert.That(metadata["Verify Receipt"], Is.EqualTo("No"));
    }
}
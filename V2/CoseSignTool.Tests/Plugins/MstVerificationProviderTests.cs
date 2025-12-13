// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using CoseSign1.Validation;
using CoseSignTool.MST.Plugin;
using CoseSignTool.Plugins;

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
        Provider.ProviderName.Should().Be("MST");
    }

    [Test]
    public void Description_ReturnsExpectedDescription()
    {
        // Assert
        Provider.Description.Should().Contain("Microsoft Signing Transparency");
    }

    [Test]
    public void Priority_Returns100()
    {
        // Assert - MST should run after signature and chain validation
        Provider.Priority.Should().Be(100);
    }

    [Test]
    public void AddVerificationOptions_AddsAllRequiredOptions()
    {
        // Assert
        Command.Options.Any(o => o.Name == "require-receipt").Should().BeTrue();
        Command.Options.Any(o => o.Name == "mst-endpoint").Should().BeTrue();
        Command.Options.Any(o => o.Name == "verify-receipt").Should().BeTrue();
    }

    [Test]
    public void IsActivated_WithDefaultOptions_ReturnsFalse()
    {
        // Arrange - no MST options specified
        var parseResult = Parser.Parse("");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        isActivated.Should().BeFalse("MST provider should not be activated by default");
    }

    [Test]
    public void IsActivated_WithRequireReceipt_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--require-receipt");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        isActivated.Should().BeTrue("provider should activate when receipt is required");
    }

    [Test]
    public void IsActivated_WithMstEndpoint_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--mst-endpoint https://example.com");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        isActivated.Should().BeTrue("provider should activate when endpoint is provided");
    }

    [Test]
    public void CreateValidators_WithNoOptions_ReturnsEmpty()
    {
        // Arrange
        var parseResult = Parser.Parse("");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().BeEmpty("no validators when no MST options specified");
    }

    [Test]
    public void CreateValidators_WithRequireReceipt_IncludesPresenceValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--require-receipt");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().HaveCount(1);
        validators[0].Should().BeOfType<MstReceiptPresenceValidator>();
    }

    [Test]
    public void CreateValidators_WithEndpoint_IncludesReceiptValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--mst-endpoint https://example.codetransparency.azure.net");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().HaveCount(1);
        validators[0].Should().BeOfType<CoseSign1.Transparent.MST.Validation.MstReceiptValidator>();
    }

    [Test]
    public void CreateValidators_WithEndpointAndNoVerify_ReturnsEmpty()
    {
        // Arrange - endpoint but verify-receipt set to false
        var parseResult = Parser.Parse("--mst-endpoint https://example.com --verify-receipt false");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().BeEmpty("no receipt validator when verify-receipt is false");
    }

    [Test]
    public void CreateValidators_WithBothOptions_IncludesBothValidators()
    {
        // Arrange
        var parseResult = Parser.Parse("--require-receipt --mst-endpoint https://example.codetransparency.azure.net");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().HaveCount(2);
        validators.Any(v => v is MstReceiptPresenceValidator).Should().BeTrue();
        validators.Any(v => v.GetType().Name == "MstReceiptValidator").Should().BeTrue();
    }

    [Test]
    public void GetVerificationMetadata_WithNoOptions_ShowsNotRequired()
    {
        // Arrange
        var parseResult = Parser.Parse("");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Receipt Required");
        metadata["Receipt Required"].Should().Be("No");
    }

    [Test]
    public void GetVerificationMetadata_WithRequireReceipt_ShowsRequired()
    {
        // Arrange
        var parseResult = Parser.Parse("--require-receipt");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Receipt Required");
        metadata["Receipt Required"].Should().Be("Yes");
    }

    [Test]
    public void GetVerificationMetadata_WithEndpoint_IncludesEndpointInfo()
    {
        // Arrange
        var parseResult = Parser.Parse("--mst-endpoint https://myservice.codetransparency.azure.net");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("MST Endpoint");
        metadata["MST Endpoint"].Should().Be("https://myservice.codetransparency.azure.net");
        metadata.Should().ContainKey("Verify Receipt");
        metadata["Verify Receipt"].Should().Be("Yes");
    }

    [Test]
    public void GetVerificationMetadata_WithEndpointNoVerify_ShowsNoVerify()
    {
        // Arrange
        var parseResult = Parser.Parse("--mst-endpoint https://example.com --verify-receipt false");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Verify Receipt");
        metadata["Verify Receipt"].Should().Be("No");
    }
}

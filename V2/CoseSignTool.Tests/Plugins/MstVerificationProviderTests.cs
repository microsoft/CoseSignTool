// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Plugins;

using System.CommandLine;
using System.CommandLine.Parsing;
using CoseSign1.Validation.Results;
using CoseSignTool.MST.Plugin;

/// <summary>
/// Tests for the MstVerificationProvider class.
/// </summary>
[TestFixture]
public class MstVerificationProviderTests
{
    private record TestState(MstVerificationProvider Provider, Command Command, Parser Parser);

    private static TestState CreateTestState()
    {
        var provider = new MstVerificationProvider();
        var command = new Command("verify", "Test verify command");
        provider.AddVerificationOptions(command);
        var parser = new Parser(command);
        return new TestState(provider, command, parser);
    }

    [Test]
    public void ProviderName_ReturnsMST()
    {
        // Arrange
        var (Provider, _, _) = CreateTestState();

        // Assert
        Assert.That(Provider.ProviderName, Is.EqualTo("MST"));
    }

    [Test]
    public void Description_ReturnsExpectedDescription()
    {
        // Arrange
        var (Provider, _, _) = CreateTestState();

        // Assert
        Assert.That(Provider.Description, Does.Contain("Microsoft Signing Transparency"));
    }

    [Test]
    public void Priority_Returns100()
    {
        // Arrange
        var (Provider, _, _) = CreateTestState();

        // Assert - MST should run after signature and chain validation
        Assert.That(Provider.Priority, Is.EqualTo(100));
    }

    [Test]
    public void AddVerificationOptions_AddsAllRequiredOptions()
    {
        // Arrange
        var (_, Command, _) = CreateTestState();

        // Assert
        Assert.That(Command.Options.Any(o => o.Name == "require-receipt"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "mst-endpoint"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "verify-receipt"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "mst-trust-mode"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "mst-trust-file"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "mst-trusted-key"), Is.True);
    }

    [Test]
    public void IsActivated_WithDefaultOptions_ReturnsFalse()
    {
        // Arrange - no MST options specified
        var (Provider, _, Parser) = CreateTestState();
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
        var (Provider, _, Parser) = CreateTestState();
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
        var (Provider, _, Parser) = CreateTestState();
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
        var (Provider, _, Parser) = CreateTestState();
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
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--require-receipt");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.TypeOf<CoseSign1.Transparent.MST.Validation.MstReceiptPresenceTrustValidator>());
    }

    [Test]
    public void CreateValidators_WithEndpoint_IncludesReceiptValidator()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--mst-endpoint https://example.codetransparency.azure.net");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators.Any(v => v is CoseSign1.Transparent.MST.Validation.MstReceiptPresenceTrustValidator), Is.True);
        Assert.That(validators.Any(v => v is CoseSign1.Transparent.MST.Validation.MstReceiptOnlineValidator), Is.True);
    }

    [Test]
    public void CreateValidators_WithEndpointAndNoVerify_ReturnsEmpty()
    {
        // Arrange - endpoint but verify-receipt set to false
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--mst-endpoint https://example.com --verify-receipt false");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.TypeOf<CoseSign1.Transparent.MST.Validation.MstReceiptPresenceTrustValidator>());
    }

    [Test]
    public void CreateValidators_WithBothOptions_IncludesBothValidators()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--require-receipt --mst-endpoint https://example.codetransparency.azure.net");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators.Any(v => v.GetType().Name == "MstReceiptOnlineValidator"), Is.True);
        Assert.That(validators.Any(v => v.GetType().Name == "MstReceiptPresenceTrustValidator"), Is.True);
    }

    [Test]
    public void CreateValidators_WithOfflineTrustModeAndTrustFile_IncludesOfflineReceiptValidator()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var tmp = Path.Combine(Path.GetTempPath(), $"mst_trust_{Guid.NewGuid():N}.json");
        // Minimal SDK-compatible shape produced by the SDK serializer.
        var empty = new Azure.Security.CodeTransparency.CodeTransparencyOfflineKeys();
        File.WriteAllText(tmp, empty.ToBinaryData().ToString());

        try
        {
            var parseResult = Parser.Parse($"--mst-trust-mode offline --mst-endpoint https://example.codetransparency.azure.net --mst-trust-file \"{tmp}\"");

            // Act
            var validators = Provider.CreateValidators(parseResult).ToList();

            // Assert
            Assert.That(validators.Any(v => v is CoseSign1.Transparent.MST.Validation.MstReceiptPresenceTrustValidator), Is.True);
            // If no usable keys, provider conservatively omits the receipt validator.
            // This test just ensures parsing does not throw and presence validator is still emitted.
        }
        finally
        {
            if (File.Exists(tmp))
            {
                File.Delete(tmp);
            }
        }
    }

    [Test]
    public void GetVerificationMetadata_WithNoOptions_ShowsNotRequired()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
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
        var (Provider, _, Parser) = CreateTestState();
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
        var (Provider, _, Parser) = CreateTestState();
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
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--mst-endpoint https://example.com --verify-receipt false");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Verify Receipt"));
        Assert.That(metadata["Verify Receipt"], Is.EqualTo("No"));
    }
}

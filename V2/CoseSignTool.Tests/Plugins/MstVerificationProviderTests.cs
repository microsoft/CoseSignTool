// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Plugins;

using System.CommandLine;
using System.CommandLine.Parsing;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust;
using CoseSignTool.Abstractions;
using CoseSignTool.MST.Plugin;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Tests for the MstVerificationProvider class.
/// </summary>
[TestFixture]
public class MstVerificationProviderTests
{
    private record TestState(MstVerificationProvider Provider, Command Command, Parser Parser);

    private static ServiceProvider BuildServiceProvider(MstVerificationProvider provider, ParseResult parseResult)
    {
        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();
        provider.ConfigureValidation(builder, parseResult, new VerificationContext(detachedPayload: null));
        return services.BuildServiceProvider();
    }

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
    public void ConfigureValidation_WithNoOptions_RegistersMstTrustPack()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("");

        using var sp = BuildServiceProvider(Provider, parseResult);
        Assert.That(sp.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Not.Empty);
    }

    [Test]
    public void ConfigureValidation_WithRequireReceipt_RegistersMstTrustPack()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--require-receipt");

        using var sp = BuildServiceProvider(Provider, parseResult);
        Assert.That(sp.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Not.Empty);

        // Trust requirements are expressed via TrustPlanPolicy.
        var ctx = new VerificationContext(detachedPayload: null);
        Assert.That(Provider.CreateTrustPlanPolicy(parseResult, ctx), Is.Not.Null);
    }

    [Test]
    public void ConfigureValidation_WithEndpoint_RegistersMstTrustPack()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--mst-endpoint https://example.codetransparency.azure.net");

        using var sp = BuildServiceProvider(Provider, parseResult);
        Assert.That(sp.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Not.Empty);

        var ctx = new VerificationContext(detachedPayload: null);
        Assert.That(Provider.CreateTrustPlanPolicy(parseResult, ctx), Is.Not.Null);
    }

    [Test]
    public void ConfigureValidation_WithEndpointAndNoVerify_RegistersMstTrustPack()
    {
        // Arrange - endpoint but verify-receipt set to false
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--mst-endpoint https://example.com --verify-receipt false");

        using var sp = BuildServiceProvider(Provider, parseResult);
        Assert.That(sp.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Not.Empty);

        // When verification is disabled, the provider does not require receipt trust.
        var ctx = new VerificationContext(detachedPayload: null);
        Assert.That(Provider.CreateTrustPlanPolicy(parseResult, ctx), Is.Not.Null);
    }

    [Test]
    public void ConfigureValidation_WithBothOptions_RegistersMstTrustPack()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("--require-receipt --mst-endpoint https://example.codetransparency.azure.net");

        using var sp = BuildServiceProvider(Provider, parseResult);
        Assert.That(sp.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Not.Empty);

        var ctx = new VerificationContext(detachedPayload: null);
        Assert.That(Provider.CreateTrustPlanPolicy(parseResult, ctx), Is.Not.Null);
    }

    [Test]
    public void ConfigureValidation_WithOfflineTrustModeAndTrustFile_RegistersReceiptFacts()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var tmp = Path.Combine(Path.GetTempPath(), $"mst_trust_{Guid.NewGuid():N}.json");
        // The CLI only needs a JSON object to consider the trust file present/parseable.
        // Keep this test independent of Azure SDK surface area.
        File.WriteAllText(tmp, "{}");

        try
        {
            var parseResult = Parser.Parse($"--mst-trust-mode offline --mst-endpoint https://example.codetransparency.azure.net --mst-trust-file \"{tmp}\"");

            using var sp = BuildServiceProvider(Provider, parseResult);
            var trustPack = sp.GetServices<ITrustPack>().OfType<MstTrustPack>().Single();
            Assert.That(trustPack.FactTypes, Does.Contain(typeof(MstReceiptPresentFact)));
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

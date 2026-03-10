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
    private record TestState(MstVerificationProvider Provider, Command MstCommand, Parser Parser);

    private static ServiceProvider BuildServiceProvider(MstVerificationProvider provider, ParseResult parseResult)
    {
        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();

        // Simulate CLI behavior: only configure activated providers.
        if (provider.IsActivated(parseResult))
        {
            provider.ConfigureValidation(builder, parseResult, new VerificationContext(detachedPayload: null));
        }
        return services.BuildServiceProvider();
    }

    private static TestState CreateTestState()
    {
        var provider = new MstVerificationProvider();

        var root = new RootCommand();
        var verify = new Command("verify", "Test verify command");
        var mst = new Command("mst", "Test MST root command");
        provider.AddVerificationOptions(mst);

        verify.AddCommand(mst);
        root.AddCommand(verify);

        var parser = new Parser(root);
        return new TestState(provider, mst, parser);
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
        var (_, mstCommand, _) = CreateTestState();

        // Assert
        Assert.That(mstCommand.Options.Any(o => o.Name == "mst-offline-keys"), Is.True);
        Assert.That(mstCommand.Options.Any(o => o.Name == "mst-trust-ledger-instance"), Is.True);
    }

    [Test]
    public void IsActivated_WithDefaultOptions_ReturnsFalse()
    {
        // Arrange - no MST options specified
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("verify");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.False, "MST provider should not be activated by default");
    }

    [Test]
    public void IsActivated_WithMstTrust_ReturnsTrue()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("verify mst --mst-trust-ledger-instance example.confidential-ledger.azure.com");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "provider should activate when receipt is required");
    }

    [Test]
    public void ConfigureValidation_WithNoOptions_DoesNotRegisterMstTrustPack()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("verify");

        using var sp = BuildServiceProvider(Provider, parseResult);
        Assert.That(sp.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Empty);
    }

    [Test]
    public void ConfigureValidation_WithMstTrustAndLedgerAllowList_RegistersMstTrustPackAndPolicy()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("verify mst --mst-trust-ledger-instance example.confidential-ledger.azure.com");

        using var sp = BuildServiceProvider(Provider, parseResult);
        Assert.That(sp.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Not.Empty);

        // Trust requirements are expressed via TrustPlanPolicy.
        var ctx = new VerificationContext(detachedPayload: null);
        Assert.That(Provider.CreateTrustPlanPolicy(parseResult, ctx), Is.Not.Null);
    }

    [Test]
    public void CreateTrustPlanPolicy_WithMstTrustButNoAllowListOrOfflineKeys_ThrowsArgumentException()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("verify mst");

        var ctx = new VerificationContext(detachedPayload: null);
        Assert.Throws<ArgumentException>(() => Provider.CreateTrustPlanPolicy(parseResult, ctx));
    }

    [Test]
    public void ConfigureValidation_WithMstTrustAndOfflineKeys_RegistersReceiptFacts()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var tmp = Path.Combine(Path.GetTempPath(), $"mst_offline_{Guid.NewGuid():N}.jwks.json");
        File.WriteAllText(tmp, "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}");

        try
        {
            var parseResult = Parser.Parse($"verify mst --mst-offline-keys \"{tmp}\"");

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
    public void GetVerificationMetadata_WithNoOptions_ShowsNotEnabled()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("verify");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("MST Trust"));
        Assert.That(metadata["MST Trust"], Is.EqualTo("No"));
    }

    [Test]
    public void GetVerificationMetadata_WithMstTrust_ShowsEnabled()
    {
        // Arrange
        var (Provider, _, Parser) = CreateTestState();
        var parseResult = Parser.Parse("verify mst --mst-trust-ledger-instance example.confidential-ledger.azure.com");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("MST Trust"));
        Assert.That(metadata["MST Trust"], Is.EqualTo("Yes"));
    }
}

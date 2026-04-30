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
/// Tests for the <see cref="MstVerificationProvider"/> class.
/// </summary>
[TestFixture]
public class MstVerificationProviderTests
{
    private record TestState(MstVerificationProvider Provider, Command ScittCommand, Parser Parser);

    private static ServiceProvider BuildServiceProvider(MstVerificationProvider provider, ParseResult parseResult)
    {
        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();

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
        var scitt = new Command("scitt", "Test SCITT root command");
        provider.AddVerificationOptions(scitt);

        verify.AddCommand(scitt);
        root.AddCommand(verify);

        var parser = new Parser(root);
        return new TestState(provider, scitt, parser);
    }

    [Test]
    public void ProviderName_ReturnsScitt()
    {
        var (provider, _, _) = CreateTestState();

        Assert.That(provider.ProviderName, Is.EqualTo("SCITT"));
    }

    [Test]
    public void Description_ReturnsExpectedDescription()
    {
        var (provider, _, _) = CreateTestState();

        Assert.That(provider.Description, Does.Contain("SCITT"));
    }

    [Test]
    public void Priority_Returns100()
    {
        var (provider, _, _) = CreateTestState();

        Assert.That(provider.Priority, Is.EqualTo(100));
    }

    [Test]
    public void AddVerificationOptions_AddsAllRequiredOptions()
    {
        var (_, scittCommand, _) = CreateTestState();

        Assert.That(scittCommand.Options.Any(o => o.Name == "issuer"), Is.True);
        Assert.That(scittCommand.Options.Any(o => o.Name == "issuer-offline-keys"), Is.True);
    }

    [Test]
    public void IsActivated_WithDefaultOptions_ReturnsFalse()
    {
        var (provider, _, parser) = CreateTestState();
        var parseResult = parser.Parse("verify");

        Assert.That(provider.IsActivated(parseResult), Is.False);
    }

    [Test]
    public void IsActivated_WithScittTrust_ReturnsTrue()
    {
        var (provider, _, parser) = CreateTestState();
        var parseResult = parser.Parse("verify scitt --issuer https://example.confidential-ledger.azure.com");

        Assert.That(provider.IsActivated(parseResult), Is.True);
    }

    [Test]
    public void ConfigureValidation_WithNoOptions_DoesNotRegisterMstTrustPack()
    {
        var (provider, _, parser) = CreateTestState();
        var parseResult = parser.Parse("verify");

        using var serviceProvider = BuildServiceProvider(provider, parseResult);
        Assert.That(serviceProvider.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Empty);
    }

    [Test]
    public void ConfigureValidation_WithIssuer_RegistersMstTrustPackAndPolicy()
    {
        var (provider, _, parser) = CreateTestState();
        var parseResult = parser.Parse("verify scitt --issuer https://example.confidential-ledger.azure.com");

        using var serviceProvider = BuildServiceProvider(provider, parseResult);
        Assert.That(serviceProvider.GetServices<ITrustPack>().OfType<MstTrustPack>(), Is.Not.Empty);

        var context = new VerificationContext(detachedPayload: null);
        Assert.That(provider.CreateTrustPlanPolicy(parseResult, context), Is.Not.Null);
    }

    [Test]
    public void CreateTrustPlanPolicy_WithScittTrustButNoIssuerConfiguration_ThrowsArgumentException()
    {
        var (provider, _, parser) = CreateTestState();
        var parseResult = parser.Parse("verify scitt");

        var context = new VerificationContext(detachedPayload: null);
        Assert.Throws<ArgumentException>(() => provider.CreateTrustPlanPolicy(parseResult, context));
    }

    [Test]
    public void ConfigureValidation_WithIssuerOfflineKeys_RegistersReceiptFacts()
    {
        var (provider, _, parser) = CreateTestState();
        var tmp = Path.Combine(Path.GetTempPath(), $"scitt_offline_{Guid.NewGuid():N}.jwks.json");
        File.WriteAllText(tmp, "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}");

        try
        {
            var parseResult = parser.Parse($"verify scitt --issuer-offline-keys \"https://example.confidential-ledger.azure.com={tmp}\"");

            using var serviceProvider = BuildServiceProvider(provider, parseResult);
            var trustPack = serviceProvider.GetServices<ITrustPack>().OfType<MstTrustPack>().Single();
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
        var (provider, _, parser) = CreateTestState();
        var parseResult = parser.Parse("verify");

        var metadata = provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        Assert.That(metadata, Does.ContainKey("SCITT Trust"));
        Assert.That(metadata["SCITT Trust"], Is.EqualTo("No"));
    }

    [Test]
    public void GetVerificationMetadata_WithScittTrust_ShowsEnabled()
    {
        var (provider, _, parser) = CreateTestState();
        var parseResult = parser.Parse("verify scitt --issuer https://example.confidential-ledger.azure.com");

        var metadata = provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        Assert.That(metadata, Does.ContainKey("SCITT Trust"));
        Assert.That(metadata["SCITT Trust"], Is.EqualTo("Yes"));
        Assert.That(metadata["SCITT Trusted Issuers"], Is.EqualTo("example.confidential-ledger.azure.com"));
    }
}

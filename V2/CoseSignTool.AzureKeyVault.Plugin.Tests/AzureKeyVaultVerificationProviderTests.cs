// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Subjects;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Tests for <see cref="AzureKeyVaultVerificationProvider"/>.
/// </summary>
[TestFixture]
public class AzureKeyVaultVerificationProviderTests
{
    private static readonly CoseHeaderLabel KidLabel = new(4);

    private static ServiceProvider BuildServiceProvider(
        AzureKeyVaultVerificationProvider provider,
        ParseResult parseResult,
        VerificationContext? context = null)
    {
        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();
        provider.ConfigureValidation(builder, parseResult, context ?? new VerificationContext(detachedPayload: null));
        return services.BuildServiceProvider();
    }

    private static CoseSign1Message CreateMessageWithKid(string kid)
    {
        using RSA rsa = RSA.Create(2048);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(KidLabel, Encoding.UTF8.GetBytes(kid));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pkcs1, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders: null);
        byte[] coseBytes = CoseSign1Message.SignEmbedded(Encoding.UTF8.GetBytes("payload"), signer);
        return CoseMessage.DecodeSign1(coseBytes);
    }

    private static TrustFactContext CreateMessageContext(CoseSign1Message message)
    {
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject subject = TrustSubject.Message(messageId);
        return new TrustFactContext(messageId, subject, new TrustEvaluationOptions(), memoryCache: null, message: message);
    }

    [Test]
    public void Properties_ReturnExpectedValues()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();

        // Act & Assert
        Assert.That(provider.ProviderName, Is.EqualTo("AzureKeyVault"));
        Assert.That(provider.Description, Is.Not.Null.And.Not.Empty);
        Assert.That(provider.Priority, Is.EqualTo(20));
    }

    [Test]
    public void AddVerificationOptions_AddsExpectedOptions()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var verifyCommand = new Command("verify");

        // Act
        provider.AddVerificationOptions(verifyCommand);

        // Assert
        Assert.That(verifyCommand.Options.Select(o => o.Name), Does.Contain("require-az-key"));
        Assert.That(verifyCommand.Options.Select(o => o.Name), Does.Contain("allowed-vaults"));
    }

    [Test]
    public void IsActivated_WhenNoOptionsConfigured_ReturnsFalse()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var root = new RootCommand();
        var verify = new Command("verify");
        root.AddCommand(verify);

        ParseResult parseResult = root.Parse("verify");

        // Act
        bool activated = provider.IsActivated(parseResult);

        // Assert
        Assert.That(activated, Is.False);
    }

    [Test]
    public void IsActivated_WhenOptionsRegisteredButNotProvided_ReturnsFalse()
    {
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify");

        bool activated = provider.IsActivated(parseResult);

        Assert.That(activated, Is.False);
    }

    [Test]
    public void IsActivated_WithRequireAzKey_ReturnsTrue()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --require-az-key");

        // Act
        bool activated = provider.IsActivated(parseResult);

        // Assert
        Assert.That(activated, Is.True);
    }

    [Test]
    public void IsActivated_WithAllowedVaults_ReturnsTrue()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --allowed-vaults https://example.vault.azure.net/");

        // Act
        bool activated = provider.IsActivated(parseResult);

        // Assert
        Assert.That(activated, Is.True);
    }

    [Test]
    public void IsActivated_WithAllowedVaultsButNoValues_ReturnsFalse()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --allowed-vaults");

        // Act
        bool activated = provider.IsActivated(parseResult);

        // Assert
        Assert.That(activated, Is.False);
    }

    [Test]
    public void ConfigureValidation_WithRequireAzKeyOnly_RegistersResolver()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --require-az-key");

        using var sp = BuildServiceProvider(provider, parseResult);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();
        Assert.That(resolvers.OfType<AzureKeyVaultCoseKeySigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    public void ConfigureValidation_WithAllowedVaults_RegistersResolver()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --require-az-key --allowed-vaults https://example.vault.azure.net/");

        using var sp = BuildServiceProvider(provider, parseResult);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();
        Assert.That(resolvers.OfType<AzureKeyVaultCoseKeySigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    public void ConfigureValidation_WithContext_WithAllowedVaults_RegistersResolver()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --allowed-vaults https://example.vault.azure.net/");
        var context = new VerificationContext(detachedPayload: null);

        using var sp = BuildServiceProvider(provider, parseResult, context);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();
        Assert.That(resolvers.OfType<AzureKeyVaultCoseKeySigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    public void GetVerificationMetadata_WhenNoAllowedVaults_ReturnsNone()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify");

        // Act
        var metadata = provider.GetVerificationMetadata(parseResult, message: null!, validationResult: null!);

        // Assert
        Assert.That(metadata, Does.ContainKey("AKV Validation"));
        Assert.That(metadata["AKV Validation"], Is.EqualTo("Enabled"));
        Assert.That(metadata["Require AKV Key"], Is.EqualTo("No"));
        Assert.That(metadata["Allowed Vault Patterns"], Is.EqualTo("None"));
    }

    [Test]
    public void GetVerificationMetadata_WhenAllowedVaultsProvided_JoinsValues()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse(
            "verify --require-az-key --allowed-vaults https://a.vault.azure.net/ https://b.vault.azure.net/");

        // Act
        var metadata = provider.GetVerificationMetadata(parseResult, message: null!, validationResult: null!);

        // Assert
        Assert.That(metadata["Require AKV Key"], Is.EqualTo("Yes"));
        Assert.That(metadata["Allowed Vault Patterns"], Is.EqualTo("https://a.vault.azure.net/, https://b.vault.azure.net/"));
    }

    [Test]
    public async Task CreateTrustPlanPolicy_WithAllowedVaults_UsesAllowedFactPath()
    {
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --allowed-vaults https://myvault.vault.azure.net/keys/*");
        var context = new VerificationContext(detachedPayload: null);

        var policy = provider.CreateTrustPlanPolicy(parseResult, context);
        Assert.That(policy, Is.Not.Null);

        using var sp = BuildServiceProvider(provider, parseResult, context);
        var trustPack = sp.GetServices<ITrustPack>().OfType<AzureKeyVaultTrustPack>().Single();

        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey/123");
        var factContext = CreateMessageContext(message);

        var allowedSet = await trustPack.ProduceAsync(factContext, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);
        var typed = (ITrustFactSet<AzureKeyVaultKidAllowedFact>)allowedSet;
        Assert.That(typed.Values[0].IsAllowed, Is.True);
    }

    [Test]
    public async Task CreateTrustPlanPolicy_WithRequireAzKey_UsesDetectedFactPath()
    {
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --require-az-key");
        var context = new VerificationContext(detachedPayload: null);

        var policy = provider.CreateTrustPlanPolicy(parseResult, context);
        Assert.That(policy, Is.Not.Null);

        using var sp = BuildServiceProvider(provider, parseResult, context);
        var trustPack = sp.GetServices<ITrustPack>().OfType<AzureKeyVaultTrustPack>().Single();

        var message = CreateMessageWithKid("https://example.com/keys/mykey/123");
        var factContext = CreateMessageContext(message);

        var detectedSet = await trustPack.ProduceAsync(factContext, typeof(AzureKeyVaultKidDetectedFact), CancellationToken.None);
        var typed = (ITrustFactSet<AzureKeyVaultKidDetectedFact>)detectedSet;
        Assert.That(typed.Values[0].IsAzureKeyVaultKey, Is.False);
    }

    [Test]
    public void CreateTrustPlanPolicy_WithNoOptions_ReturnsNoOpPolicy()
    {
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify");
        var context = new VerificationContext(detachedPayload: null);

        var policy = provider.CreateTrustPlanPolicy(parseResult, context);

        Assert.That(policy, Is.Not.Null);
    }

    private static (RootCommand root, Command verify) CreateVerifyCommand()
    {
        var root = new RootCommand();
        var verify = new Command("verify");
        root.AddCommand(verify);
        return (root, verify);
    }
}

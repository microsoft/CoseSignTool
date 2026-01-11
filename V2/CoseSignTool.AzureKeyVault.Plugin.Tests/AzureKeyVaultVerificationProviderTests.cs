// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

using System.CommandLine.Parsing;

/// <summary>
/// Tests for <see cref="AzureKeyVaultVerificationProvider"/>.
/// </summary>
[TestFixture]
public class AzureKeyVaultVerificationProviderTests
{
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
    public void CreateValidators_WithRequireAzKeyOnly_ReturnsResolverAndAssertionProvider()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --require-az-key");

        // Act
        var validators = provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators[0].GetType().Name, Is.EqualTo("AzureKeyVaultCoseKeySigningKeyResolver"));
        Assert.That(validators[1].GetType().Name, Is.EqualTo("AzureKeyVaultAssertionProvider"));
    }

    [Test]
    public void CreateValidators_WithAllowedVaults_ReturnsResolverAndAssertionProvider()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --require-az-key --allowed-vaults https://example.vault.azure.net/");

        // Act
        var validators = provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators[0].GetType().Name, Is.EqualTo("AzureKeyVaultCoseKeySigningKeyResolver"));
        Assert.That(validators[1].GetType().Name, Is.EqualTo("AzureKeyVaultAssertionProvider"));
    }

    [Test]
    public void CreateValidators_WithContext_WithAllowedVaults_ReturnsResolverAndAssertionProvider()
    {
        // Arrange
        var provider = new AzureKeyVaultVerificationProvider();
        var (root, verify) = CreateVerifyCommand();
        provider.AddVerificationOptions(verify);

        ParseResult parseResult = root.Parse("verify --allowed-vaults https://example.vault.azure.net/");
        var context = new VerificationContext(detachedPayload: null);

        // Act
        var validators = provider.CreateValidators(parseResult, context).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators[0].GetType().Name, Is.EqualTo("AzureKeyVaultCoseKeySigningKeyResolver"));
        Assert.That(validators[1].GetType().Name, Is.EqualTo("AzureKeyVaultAssertionProvider"));
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

    private static (RootCommand root, Command verify) CreateVerifyCommand()
    {
        var root = new RootCommand();
        var verify = new Command("verify");
        root.AddCommand(verify);
        return (root, verify);
    }
}

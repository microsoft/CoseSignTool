// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

/// <summary>
/// Tests for <see cref="AzureKeyVaultKeyCommandProvider"/>.
/// </summary>
[TestFixture]
public class AzureKeyVaultKeyCommandProviderTests
{
    private const string TestKeyName = "test-key";
    private const string TestKeyVersion = "v1";
    private static readonly Uri TestVaultUri = new("https://test-vault.vault.azure.net");

    [Test]
    public void CommandName_ReturnsSignAkvKey()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("sign-akv-key"));
    }

    [Test]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToLowerInvariant(), Does.Contain("key"));
        Assert.That(description.ToLowerInvariant(), Does.Contain("key vault"));
    }

    [Test]
    public void CommandDescription_MentionsKidHeader()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert - Should mention kid header per RFC 9052
        Assert.That(description.ToLowerInvariant(), Does.Contain("kid"));
    }

    [Test]
    public void ExampleUsage_ContainsRequiredOptions()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();

        // Act
        var example = provider.ExampleUsage;

        // Assert
        Assert.That(example, Is.Not.Null);
        Assert.That(example, Does.Contain("--akv-vault"));
        Assert.That(example, Does.Contain("--akv-key-name"));
    }

    [Test]
    public void AddCommandOptions_AddsVaultOption()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "akv-vault"));
    }

    [Test]
    public void AddCommandOptions_AddsKeyNameOption()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "akv-key-name"));
    }

    [Test]
    public void AddCommandOptions_AddsKeyVersionOption()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "akv-key-version"));
    }

    [Test]
    public void AddCommandOptions_AddsRefreshIntervalOption()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "akv-refresh-interval"));
    }

    [Test]
    public void AddCommandOptions_VaultOptionIsRequired()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var vaultOption = command.Options.FirstOrDefault(o => o.Name == "akv-vault");
        Assert.That(vaultOption, Is.Not.Null);
        Assert.That(vaultOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_KeyNameOptionIsRequired()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var keyNameOption = command.Options.FirstOrDefault(o => o.Name == "akv-key-name");
        Assert.That(keyNameOption, Is.Not.Null);
        Assert.That(keyNameOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_KeyVersionOptionIsOptional()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var keyVersionOption = command.Options.FirstOrDefault(o => o.Name == "akv-key-version");
        Assert.That(keyVersionOption, Is.Not.Null);
        Assert.That(keyVersionOption!.IsRequired, Is.False);
    }

    [Test]
    public void AddCommandOptions_RefreshIntervalOptionIsOptional()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var refreshOption = command.Options.FirstOrDefault(o => o.Name == "akv-refresh-interval");
        Assert.That(refreshOption, Is.Not.Null);
        Assert.That(refreshOption!.IsRequired, Is.False);
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingVault_ThrowsException()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-key-name"] = "test-key"
        };

        // Act & Assert - Missing key throws KeyNotFoundException when accessing dictionary
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithNullVault_ThrowsInvalidOperationException()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = null,
            ["akv-key-name"] = "test-key"
        };

        // Act & Assert - Null value throws InvalidOperationException
        Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingKeyName_ThrowsException()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = "https://test-vault.vault.azure.net"
        };

        // Act & Assert - Missing key throws KeyNotFoundException when accessing dictionary
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithNullKeyName_ThrowsInvalidOperationException()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = "https://test-vault.vault.azure.net",
            ["akv-key-name"] = null
        };

        // Act & Assert - Null value throws InvalidOperationException
        Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithInvalidVaultUri_ThrowsArgumentException()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = "not-a-valid-uri",
            ["akv-key-name"] = "test-key"
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithValidOptions_UsesInjectedSigningServiceAndPopulatesMetadata()
    {
        using var signingService = CreateFakeSigningService(
            vaultUri: TestVaultUri,
            keyName: TestKeyName,
            keyVersion: TestKeyVersion);

        var provider = new TestableKeyProvider(signingService);
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = TestVaultUri.ToString().TrimEnd('/'),
            ["akv-key-name"] = TestKeyName,
            ["akv-key-version"] = TestKeyVersion,
            ["akv-refresh-interval"] = 15
        };

        var service = await provider.CreateSigningServiceAsync(options);
        Assert.That(service, Is.Not.Null);

        var metadata = provider.GetSigningMetadata();
        Assert.That(metadata["Vault URL"], Is.EqualTo(TestVaultUri.ToString().TrimEnd('/')));
        Assert.That(metadata["Key Name"], Is.EqualTo(TestKeyName));
        Assert.That(metadata.Keys, Does.Contain("Key Version"));
        Assert.That(metadata.Keys, Does.Contain("Key ID (kid)"));
        Assert.That(metadata.Keys, Does.Contain("Pinned Version"));
        Assert.That(metadata.Keys, Does.Contain("Key Type"));
    }

    [Test]
    public void GetSigningMetadata_ReturnsBasicMetadata()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.Keys, Does.Contain("Key Source"));
        Assert.That(metadata["Key Source"], Is.EqualTo("Azure Key Vault"));
    }

    [Test]
    public void GetSigningMetadata_BeforeSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Vault URL"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Key Name"], Is.EqualTo("Unknown"));
    }

    [Test]
    public void ISigningCommandProvider_Interface_ImplementedCorrectly()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();

        // Assert
        Assert.That(provider, Is.InstanceOf<ISigningCommandProvider>());
    }

    [Test]
    public void CommandName_DifferentFromCertificateProvider()
    {
        // Arrange
        var keyProvider = new AzureKeyVaultKeyCommandProvider();
        var certProvider = new AzureKeyVaultCertificateCommandProvider();

        // Assert - Commands should be different
        Assert.That(keyProvider.CommandName, Is.Not.EqualTo(certProvider.CommandName));
    }

    [Test]
    public void GetSigningMetadata_IncludesKeyIdPlaceholder()
    {
        // Arrange
        var provider = new AzureKeyVaultKeyCommandProvider();

        // Act - Before CreateSigningServiceAsync is called
        var metadata = provider.GetSigningMetadata();

        // Assert - Should not have Key ID yet as no signing service created
        Assert.That(metadata.Keys, Has.No.Member("Key ID (kid)").Or.Member("Key ID (kid)").With.Property("Value").EqualTo(null));
    }

    private sealed class TestableKeyProvider : AzureKeyVaultKeyCommandProvider
    {
        private readonly CoseSign1.AzureKeyVault.AzureKeyVaultSigningService Service;

        public TestableKeyProvider(CoseSign1.AzureKeyVault.AzureKeyVaultSigningService service)
        {
            Service = service;
        }

        protected override Azure.Core.TokenCredential CreateCredential()
        {
            return new Mock<Azure.Core.TokenCredential>(MockBehavior.Strict).Object;
        }

        protected override Task<CoseSign1.AzureKeyVault.AzureKeyVaultSigningService> CreateAzureKeyVaultSigningServiceAsync(
            Uri vaultUri,
            string keyName,
            Azure.Core.TokenCredential credential,
            string? keyVersion,
            TimeSpan? autoRefreshInterval)
        {
            return Task.FromResult(Service);
        }
    }

    private static CoseSign1.AzureKeyVault.AzureKeyVaultSigningService CreateFakeSigningService(
        Uri vaultUri,
        string keyName,
        string keyVersion)
    {
        var credential = new Mock<Azure.Core.TokenCredential>(MockBehavior.Strict);

        var keyId = new Uri($"{vaultUri}keys/{keyName}/{keyVersion}");

        using var rsa = RSA.Create(2048);
        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(rsa, includePrivateParameters: false);
        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: keyId,
            vaultUri: new Uri(keyId.GetLeftPart(UriPartial.Authority)),
            name: keyName,
            version: keyVersion);

        var key = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);

        var mockCryptoClient = new Mock<Azure.Security.KeyVault.Keys.Cryptography.CryptographyClient>(
            MockBehavior.Strict,
            keyId,
            credential.Object);

        var wrapper = new CoseSign1.AzureKeyVault.Common.KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);
        var keyClient = new Mock<Azure.Security.KeyVault.Keys.KeyClient>(MockBehavior.Strict);

        return CoseSign1.AzureKeyVault.AzureKeyVaultSigningService.Create(
            vaultUri,
            keyClient.Object,
            credential.Object,
            wrapper,
            pinnedVersion: keyVersion,
            refreshInterval: TimeSpan.FromMinutes(15));
    }
}

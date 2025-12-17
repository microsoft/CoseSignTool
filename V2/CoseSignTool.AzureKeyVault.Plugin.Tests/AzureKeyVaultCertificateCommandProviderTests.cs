// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

/// <summary>
/// Tests for <see cref="AzureKeyVaultCertificateCommandProvider"/>.
/// </summary>
[TestFixture]
public class AzureKeyVaultCertificateCommandProviderTests
{
    private const string TestCertificateName = "test-cert";
    private const string TestCertificateVersion = "v1";
    private static readonly Uri TestVaultUri = new("https://test-vault.vault.azure.net");

    private sealed class TestableAzureKeyVaultCertificateCommandProvider : AzureKeyVaultCertificateCommandProvider
    {
        public Azure.Core.TokenCredential CreateCredentialPublic() => CreateCredential();

        public CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory CreateClientFactoryPublic(
            Uri vaultUri,
            Azure.Core.TokenCredential credential)
        {
            return CreateClientFactory(vaultUri, credential);
        }
    }

    [Test]
    public void CommandName_ReturnsSignAkvCert()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("sign-akv-cert"));
    }

    [Test]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToLowerInvariant(), Does.Contain("certificate"));
        Assert.That(description.ToLowerInvariant(), Does.Contain("key vault"));
    }

    [Test]
    public void ExampleUsage_ContainsRequiredOptions()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();

        // Act
        var example = provider.ExampleUsage;

        // Assert
        Assert.That(example, Is.Not.Null);
        Assert.That(example, Does.Contain("--akv-vault"));
        Assert.That(example, Does.Contain("--akv-cert-name"));
    }

    [Test]
    public void AddCommandOptions_AddsVaultOption()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "akv-vault"));
    }

    [Test]
    public void AddCommandOptions_AddsCertNameOption()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "akv-cert-name"));
    }

    [Test]
    public void AddCommandOptions_AddsCertVersionOption()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "akv-cert-version"));
    }

    [Test]
    public void AddCommandOptions_AddsRefreshIntervalOption()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
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
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var vaultOption = command.Options.FirstOrDefault(o => o.Name == "akv-vault");
        Assert.That(vaultOption, Is.Not.Null);
        Assert.That(vaultOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_CertNameOptionIsRequired()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var certNameOption = command.Options.FirstOrDefault(o => o.Name == "akv-cert-name");
        Assert.That(certNameOption, Is.Not.Null);
        Assert.That(certNameOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_CertVersionOptionIsOptional()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var certVersionOption = command.Options.FirstOrDefault(o => o.Name == "akv-cert-version");
        Assert.That(certVersionOption, Is.Not.Null);
        Assert.That(certVersionOption!.IsRequired, Is.False);
    }

    [Test]
    public void AddCommandOptions_RefreshIntervalOptionIsOptional()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var refreshOption = command.Options.FirstOrDefault(o => o.Name == "akv-refresh-interval");
        Assert.That(refreshOption, Is.Not.Null);
        Assert.That(refreshOption!.IsRequired, Is.False);
    }

    [Test]
    public void CreateCredential_ReturnsNonNullTokenCredential()
    {
        var provider = new TestableAzureKeyVaultCertificateCommandProvider();

        var credential = provider.CreateCredentialPublic();

        Assert.That(credential, Is.Not.Null);
    }

    [Test]
    public void CreateClientFactory_WithNullCredential_ThrowsArgumentNullException()
    {
        var provider = new TestableAzureKeyVaultCertificateCommandProvider();

        var ex = Assert.Throws<ArgumentNullException>(() =>
            provider.CreateClientFactoryPublic(new Uri("https://example.vault.azure.net"), credential: null!));

        Assert.That(ex!.ParamName, Is.EqualTo("credential"));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingVault_ThrowsException()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-cert-name"] = "test-cert"
        };

        // Act & Assert - Missing key throws KeyNotFoundException when accessing dictionary
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithNullVault_ThrowsInvalidOperationException()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = null,
            ["akv-cert-name"] = "test-cert"
        };

        // Act & Assert - Null value throws InvalidOperationException
        Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingCertName_ThrowsException()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = "https://test-vault.vault.azure.net"
        };

        // Act & Assert - Missing key throws KeyNotFoundException when accessing dictionary
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithNullCertName_ThrowsInvalidOperationException()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = "https://test-vault.vault.azure.net",
            ["akv-cert-name"] = null
        };

        // Act & Assert - Null value throws InvalidOperationException
        Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithInvalidVaultUri_ThrowsArgumentException()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = "not-a-valid-uri",
            ["akv-cert-name"] = "test-cert"
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithValidOptions_UsesInjectedFactoryAndReturnsSigningService()
    {
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvProvider", 2048);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            certificateName: TestCertificateName,
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        var mockCertificateClient = new Mock<Azure.Security.KeyVault.Certificates.CertificateClient>(MockBehavior.Strict);
        mockCertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(kvCert, new Mock<Azure.Response>().Object));

        var secret = new Azure.Security.KeyVault.Secrets.KeyVaultSecret(TestCertificateName, secretValue);
        secret.Properties.ContentType = "application/x-pkcs12";

        var mockSecretClient = new Mock<Azure.Security.KeyVault.Secrets.SecretClient>(MockBehavior.Strict);
        mockSecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(secret, new Mock<Azure.Response>().Object));

        var mockKeyClient = new Mock<Azure.Security.KeyVault.Keys.KeyClient>(MockBehavior.Strict);

        var mockFactory = new Mock<CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(TestVaultUri);
        mockFactory.SetupGet(f => f.CertificateClient).Returns(mockCertificateClient.Object);
        mockFactory.SetupGet(f => f.SecretClient).Returns(mockSecretClient.Object);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);

        var provider = new TestableCertificateProvider(mockFactory.Object);
        var options = new Dictionary<string, object?>
        {
            ["akv-vault"] = TestVaultUri.ToString().TrimEnd('/'),
            ["akv-cert-name"] = TestCertificateName,
            ["akv-refresh-interval"] = 15
        };

        var service = await provider.CreateSigningServiceAsync(options);
        Assert.That(service, Is.Not.Null);

        var metadata = provider.GetSigningMetadata();
        Assert.That(metadata["Vault URL"], Is.EqualTo(TestVaultUri.ToString().TrimEnd('/')));
        Assert.That(metadata["Certificate Name"], Is.EqualTo(TestCertificateName));
        Assert.That(metadata.Keys, Does.Contain("Pinned Version"));
        Assert.That(metadata.Keys, Does.Contain("Key Mode"));

        mockKeyClient.VerifyNoOtherCalls();
    }

    [Test]
    public void GetSigningMetadata_ReturnsBasicMetadata()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.Keys, Does.Contain("Certificate Source"));
        Assert.That(metadata["Certificate Source"], Is.EqualTo("Azure Key Vault"));
    }

    [Test]
    public void GetSigningMetadata_BeforeSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Vault URL"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Certificate Name"], Is.EqualTo("Unknown"));
    }

    [Test]
    public void ISigningCommandProvider_Interface_ImplementedCorrectly()
    {
        // Arrange
        var provider = new AzureKeyVaultCertificateCommandProvider();

        // Assert
        Assert.That(provider, Is.InstanceOf<ISigningCommandProvider>());
    }

    private sealed class TestableCertificateProvider : AzureKeyVaultCertificateCommandProvider
    {
        private readonly CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory Factory;

        public TestableCertificateProvider(CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory factory)
        {
            Factory = factory;
        }

        protected override Azure.Core.TokenCredential CreateCredential()
        {
            return new Mock<Azure.Core.TokenCredential>(MockBehavior.Strict).Object;
        }

        protected override CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory CreateClientFactory(
            Uri vaultUri,
            Azure.Core.TokenCredential credential)
        {
            return Factory;
        }
    }

    private static Azure.Security.KeyVault.Certificates.CertificatePolicy CreateCertificatePolicy(bool exportable)
    {
        // CertificatePolicy constructors vary across Azure SDK versions.
        // We only need Policy.Exportable to be true/false so the production logic can branch.
        var policyType = typeof(Azure.Security.KeyVault.Certificates.CertificatePolicy);

        var constructors = policyType.GetConstructors(
            System.Reflection.BindingFlags.Public |
            System.Reflection.BindingFlags.NonPublic |
            System.Reflection.BindingFlags.Instance);

        // Prefer a ctor that accepts an exportable/isExportable bool parameter.
        var preferredCtor = constructors
            .Select(c => new { Ctor = c, Params = c.GetParameters() })
            .Where(x => x.Params.Any(p =>
                p.ParameterType == typeof(bool) &&
                p.Name != null &&
                p.Name.Contains("export", StringComparison.OrdinalIgnoreCase)))
            .OrderBy(x => x.Params.Length)
            .FirstOrDefault();

        var chosen = preferredCtor?.Ctor
            ?? constructors.OrderBy(c => c.GetParameters().Length).First();

        var args = chosen.GetParameters()
            .Select(p =>
            {
                if (p.ParameterType == typeof(bool) && p.Name != null && p.Name.Contains("export", StringComparison.OrdinalIgnoreCase))
                {
                    return (object)exportable;
                }

                if (p.ParameterType == typeof(string))
                {
                    return (object)"CN=Test";
                }

                if (p.ParameterType == typeof(Uri))
                {
                    return (object)new Uri("https://example.vault.azure.net/");
                }

                if (p.ParameterType.IsValueType)
                {
                    return Activator.CreateInstance(p.ParameterType)!;
                }

                return null!;
            })
            .ToArray();

        var policy = (Azure.Security.KeyVault.Certificates.CertificatePolicy)chosen.Invoke(args);

        // If the property has a setter, set it explicitly for safety.
        var exportableProp = policyType.GetProperty("Exportable");
        if (exportableProp?.CanWrite == true)
        {
            exportableProp.SetValue(policy, exportable);
        }

        return policy;
    }

    private static Azure.Security.KeyVault.Certificates.KeyVaultCertificateWithPolicy CreateKeyVaultCertificateWithPolicy(
        string certificateName,
        bool exportable,
        string version,
        byte[] cerBytes)
    {
        var properties = Azure.Security.KeyVault.Certificates.CertificateModelFactory.CertificateProperties(
            name: certificateName,
            id: new Uri($"{TestVaultUri}certificates/{certificateName}/{version}"),
            vaultUri: TestVaultUri,
            version: version);

        var policy = CreateCertificatePolicy(exportable);

        return Azure.Security.KeyVault.Certificates.CertificateModelFactory.KeyVaultCertificateWithPolicy(
            properties,
            keyId: new Uri($"{TestVaultUri}keys/{certificateName}/{version}"),
            secretId: new Uri($"{TestVaultUri}secrets/{certificateName}/{version}"),
            cer: cerBytes,
            policy: policy);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin.Tests;

using System.CommandLine;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;

/// <summary>
/// Tests for EphemeralSigningCommandProvider.
/// </summary>
[TestFixture]
public class EphemeralSigningCommandProviderTests
{
    [Test]
    public void CommandName_ReturnsSignEphemeral()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("sign-ephemeral"));
    }

    [Test]
    public void CommandDescription_ReturnsDescriptionWithDefaults()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description, Does.Contain("ephemeral"));
        Assert.That(description, Does.Contain("RSA-4096"));
        Assert.That(description, Does.Contain("CodeSigning"));
    }

    [Test]
    public void ExampleUsage_ReturnsValidExample()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();

        // Act
        var example = provider.ExampleUsage;

        // Assert
        Assert.That(example, Is.Not.Null);
        Assert.That(example, Does.Contain("--config"));
    }

    [Test]
    public void AddCommandOptions_AddsAllExpectedOptions()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var options = command.Options.Select(o => o.Name).ToList();
        Assert.That(options, Does.Contain("config"));
        Assert.That(options, Does.Contain("subject"));
        Assert.That(options, Does.Contain("algorithm"));
        Assert.That(options, Does.Contain("key-size"));
        Assert.That(options, Does.Contain("validity-days"));
        Assert.That(options, Does.Contain("no-chain"));
        Assert.That(options, Does.Contain("minimal"));
        Assert.That(options, Does.Contain("pqc"));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithDefaultOptions_ReturnsSigningService()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>();

        // Act
        var service = await provider.CreateSigningServiceAsync(options);

        // Assert
        Assert.That(service, Is.Not.Null);
        Assert.That(service, Is.InstanceOf<ISigningService<SigningOptions>>());
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithDefaultOptions_CreatesRsa4096WithChain()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>();

        // Act
        var service = await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Key Algorithm"], Does.Contain("RSA"));
        Assert.That(metadata["Key Algorithm"], Does.Contain("4096"));
        Assert.That(metadata["Certificate Chain"], Does.Contain("Root"));
        Assert.That(metadata["Configuration"], Does.Contain("Default"));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithMinimalOption_CreatesRsa2048SelfSigned()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["minimal"] = true
        };

        // Act
        var service = await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Key Algorithm"], Does.Contain("RSA"));
        Assert.That(metadata["Key Algorithm"], Does.Contain("2048"));
        Assert.That(metadata["Certificate Chain"], Does.Contain("Self-signed"));
        Assert.That(metadata["Configuration"], Does.Contain("Minimal"));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithPqcOption_CreatesMlDsaWithChain()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["pqc"] = true
        };

        // Act
        var service = await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Key Algorithm"], Does.Contain("MLDSA"));
        Assert.That(metadata["Key Algorithm"], Does.Contain("65"));
        Assert.That(metadata["Certificate Chain"], Does.Contain("Root"));
        Assert.That(metadata["Configuration"], Does.Contain("Post-Quantum"));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithCustomSubject_UsesCustomSubject()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["subject"] = "CN=My Custom Signer, O=Test Corp"
        };

        // Act
        var service = await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Certificate Subject"], Does.Contain("My Custom Signer"));
        Assert.That(metadata["Certificate Subject"], Does.Contain("Test Corp"));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithEcdsaAlgorithm_CreatesEcdsaCertificate()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["algorithm"] = "ECDSA",
            ["no-chain"] = true
        };

        // Act
        var service = await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Key Algorithm"], Does.Contain("ECDSA"));
        Assert.That(metadata["Key Algorithm"], Does.Contain("384")); // Default ECDSA key size
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithCustomKeySize_UsesCustomKeySize()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["algorithm"] = "RSA",
            ["key-size"] = 3072,
            ["no-chain"] = true
        };

        // Act
        var service = await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Key Algorithm"], Does.Contain("RSA"));
        Assert.That(metadata["Key Algorithm"], Does.Contain("3072"));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithNoChain_CreatesSelfSignedCertificate()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["no-chain"] = true
        };

        // Act
        var service = await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Certificate Chain"], Does.Contain("Self-signed"));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithValidityDays_UsesCustomValidity()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["validity-days"] = 30,
            ["no-chain"] = true
        };

        // Act
        var service = await provider.CreateSigningServiceAsync(options);

        // Assert - Just verify it doesn't throw; actual validity is internal
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task CreateSigningServiceAsync_ServiceCanProvideCoseSigner()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["no-chain"] = true // Use self-signed for faster test
        };

        var service = await provider.CreateSigningServiceAsync(options);
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes("Test payload to sign");

        // Act
        var context = new SigningContext(payloadBytes, "application/octet-stream");
        var coseSigner = service.GetCoseSigner(context);

        // Assert
        Assert.That(coseSigner, Is.Not.Null);

        // Verify we can create a CoseSign1Message with this signer
        // CoseSign1Message.SignEmbedded returns byte[], not CoseSign1Message
        var coseBytes = CoseSign1Message.SignEmbedded(payloadBytes, coseSigner);
        Assert.That(coseBytes, Is.Not.Null);
        Assert.That(coseBytes.Length, Is.GreaterThan(0));

        // Verify we can decode the message
        var decodedMessage = CoseMessage.DecodeSign1(coseBytes);
        Assert.That(decodedMessage, Is.Not.Null);
        Assert.That(decodedMessage.Content!.Value.Length, Is.GreaterThan(0));
    }

    [Test]
    public void GetSigningMetadata_BeforeCreation_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata["Certificate Source"], Is.EqualTo("Ephemeral (in-memory)"));
        Assert.That(metadata["Certificate Subject"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Certificate Thumbprint"], Is.EqualTo("Unknown"));
    }

    [Test]
    public async Task GetSigningMetadata_AfterCreation_ReturnsActualValues()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["subject"] = "CN=Test Subject"
        };

        // Act
        await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Certificate Source"], Is.EqualTo("Ephemeral (in-memory)"));
        Assert.That(metadata["Certificate Subject"], Does.Contain("Test Subject"));
        Assert.That(metadata["Certificate Thumbprint"], Has.Length.EqualTo(40)); // SHA1 thumbprint
        Assert.That(metadata.ContainsKey("⚠️ Warning"), Is.True);
    }

    [Test]
    public async Task CreateSigningServiceAsync_CommandLineOverridesConfig()
    {
        // Create a minimal config first, then override with command line
        var provider = new EphemeralSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["minimal"] = true, // Starts with RSA-2048
            ["algorithm"] = "ECDSA", // Override to ECDSA
            ["key-size"] = 521 // Override to P-521
        };

        // Act
        var service = await provider.CreateSigningServiceAsync(options);
        var metadata = provider.GetSigningMetadata();

        // Assert - Command line overrides should win
        Assert.That(metadata["Key Algorithm"], Does.Contain("ECDSA"));
        Assert.That(metadata["Key Algorithm"], Does.Contain("521"));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingConfigFile_ThrowsFileNotFoundException()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var missingConfig = new FileInfo(Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid():N}.json"));
        var options = new Dictionary<string, object?>
        {
            ["config"] = missingConfig
        };

        // Act & Assert
        Assert.ThrowsAsync<FileNotFoundException>(async () => await provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithConfigFile_LoadsConfigurationAndUsesEkuAliases()
    {
        // Arrange
        var provider = new EphemeralSigningCommandProvider();
        var tempDir = Path.Combine(Path.GetTempPath(), $"ephemeral_cfg_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var configPath = Path.Combine(tempDir, "ephemeral.json");

        // Include several EKU forms to cover alias mapping and raw OID handling.
        var config = new EphemeralCertificateConfig
        {
            Subject = "CN=Config File Subject",
            Algorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 1,
            GenerateChain = false,
            EnhancedKeyUsages = new List<string>
            {
                "TimeStamping",
                "ServerAuth",
                "1.2.3.4.5"
            }
        };
        await File.WriteAllTextAsync(configPath, config.ToJson());

        var options = new Dictionary<string, object?>
        {
            ["config"] = new FileInfo(configPath)
        };

        try
        {
            // Act
            var service = await provider.CreateSigningServiceAsync(options);
            var metadata = provider.GetSigningMetadata();

            // Assert
            Assert.That(service, Is.Not.Null);
            Assert.That(metadata["Configuration"], Does.Contain("Config file:"));
            Assert.That(metadata["Certificate Chain"], Does.Contain("Self-signed"));
            Assert.That(metadata["Certificate Subject"], Does.Contain("Config File Subject"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}
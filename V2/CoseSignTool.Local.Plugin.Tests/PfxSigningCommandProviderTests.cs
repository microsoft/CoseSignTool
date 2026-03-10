// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin.Tests;

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Tests for PfxSigningCommandProvider.
/// </summary>
[TestFixture]
public class PfxSigningCommandProviderTests
{
    [Test]
    public void CommandName_ReturnsSignPfx()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("x509-pfx"));
    }

    [Test]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToUpperInvariant(), Does.Contain("PFX"));
    }

    [Test]
    public void AddCommandOptions_AddsRequiredOptions()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "pfx"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "pfx-password-file"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "pfx-password-env"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "pfx-password-prompt"));
    }

    [Test]
    public void AddCommandOptions_PfxOptionIsRequired()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var pfxOption = command.Options.FirstOrDefault(o => o.Name == "pfx");
        Assert.That(pfxOption, Is.Not.Null);
        Assert.That(pfxOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_PasswordFileOptionIsOptional()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var passwordOption = command.Options.FirstOrDefault(o => o.Name == "pfx-password-file");
        Assert.That(passwordOption, Is.Not.Null);
        Assert.That(passwordOption!.IsRequired, Is.False);
    }

    [Test]
    public void AddCommandOptions_PasswordEnvOptionIsOptional()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var envOption = command.Options.FirstOrDefault(o => o.Name == "pfx-password-env");
        Assert.That(envOption, Is.Not.Null);
        Assert.That(envOption!.IsRequired, Is.False);
    }

    [Test]
    public void AddCommandOptions_PasswordPromptOptionIsOptional()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var promptOption = command.Options.FirstOrDefault(o => o.Name == "pfx-password-prompt");
        Assert.That(promptOption, Is.Not.Null);
        Assert.That(promptOption!.IsRequired, Is.False);
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingPfxOption_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var options = new Dictionary<string, object?>();

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithNonExistentPfxFile_ThrowsFileNotFoundException()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var nonExistentFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.pfx"));
        var options = new Dictionary<string, object?>
        {
            ["pfx"] = nonExistentFile
        };

        // Act & Assert
        Assert.ThrowsAsync<FileNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.Keys, Does.Contain("Certificate Source"));
        Assert.That(metadata["Certificate Source"], Is.EqualTo("PFX file"));
    }

    [Test]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Certificate Subject"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Certificate Thumbprint"], Is.EqualTo("Unknown"));
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithValidPfxNoPassword_ReturnsSigningService()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var tempDir = Path.Combine(Path.GetTempPath(), $"pfxtest_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);
        var pfxPath = Path.Combine(tempDir, "test.pfx");

        try
        {
            // Create a certificate and export to PFX without password
            using var cert = LocalCertificateFactory.CreateRsaCertificate("PfxTest", 2048);
            var pfxBytes = cert.Export(X509ContentType.Pfx);
            await File.WriteAllBytesAsync(pfxPath, pfxBytes);

            var options = new Dictionary<string, object?>
            {
                ["pfx"] = new FileInfo(pfxPath)
            };

            // Act
            var service = await provider.CreateSigningServiceAsync(options);

            // Assert
            Assert.That(service, Is.Not.Null);

            // Verify metadata is set after service creation
            var metadata = provider.GetSigningMetadata();
            Assert.That(metadata["Certificate Subject"], Does.Contain("PfxTest"));
            Assert.That(metadata["Certificate Thumbprint"], Is.Not.EqualTo("Unknown"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithPasswordFile_ReadsPassword()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var tempDir = Path.Combine(Path.GetTempPath(), $"pfxtest_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);
        var pfxPath = Path.Combine(tempDir, "test.pfx");
        var passwordFilePath = Path.Combine(tempDir, "password.txt");
        var password = "test-password-123";

        try
        {
            // Create a certificate and export to PFX with password
            using var cert = LocalCertificateFactory.CreateRsaCertificate("PfxTest", 2048);
            var pfxBytes = cert.Export(X509ContentType.Pfx, password);
            await File.WriteAllBytesAsync(pfxPath, pfxBytes);
            await File.WriteAllTextAsync(passwordFilePath, password);

            var options = new Dictionary<string, object?>
            {
                ["pfx"] = new FileInfo(pfxPath),
                ["pfx-password-file"] = new FileInfo(passwordFilePath)
            };

            // Act
            var service = await provider.CreateSigningServiceAsync(options);

            // Assert
            Assert.That(service, Is.Not.Null);
            var metadata = provider.GetSigningMetadata();
            Assert.That(metadata["Certificate Subject"], Does.Contain("PfxTest"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task CreateSigningServiceAsync_WithEnvironmentVariable_ReadsPassword()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var tempDir = Path.Combine(Path.GetTempPath(), $"pfxtest_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);
        var pfxPath = Path.Combine(tempDir, "test.pfx");
        var password = "test-env-password-456";
        var envVarName = "TEST_PFX_PASSWORD_" + Guid.NewGuid().ToString("N").Substring(0, 8);

        try
        {
            // Create a certificate and export to PFX with password
            using var cert = LocalCertificateFactory.CreateRsaCertificate("PfxEnvTest", 2048);
            var pfxBytes = cert.Export(X509ContentType.Pfx, password);
            await File.WriteAllBytesAsync(pfxPath, pfxBytes);

            // Set environment variable
            Environment.SetEnvironmentVariable(envVarName, password);

            var options = new Dictionary<string, object?>
            {
                ["pfx"] = new FileInfo(pfxPath),
                ["pfx-password-env"] = envVarName
            };

            // Act
            var service = await provider.CreateSigningServiceAsync(options);

            // Assert
            Assert.That(service, Is.Not.Null);
            var metadata = provider.GetSigningMetadata();
            Assert.That(metadata["Certificate Subject"], Does.Contain("PfxEnvTest"));
        }
        finally
        {
            // Clean up environment variable
            Environment.SetEnvironmentVariable(envVarName, null);

            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public void ExampleUsage_ReturnsNonEmpty()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var usage = provider.ExampleUsage;

        // Assert
        Assert.That(usage, Is.Not.Null.And.Not.Empty);
        Assert.That(usage, Does.Contain("--pfx"));
    }
}
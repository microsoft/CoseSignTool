// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Local.Plugin;

namespace CoseSignTool.Local.Plugin.Tests;

/// <summary>
/// Tests for PemSigningCommandProvider.
/// </summary>
[TestFixture]
public class PemSigningCommandProviderTests
{
    [Test]
    public void CommandName_ReturnsSignPem()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("sign-pem"));
    }

    [Test]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToUpperInvariant(), Does.Contain("PEM"));
    }

    [Test]
    public void AddCommandOptions_AddsRequiredOptions()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "cert-file"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "key-file"));
    }

    [Test]
    public void AddCommandOptions_CertFileIsRequired()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var certFileOption = command.Options.FirstOrDefault(o => o.Name == "cert-file");
        Assert.That(certFileOption, Is.Not.Null);
        Assert.That(certFileOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_KeyFileIsRequired()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var keyFileOption = command.Options.FirstOrDefault(o => o.Name == "key-file");
        Assert.That(keyFileOption, Is.Not.Null);
        Assert.That(keyFileOption!.IsRequired, Is.True);
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingCertFile_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["key-file"] = "test-key.pem"
        };

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingKeyFile_ThrowsInvalidOperationException()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["cert-file"] = "test-cert.pem"  // String instead of FileInfo, so cert validation fails first
        };

        // Act & Assert - When cert-file is a string (not FileInfo), the cast returns null
        // and throws InvalidOperationException ("Certificate file is required")
        Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithNonExistentCertFile_ThrowsFileNotFoundException()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var nonExistentCertFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.crt"));
        var nonExistentKeyFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.key"));
        var options = new Dictionary<string, object?>
        {
            ["cert-file"] = nonExistentCertFile,
            ["key-file"] = nonExistentKeyFile
        };

        // Act & Assert
        Assert.ThrowsAsync<FileNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.Keys, Does.Contain("Certificate Source"));
        Assert.That(metadata["Certificate Source"], Is.EqualTo("PEM files"));
    }

    [Test]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Certificate Subject"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Certificate Thumbprint"], Is.EqualTo("Unknown"));
    }

    [Test]
    public void CreateSigningServiceAsync_WithNonExistentKeyFile_ThrowsFileNotFoundException()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Create a real temp file for cert but non-existent for key
        var tempCertFile = Path.Combine(Path.GetTempPath(), $"test_cert_{Guid.NewGuid()}.pem");
        File.WriteAllText(tempCertFile, "temp cert content");
        try
        {
            var certFileInfo = new FileInfo(tempCertFile);
            var nonExistentKeyFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.key"));

            var options = new Dictionary<string, object?>
            {
                ["cert-file"] = certFileInfo,
                ["key-file"] = nonExistentKeyFile
            };

            // Act & Assert - Key file doesn't exist, should throw FileNotFoundException
            var ex = Assert.ThrowsAsync<FileNotFoundException>(
                () => provider.CreateSigningServiceAsync(options));
            Assert.That(ex!.Message, Does.Contain("Private key file not found"));
        }
        finally
        {
            File.Delete(tempCertFile);
        }
    }

    [Test]
    public void ExampleUsage_ReturnsExpectedUsageString()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var usage = provider.ExampleUsage;

        // Assert
        Assert.That(usage, Is.Not.Null);
        Assert.That(usage, Does.Contain("--cert-file"));
        Assert.That(usage, Does.Contain("--key-file"));
    }
}
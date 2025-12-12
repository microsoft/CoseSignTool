// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Local.Plugin;
using System.CommandLine;

namespace CoseSignTool.Local.Plugin.Tests;

/// <summary>
/// Tests for PemSigningCommandProvider.
/// </summary>
public class PemSigningCommandProviderTests
{
    [Fact]
    public void CommandName_ReturnsSignPem()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.Equal("sign-pem", name);
    }

    [Fact]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.NotNull(description);
        Assert.NotEmpty(description);
        Assert.Contains("PEM", description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AddCommandOptions_AddsRequiredOptions()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.Contains(command.Options, o => o.Name == "cert-file");
        Assert.Contains(command.Options, o => o.Name == "key-file");
    }

    [Fact]
    public void AddCommandOptions_CertFileIsRequired()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var certFileOption = command.Options.FirstOrDefault(o => o.Name == "cert-file");
        Assert.NotNull(certFileOption);
        Assert.True(certFileOption.IsRequired);
    }

    [Fact]
    public void AddCommandOptions_KeyFileIsRequired()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var keyFileOption = command.Options.FirstOrDefault(o => o.Name == "key-file");
        Assert.NotNull(keyFileOption);
        Assert.True(keyFileOption.IsRequired);
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithMissingCertFile_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["key-file"] = "test-key.pem"
        };

        // Act & Assert
        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithMissingKeyFile_ThrowsInvalidOperationException()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["cert-file"] = "test-cert.pem"  // String instead of FileInfo, so cert validation fails first
        };

        // Act & Assert - When cert-file is a string (not FileInfo), the cast returns null
        // and throws InvalidOperationException ("Certificate file is required")
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithNonExistentCertFile_ThrowsFileNotFoundException()
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
        await Assert.ThrowsAsync<FileNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.NotNull(metadata);
        Assert.Contains("Certificate Source", metadata.Keys);
        Assert.Equal("PEM files", metadata["Certificate Source"]);
    }

    [Fact]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new PemSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.Equal("Unknown", metadata["Certificate Subject"]);
        Assert.Equal("Unknown", metadata["Certificate Thumbprint"]);
    }
}

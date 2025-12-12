// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Local.Plugin;
using System.CommandLine;

namespace CoseSignTool.Local.Plugin.Tests;

/// <summary>
/// Tests for LinuxCertStoreSigningCommandProvider.
/// </summary>
public class LinuxCertStoreSigningCommandProviderTests
{
    [Fact]
    public void CommandName_ReturnsSignCertstore()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.Equal("sign-certstore", name);
    }

    [Fact]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.NotNull(description);
        Assert.NotEmpty(description);
        Assert.Contains("certificate", description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AddCommandOptions_AddsRequiredOptions()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.Contains(command.Options, o => o.Name == "thumbprint");
        Assert.Contains(command.Options, o => o.Name == "store-paths");
    }

    [Fact]
    public void AddCommandOptions_ThumbprintIsRequired()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var thumbprintOption = command.Options.FirstOrDefault(o => o.Name == "thumbprint");
        Assert.NotNull(thumbprintOption);
        Assert.True(thumbprintOption.IsRequired);
    }

    [Fact]
    public void AddCommandOptions_StorePathsIsOptional()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var storePathsOption = command.Options.FirstOrDefault(o => o.Name == "store-paths");
        Assert.NotNull(storePathsOption);
        Assert.False(storePathsOption.IsRequired);
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithMissingThumbprint_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();
        var options = new Dictionary<string, object?>();

        // Act & Assert
        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.NotNull(metadata);
        Assert.Contains("Certificate Source", metadata.Keys);
        Assert.Equal("Linux certificate store", metadata["Certificate Source"]);
    }

    [Fact]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.Equal("Unknown", metadata["Certificate Subject"]);
        Assert.Equal("Unknown", metadata["Certificate Thumbprint"]);
    }
}

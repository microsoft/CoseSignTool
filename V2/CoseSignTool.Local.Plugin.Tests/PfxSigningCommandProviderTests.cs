// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Local.Plugin;
using System.CommandLine;

namespace CoseSignTool.Local.Plugin.Tests;

/// <summary>
/// Tests for PfxSigningCommandProvider.
/// </summary>
public class PfxSigningCommandProviderTests
{
    [Fact]
    public void CommandName_ReturnsSignPfx()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.Equal("sign-pfx", name);
    }

    [Fact]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.NotNull(description);
        Assert.NotEmpty(description);
        Assert.Contains("PFX", description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AddCommandOptions_AddsRequiredOptions()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.Contains(command.Options, o => o.Name == "pfx");
        Assert.Contains(command.Options, o => o.Name == "pfx-password");
    }

    [Fact]
    public void AddCommandOptions_PfxOptionIsRequired()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var pfxOption = command.Options.FirstOrDefault(o => o.Name == "pfx");
        Assert.NotNull(pfxOption);
        Assert.True(pfxOption.IsRequired);
    }

    [Fact]
    public void AddCommandOptions_PasswordOptionIsOptional()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var passwordOption = command.Options.FirstOrDefault(o => o.Name == "pfx-password");
        Assert.NotNull(passwordOption);
        Assert.False(passwordOption.IsRequired);
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithMissingPfxOption_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var options = new Dictionary<string, object?>();

        // Act & Assert
        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithNonExistentPfxFile_ThrowsFileNotFoundException()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var nonExistentFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.pfx"));
        var options = new Dictionary<string, object?>
        {
            ["pfx"] = nonExistentFile
        };

        // Act & Assert
        await Assert.ThrowsAsync<FileNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.NotNull(metadata);
        Assert.Contains("Certificate Source", metadata.Keys);
        Assert.Equal("PFX file", metadata["Certificate Source"]);
    }

    [Fact]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.Equal("Unknown", metadata["Certificate Subject"]);
        Assert.Equal("Unknown", metadata["Certificate Thumbprint"]);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Local.Plugin;

namespace CoseSignTool.Local.Plugin.Tests;

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
        Assert.That(name, Is.EqualTo("sign-pfx"));
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
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "pfx-password"));
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
    public void AddCommandOptions_PasswordOptionIsOptional()
    {
        // Arrange
        var provider = new PfxSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var passwordOption = command.Options.FirstOrDefault(o => o.Name == "pfx-password");
        Assert.That(passwordOption, Is.Not.Null);
        Assert.That(passwordOption!.IsRequired, Is.False);
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
}
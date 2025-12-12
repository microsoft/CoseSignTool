// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Local.Plugin;

namespace CoseSignTool.Local.Plugin.Tests;

/// <summary>
/// Tests for LinuxCertStoreSigningCommandProvider.
/// </summary>
[TestFixture]
public class LinuxCertStoreSigningCommandProviderTests
{
    [Test]
    public void CommandName_ReturnsSignCertstore()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("sign-certstore"));
    }

    [Test]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToLowerInvariant(), Does.Contain("certificate"));
    }

    [Test]
    public void AddCommandOptions_AddsRequiredOptions()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "thumbprint"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "store-paths"));
    }

    [Test]
    public void AddCommandOptions_ThumbprintIsRequired()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var thumbprintOption = command.Options.FirstOrDefault(o => o.Name == "thumbprint");
        Assert.That(thumbprintOption, Is.Not.Null);
        Assert.That(thumbprintOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_StorePathsIsOptional()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var storePathsOption = command.Options.FirstOrDefault(o => o.Name == "store-paths");
        Assert.That(storePathsOption, Is.Not.Null);
        Assert.That(storePathsOption!.IsRequired, Is.False);
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingThumbprint_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();
        var options = new Dictionary<string, object?>();

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.Keys, Does.Contain("Certificate Source"));
        Assert.That(metadata["Certificate Source"], Is.EqualTo("Linux certificate store"));
    }

    [Test]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new LinuxCertStoreSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Certificate Subject"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Certificate Thumbprint"], Is.EqualTo("Unknown"));
    }
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Local.Plugin;
using System.CommandLine;

namespace CoseSignTool.Local.Plugin.Tests;

/// <summary>
/// Tests for WindowsCertStoreSigningCommandProvider.
/// </summary>
[TestFixture]
public class WindowsCertStoreSigningCommandProviderTests
{
    [Test]
    public void CommandName_ReturnsSignCertstore()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("sign-certstore"));
    }

    [Test]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();

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
        var provider = new WindowsCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "thumbprint"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "store-location"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "store-name"));
    }

    [Test]
    public void AddCommandOptions_ThumbprintIsRequired()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var thumbprintOption = command.Options.FirstOrDefault(o => o.Name == "thumbprint");
        Assert.That(thumbprintOption, Is.Not.Null);
        Assert.That(thumbprintOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_StoreLocationHasDefault()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var storeLocationOption = command.Options.FirstOrDefault(o => o.Name == "store-location");
        Assert.That(storeLocationOption, Is.Not.Null);
        Assert.That(storeLocationOption!.IsRequired, Is.False);
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingThumbprint_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();
        var options = new Dictionary<string, object?>();

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.Keys, Does.Contain("Certificate Source"));
        Assert.That(metadata["Certificate Source"], Is.EqualTo("Windows certificate store"));
    }

    [Test]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Certificate Subject"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Certificate Thumbprint"], Is.EqualTo("Unknown"));
    }
}

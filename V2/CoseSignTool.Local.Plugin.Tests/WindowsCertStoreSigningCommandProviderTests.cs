// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Local.Plugin;

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

    [Test]
    public void ExampleUsage_ContainsThumbprint()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();

        // Act
        var usage = provider.ExampleUsage;

        // Assert
        Assert.That(usage, Does.Contain("--thumbprint"));
    }

    [Test]
    public void CreateSigningServiceAsync_WithNullThumbprint_ThrowsInvalidOperationException()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["thumbprint"] = null
        };

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithInvalidStoreLocation_ThrowsArgumentException()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["thumbprint"] = "ABCD1234",
            ["store-location"] = "InvalidLocation"
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithInvalidStoreName_ThrowsArgumentException()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["thumbprint"] = "ABCD1234",
            ["store-location"] = "CurrentUser",
            ["store-name"] = "InvalidStoreName"
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithDefaultStoreSettings_UsesCurrentUserMy()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["thumbprint"] = "ABCD1234"
            // store-location and store-name not provided, should use defaults
        };

        // Act & Assert - Will throw because cert doesn't exist, but that's expected
        var ex = Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateSigningServiceAsync(options));

        // The exception message should indicate it tried to find the cert in CurrentUser\My (the defaults)
        Assert.That(ex?.Message ?? "",
            Does.Contain("ABCD1234").And.Contain("CurrentUser").And.Contain("My"));
    }

    [Test]
    public void AddCommandOptions_StoreNameHasDefault()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var storeNameOption = command.Options.FirstOrDefault(o => o.Name == "store-name");
        Assert.That(storeNameOption, Is.Not.Null);
        Assert.That(storeNameOption!.IsRequired, Is.False);
    }

    [Test]
    public void GetSigningMetadata_ContainsAllExpectedKeys()
    {
        // Arrange
        var provider = new WindowsCertStoreSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Does.ContainKey("Certificate Source"));
        Assert.That(metadata, Does.ContainKey("Certificate Subject"));
        Assert.That(metadata, Does.ContainKey("Certificate Thumbprint"));
    }
}
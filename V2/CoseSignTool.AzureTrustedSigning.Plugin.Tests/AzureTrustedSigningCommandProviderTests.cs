// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureTrustedSigning.Plugin.Tests;

using System.CommandLine;

/// <summary>
/// Tests for AzureTrustedSigningCommandProvider.
/// </summary>
[TestFixture]
public class AzureTrustedSigningCommandProviderTests
{
    [Test]
    public void CommandName_ReturnsSignAzure()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("sign-azure"));
    }

    [Test]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.That(description, Is.Not.Null);
        Assert.That(description, Is.Not.Empty);
        Assert.That(description.ToLowerInvariant(), Does.Contain("azure"));
    }

    [Test]
    public void AddCommandOptions_AddsRequiredOptions()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "ats-endpoint"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "ats-account-name"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "ats-cert-profile-name"));
    }

    [Test]
    public void AddCommandOptions_EndpointIsRequired()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var endpointOption = command.Options.FirstOrDefault(o => o.Name == "ats-endpoint");
        Assert.That(endpointOption, Is.Not.Null);
        Assert.That(endpointOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_AccountNameIsRequired()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var accountNameOption = command.Options.FirstOrDefault(o => o.Name == "ats-account-name");
        Assert.That(accountNameOption, Is.Not.Null);
        Assert.That(accountNameOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_CertProfileIsRequired()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var certProfileOption = command.Options.FirstOrDefault(o => o.Name == "ats-cert-profile-name");
        Assert.That(certProfileOption, Is.Not.Null);
        Assert.That(certProfileOption!.IsRequired, Is.True);
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingEndpoint_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["ats-account-name"] = "testaccount",
            ["ats-cert-profile-name"] = "testprofile"
        };

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingAccountName_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["ats-endpoint"] = "https://test.codesigning.azure.net",
            ["ats-cert-profile-name"] = "testprofile"
        };

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingCertProfile_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["ats-endpoint"] = "https://test.codesigning.azure.net",
            ["ats-account-name"] = "testaccount"
        };

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithInvalidEndpoint_ThrowsArgumentException()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["ats-endpoint"] = "not-a-valid-url",
            ["ats-account-name"] = "testaccount",
            ["ats-cert-profile-name"] = "testprofile"
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.Keys, Does.Contain("Certificate Source"));
        Assert.That(metadata["Certificate Source"], Is.EqualTo("Azure Trusted Signing"));
    }

    [Test]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Account Name"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Certificate Profile"], Is.EqualTo("Unknown"));
    }
}
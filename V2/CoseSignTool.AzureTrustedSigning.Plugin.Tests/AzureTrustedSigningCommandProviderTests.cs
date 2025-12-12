// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.AzureTrustedSigning.Plugin;
using System.CommandLine;

namespace CoseSignTool.AzureTrustedSigning.Plugin.Tests;

/// <summary>
/// Tests for AzureTrustedSigningCommandProvider.
/// </summary>
public class AzureTrustedSigningCommandProviderTests
{
    [Fact]
    public void CommandName_ReturnsSignAzure()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.Equal("sign-azure", name);
    }

    [Fact]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();

        // Act
        var description = provider.CommandDescription;

        // Assert
        Assert.NotNull(description);
        Assert.NotEmpty(description);
        Assert.Contains("Azure", description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AddCommandOptions_AddsRequiredOptions()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.Contains(command.Options, o => o.Name == "ats-endpoint");
        Assert.Contains(command.Options, o => o.Name == "ats-account-name");
        Assert.Contains(command.Options, o => o.Name == "ats-cert-profile-name");
    }

    [Fact]
    public void AddCommandOptions_EndpointIsRequired()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var endpointOption = command.Options.FirstOrDefault(o => o.Name == "ats-endpoint");
        Assert.NotNull(endpointOption);
        Assert.True(endpointOption.IsRequired);
    }

    [Fact]
    public void AddCommandOptions_AccountNameIsRequired()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var accountNameOption = command.Options.FirstOrDefault(o => o.Name == "ats-account-name");
        Assert.NotNull(accountNameOption);
        Assert.True(accountNameOption.IsRequired);
    }

    [Fact]
    public void AddCommandOptions_CertProfileIsRequired()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var certProfileOption = command.Options.FirstOrDefault(o => o.Name == "ats-cert-profile-name");
        Assert.NotNull(certProfileOption);
        Assert.True(certProfileOption.IsRequired);
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithMissingEndpoint_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["ats-account-name"] = "testaccount",
            ["ats-cert-profile-name"] = "testprofile"
        };

        // Act & Assert
        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithMissingAccountName_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["ats-endpoint"] = "https://test.codesigning.azure.net",
            ["ats-cert-profile-name"] = "testprofile"
        };

        // Act & Assert
        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithMissingCertProfile_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["ats-endpoint"] = "https://test.codesigning.azure.net",
            ["ats-account-name"] = "testaccount"
        };

        // Act & Assert
        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public async Task CreateSigningServiceAsync_WithInvalidEndpoint_ThrowsArgumentException()
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
        await Assert.ThrowsAsync<ArgumentException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Fact]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.NotNull(metadata);
        Assert.Contains("Certificate Source", metadata.Keys);
        Assert.Equal("Azure Trusted Signing", metadata["Certificate Source"]);
    }

    [Fact]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new AzureTrustedSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.Equal("Unknown", metadata["Account Name"]);
        Assert.Equal("Unknown", metadata["Certificate Profile"]);
    }
}

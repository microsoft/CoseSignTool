// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureArtifactSigning.Plugin.Tests;

using System.CommandLine;

/// <summary>
/// Tests for AzureArtifactSigningCommandProvider.
/// </summary>
[TestFixture]
public class AzureArtifactSigningCommandProviderTests
{
    [Test]
    public void CommandName_ReturnsSignAzure()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();

        // Act
        var name = provider.CommandName;

        // Assert
        Assert.That(name, Is.EqualTo("x509-aas"));
    }

    [Test]
    public void CommandDescription_ReturnsDescription()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();

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
        var provider = new AzureArtifactSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "aas-endpoint"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "aas-account-name"));
        Assert.That(command.Options, Has.Some.Matches<Option>(o => o.Name == "aas-cert-profile-name"));
    }

    [Test]
    public void AddCommandOptions_EndpointIsRequired()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var endpointOption = command.Options.FirstOrDefault(o => o.Name == "aas-endpoint");
        Assert.That(endpointOption, Is.Not.Null);
        Assert.That(endpointOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_AccountNameIsRequired()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var accountNameOption = command.Options.FirstOrDefault(o => o.Name == "aas-account-name");
        Assert.That(accountNameOption, Is.Not.Null);
        Assert.That(accountNameOption!.IsRequired, Is.True);
    }

    [Test]
    public void AddCommandOptions_CertProfileIsRequired()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();
        var command = new Command("test");

        // Act
        provider.AddCommandOptions(command);

        // Assert
        var certProfileOption = command.Options.FirstOrDefault(o => o.Name == "aas-cert-profile-name");
        Assert.That(certProfileOption, Is.Not.Null);
        Assert.That(certProfileOption!.IsRequired, Is.True);
    }

    [Test]
    public void TransparencyEndpoints_ReturnsDefaultMstEndpoint()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();

        // Act
        var transparencyEndpoint = provider.TransparencyEndpoints.Single();

        // Assert
        Assert.That(transparencyEndpoint.ServiceType, Is.EqualTo("mst"));
        Assert.That(transparencyEndpoint.Endpoint, Is.EqualTo("https://dataplane.codetransparency.azure.net"));
        Assert.That(transparencyEndpoint.AutoSubmit, Is.True);
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingEndpoint_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["aas-account-name"] = "testaccount",
            ["aas-cert-profile-name"] = "testprofile"
        };

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingAccountName_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["aas-endpoint"] = "https://test.codesigning.azure.net",
            ["aas-cert-profile-name"] = "testprofile"
        };

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithMissingCertProfile_ThrowsKeyNotFoundException()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["aas-endpoint"] = "https://test.codesigning.azure.net",
            ["aas-account-name"] = "testaccount"
        };

        // Act & Assert
        Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void CreateSigningServiceAsync_WithInvalidEndpoint_ThrowsArgumentException()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();
        var options = new Dictionary<string, object?>
        {
            ["aas-endpoint"] = "not-a-valid-url",
            ["aas-account-name"] = "testaccount",
            ["aas-cert-profile-name"] = "testprofile"
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(
            () => provider.CreateSigningServiceAsync(options));
    }

    [Test]
    public void GetSigningMetadata_ReturnsMetadata()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.Keys, Does.Contain("Certificate Source"));
        Assert.That(metadata["Certificate Source"], Is.EqualTo("Azure Artifact Signing"));
    }

    [Test]
    public void GetSigningMetadata_WithNoSigningService_ReturnsUnknownValues()
    {
        // Arrange
        var provider = new AzureArtifactSigningCommandProvider();

        // Act
        var metadata = provider.GetSigningMetadata();

        // Assert
        Assert.That(metadata["Account Name"], Is.EqualTo("Unknown"));
        Assert.That(metadata["Certificate Profile"], Is.EqualTo("Unknown"));
    }
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureArtifactSigning.Plugin.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using Azure.Core;
using CoseSignTool.AzureArtifactSigning.Plugin;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

/// <summary>
/// Tests for <see cref="AzureCredentialFactory"/>.
/// </summary>
[TestClass]
public class AzureCredentialFactoryTests
{
    /// <summary>
    /// Verifies the factory does not retain credentials in a process-wide cache.
    /// </summary>
    [TestMethod]
    public void CreateCredential_SameExclusions_ReturnsNewInstances()
    {
        TokenCredential first = AzureCredentialFactory.CreateCredential(new[] { "ManagedIdentityCredential" });
        TokenCredential second = AzureCredentialFactory.CreateCredential(new[] { "ManagedIdentityCredential" });

        Assert.AreNotSame(first, second);
    }

    /// <summary>
    /// Verifies that null and empty exclusions are accepted.
    /// </summary>
    [TestMethod]
    public void CreateCredential_NullAndEmptyExclusions_AreAccepted()
    {
        Assert.IsNotNull(AzureCredentialFactory.CreateCredential(null));
        Assert.IsNotNull(AzureCredentialFactory.CreateCredential(Array.Empty<string>()));
    }

    /// <summary>
    /// Verifies that names differing only by case, the optional "Credential" suffix, whitespace, or
    /// ordering or duplication are accepted.
    /// </summary>
    [TestMethod]
    public void CreateCredential_EquivalentNames_AreAccepted()
    {
        Assert.IsNotNull(AzureCredentialFactory.CreateCredential(
            new[] { " azurecli ", "managedidentity", "ManagedIdentityCredential" }));
    }

    /// <summary>
    /// Verifies that blank entries are ignored rather than treated as an unknown credential.
    /// </summary>
    [TestMethod]
    public void CreateCredential_BlankEntries_AreIgnored()
    {
        Assert.IsNotNull(AzureCredentialFactory.CreateCredential(new[] { string.Empty, "   " }));
    }

    /// <summary>
    /// Verifies that an unrecognized name fails fast instead of being silently ignored, which would
    /// leave a credential the caller believes is excluded still in the chain.
    /// </summary>
    [TestMethod]
    public void CreateCredential_UnknownName_Throws()
    {
        ArgumentException exception = Assert.ThrowsException<ArgumentException>(
            () => AzureCredentialFactory.CreateCredential(new[] { "NotARealCredential" }));

        StringAssert.Contains(exception.Message, "NotARealCredential");
    }

    /// <summary>
    /// Verifies that every documented exclusion name is accepted.
    /// </summary>
    [TestMethod]
    public void SupportedExclusionNames_AreAllAccepted()
    {
        Assert.IsTrue(AzureCredentialFactory.SupportedExclusionNames.Count > 0);

        foreach (string name in AzureCredentialFactory.SupportedExclusionNames)
        {
            Assert.IsNotNull(AzureCredentialFactory.CreateCredential(new[] { name }));
        }
    }

    /// <summary>
    /// Verifies a supplied credential bypasses default-chain settings and is not authenticated during provider creation.
    /// </summary>
    [TestMethod]
    public void CreateProvider_WithSuppliedCredential_DoesNotCreateDefaultCredential()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["aas-endpoint"] = "https://contoso.codesigning.azure.net/",
                ["aas-account-name"] = "test-account",
                ["aas-cert-profile-name"] = "test-profile",
                ["aas-exclude-credentials"] = "NotARealCredential"
            })
            .Build();
        Mock<TokenCredential> credential = new(MockBehavior.Strict);
        AzureArtifactSigningCertificateProviderPlugin plugin = new();

        Assert.IsNotNull(plugin.CreateProvider(configuration, logger: null, credential.Object));

        credential.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies that the comma-separated command line value is parsed.
    /// </summary>
    [TestMethod]
    public void GetExclusions_ReadsCommandLineValue()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["aas-exclude-credentials"] = "ManagedIdentityCredential, AzureCliCredential"
            })
            .Build();

        IReadOnlyList<string> exclusions = AzureCredentialFactory.GetExclusions(configuration);

        CollectionAssert.AreEquivalent(
            new[] { "ManagedIdentityCredential", "AzureCliCredential" },
            exclusions.ToArray());
    }

    /// <summary>
    /// Verifies that the JSON array form documented in the plugin usage is honored.
    /// </summary>
    [TestMethod]
    public void GetExclusions_ReadsJsonArraySection()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ExcludeCredentials:0"] = "ManagedIdentityCredential",
                ["ExcludeCredentials:1"] = "VisualStudioCredential"
            })
            .Build();

        IReadOnlyList<string> exclusions = AzureCredentialFactory.GetExclusions(configuration);

        CollectionAssert.AreEquivalent(
            new[] { "ManagedIdentityCredential", "VisualStudioCredential" },
            exclusions.ToArray());
    }

    /// <summary>
    /// Verifies that values from both sources are combined.
    /// </summary>
    [TestMethod]
    public void GetExclusions_CombinesBothSources()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["aas-exclude-credentials"] = "AzureCliCredential",
                ["ExcludeCredentials:0"] = "ManagedIdentityCredential"
            })
            .Build();

        IReadOnlyList<string> exclusions = AzureCredentialFactory.GetExclusions(configuration);

        CollectionAssert.AreEquivalent(
            new[] { "AzureCliCredential", "ManagedIdentityCredential" },
            exclusions.ToArray());
    }

    /// <summary>
    /// Verifies that an empty configuration yields no exclusions.
    /// </summary>
    [TestMethod]
    public void GetExclusions_EmptyConfiguration_ReturnsEmpty()
    {
        IReadOnlyList<string> exclusions = AzureCredentialFactory.GetExclusions(new ConfigurationBuilder().Build());

        Assert.AreEqual(0, exclusions.Count);
    }

    /// <summary>
    /// Verifies that a null configuration is rejected.
    /// </summary>
    [TestMethod]
    public void GetExclusions_NullConfiguration_Throws()
    {
        Assert.ThrowsException<ArgumentNullException>(() => AzureCredentialFactory.GetExclusions(null!));
    }
}

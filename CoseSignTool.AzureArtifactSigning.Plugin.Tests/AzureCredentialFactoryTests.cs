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

/// <summary>
/// Tests for <see cref="AzureCredentialFactory"/>.
/// </summary>
[TestClass]
public class AzureCredentialFactoryTests
{
    /// <summary>
    /// Clears the shared cache so each test observes a known starting state.
    /// </summary>
    [TestInitialize]
    public void Initialize()
    {
        AzureCredentialFactory.ClearCache();
    }

    /// <summary>
    /// Releases the shared cache so cached credentials do not leak between test classes.
    /// </summary>
    [TestCleanup]
    public void Cleanup()
    {
        AzureCredentialFactory.ClearCache();
    }

    /// <summary>
    /// Verifies that repeated requests for the same exclusion set reuse one credential, which is the
    /// whole point of the cache: a fresh credential would discard the token cache it holds.
    /// </summary>
    [TestMethod]
    public void GetCredential_SameExclusions_ReturnsSameInstance()
    {
        TokenCredential first = AzureCredentialFactory.GetCredential(new[] { "ManagedIdentityCredential" });
        TokenCredential second = AzureCredentialFactory.GetCredential(new[] { "ManagedIdentityCredential" });

        Assert.AreSame(first, second);
    }

    /// <summary>
    /// Verifies that no exclusions and an empty exclusion list share the same cache entry.
    /// </summary>
    [TestMethod]
    public void GetCredential_NullAndEmptyExclusions_ShareInstance()
    {
        TokenCredential fromNull = AzureCredentialFactory.GetCredential(null);
        TokenCredential fromEmpty = AzureCredentialFactory.GetCredential(Array.Empty<string>());

        Assert.AreSame(fromNull, fromEmpty);
    }

    /// <summary>
    /// Verifies that different exclusion sets get their own credential, since they configure
    /// different chains.
    /// </summary>
    [TestMethod]
    public void GetCredential_DifferentExclusions_ReturnsDifferentInstances()
    {
        TokenCredential withManagedIdentity = AzureCredentialFactory.GetCredential(new[] { "ManagedIdentityCredential" });
        TokenCredential withAzureCli = AzureCredentialFactory.GetCredential(new[] { "AzureCliCredential" });

        Assert.AreNotSame(withManagedIdentity, withAzureCli);
    }

    /// <summary>
    /// Verifies that names differing only by case, the optional "Credential" suffix, whitespace, or
    /// ordering resolve to the same cache entry.
    /// </summary>
    [TestMethod]
    public void GetCredential_EquivalentNames_ShareInstance()
    {
        TokenCredential canonical = AzureCredentialFactory.GetCredential(
            new[] { "ManagedIdentityCredential", "AzureCliCredential" });

        TokenCredential equivalent = AzureCredentialFactory.GetCredential(
            new[] { " azurecli ", "managedidentity", "ManagedIdentityCredential" });

        Assert.AreSame(canonical, equivalent);
    }

    /// <summary>
    /// Verifies that blank entries are ignored rather than treated as an unknown credential.
    /// </summary>
    [TestMethod]
    public void GetCredential_BlankEntries_AreIgnored()
    {
        TokenCredential withBlanks = AzureCredentialFactory.GetCredential(new[] { string.Empty, "   " });
        TokenCredential withNone = AzureCredentialFactory.GetCredential(null);

        Assert.AreSame(withNone, withBlanks);
    }

    /// <summary>
    /// Verifies that an unrecognized name fails fast instead of being silently ignored, which would
    /// leave a credential the caller believes is excluded still in the chain.
    /// </summary>
    [TestMethod]
    public void GetCredential_UnknownName_Throws()
    {
        ArgumentException exception = Assert.ThrowsException<ArgumentException>(
            () => AzureCredentialFactory.GetCredential(new[] { "NotARealCredential" }));

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
            Assert.IsNotNull(AzureCredentialFactory.GetCredential(new[] { name }));
        }
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

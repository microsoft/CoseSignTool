// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests;

using System.Security.Cryptography;
using CoseSignTool.Abstractions.Helpers;

/// <summary>
/// Tests for <see cref="CoseSigningAlgorithmHelper"/>.
/// </summary>
[TestClass]
public class CoseSigningAlgorithmHelperTests
{
    /// <summary>
    /// Verifies the default signing algorithm values.
    /// </summary>
    [TestMethod]
    public void GetSigningAlgorithms_WithoutConfiguration_UsesDefaults()
    {
        IConfiguration configuration = new ConfigurationBuilder().Build();

        Assert.AreEqual(HashAlgorithmName.SHA256, CoseSigningAlgorithmHelper.GetHashAlgorithm(configuration));
        Assert.AreSame(RSASignaturePadding.Pss, CoseSigningAlgorithmHelper.GetRsaSignaturePadding(configuration));
    }

    /// <summary>
    /// Verifies configured SHA-384 and PKCS#1 values.
    /// </summary>
    [TestMethod]
    public void GetSigningAlgorithms_WithConfiguration_ParsesValues()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["hash-algorithm"] = "SHA384",
                ["rsa-signature-padding"] = "PKCS1",
            })
            .Build();

        Assert.AreEqual(HashAlgorithmName.SHA384, CoseSigningAlgorithmHelper.GetHashAlgorithm(configuration));
        Assert.AreSame(RSASignaturePadding.Pkcs1, CoseSigningAlgorithmHelper.GetRsaSignaturePadding(configuration));
    }

    /// <summary>
    /// Verifies invalid algorithm values fail before signing.
    /// </summary>
    [TestMethod]
    public void ParseSigningAlgorithms_WithInvalidValues_Throws()
    {
        Assert.ThrowsException<InvalidOperationException>(
            () => CoseSigningAlgorithmHelper.ParseHashAlgorithm("MD5"));
        Assert.ThrowsException<InvalidOperationException>(
            () => CoseSigningAlgorithmHelper.ParseRsaSignaturePadding("OAEP"));
    }
}

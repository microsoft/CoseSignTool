// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests;

using System.Security.Cryptography;
using CoseSignTool.Abstractions.Helpers;

/// <summary>
/// Tests for <see cref="RsaSignaturePaddingHelper"/>.
/// </summary>
[TestClass]
public class RsaSignaturePaddingHelperTests
{
    /// <summary>
    /// Verifies that the PSS spellings, including the COSE algorithm prefix, resolve to PSS.
    /// </summary>
    /// <param name="value">The padding name to parse.</param>
    [TestMethod]
    [DataRow("PSS")]
    [DataRow("pss")]
    [DataRow("PS")]
    [DataRow("  ps  ")]
    public void Parse_PssSpellings_ReturnPss(string value)
    {
        Assert.AreEqual(RSASignaturePadding.Pss, RsaSignaturePaddingHelper.Parse(value));
    }

    /// <summary>
    /// Verifies that the PKCS#1 spellings, including the COSE algorithm prefix "RS", resolve to PKCS#1.
    /// </summary>
    /// <param name="value">The padding name to parse.</param>
    [TestMethod]
    [DataRow("PKCS1")]
    [DataRow("pkcs1")]
    [DataRow("PKCS1V15")]
    [DataRow("RS")]
    [DataRow("rs")]
    public void Parse_Pkcs1Spellings_ReturnPkcs1(string value)
    {
        Assert.AreEqual(RSASignaturePadding.Pkcs1, RsaSignaturePaddingHelper.Parse(value));
    }

    /// <summary>
    /// Verifies that an absent value keeps the historical PSS behavior.
    /// </summary>
    /// <param name="value">The padding name to parse.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    public void Parse_MissingValue_ReturnsPssDefault(string? value)
    {
        Assert.AreEqual(RSASignaturePadding.Pss, RsaSignaturePaddingHelper.Parse(value));
        Assert.AreEqual(RsaSignaturePaddingHelper.DefaultPadding, RsaSignaturePaddingHelper.Parse(value));
    }

    /// <summary>
    /// Verifies that an unrecognized padding name is rejected.
    /// </summary>
    [TestMethod]
    public void Parse_UnsupportedValue_Throws()
    {
        ArgumentException exception = Assert.ThrowsException<ArgumentException>(
            () => RsaSignaturePaddingHelper.Parse("oaep"));

        StringAssert.Contains(exception.Message, "oaep");
    }

    /// <summary>
    /// Verifies that the configuration overload reads the requested key.
    /// </summary>
    [TestMethod]
    public void Parse_FromConfiguration_ReadsRequestedKey()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["aas-rsa-padding"] = "PKCS1" })
            .Build();

        Assert.AreEqual(
            RSASignaturePadding.Pkcs1,
            RsaSignaturePaddingHelper.Parse(configuration, "aas-rsa-padding"));
    }

    /// <summary>
    /// Verifies that a missing configuration key falls back to the default.
    /// </summary>
    [TestMethod]
    public void Parse_FromConfiguration_MissingKey_ReturnsDefault()
    {
        Assert.AreEqual(
            RsaSignaturePaddingHelper.DefaultPadding,
            RsaSignaturePaddingHelper.Parse(new ConfigurationBuilder().Build(), "aas-rsa-padding"));
    }

    /// <summary>
    /// Verifies that a null configuration is rejected.
    /// </summary>
    [TestMethod]
    public void Parse_FromNullConfiguration_Throws()
    {
        Assert.ThrowsException<ArgumentNullException>(
            () => RsaSignaturePaddingHelper.Parse(null!, "aas-rsa-padding"));
    }

    /// <summary>
    /// Verifies the documented mapping from hash algorithm and padding to COSE algorithm name.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm name.</param>
    /// <param name="padding">The padding name.</param>
    /// <param name="expected">The expected COSE algorithm name.</param>
    [TestMethod]
    [DataRow("SHA256", "PKCS1", "RS256")]
    [DataRow("SHA384", "PKCS1", "RS384")]
    [DataRow("SHA512", "PKCS1", "RS512")]
    [DataRow("SHA256", "PSS", "PS256")]
    [DataRow("SHA384", "PSS", "PS384")]
    [DataRow("SHA512", "PSS", "PS512")]
    public void GetCoseAlgorithmName_MapsHashAndPadding(string hashAlgorithm, string padding, string expected)
    {
        string actual = RsaSignaturePaddingHelper.GetCoseAlgorithmName(
            HashAlgorithmHelper.Parse(hashAlgorithm),
            RsaSignaturePaddingHelper.Parse(padding));

        Assert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Verifies that a hash algorithm with no COSE RSA algorithm is rejected.
    /// </summary>
    [TestMethod]
    public void GetCoseAlgorithmName_UnsupportedHash_Throws()
    {
        Assert.ThrowsException<ArgumentException>(
            () => RsaSignaturePaddingHelper.GetCoseAlgorithmName(HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
    }
}
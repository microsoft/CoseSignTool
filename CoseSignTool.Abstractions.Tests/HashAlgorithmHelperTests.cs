// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests;

using System.Security.Cryptography;
using CoseSignTool.Abstractions.Helpers;

/// <summary>
/// Tests for <see cref="HashAlgorithmHelper"/>.
/// </summary>
[TestClass]
public class HashAlgorithmHelperTests
{
    /// <summary>
    /// Verifies that each supported algorithm name maps to the matching <see cref="HashAlgorithmName"/>.
    /// </summary>
    /// <param name="value">The algorithm name to parse.</param>
    /// <param name="expected">The expected <see cref="HashAlgorithmName.Name"/>.</param>
    [TestMethod]
    [DataRow("SHA256", "SHA256")]
    [DataRow("SHA384", "SHA384")]
    [DataRow("SHA512", "SHA512")]
    public void Parse_SupportedAlgorithm_ReturnsMatchingName(string value, string expected)
    {
        HashAlgorithmName result = HashAlgorithmHelper.Parse(value);

        Assert.AreEqual(expected, result.Name);
    }

    /// <summary>
    /// Verifies that casing, dashes, and surrounding whitespace are all tolerated.
    /// </summary>
    /// <param name="value">The algorithm name to parse.</param>
    [TestMethod]
    [DataRow("sha384")]
    [DataRow("Sha-384")]
    [DataRow("SHA-384")]
    [DataRow("  sha384  ")]
    public void Parse_NormalizesCaseDashAndWhitespace(string value)
    {
        HashAlgorithmName result = HashAlgorithmHelper.Parse(value);

        Assert.AreEqual(HashAlgorithmName.SHA384, result);
    }

    /// <summary>
    /// Verifies that an absent value falls back to the default algorithm.
    /// </summary>
    /// <param name="value">The algorithm name to parse.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    public void Parse_MissingValue_ReturnsDefault(string? value)
    {
        HashAlgorithmName result = HashAlgorithmHelper.Parse(value);

        Assert.AreEqual(HashAlgorithmHelper.DefaultHashAlgorithm, result);
        Assert.AreEqual(HashAlgorithmName.SHA256, result);
    }

    /// <summary>
    /// Verifies that algorithms outside the allow-list are rejected, including ones the platform
    /// otherwise supports such as SHA1 and MD5.
    /// </summary>
    /// <param name="value">The algorithm name to parse.</param>
    [TestMethod]
    [DataRow("SHA1")]
    [DataRow("MD5")]
    [DataRow("SHA3-256")]
    [DataRow("notahash")]
    public void Parse_UnsupportedAlgorithm_Throws(string value)
    {
        ArgumentException exception = Assert.ThrowsException<ArgumentException>(
            () => HashAlgorithmHelper.Parse(value));

        StringAssert.Contains(exception.Message, value);
        StringAssert.Contains(exception.Message, "SHA384");
    }

    /// <summary>
    /// Verifies that the configuration overload reads the requested key.
    /// </summary>
    [TestMethod]
    public void Parse_FromConfiguration_ReadsRequestedKey()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["hash-algorithm"] = "SHA512" })
            .Build();

        HashAlgorithmName result = HashAlgorithmHelper.Parse(configuration, "hash-algorithm");

        Assert.AreEqual(HashAlgorithmName.SHA512, result);
    }

    /// <summary>
    /// Verifies that a missing configuration key falls back to the default algorithm.
    /// </summary>
    [TestMethod]
    public void Parse_FromConfiguration_MissingKey_ReturnsDefault()
    {
        IConfiguration configuration = new ConfigurationBuilder().Build();

        HashAlgorithmName result = HashAlgorithmHelper.Parse(configuration, "hash-algorithm");

        Assert.AreEqual(HashAlgorithmHelper.DefaultHashAlgorithm, result);
    }

    /// <summary>
    /// Verifies that a null configuration is rejected.
    /// </summary>
    [TestMethod]
    public void Parse_FromNullConfiguration_Throws()
    {
        Assert.ThrowsException<ArgumentNullException>(
            () => HashAlgorithmHelper.Parse(null!, "hash-algorithm"));
    }

    /// <summary>
    /// Verifies the documented allow-list matches what <see cref="HashAlgorithmHelper.Parse(string?)"/> accepts.
    /// </summary>
    [TestMethod]
    public void SupportedHashAlgorithms_AreAllParsable()
    {
        foreach (string name in HashAlgorithmHelper.SupportedHashAlgorithms)
        {
            Assert.AreEqual(name, HashAlgorithmHelper.Parse(name).Name);
        }
    }
}

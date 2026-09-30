// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Headers;
using CoseSign1.Headers.Local;
using CoseSignTool.Abstractions.Helpers;

/// <summary>
/// Tests for <see cref="CoseHeaderHelper"/>.
/// </summary>
[TestClass]
public class CoseHeaderHelperTests
{
    private static readonly string SampleCborBase64 = EncodeByteString(new byte[] { 0x01, 0x02, 0x03, 0x04 });

    /// <summary>
    /// Verifies that integer and string labels preserve their encoded CBOR values.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_WithCborHeaders_PreservesEncodedValues()
    {
        CoseHeaderExtender? extender = CoseHeaderHelper.CreateHeaderExtender(
            null,
            null,
            CoseHeaderHelper.ParseCborHeaders($"4242={SampleCborBase64}"),
            CoseHeaderHelper.ParseCborHeaders($"vendor-signature={SampleCborBase64}"));

        Assert.IsNotNull(extender);
        CoseHeaderMap protectedHeaders = extender.ExtendProtectedHeaders(new CoseHeaderMap());
        CoseHeaderMap unprotectedHeaders = extender.ExtendUnProtectedHeaders(new CoseHeaderMap());

        CollectionAssert.AreEqual(
            Convert.FromBase64String(SampleCborBase64),
            protectedHeaders[new CoseHeaderLabel(4242)].EncodedValue.ToArray());
        CollectionAssert.AreEqual(
            Convert.FromBase64String(SampleCborBase64),
            unprotectedHeaders[new CoseHeaderLabel("vendor-signature")].EncodedValue.ToArray());
    }

    /// <summary>
    /// Verifies that typed and CBOR-valued headers can be used together.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_WithTypedAndCborHeaders_IncludesBoth()
    {
        List<CoseHeader<int>> intHeaders = new()
        {
            new CoseHeader<int>("version", 1, true)
        };

        CoseHeaderExtender? extender = CoseHeaderHelper.CreateHeaderExtender(
            intHeaders,
            null,
            CoseHeaderHelper.ParseCborHeaders($"4242={SampleCborBase64}"),
            null);

        Assert.IsNotNull(extender);
        CoseHeaderMap protectedHeaders = extender.ExtendProtectedHeaders(new CoseHeaderMap());
        Assert.IsTrue(protectedHeaders.ContainsKey(new CoseHeaderLabel("version")));
        Assert.IsTrue(protectedHeaders.ContainsKey(new CoseHeaderLabel(4242)));
    }

    /// <summary>
    /// Verifies that configuration-based consumers, including plugins, receive CBOR header support.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_FromConfiguration_AddsCborHeaders()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["cbor-protected-headers"] = $"1000={SampleCborBase64}",
                ["cbor-unprotected-headers"] = $"2000={SampleCborBase64}"
            })
            .Build();

        CoseHeaderExtender? extender = CoseHeaderHelper.CreateHeaderExtender(configuration);

        Assert.IsNotNull(extender);
        Assert.IsTrue(extender.ExtendProtectedHeaders(new CoseHeaderMap()).ContainsKey(new CoseHeaderLabel(1000)));
        Assert.IsTrue(extender.ExtendUnProtectedHeaders(new CoseHeaderMap()).ContainsKey(new CoseHeaderLabel(2000)));
    }

    /// <summary>
    /// Verifies that malformed specifications fail before signing.
    /// </summary>
    /// <param name="specification">The invalid header specification.</param>
    [TestMethod]
    [DataRow("missing-separator")]
    [DataRow("=RAECAwQ=")]
    [DataRow("4242=")]
    [DataRow("4242=not-base64")]
    public void ParseCborHeaders_WithInvalidSpecification_Throws(string specification)
    {
        Assert.ThrowsException<ArgumentException>(
            () => CoseHeaderHelper.ParseCborHeaders(specification));
    }

    /// <summary>
    /// Verifies that malformed CBOR and trailing data are rejected.
    /// </summary>
    /// <param name="encodedValue">The invalid base64-encoded CBOR.</param>
    [TestMethod]
    [DataRow("Xw==")]
    [DataRow("AQI=")]
    public void ParseCborHeaders_WithInvalidCbor_Throws(string encodedValue)
    {
        Assert.ThrowsException<ArgumentException>(
            () => CoseHeaderHelper.ParseCborHeaders($"4242={encodedValue}"));
    }

    private static string EncodeByteString(byte[] value)
    {
        CborWriter writer = new();
        writer.WriteByteString(value);
        return Convert.ToBase64String(writer.Encode());
    }
}

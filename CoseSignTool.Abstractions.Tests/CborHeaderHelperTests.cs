// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Headers;
using CoseSignTool.Abstractions.Helpers;

/// <summary>
/// Tests for <see cref="CborHeaderHelper"/>.
/// </summary>
[TestClass]
public class CborHeaderHelperTests
{
    /// <summary>
    /// A base64-encoded CBOR byte string, standing in for a vendor signature blob.
    /// </summary>
    private static readonly string SampleCborBase64 = EncodeByteString(new byte[] { 0x01, 0x02, 0x03, 0x04 });

    /// <summary>
    /// Verifies that a numeric label produces an integer <see cref="CoseHeaderLabel"/> carrying the
    /// exact bytes that were supplied, so the original encoding survives round-trip.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_IntegerLabel_AddsEncodedValueVerbatim()
    {
        CoseHeaderExtender? extender = CborHeaderHelper.CreateHeaderExtender(
            new[] { $"4242={SampleCborBase64}" },
            null);

        Assert.IsNotNull(extender);
        CoseHeaderMap result = extender!.ExtendProtectedHeaders(new CoseHeaderMap());

        Assert.IsTrue(result.TryGetValue(new CoseHeaderLabel(4242), out CoseHeaderValue value));
        CollectionAssert.AreEqual(
            Convert.FromBase64String(SampleCborBase64),
            value.EncodedValue.ToArray());
    }

    /// <summary>
    /// Verifies that a non-numeric label produces a string <see cref="CoseHeaderLabel"/>.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_StringLabel_UsesStringHeaderLabel()
    {
        CoseHeaderExtender? extender = CborHeaderHelper.CreateHeaderExtender(
            new[] { $"vendor-signature={SampleCborBase64}" },
            null);

        Assert.IsNotNull(extender);
        CoseHeaderMap result = extender!.ExtendProtectedHeaders(new CoseHeaderMap());

        Assert.IsTrue(result.ContainsKey(new CoseHeaderLabel("vendor-signature")));
        Assert.IsFalse(result.ContainsKey(new CoseHeaderLabel(4242)));
    }

    /// <summary>
    /// Verifies that protected and unprotected specifications land in their respective maps.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_SeparatesProtectedAndUnprotectedHeaders()
    {
        CoseHeaderExtender? extender = CborHeaderHelper.CreateHeaderExtender(
            new[] { $"1000={SampleCborBase64}" },
            new[] { $"2000={SampleCborBase64}" });

        Assert.IsNotNull(extender);
        CoseHeaderMap protectedMap = extender!.ExtendProtectedHeaders(new CoseHeaderMap());
        CoseHeaderMap unProtectedMap = extender.ExtendUnProtectedHeaders(new CoseHeaderMap());

        Assert.IsTrue(protectedMap.ContainsKey(new CoseHeaderLabel(1000)));
        Assert.IsFalse(protectedMap.ContainsKey(new CoseHeaderLabel(2000)));
        Assert.IsTrue(unProtectedMap.ContainsKey(new CoseHeaderLabel(2000)));
        Assert.IsFalse(unProtectedMap.ContainsKey(new CoseHeaderLabel(1000)));
    }

    /// <summary>
    /// Verifies that existing headers are preserved when the extender merges its own values in.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_PreservesExistingHeaders()
    {
        CoseHeaderMap existing = new()
        {
            { new CoseHeaderLabel("pre-existing"), CoseHeaderValue.FromString("kept") }
        };

        CoseHeaderExtender? extender = CborHeaderHelper.CreateHeaderExtender(
            new[] { $"4242={SampleCborBase64}" },
            null);

        CoseHeaderMap result = extender!.ExtendProtectedHeaders(existing);

        Assert.IsTrue(result.ContainsKey(new CoseHeaderLabel("pre-existing")));
        Assert.IsTrue(result.ContainsKey(new CoseHeaderLabel(4242)));
    }

    /// <summary>
    /// Verifies that supplying nothing yields no extender, so callers can skip chaining entirely.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_NoSpecifications_ReturnsNull()
    {
        Assert.IsNull(CborHeaderHelper.CreateHeaderExtender(null, null));
        Assert.IsNull(CborHeaderHelper.CreateHeaderExtender(Array.Empty<string>(), Array.Empty<string>()));
        Assert.IsNull(CborHeaderHelper.CreateHeaderExtender(new[] { "   " }, null));
    }

    /// <summary>
    /// Verifies that malformed specifications are rejected during parsing.
    /// </summary>
    /// <param name="specification">The specification to parse.</param>
    [TestMethod]
    [DataRow("noequalssign")]
    [DataRow("=RgABAgME")]
    public void CreateHeaderExtender_MalformedSpecification_Throws(string specification)
    {
        Assert.ThrowsException<ArgumentException>(
            () => CborHeaderHelper.CreateHeaderExtender(new[] { specification }, null));
    }

    /// <summary>
    /// Verifies that a value which is not valid base64 is rejected.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_InvalidBase64_Throws()
    {
        ArgumentException exception = Assert.ThrowsException<ArgumentException>(
            () => CborHeaderHelper.CreateHeaderExtender(new[] { "4242=not!base64!" }, null));

        StringAssert.Contains(exception.Message, "4242");
    }

    /// <summary>
    /// Verifies that an empty value is rejected rather than producing a zero-length header.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_EmptyValue_Throws()
    {
        Assert.ThrowsException<ArgumentException>(
            () => CborHeaderHelper.CreateHeaderExtender(new[] { "4242=" }, null));
    }

    /// <summary>
    /// Verifies that bytes which are not well-formed CBOR are rejected, so a signature is never
    /// produced with an undecodable header.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_MalformedCbor_Throws()
    {
        // 0x5F starts an indefinite-length byte string that is never terminated.
        string malformed = Convert.ToBase64String(new byte[] { 0x5F });

        ArgumentException exception = Assert.ThrowsException<ArgumentException>(
            () => CborHeaderHelper.CreateHeaderExtender(new[] { $"4242={malformed}" }, null));

        StringAssert.Contains(exception.Message, "4242");
    }

    /// <summary>
    /// Verifies that more than one CBOR data item in a single value is rejected.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_TrailingBytes_Throws()
    {
        // Two consecutive unsigned integers: 1 followed by 2.
        string twoItems = Convert.ToBase64String(new byte[] { 0x01, 0x02 });

        ArgumentException exception = Assert.ThrowsException<ArgumentException>(
            () => CborHeaderHelper.CreateHeaderExtender(new[] { $"4242={twoItems}" }, null));

        StringAssert.Contains(exception.Message, "trailing");
    }

    /// <summary>
    /// Verifies that a base64 value containing '=' padding is not truncated by the label split.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_ValueContainingPadding_IsParsedIntact()
    {
        string padded = EncodeByteString(new byte[] { 0xAA });
        Assert.IsTrue(padded.Contains('='), "Test vector should exercise base64 padding.");

        CoseHeaderExtender? extender = CborHeaderHelper.CreateHeaderExtender(
            new[] { $"4242={padded}" },
            null);

        CoseHeaderMap result = extender!.ExtendProtectedHeaders(new CoseHeaderMap());

        Assert.IsTrue(result.TryGetValue(new CoseHeaderLabel(4242), out CoseHeaderValue value));
        CollectionAssert.AreEqual(Convert.FromBase64String(padded), value.EncodedValue.ToArray());
    }

    /// <summary>
    /// Verifies that the configuration overload splits comma-separated specifications.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_FromConfiguration_SplitsCommaSeparatedValues()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["cbor-protected-headers"] = $"1000={SampleCborBase64}, 1001={SampleCborBase64}",
                ["cbor-unprotected-headers"] = $"2000={SampleCborBase64}"
            })
            .Build();

        CoseHeaderExtender? extender = CborHeaderHelper.CreateHeaderExtender(configuration);

        Assert.IsNotNull(extender);
        CoseHeaderMap protectedMap = extender!.ExtendProtectedHeaders(new CoseHeaderMap());

        Assert.IsTrue(protectedMap.ContainsKey(new CoseHeaderLabel(1000)));
        Assert.IsTrue(protectedMap.ContainsKey(new CoseHeaderLabel(1001)));
        Assert.IsTrue(extender.ExtendUnProtectedHeaders(new CoseHeaderMap()).ContainsKey(new CoseHeaderLabel(2000)));
    }

    /// <summary>
    /// Verifies that an empty configuration yields no extender.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_FromEmptyConfiguration_ReturnsNull()
    {
        Assert.IsNull(CborHeaderHelper.CreateHeaderExtender(new ConfigurationBuilder().Build()));
    }

    /// <summary>
    /// Verifies that a null configuration is rejected.
    /// </summary>
    [TestMethod]
    public void CreateHeaderExtender_FromNullConfiguration_Throws()
    {
        Assert.ThrowsException<ArgumentNullException>(
            () => CborHeaderHelper.CreateHeaderExtender((IConfiguration)null!));
    }

    /// <summary>
    /// Encodes bytes as a CBOR byte string and returns the base64 form.
    /// </summary>
    /// <param name="value">The bytes to wrap in a CBOR byte string.</param>
    /// <returns>The base64-encoded CBOR data item.</returns>
    private static string EncodeByteString(byte[] value)
    {
        CborWriter writer = new();
        writer.WriteByteString(value);
        return Convert.ToBase64String(writer.Encode());
    }
}

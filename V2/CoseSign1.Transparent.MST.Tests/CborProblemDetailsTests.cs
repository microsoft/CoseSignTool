// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System.Formats.Cbor;
using CoseSign1.Transparent.MST;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class CborProblemDetailsTests
{
    #region TryParse Tests

    [Test]
    public void TryParse_NullInput_ReturnsNull()
    {
        CborProblemDetails? result = CborProblemDetails.TryParse(null!);
        Assert.That(result, Is.Null);
    }

    [Test]
    public void TryParse_EmptyInput_ReturnsNull()
    {
        CborProblemDetails? result = CborProblemDetails.TryParse(Array.Empty<byte>());
        Assert.That(result, Is.Null);
    }

    [Test]
    public void TryParse_InvalidCbor_ReturnsNull()
    {
        CborProblemDetails? result = CborProblemDetails.TryParse(new byte[] { 0xFF, 0xFE, 0xFD });
        Assert.That(result, Is.Null);
    }

    [Test]
    public void TryParse_NonMapCbor_ReturnsNull()
    {
        // Encode a CBOR array instead of a map
        CborWriter writer = new();
        writer.WriteStartArray(1);
        writer.WriteTextString("not a map");
        writer.WriteEndArray();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());
        Assert.That(result, Is.Null);
    }

    [Test]
    public void TryParse_IntegerKeys_ParsesAllStandardFields()
    {
        // Build a CBOR map with integer keys per RFC 9290
        CborWriter writer = new();
        writer.WriteStartMap(5);
        writer.WriteInt32(-1); writer.WriteTextString("urn:example:type");
        writer.WriteInt32(-2); writer.WriteTextString("Bad Request");
        writer.WriteInt32(-3); writer.WriteInt32(400);
        writer.WriteInt32(-4); writer.WriteTextString("The input was invalid");
        writer.WriteInt32(-5); writer.WriteTextString("urn:example:instance:123");
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Type, Is.EqualTo("urn:example:type"));
            Assert.That(result.Title, Is.EqualTo("Bad Request"));
            Assert.That(result.Status, Is.EqualTo(400));
            Assert.That(result.Detail, Is.EqualTo("The input was invalid"));
            Assert.That(result.Instance, Is.EqualTo("urn:example:instance:123"));
            Assert.That(result.Extensions, Is.Null);
        });
    }

    [Test]
    public void TryParse_StringKeys_ParsesAllStandardFields()
    {
        CborWriter writer = new();
        writer.WriteStartMap(5);
        writer.WriteTextString("type"); writer.WriteTextString("urn:example:type");
        writer.WriteTextString("title"); writer.WriteTextString("Not Found");
        writer.WriteTextString("status"); writer.WriteInt32(404);
        writer.WriteTextString("detail"); writer.WriteTextString("Resource missing");
        writer.WriteTextString("instance"); writer.WriteTextString("urn:example:instance:456");
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Type, Is.EqualTo("urn:example:type"));
            Assert.That(result.Title, Is.EqualTo("Not Found"));
            Assert.That(result.Status, Is.EqualTo(404));
            Assert.That(result.Detail, Is.EqualTo("Resource missing"));
            Assert.That(result.Instance, Is.EqualTo("urn:example:instance:456"));
        });
    }

    [Test]
    public void TryParse_WithExtensionFields_CapturesExtensions()
    {
        CborWriter writer = new();
        writer.WriteStartMap(3);
        writer.WriteInt32(-2); writer.WriteTextString("Error");
        writer.WriteInt32(42); writer.WriteTextString("custom-extension-value");
        writer.WriteTextString("EntryId"); writer.WriteTextString("abc-123");
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Title, Is.EqualTo("Error"));
            Assert.That(result.Extensions, Is.Not.Null);
            Assert.That(result.Extensions!["key_42"], Is.EqualTo("custom-extension-value"));
            Assert.That(result.Extensions["EntryId"], Is.EqualTo("abc-123"));
        });
    }

    [Test]
    public void TryParse_WithNullValues_HandlesGracefully()
    {
        CborWriter writer = new();
        writer.WriteStartMap(3);
        writer.WriteInt32(-1); writer.WriteNull();
        writer.WriteInt32(-3); writer.WriteNull();
        writer.WriteInt32(-4); writer.WriteNull();
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Type, Is.Null);
            Assert.That(result.Status, Is.Null);
            Assert.That(result.Detail, Is.Null);
        });
    }

    [Test]
    public void TryParse_EmptyMap_ReturnsEmptyDetails()
    {
        CborWriter writer = new();
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Type, Is.Null);
            Assert.That(result.Title, Is.Null);
            Assert.That(result.Status, Is.Null);
            Assert.That(result.Detail, Is.Null);
            Assert.That(result.Instance, Is.Null);
            Assert.That(result.Extensions, Is.Null);
        });
    }

    [Test]
    public void TryParse_WithNonStringNonIntKey_SkipsEntry()
    {
        // Build a CBOR map with a byte-string key that should be skipped
        CborWriter writer = new();
        writer.WriteStartMap(2);
        writer.WriteInt32(-2); writer.WriteTextString("Title");
        writer.WriteByteString(new byte[] { 0x01 }); writer.WriteTextString("skipped-value");
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Title, Is.EqualTo("Title"));
    }

    [Test]
    public void TryParse_TypeMismatch_SkipsField()
    {
        // status field as string instead of int - ReadIntValue should skip
        CborWriter writer = new();
        writer.WriteStartMap(2);
        writer.WriteInt32(-2); writer.WriteTextString("Title");
        writer.WriteInt32(-3); writer.WriteTextString("not-an-int");
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Title, Is.EqualTo("Title"));
            Assert.That(result.Status, Is.Null);
        });
    }

    [Test]
    public void TryParse_StringFieldAsInt_SkipsField()
    {
        // type field (-1) as integer instead of string - ReadStringValue should skip
        CborWriter writer = new();
        writer.WriteStartMap(2);
        writer.WriteInt32(-1); writer.WriteInt32(42);
        writer.WriteInt32(-2); writer.WriteTextString("Title");
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(result!.Type, Is.Null);
            Assert.That(result.Title, Is.EqualTo("Title"));
        });
    }

    #endregion

    #region ToString Tests

    [Test]
    public void ToString_WithAllFields_FormatsCorrectly()
    {
        CborProblemDetails details = new()
        {
            Type = "urn:example:type",
            Title = "Bad Request",
            Status = 400,
            Detail = "Input invalid",
            Instance = "urn:example:123"
        };

        string result = details.ToString();

        Assert.Multiple(() =>
        {
            Assert.That(result, Does.Contain("Title: Bad Request"));
            Assert.That(result, Does.Contain("Status: 400"));
            Assert.That(result, Does.Contain("Detail: Input invalid"));
            Assert.That(result, Does.Contain("Type: urn:example:type"));
            Assert.That(result, Does.Contain("Instance: urn:example:123"));
        });
    }

    [Test]
    public void ToString_WithNoFields_ReturnsNoDetailsAvailable()
    {
        CborProblemDetails details = new();

        string result = details.ToString();

        Assert.That(result, Is.EqualTo("No details available"));
    }

    [Test]
    public void ToString_WithPartialFields_IncludesOnlyAvailable()
    {
        CborProblemDetails details = new()
        {
            Title = "Server Error",
            Status = 500
        };

        string result = details.ToString();

        Assert.Multiple(() =>
        {
            Assert.That(result, Does.Contain("Title: Server Error"));
            Assert.That(result, Does.Contain("Status: 500"));
            Assert.That(result, Does.Not.Contain("Detail:"));
            Assert.That(result, Does.Not.Contain("Type:"));
        });
    }

    #endregion

    #region ReadAnyValue Coverage Tests

    [Test]
    public void TryParse_ExtensionWithBooleanValue_ParsesCorrectly()
    {
        CborWriter writer = new();
        writer.WriteStartMap(1);
        writer.WriteTextString("isRetryable"); writer.WriteBoolean(true);
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Extensions!["isRetryable"], Is.EqualTo(true));
    }

    [Test]
    public void TryParse_ExtensionWithByteStringValue_ParsesCorrectly()
    {
        CborWriter writer = new();
        writer.WriteStartMap(1);
        writer.WriteTextString("rawData"); writer.WriteByteString(new byte[] { 0xDE, 0xAD });
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Extensions!["rawData"], Is.EqualTo(new byte[] { 0xDE, 0xAD }));
    }

    [Test]
    public void TryParse_ExtensionWithIntegerValue_ParsesCorrectly()
    {
        CborWriter writer = new();
        writer.WriteStartMap(1);
        writer.WriteTextString("retryCount"); writer.WriteInt64(42);
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Extensions!["retryCount"], Is.EqualTo(42L));
    }

    [Test]
    public void TryParse_ExtensionWithNullValue_ParsesAsNull()
    {
        CborWriter writer = new();
        writer.WriteStartMap(1);
        writer.WriteTextString("optional"); writer.WriteNull();
        writer.WriteEndMap();

        CborProblemDetails? result = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Extensions!["optional"], Is.Null);
    }

    #endregion
}
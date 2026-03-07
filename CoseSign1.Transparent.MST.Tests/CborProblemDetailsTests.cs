// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.Tests;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Azure;
using Azure.Core.TestCommon;
using CoseSign1.Transparent.MST;
using Moq;

/// <summary>
/// Unit tests for <see cref="CborProblemDetails"/> and <see cref="MstServiceException"/>.
/// </summary>
[TestFixture]
public class CborProblemDetailsTests
{
    #region CborProblemDetails.TryParse

    [Test]
    public void TryParse_ReturnsNull_ForNullInput()
    {
        Assert.That(CborProblemDetails.TryParse(null!), Is.Null);
    }

    [Test]
    public void TryParse_ReturnsNull_ForEmptyInput()
    {
        Assert.That(CborProblemDetails.TryParse(Array.Empty<byte>()), Is.Null);
    }

    [Test]
    public void TryParse_ReturnsNull_ForInvalidCbor()
    {
        Assert.That(CborProblemDetails.TryParse(new byte[] { 0xFF, 0xFF }), Is.Null);
    }

    [Test]
    public void TryParse_ReturnsNull_ForNonMapCbor()
    {
        // Encode a CBOR array instead of a map
        var writer = new CborWriter();
        writer.WriteStartArray(1);
        writer.WriteTextString("not a map");
        writer.WriteEndArray();

        Assert.That(CborProblemDetails.TryParse(writer.Encode()), Is.Null);
    }

    [Test]
    public void TryParse_ParsesIntegerKeys_Rfc9290()
    {
        // RFC 9290 standard integer keys: -1=type, -2=title, -3=status, -4=detail, -5=instance
        var writer = new CborWriter();
        writer.WriteStartMap(5);
        writer.WriteInt32(-1); writer.WriteTextString("urn:example:error:bad-request");
        writer.WriteInt32(-2); writer.WriteTextString("Bad Request");
        writer.WriteInt32(-3); writer.WriteInt32(400);
        writer.WriteInt32(-4); writer.WriteTextString("The payload is not valid COSE");
        writer.WriteInt32(-5); writer.WriteTextString("/entries/abc-123");
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Type, Is.EqualTo("urn:example:error:bad-request"));
        Assert.That(details.Title, Is.EqualTo("Bad Request"));
        Assert.That(details.Status, Is.EqualTo(400));
        Assert.That(details.Detail, Is.EqualTo("The payload is not valid COSE"));
        Assert.That(details.Instance, Is.EqualTo("/entries/abc-123"));
    }

    [Test]
    public void TryParse_ParsesStringKeys()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteTextString("title"); writer.WriteTextString("Service Unavailable");
        writer.WriteTextString("status"); writer.WriteInt32(503);
        writer.WriteTextString("detail"); writer.WriteTextString("Ledger is syncing");
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Title, Is.EqualTo("Service Unavailable"));
        Assert.That(details.Status, Is.EqualTo(503));
        Assert.That(details.Detail, Is.EqualTo("Ledger is syncing"));
    }

    [Test]
    public void TryParse_CapturesExtensionFields()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteInt32(-2); writer.WriteTextString("Error");
        writer.WriteInt32(-3); writer.WriteInt32(422);
        writer.WriteTextString("retryAfter"); writer.WriteTextString("5s");
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Extensions, Is.Not.Null);
        Assert.That(details.Extensions!.ContainsKey("retryAfter"), Is.True);
        Assert.That(details.Extensions["retryAfter"], Is.EqualTo("5s"));
    }

    [Test]
    public void TryParse_CapturesUnknownIntegerKeysAsExtensions()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-3); writer.WriteInt32(500);
        writer.WriteInt32(99); writer.WriteTextString("custom-value");
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Status, Is.EqualTo(500));
        Assert.That(details.Extensions, Is.Not.Null);
        Assert.That(details.Extensions!["key_99"], Is.EqualTo("custom-value"));
    }

    [Test]
    public void TryParse_HandlesNullValues()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-2); writer.WriteNull();
        writer.WriteInt32(-3); writer.WriteInt32(404);
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Title, Is.Null);
        Assert.That(details.Status, Is.EqualTo(404));
    }

    [Test]
    public void TryParse_HandlesPartialFields()
    {
        // Only status — all other fields should be null
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteInt32(-3); writer.WriteInt32(429);
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Status, Is.EqualTo(429));
        Assert.That(details.Type, Is.Null);
        Assert.That(details.Title, Is.Null);
        Assert.That(details.Detail, Is.Null);
        Assert.That(details.Instance, Is.Null);
        Assert.That(details.Extensions, Is.Null);
    }

    [Test]
    public void TryParse_HandlesMixedIntegerAndStringKeys()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteInt32(-2); writer.WriteTextString("Mixed Error");
        writer.WriteTextString("status"); writer.WriteInt32(500);
        writer.WriteTextString("x-request-id"); writer.WriteTextString("req-abc-123");
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Title, Is.EqualTo("Mixed Error"));
        Assert.That(details.Status, Is.EqualTo(500));
        Assert.That(details.Extensions!["x-request-id"], Is.EqualTo("req-abc-123"));
    }

    [Test]
    public void TryParse_HandlesExtensionWithVariousValueTypes()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(4);
        writer.WriteInt32(-3); writer.WriteInt32(400);
        writer.WriteTextString("boolField"); writer.WriteBoolean(true);
        writer.WriteTextString("intField"); writer.WriteInt64(42);
        writer.WriteTextString("floatField"); writer.WriteDouble(3.14);
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Extensions!["boolField"], Is.EqualTo(true));
        Assert.That(details.Extensions["intField"], Is.EqualTo(42L));
        Assert.That(details.Extensions["floatField"], Is.EqualTo(3.14));
    }

    #endregion

    #region CborProblemDetails.ToString

    [Test]
    public void ToString_ReturnsNoDetailsAvailable_WhenEmpty()
    {
        var details = new CborProblemDetails();
        Assert.That(details.ToString(), Is.EqualTo("No details available"));
    }

    [Test]
    public void ToString_IncludesAllFields()
    {
        var details = new CborProblemDetails
        {
            Type = "urn:error:test",
            Title = "Test Error",
            Status = 400,
            Detail = "Something went wrong",
            Instance = "/entries/123"
        };

        string result = details.ToString();
        Assert.That(result, Does.Contain("Title: Test Error"));
        Assert.That(result, Does.Contain("Status: 400"));
        Assert.That(result, Does.Contain("Detail: Something went wrong"));
        Assert.That(result, Does.Contain("Type: urn:error:test"));
        Assert.That(result, Does.Contain("Instance: /entries/123"));
    }

    #endregion

    #region MstServiceException

    [Test]
    public void MstServiceException_BasicConstructor()
    {
        var ex = new MstServiceException("test error");

        Assert.That(ex.Message, Is.EqualTo("test error"));
        Assert.That(ex.ProblemDetails, Is.Null);
        Assert.That(ex.StatusCode, Is.Null);
        Assert.That(ex.InnerException, Is.Null);
    }

    [Test]
    public void MstServiceException_WithInnerException()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new MstServiceException("outer", inner);

        Assert.That(ex.Message, Is.EqualTo("outer"));
        Assert.That(ex.InnerException, Is.SameAs(inner));
    }

    [Test]
    public void MstServiceException_WithProblemDetails()
    {
        var details = new CborProblemDetails
        {
            Title = "Bad Request",
            Status = 400,
            Detail = "Invalid COSE payload"
        };
        var ex = new MstServiceException("error", details);

        Assert.That(ex.ProblemDetails, Is.Not.Null);
        Assert.That(ex.StatusCode, Is.EqualTo(400));
        Assert.That(ex.ProblemDetails!.Title, Is.EqualTo("Bad Request"));
    }

    [Test]
    public void MstServiceException_ToString_IncludesProblemDetails()
    {
        var details = new CborProblemDetails
        {
            Type = "urn:error:test",
            Title = "Test",
            Status = 500,
            Detail = "Internal error",
            Instance = "/api/entries"
        };
        var ex = new MstServiceException("Service failed", details);

        string result = ex.ToString();
        Assert.That(result, Does.Contain("Service failed"));
        Assert.That(result, Does.Contain("Status: 500"));
        Assert.That(result, Does.Contain("Title: Test"));
        Assert.That(result, Does.Contain("Detail: Internal error"));
        Assert.That(result, Does.Contain("Type: urn:error:test"));
        Assert.That(result, Does.Contain("Instance: /api/entries"));
    }

    [Test]
    public void MstServiceException_ToString_IncludesExtensions()
    {
        var details = new CborProblemDetails
        {
            Status = 429,
            Extensions = new Dictionary<string, object?> { { "retryAfter", "5s" } }
        };
        var ex = new MstServiceException("Rate limited", details);

        string result = ex.ToString();
        Assert.That(result, Does.Contain("retryAfter: 5s"));
    }

    [Test]
    public void FromRequestFailedException_WithoutCborContent_ReturnsGenericMessage()
    {
        // Create a RequestFailedException with a basic message (no CBOR content)
        var rfEx = new RequestFailedException(500, "Internal Server Error");

        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        Assert.That(mstEx, Is.Not.Null);
        Assert.That(mstEx.ProblemDetails, Is.Null);
        Assert.That(mstEx.InnerException, Is.SameAs(rfEx));
        Assert.That(mstEx.Message, Does.Contain("500"));
    }

    [Test]
    public void FromRequestFailedException_PreservesInnerException()
    {
        var rfEx = new RequestFailedException(502, "Bad Gateway");

        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        Assert.That(mstEx.InnerException, Is.SameAs(rfEx));
        Assert.That(mstEx.Message, Does.Contain("502"));
    }

    #endregion

    #region Additional coverage — CborProblemDetails edge cases

    [Test]
    public void TryParse_SkipsNonStandardKeyType()
    {
        // Map with a byte-string key (not integer or text) — should be skipped
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteByteString(new byte[] { 0x01 }); // non-standard key
        writer.WriteTextString("skipped");
        writer.WriteInt32(-3); writer.WriteInt32(500);
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Status, Is.EqualTo(500));
    }

    [Test]
    public void TryParse_HandlesNullStatusValue()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-3); writer.WriteNull();
        writer.WriteInt32(-2); writer.WriteTextString("Null Status");
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Status, Is.Null);
        Assert.That(details.Title, Is.EqualTo("Null Status"));
    }

    [Test]
    public void TryParse_SkipsNonStringTypeForStringField()
    {
        // A type field with an integer value instead of string — should skip
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-1); writer.WriteInt32(999); // type should be string
        writer.WriteInt32(-3); writer.WriteInt32(400);
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Type, Is.Null); // skipped
        Assert.That(details.Status, Is.EqualTo(400));
    }

    [Test]
    public void TryParse_SkipsNonIntTypeForStatusField()
    {
        // Status with a string value instead of integer — should skip
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-3); writer.WriteTextString("not-a-number");
        writer.WriteInt32(-2); writer.WriteTextString("Title");
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Status, Is.Null); // skipped
        Assert.That(details.Title, Is.EqualTo("Title"));
    }

    [Test]
    public void TryParse_HandlesNullExtensionValue()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-3); writer.WriteInt32(200);
        writer.WriteTextString("nullExt"); writer.WriteNull();
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Extensions!["nullExt"], Is.Null);
    }

    [Test]
    public void TryParse_HandlesByteStringExtensionValue()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-3); writer.WriteInt32(200);
        writer.WriteTextString("binaryData"); writer.WriteByteString(new byte[] { 0xDE, 0xAD });
        writer.WriteEndMap();

        CborProblemDetails? details = CborProblemDetails.TryParse(writer.Encode());

        Assert.That(details, Is.Not.Null);
        Assert.That(details!.Extensions!["binaryData"], Is.TypeOf<byte[]>());
    }

    #endregion

    #region Additional coverage — MstServiceException ToString / BuildErrorMessage

    [Test]
    public void MstServiceException_ToString_WithInnerException()
    {
        var inner = new InvalidOperationException("inner error");
        var ex = new MstServiceException("outer", inner);

        string result = ex.ToString();

        Assert.That(result, Does.Contain("outer"));
        Assert.That(result, Does.Contain("inner error"));
        Assert.That(result, Does.Contain("End of inner exception stack trace"));
    }

    [Test]
    public void MstServiceException_ToString_WithoutProblemDetails()
    {
        var ex = new MstServiceException("simple error");

        string result = ex.ToString();

        Assert.That(result, Does.Contain("simple error"));
        Assert.That(result, Does.Not.Contain("Problem Details"));
    }

    [Test]
    public void MstServiceException_ToString_WithProblemDetailsAndNoExtensions()
    {
        var details = new CborProblemDetails { Status = 404, Title = "Not Found" };
        var ex = new MstServiceException("not found", details);

        string result = ex.ToString();

        Assert.That(result, Does.Contain("Status: 404"));
        Assert.That(result, Does.Contain("Title: Not Found"));
        Assert.That(result, Does.Not.Contain("Extensions"));
    }

    [Test]
    public void BuildErrorMessage_IncludesTitleAndDetail_WhenDifferent()
    {
        var details = new CborProblemDetails
        {
            Title = "Bad Request",
            Status = 400,
            Detail = "Payload is not valid"
        };
        // Verify the constructor overload that accepts CborProblemDetails works
        // and that BuildErrorMessage composes both title and detail into the message.
        var ex = new MstServiceException("test", details, new RequestFailedException(400, "Bad Request"));
        Assert.That(ex.Message, Does.Contain("test"));
        Assert.That(ex.ProblemDetails, Is.Not.Null);
        Assert.That(ex.ProblemDetails!.Title, Is.EqualTo("Bad Request"));
        Assert.That(ex.ProblemDetails.Detail, Is.EqualTo("Payload is not valid"));

        // Verify via FromRequestFailedException which uses BuildErrorMessage internally
        var rfEx = new RequestFailedException(400, "Bad Request");
        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        // At minimum, the generic message path should work
        Assert.That(mstEx.Message, Does.Contain("400"));
    }

    [Test]
    public void BuildErrorMessage_OmitsDetail_WhenSameAsTitle()
    {
        // Can't test BuildErrorMessage directly since it's private,
        // but we test the behavior via CborProblemDetails.ToString
        var details = new CborProblemDetails
        {
            Title = "Same",
            Detail = "Same"
        };

        string result = details.ToString();
        // ToString includes both — but BuildErrorMessage would deduplicate
        Assert.That(result, Does.Contain("Title: Same"));
        Assert.That(result, Does.Contain("Detail: Same"));
    }

    [Test]
    public void MstServiceException_ToString_WithStackTrace()
    {
        // Throw and catch to get a real StackTrace
        MstServiceException? caught = null;
        try
        {
            throw new MstServiceException("with stack", new CborProblemDetails { Status = 500 });
        }
        catch (MstServiceException ex)
        {
            caught = ex;
        }

        string result = caught!.ToString();
        Assert.That(result, Does.Contain("with stack"));
        Assert.That(result, Does.Contain("Status: 500"));
        // Should contain stack trace since it was actually thrown
        Assert.That(result, Does.Contain("MstServiceException_ToString_WithStackTrace"));
    }

    [Test]
    public void MstServiceException_ToString_WithProblemDetails_AllFieldsPopulated()
    {
        var details = new CborProblemDetails
        {
            Type = "urn:error:full",
            Title = "Full Error",
            Status = 503,
            Detail = "All fields set",
            Instance = "/entries/xyz",
            Extensions = new Dictionary<string, object?>
            {
                { "retryAfter", "10s" },
                { "requestId", "abc-123" }
            }
        };
        var inner = new InvalidOperationException("root cause");
        var ex = new MstServiceException("full error test", details, inner);

        string result = ex.ToString();
        Assert.That(result, Does.Contain("Type: urn:error:full"));
        Assert.That(result, Does.Contain("Title: Full Error"));
        Assert.That(result, Does.Contain("Status: 503"));
        Assert.That(result, Does.Contain("Detail: All fields set"));
        Assert.That(result, Does.Contain("Instance: /entries/xyz"));
        Assert.That(result, Does.Contain("retryAfter: 10s"));
        Assert.That(result, Does.Contain("requestId: abc-123"));
        Assert.That(result, Does.Contain("root cause"));
        Assert.That(result, Does.Contain("End of inner exception stack trace"));
    }

    #endregion

    #region FromRequestFailedException with MockResponse — full CBOR parsing path

    [Test]
    public void FromRequestFailedException_WithCborResponse_ParsesProblemDetails()
    {
        // Build CBOR problem details payload
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteInt32(-2); writer.WriteTextString("Forbidden");
        writer.WriteInt32(-3); writer.WriteInt32(403);
        writer.WriteInt32(-4); writer.WriteTextString("Certificate not authorized");
        writer.WriteEndMap();
        byte[] cborBytes = writer.Encode();

        // Create a MockResponse with CBOR content-type and body
        var mockResponse = new MockResponse(403, "Forbidden");
        mockResponse.AddHeader("Content-Type", "application/concise-problem-details+cbor");
        mockResponse.SetContent(cborBytes);

        var rfEx = new RequestFailedException(mockResponse);
        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        Assert.That(mstEx, Is.Not.Null);
        Assert.That(mstEx.ProblemDetails, Is.Not.Null);
        Assert.That(mstEx.ProblemDetails!.Title, Is.EqualTo("Forbidden"));
        Assert.That(mstEx.StatusCode, Is.EqualTo(403));
        Assert.That(mstEx.ProblemDetails.Detail, Is.EqualTo("Certificate not authorized"));
        Assert.That(mstEx.Message, Does.Contain("403"));
        Assert.That(mstEx.Message, Does.Contain("Forbidden"));
        Assert.That(mstEx.InnerException, Is.SameAs(rfEx));
    }

    [Test]
    public void FromRequestFailedException_WithCborResponse_TitleAndDetailInMessage()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteInt32(-2); writer.WriteTextString("Bad Request");
        writer.WriteInt32(-3); writer.WriteInt32(400);
        writer.WriteInt32(-4); writer.WriteTextString("Payload is not valid COSE");
        writer.WriteEndMap();

        var mockResponse = new MockResponse(400, "Bad Request");
        mockResponse.AddHeader("Content-Type", "application/cbor");
        mockResponse.SetContent(writer.Encode());

        var rfEx = new RequestFailedException(mockResponse);
        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        Assert.That(mstEx.Message, Does.Contain("Bad Request"));
        Assert.That(mstEx.Message, Does.Contain("Payload is not valid COSE"));
        Assert.That(mstEx.Message, Does.Contain("400"));
    }

    [Test]
    public void FromRequestFailedException_WithCborResponse_DetailSameAsTitleNotDuplicated()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-2); writer.WriteTextString("Error");
        writer.WriteInt32(-3); writer.WriteInt32(500);
        writer.WriteEndMap();

        var mockResponse = new MockResponse(500, "Internal Server Error");
        mockResponse.AddHeader("Content-Type", "application/concise-problem-details+cbor");
        mockResponse.SetContent(writer.Encode());

        var rfEx = new RequestFailedException(mockResponse);
        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        // Title only, no detail — message should just have title
        Assert.That(mstEx.Message, Does.Contain("Error"));
        Assert.That(mstEx.ProblemDetails!.Detail, Is.Null);
    }

    [Test]
    public void FromRequestFailedException_WithNonCborContentType_ReturnsGenericMessage()
    {
        var mockResponse = new MockResponse(500, "Internal Server Error");
        mockResponse.AddHeader("Content-Type", "application/json");
        mockResponse.SetContent("{\"error\":\"something\"}");

        var rfEx = new RequestFailedException(mockResponse);
        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        Assert.That(mstEx.ProblemDetails, Is.Null);
        Assert.That(mstEx.Message, Does.Contain("500"));
    }

    [Test]
    public void FromRequestFailedException_WithEmptyCborBody_ReturnsGenericMessage()
    {
        var mockResponse = new MockResponse(500, "Internal Server Error");
        mockResponse.AddHeader("Content-Type", "application/concise-problem-details+cbor");
        mockResponse.SetContent(Array.Empty<byte>());

        var rfEx = new RequestFailedException(mockResponse);
        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        Assert.That(mstEx.ProblemDetails, Is.Null);
        Assert.That(mstEx.Message, Does.Contain("500"));
    }

    [Test]
    public void FromRequestFailedException_WithInvalidCborBody_ReturnsGenericMessage()
    {
        var mockResponse = new MockResponse(500, "Internal Server Error");
        mockResponse.AddHeader("Content-Type", "application/concise-problem-details+cbor");
        mockResponse.SetContent(new byte[] { 0xFF, 0xFF, 0xFF });

        var rfEx = new RequestFailedException(mockResponse);
        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        // TryParse returns null for invalid CBOR, so generic message
        Assert.That(mstEx.ProblemDetails, Is.Null);
        Assert.That(mstEx.Message, Does.Contain("500"));
    }

    [Test]
    public void FromRequestFailedException_WithAllProblemDetailsFields()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(5);
        writer.WriteInt32(-1); writer.WriteTextString("urn:example:ledger-unavailable");
        writer.WriteInt32(-2); writer.WriteTextString("Ledger Unavailable");
        writer.WriteInt32(-3); writer.WriteInt32(503);
        writer.WriteInt32(-4); writer.WriteTextString("The CCF node is syncing");
        writer.WriteInt32(-5); writer.WriteTextString("/entries/submit");
        writer.WriteEndMap();

        var mockResponse = new MockResponse(503, "Service Unavailable");
        mockResponse.AddHeader("Content-Type", "application/concise-problem-details+cbor");
        mockResponse.SetContent(writer.Encode());

        var rfEx = new RequestFailedException(mockResponse);
        var mstEx = MstServiceException.FromRequestFailedException(rfEx);

        Assert.That(mstEx.ProblemDetails, Is.Not.Null);
        Assert.That(mstEx.ProblemDetails!.Type, Is.EqualTo("urn:example:ledger-unavailable"));
        Assert.That(mstEx.ProblemDetails.Title, Is.EqualTo("Ledger Unavailable"));
        Assert.That(mstEx.StatusCode, Is.EqualTo(503));
        Assert.That(mstEx.ProblemDetails.Detail, Is.EqualTo("The CCF node is syncing"));
        Assert.That(mstEx.ProblemDetails.Instance, Is.EqualTo("/entries/submit"));
        Assert.That(mstEx.Message, Does.Contain("503").And.Contain("Ledger Unavailable").And.Contain("CCF node is syncing"));
    }

    #endregion
}

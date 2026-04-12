// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System.Formats.Cbor;
using Azure;
using Azure.Core.TestCommon;
using CoseSign1.Transparent.MST;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class MstServiceExceptionTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_WithMessage_SetsMessage()
    {
        MstServiceException ex = new("test error");

        Assert.Multiple(() =>
        {
            Assert.That(ex.Message, Is.EqualTo("test error"));
            Assert.That(ex.InnerException, Is.Null);
            Assert.That(ex.ProblemDetails, Is.Null);
            Assert.That(ex.StatusCode, Is.Null);
        });
    }

    [Test]
    public void Constructor_WithMessageAndInner_SetsProperties()
    {
        Exception inner = new InvalidOperationException("inner error");
        MstServiceException ex = new("test error", inner);

        Assert.Multiple(() =>
        {
            Assert.That(ex.Message, Is.EqualTo("test error"));
            Assert.That(ex.InnerException, Is.SameAs(inner));
            Assert.That(ex.ProblemDetails, Is.Null);
        });
    }

    [Test]
    public void Constructor_WithProblemDetails_SetsProperties()
    {
        CborProblemDetails details = new()
        {
            Title = "Bad Request",
            Status = 400,
            Detail = "Invalid input"
        };

        MstServiceException ex = new("test error", details);

        Assert.Multiple(() =>
        {
            Assert.That(ex.Message, Is.EqualTo("test error"));
            Assert.That(ex.ProblemDetails, Is.SameAs(details));
            Assert.That(ex.StatusCode, Is.EqualTo(400));
        });
    }

    [Test]
    public void Constructor_WithProblemDetailsAndInner_SetsAllProperties()
    {
        CborProblemDetails details = new() { Status = 503 };
        Exception inner = new InvalidOperationException("inner");

        MstServiceException ex = new("error", details, inner);

        Assert.Multiple(() =>
        {
            Assert.That(ex.ProblemDetails, Is.SameAs(details));
            Assert.That(ex.InnerException, Is.SameAs(inner));
            Assert.That(ex.StatusCode, Is.EqualTo(503));
        });
    }

    #endregion

    #region ToString Tests

    [Test]
    public void ToString_WithoutProblemDetails_ContainsMessage()
    {
        MstServiceException ex = new("simple error");

        string result = ex.ToString();

        Assert.That(result, Does.Contain("simple error"));
        Assert.That(result, Does.Contain("MstServiceException"));
    }

    [Test]
    public void ToString_WithProblemDetails_ContainsAllFields()
    {
        CborProblemDetails details = new()
        {
            Type = "urn:example:type",
            Title = "Bad Request",
            Status = 400,
            Detail = "Invalid input",
            Instance = "urn:example:123",
            Extensions = new Dictionary<string, object?> { ["extra"] = "value" }
        };

        MstServiceException ex = new("error with details", details);

        string result = ex.ToString();

        Assert.Multiple(() =>
        {
            Assert.That(result, Does.Contain("Problem Details:"));
            Assert.That(result, Does.Contain("Status: 400"));
            Assert.That(result, Does.Contain("Type: urn:example:type"));
            Assert.That(result, Does.Contain("Title: Bad Request"));
            Assert.That(result, Does.Contain("Detail: Invalid input"));
            Assert.That(result, Does.Contain("Instance: urn:example:123"));
            Assert.That(result, Does.Contain("Extensions:"));
            Assert.That(result, Does.Contain("extra: value"));
        });
    }

    [Test]
    public void ToString_WithInnerException_ContainsInnerDetails()
    {
        Exception inner = new InvalidOperationException("inner failure");
        MstServiceException ex = new("outer error", inner);

        string result = ex.ToString();

        Assert.Multiple(() =>
        {
            Assert.That(result, Does.Contain("outer error"));
            Assert.That(result, Does.Contain("inner failure"));
        });
    }

    [Test]
    public void ToString_WithPartialProblemDetails_OnlyIncludesAvailableFields()
    {
        CborProblemDetails details = new()
        {
            Title = "Server Error",
            Status = 500
        };

        MstServiceException ex = new("error", details);

        string result = ex.ToString();

        Assert.Multiple(() =>
        {
            Assert.That(result, Does.Contain("Status: 500"));
            Assert.That(result, Does.Contain("Title: Server Error"));
            Assert.That(result, Does.Not.Contain("Type:"));
            Assert.That(result, Does.Not.Contain("Detail:"));
            Assert.That(result, Does.Not.Contain("Instance:"));
            Assert.That(result, Does.Not.Contain("Extensions:"));
        });
    }

    #endregion

    #region StatusCode Property Tests

    [Test]
    public void StatusCode_WithNoProblemDetails_ReturnsNull()
    {
        MstServiceException ex = new("error");

        Assert.That(ex.StatusCode, Is.Null);
    }

    [Test]
    public void StatusCode_WithProblemDetailsNoStatus_ReturnsNull()
    {
        CborProblemDetails details = new() { Title = "No status" };
        MstServiceException ex = new("error", details);

        Assert.That(ex.StatusCode, Is.Null);
    }

    [Test]
    public void StatusCode_WithProblemDetailsWithStatus_ReturnsStatus()
    {
        CborProblemDetails details = new() { Status = 429 };
        MstServiceException ex = new("error", details);

        Assert.That(ex.StatusCode, Is.EqualTo(429));
    }

    #endregion

    #region FromRequestFailedException Tests

    private static MockResponse CreateMockResponseWithCborContent(int statusCode, byte[] cborContent)
    {
        MockResponse response = new(statusCode);
        response.AddHeader("Content-Type", "application/concise-problem-details+cbor");
        response.SetContent(cborContent);
        return response;
    }

    private static byte[] CreateCborProblemDetailsBytes(int? status = null, string? title = null, string? detail = null)
    {
        CborWriter writer = new();
        int count = 0;
        if (status.HasValue)
        {
            count++;
        }

        if (title is not null)
        {
            count++;
        }

        if (detail is not null)
        {
            count++;
        }

        writer.WriteStartMap(count);
        if (status.HasValue)
        {
            writer.WriteInt32(-3);
            writer.WriteInt32(status.Value);
        }

        if (title is not null)
        {
            writer.WriteInt32(-2);
            writer.WriteTextString(title);
        }

        if (detail is not null)
        {
            writer.WriteInt32(-4);
            writer.WriteTextString(detail);
        }

        writer.WriteEndMap();
        return writer.Encode();
    }

    [Test]
    public void FromRequestFailedException_WithCborProblemDetails_ParsesDetails()
    {
        // Arrange — create a mock response with CBOR problem details
        byte[] cborContent = CreateCborProblemDetailsBytes(status: 400, title: "Bad Request", detail: "Invalid payload format");
        MockResponse mockResponse = CreateMockResponseWithCborContent(400, cborContent);
        RequestFailedException rfe = new(mockResponse);

        // Act
        MstServiceException result = MstServiceException.FromRequestFailedException(rfe);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(result.ProblemDetails, Is.Not.Null);
            Assert.That(result.ProblemDetails!.Status, Is.EqualTo(400));
            Assert.That(result.ProblemDetails.Title, Is.EqualTo("Bad Request"));
            Assert.That(result.ProblemDetails.Detail, Is.EqualTo("Invalid payload format"));
            Assert.That(result.StatusCode, Is.EqualTo(400));
            Assert.That(result.InnerException, Is.SameAs(rfe));
            Assert.That(result.Message, Does.Contain("400"));
            Assert.That(result.Message, Does.Contain("Bad Request"));
        });
    }

    [Test]
    public void FromRequestFailedException_WithNonCborResponse_UsesGenericMessage()
    {
        // Arrange — response with JSON content type (not CBOR)
        MockResponse mockResponse = new(500);
        mockResponse.AddHeader("Content-Type", "application/json");
        mockResponse.SetContent("{\"error\":\"Internal Server Error\"}");
        RequestFailedException rfe = new(mockResponse);

        // Act
        MstServiceException result = MstServiceException.FromRequestFailedException(rfe);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(result.ProblemDetails, Is.Null);
            Assert.That(result.StatusCode, Is.Null);
            Assert.That(result.InnerException, Is.SameAs(rfe));
            Assert.That(result.Message, Does.Contain("500"));
        });
    }

    [Test]
    public void FromRequestFailedException_WithCborProblemDetails_TitleAndDifferentDetail_IncludesBoth()
    {
        // Arrange — title and detail are different
        byte[] cborContent = CreateCborProblemDetailsBytes(status: 422, title: "Validation Error", detail: "Field 'name' is required");
        MockResponse mockResponse = CreateMockResponseWithCborContent(422, cborContent);
        RequestFailedException rfe = new(mockResponse);

        // Act
        MstServiceException result = MstServiceException.FromRequestFailedException(rfe);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(result.Message, Does.Contain("Validation Error"));
            Assert.That(result.Message, Does.Contain("Field 'name' is required"));
        });
    }

    [Test]
    public void FromRequestFailedException_WithCborProblemDetails_SameTitleAndDetail_IncludesTitleOnly()
    {
        // Arrange — title equals detail; BuildErrorMessage skips the duplicate detail
        byte[] cborContent = CreateCborProblemDetailsBytes(status: 400, title: "Duplicate text", detail: "Duplicate text");
        MockResponse mockResponse = CreateMockResponseWithCborContent(400, cborContent);
        RequestFailedException rfe = new(mockResponse);

        // Act
        MstServiceException result = MstServiceException.FromRequestFailedException(rfe);

        // Assert — the message should not have the detail appended twice
        string message = result.Message;
        int firstIdx = message.IndexOf("Duplicate text");
        int secondIdx = message.IndexOf("Duplicate text", firstIdx + 1);
        Assert.That(secondIdx, Is.EqualTo(-1), "Detail should not be duplicated when it matches Title");
    }

    [Test]
    public void FromRequestFailedException_WithEmptyContent_UsesGenericMessage()
    {
        // Arrange — CBOR content type but empty body
        MockResponse mockResponse = new(503);
        mockResponse.AddHeader("Content-Type", "application/concise-problem-details+cbor");
        // Don't set content, leave it empty
        RequestFailedException rfe = new(mockResponse);

        // Act
        MstServiceException result = MstServiceException.FromRequestFailedException(rfe);

        // Assert — should fall through to generic message
        Assert.That(result.ProblemDetails, Is.Null);
        Assert.That(result.Message, Does.Contain("503"));
    }

    [Test]
    public void FromRequestFailedException_WithNoResponse_UsesGenericMessage()
    {
        // Arrange — RequestFailedException with no raw response
        RequestFailedException rfe = new(500, "Internal error");

        // Act
        MstServiceException result = MstServiceException.FromRequestFailedException(rfe);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(result.ProblemDetails, Is.Null);
            Assert.That(result.Message, Does.Contain("500"));
            Assert.That(result.Message, Does.Contain("Internal error"));
        });
    }

    [Test]
    public void FromRequestFailedException_WithStatusOnlyProblemDetails_UsesHttpStatusFallback()
    {
        // Arrange — CBOR problem details without a status field, so httpStatus is used as fallback
        CborWriter writer = new();
        writer.WriteStartMap(1);
        writer.WriteInt32(-2); writer.WriteTextString("Unknown");
        writer.WriteEndMap();
        byte[] cborContent = writer.Encode();

        MockResponse mockResponse = CreateMockResponseWithCborContent(502, cborContent);
        RequestFailedException rfe = new(mockResponse);

        // Act
        MstServiceException result = MstServiceException.FromRequestFailedException(rfe);

        // Assert — message uses the HTTP status (502) since problem details has no status
        Assert.That(result.Message, Does.Contain("502"));
        Assert.That(result.ProblemDetails!.Title, Is.EqualTo("Unknown"));
    }

    #endregion
}
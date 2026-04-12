// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using Azure.Core;
using Azure.Core.TestCommon;
using CoseSign1.Transparent.MST;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class HeaderFilteringResponseTests
{
    /// <summary>
    /// Creates a mock response with the specified headers.
    /// </summary>
    private static MockResponse CreateResponseWithHeaders(int statusCode, params (string name, string value)[] headers)
    {
        MockResponse response = new(statusCode);
        foreach ((string name, string value) in headers)
        {
            response.AddHeader(new HttpHeader(name, value));
        }

        return response;
    }

    [Test]
    public void Constructor_NullInner_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new HeaderFilteringResponse(null!, "Retry-After"));
    }

    [Test]
    public void Status_ReturnsInnerStatus()
    {
        MockResponse inner = CreateResponseWithHeaders(503);
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        Assert.That(filtered.Status, Is.EqualTo(503));
    }

    [Test]
    public void ReasonPhrase_ReturnsInnerReasonPhrase()
    {
        MockResponse inner = new(200);
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        Assert.That(filtered.ReasonPhrase, Is.Not.Null);
    }

    [Test]
    public void ContentStream_GetAndSet_DelegatesToInner()
    {
        MockResponse inner = new(200);
        using HeaderFilteringResponse filtered = new(inner);

        MemoryStream testStream = new(new byte[] { 1, 2, 3 });
        filtered.ContentStream = testStream;

        Assert.That(filtered.ContentStream, Is.SameAs(testStream));
        testStream.Dispose();
    }

    [Test]
    public void ClientRequestId_GetAndSet_DelegatesToInner()
    {
        MockResponse inner = new(200);
        using HeaderFilteringResponse filtered = new(inner);

        filtered.ClientRequestId = "test-id-123";

        Assert.That(filtered.ClientRequestId, Is.EqualTo("test-id-123"));
    }

    [Test]
    public void TryGetHeader_ExcludedHeader_ReturnsFalse()
    {
        MockResponse inner = CreateResponseWithHeaders(503,
            ("Retry-After", "1"),
            ("Content-Type", "application/json"));
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        bool found = filtered.Headers.TryGetValue("Retry-After", out string? value);

        Assert.Multiple(() =>
        {
            Assert.That(found, Is.False);
            Assert.That(value, Is.Null);
        });
    }

    [Test]
    public void TryGetHeader_NonExcludedHeader_ReturnsTrue()
    {
        MockResponse inner = CreateResponseWithHeaders(200,
            ("Retry-After", "1"),
            ("Content-Type", "application/json"));
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        bool found = filtered.Headers.TryGetValue("Content-Type", out string? value);

        Assert.Multiple(() =>
        {
            Assert.That(found, Is.True);
            Assert.That(value, Is.EqualTo("application/json"));
        });
    }

    [Test]
    public void TryGetHeaderValues_ExcludedHeader_ReturnsFalse()
    {
        MockResponse inner = CreateResponseWithHeaders(503,
            ("Retry-After", "1"));
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        bool found = filtered.Headers.TryGetValues("Retry-After", out IEnumerable<string>? values);

        Assert.Multiple(() =>
        {
            Assert.That(found, Is.False);
            Assert.That(values, Is.Null);
        });
    }

    [Test]
    public void TryGetHeaderValues_NonExcludedHeader_ReturnsTrue()
    {
        MockResponse inner = CreateResponseWithHeaders(200,
            ("X-Custom", "val1"));
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        bool found = filtered.Headers.TryGetValues("X-Custom", out IEnumerable<string>? values);

        Assert.That(found, Is.True);
        Assert.That(values, Is.Not.Null);
    }

    [Test]
    public void ContainsHeader_ExcludedHeader_ReturnsFalse()
    {
        MockResponse inner = CreateResponseWithHeaders(503,
            ("Retry-After", "1"));
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        Assert.That(filtered.Headers.Contains("Retry-After"), Is.False);
    }

    [Test]
    public void ContainsHeader_NonExcludedHeader_ReturnsTrue()
    {
        MockResponse inner = CreateResponseWithHeaders(200,
            ("Content-Type", "text/plain"));
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        Assert.That(filtered.Headers.Contains("Content-Type"), Is.True);
    }

    [Test]
    public void EnumerateHeaders_ExcludesFilteredHeaders()
    {
        MockResponse inner = CreateResponseWithHeaders(503,
            ("Retry-After", "1"),
            ("retry-after-ms", "1000"),
            ("Content-Type", "text/plain"),
            ("X-Request-Id", "abc"));
        using HeaderFilteringResponse filtered = new(inner, "Retry-After", "retry-after-ms");

        List<string> headerNames = filtered.Headers.Select(h => h.Name).ToList();

        Assert.Multiple(() =>
        {
            Assert.That(headerNames, Does.Contain("Content-Type"));
            Assert.That(headerNames, Does.Contain("X-Request-Id"));
            Assert.That(headerNames, Does.Not.Contain("Retry-After"));
            Assert.That(headerNames, Does.Not.Contain("retry-after-ms"));
        });
    }

    [Test]
    public void ExcludesHeaders_CaseInsensitive()
    {
        MockResponse inner = CreateResponseWithHeaders(503,
            ("retry-after", "1"));
        using HeaderFilteringResponse filtered = new(inner, "Retry-After");

        Assert.That(filtered.Headers.Contains("retry-after"), Is.False);
    }

    [Test]
    public void Dispose_DisposesInner()
    {
        MockResponse inner = new(200);
        HeaderFilteringResponse filtered = new(inner);

        // Should not throw
        Assert.DoesNotThrow(() => filtered.Dispose());
    }

    [Test]
    public void MultipleExcludedHeaders_AllFiltered()
    {
        MockResponse inner = CreateResponseWithHeaders(503,
            ("Retry-After", "1"),
            ("retry-after-ms", "500"),
            ("x-ms-retry-after-ms", "500"),
            ("Content-Length", "42"));
        using HeaderFilteringResponse filtered = new(inner,
            "Retry-After", "retry-after-ms", "x-ms-retry-after-ms");

        Assert.Multiple(() =>
        {
            Assert.That(filtered.Headers.Contains("Retry-After"), Is.False);
            Assert.That(filtered.Headers.Contains("retry-after-ms"), Is.False);
            Assert.That(filtered.Headers.Contains("x-ms-retry-after-ms"), Is.False);
            Assert.That(filtered.Headers.Contains("Content-Length"), Is.True);
        });
    }
}
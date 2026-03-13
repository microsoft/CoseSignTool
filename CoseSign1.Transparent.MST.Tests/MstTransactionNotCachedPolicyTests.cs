// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System.Formats.Cbor;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Core.TestCommon;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class MstTransactionNotCachedPolicyTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_DefaultValues_SetsExpectedDefaults()
    {
        // Act
        var policy = new MstTransactionNotCachedPolicy();

        // Assert — verify defaults are accessible via the public constants
        Assert.That(MstTransactionNotCachedPolicy.DefaultRetryDelay, Is.EqualTo(TimeSpan.FromMilliseconds(250)));
        Assert.That(MstTransactionNotCachedPolicy.DefaultMaxRetries, Is.EqualTo(8));
        Assert.That(policy, Is.Not.Null);
    }

    [Test]
    public void Constructor_CustomValues_DoesNotThrow()
    {
        // Act & Assert
        Assert.DoesNotThrow(() => new MstTransactionNotCachedPolicy(TimeSpan.FromSeconds(1), 3));
    }

    [Test]
    public void Constructor_ZeroDelay_DoesNotThrow()
    {
        Assert.DoesNotThrow(() => new MstTransactionNotCachedPolicy(TimeSpan.Zero, 5));
    }

    [Test]
    public void Constructor_ZeroRetries_DoesNotThrow()
    {
        Assert.DoesNotThrow(() => new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(100), 0));
    }

    [Test]
    public void Constructor_NegativeDelay_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(-1), 3));
    }

    [Test]
    public void Constructor_NegativeRetries_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(100), -1));
    }

    #endregion

    #region ProcessAsync — Non-Matching Requests (Pass-Through)

    [Test]
    public async Task ProcessAsync_NonGetRequest_PassesThroughWithoutRetry()
    {
        // Arrange — POST to /entries/ returning 503 with TransactionNotCached body
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return CreateTransactionNotCachedResponse();
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Post, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — only 1 call, no retries (POST is not matched)
        Assert.That(callCount, Is.EqualTo(1));
        Assert.That(message.Response.Status, Is.EqualTo(503));
    }

    [Test]
    public async Task ProcessAsync_GetNonEntriesPath_PassesThroughWithoutRetry()
    {
        // Arrange — GET to /operations/ returning 503 with TransactionNotCached body
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return CreateTransactionNotCachedResponse();
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/operations/abc");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — only 1 call
        Assert.That(callCount, Is.EqualTo(1));
    }

    [Test]
    public async Task ProcessAsync_GetEntriesPath_Non503Status_PassesThroughWithoutRetry()
    {
        // Arrange — GET to /entries/ returning 200
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return new MockResponse(200);
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — only 1 call
        Assert.That(callCount, Is.EqualTo(1));
        Assert.That(message.Response.Status, Is.EqualTo(200));
    }

    [Test]
    public async Task ProcessAsync_503WithoutCborBody_DoesNotRetry()
    {
        // Arrange — 503 with empty body (no CBOR problem details)
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return new MockResponse(503);
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — only 1 call (no TransactionNotCached in body)
        Assert.That(callCount, Is.EqualTo(1));
    }

    [Test]
    public async Task ProcessAsync_503WithDifferentCborError_DoesNotRetry()
    {
        // Arrange — 503 with CBOR body containing a different error
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            var response = new MockResponse(503);
            response.SetContent(CreateCborProblemDetailsBytes("ServiceTooBusy"));
            return response;
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — only 1 call (not TransactionNotCached)
        Assert.That(callCount, Is.EqualTo(1));
    }

    #endregion

    #region ProcessAsync — Matching Requests (Retry Behavior)

    [Test]
    public async Task ProcessAsync_TransactionNotCached_RetriesUntilSuccess()
    {
        // Arrange — first 2 calls return 503/TransactionNotCached, third returns 200
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount <= 2)
            {
                return CreateTransactionNotCachedResponse();
            }
            return new MockResponse(200);
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 5));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — 3 calls total (1 initial + 2 retries before success)
        Assert.That(callCount, Is.EqualTo(3));
        Assert.That(message.Response.Status, Is.EqualTo(200));
    }

    [Test]
    public async Task ProcessAsync_TransactionNotCached_ExhaustsRetries_Returns503()
    {
        // Arrange — always return 503/TransactionNotCached
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return CreateTransactionNotCachedResponse();
        });

        int maxRetries = 3;
        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), maxRetries));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — 1 initial + maxRetries retries = 4 total calls
        Assert.That(callCount, Is.EqualTo(1 + maxRetries));
        Assert.That(message.Response.Status, Is.EqualTo(503));
    }

    [Test]
    public async Task ProcessAsync_ZeroMaxRetries_NoRetries()
    {
        // Arrange
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return CreateTransactionNotCachedResponse();
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 0));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — only the initial call, no retries
        Assert.That(callCount, Is.EqualTo(1));
    }

    [Test]
    public async Task ProcessAsync_TransactionNotCached_InTitle_IsDetected()
    {
        // Arrange — error code in Title field instead of Detail
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount <= 1)
            {
                var response = new MockResponse(503);
                response.SetContent(CreateCborProblemDetailsBytesInTitle("TransactionNotCached"));
                return response;
            }
            return new MockResponse(200);
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — retried and succeeded on second call
        Assert.That(callCount, Is.EqualTo(2));
        Assert.That(message.Response.Status, Is.EqualTo(200));
    }

    [Test]
    public async Task ProcessAsync_TransactionNotCached_CaseInsensitive()
    {
        // Arrange — lowercase error code
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount <= 1)
            {
                var response = new MockResponse(503);
                response.SetContent(CreateCborProblemDetailsBytes("transactionnotcached"));
                return response;
            }
            return new MockResponse(200);
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert
        Assert.That(callCount, Is.EqualTo(2));
        Assert.That(message.Response.Status, Is.EqualTo(200));
    }

    [Test]
    public async Task ProcessAsync_EntriesPath_CaseInsensitive()
    {
        // Arrange — uppercase ENTRIES in path
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount <= 1)
            {
                return CreateTransactionNotCachedResponse();
            }
            return new MockResponse(200);
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/ENTRIES/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — path matching is case-insensitive
        Assert.That(callCount, Is.EqualTo(2));
    }

    [Test]
    public async Task ProcessAsync_503WithInvalidCborBody_DoesNotRetry()
    {
        // Arrange — 503 with garbage body (not valid CBOR)
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            var response = new MockResponse(503);
            response.SetContent(new byte[] { 0xFF, 0xFE, 0x00 });
            return response;
        });

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — no retry on invalid CBOR
        Assert.That(callCount, Is.EqualTo(1));
    }

    #endregion

    #region Process (Sync)

    [Test]
    public void Process_TransactionNotCached_RetriesUntilSuccess()
    {
        // Arrange
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount <= 2)
            {
                return CreateTransactionNotCachedResponse();
            }
            return new MockResponse(200);
        });
        transport.ExpectSyncPipeline = true;

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 5));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        pipeline.Send(message, CancellationToken.None);

        // Assert
        Assert.That(callCount, Is.EqualTo(3));
        Assert.That(message.Response.Status, Is.EqualTo(200));
    }

    [Test]
    public void Process_NonMatchingRequest_DoesNotRetry()
    {
        // Arrange
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return CreateTransactionNotCachedResponse();
        });
        transport.ExpectSyncPipeline = true;

        var pipeline = CreatePipeline(transport, new MstTransactionNotCachedPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Post, "https://mst.example.com/entries/1.234");

        // Act
        pipeline.Send(message, CancellationToken.None);

        // Assert
        Assert.That(callCount, Is.EqualTo(1));
    }

    #endregion

    #region MstClientOptionsExtensions Tests

    [Test]
    public void ConfigureTransactionNotCachedRetry_NullOptions_ThrowsArgumentNullException()
    {
        CodeTransparencyClientOptions? options = null;

        Assert.Throws<ArgumentNullException>(() =>
            options!.ConfigureTransactionNotCachedRetry());
    }

    [Test]
    public void ConfigureTransactionNotCachedRetry_DefaultParams_ReturnsSameInstance()
    {
        var options = new CodeTransparencyClientOptions();

        var result = options.ConfigureTransactionNotCachedRetry();

        Assert.That(result, Is.SameAs(options));
    }

    [Test]
    public void ConfigureTransactionNotCachedRetry_CustomParams_ReturnsSameInstance()
    {
        var options = new CodeTransparencyClientOptions();

        var result = options.ConfigureTransactionNotCachedRetry(
            retryDelay: TimeSpan.FromMilliseconds(100),
            maxRetries: 16);

        Assert.That(result, Is.SameAs(options));
    }

    #endregion

    #region Test Helpers

    /// <summary>
    /// Builds a pipeline with the policy under test inserted before the transport.
    /// The pipeline has no SDK retry policy — just the custom policy + transport.
    /// </summary>
    private static HttpPipeline CreatePipeline(MockTransport transport, MstTransactionNotCachedPolicy policy)
    {
        return HttpPipelineBuilder.Build(
            new TestClientOptions(transport, policy));
    }

    /// <summary>
    /// Creates an HttpMessage with the given method and URI, ready to send through the pipeline.
    /// </summary>
    private static HttpMessage CreateHttpMessage(HttpPipeline pipeline, RequestMethod method, string uri)
    {
        var message = pipeline.CreateMessage();
        message.Request.Method = method;
        message.Request.Uri.Reset(new Uri(uri));
        return message;
    }

    /// <summary>
    /// Creates a mock 503 response with a CBOR problem-details body containing TransactionNotCached.
    /// </summary>
    private static MockResponse CreateTransactionNotCachedResponse()
    {
        var response = new MockResponse(503);
        response.AddHeader("Retry-After", "1");
        response.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
        return response;
    }

    /// <summary>
    /// Creates CBOR problem details bytes with the error code in the Detail field (key -4).
    /// </summary>
    private static byte[] CreateCborProblemDetailsBytes(string detailValue)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-3); // status
        writer.WriteInt32(503);
        writer.WriteInt32(-4); // detail
        writer.WriteTextString(detailValue);
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>
    /// Creates CBOR problem details bytes with the error code in the Title field (key -2).
    /// </summary>
    private static byte[] CreateCborProblemDetailsBytesInTitle(string titleValue)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(-3); // status
        writer.WriteInt32(503);
        writer.WriteInt32(-2); // title
        writer.WriteTextString(titleValue);
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>
    /// Minimal ClientOptions subclass for building a pipeline with our custom policy and a mock transport.
    /// Disables the SDK's default retry to isolate the policy's behavior.
    /// </summary>
    private sealed class TestClientOptions : ClientOptions
    {
        public TestClientOptions(MockTransport transport, MstTransactionNotCachedPolicy policy)
        {
            Transport = transport;
            Retry.MaxRetries = 0; // Disable SDK retries to test policy in isolation
            AddPolicy(policy, HttpPipelinePosition.PerRetry);
        }
    }

    #endregion
}

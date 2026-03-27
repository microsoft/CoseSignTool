// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Formats.Cbor;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Core.TestCommon;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class MstPerformanceOptimizationPolicyTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_DefaultValues_SetsExpectedDefaults()
    {
        // Act
        var policy = new MstPerformanceOptimizationPolicy();

        // Assert — verify defaults are accessible via the public constants
        Assert.That(MstPerformanceOptimizationPolicy.DefaultRetryDelay, Is.EqualTo(TimeSpan.FromMilliseconds(250)));
        Assert.That(MstPerformanceOptimizationPolicy.DefaultMaxRetries, Is.EqualTo(8));
        Assert.That(policy, Is.Not.Null);
    }

    [Test]
    public void Constructor_CustomValues_DoesNotThrow()
    {
        // Act & Assert
        Assert.DoesNotThrow(() => new MstPerformanceOptimizationPolicy(TimeSpan.FromSeconds(1), 3));
    }

    [Test]
    public void Constructor_ZeroDelay_DoesNotThrow()
    {
        Assert.DoesNotThrow(() => new MstPerformanceOptimizationPolicy(TimeSpan.Zero, 5));
    }

    [Test]
    public void Constructor_ZeroRetries_DoesNotThrow()
    {
        Assert.DoesNotThrow(() => new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(100), 0));
    }

    [Test]
    public void Constructor_NegativeDelay_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(-1), 3));
    }

    [Test]
    public void Constructor_NegativeRetries_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(100), -1));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — only 1 call
        Assert.That(callCount, Is.EqualTo(1));
        Assert.That(message.Response.Status, Is.EqualTo(200));
    }

    [Test]
    public async Task ProcessAsync_503WithoutCborBody_StillRetries()
    {
        // Arrange — 503 with empty body (no CBOR problem details)
        // With simplified policy, we retry ANY 503 on /entries/ (no CBOR parsing)
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return new MockResponse(503);
        });

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — 4 calls (1 initial + 3 retries) since we retry any 503 on /entries/
        Assert.That(callCount, Is.EqualTo(4));
    }

    [Test]
    public async Task ProcessAsync_503WithDifferentCborError_StillRetries()
    {
        // Arrange — 503 with CBOR body containing a different error
        // With simplified policy, we retry ANY 503 on /entries/ (no CBOR parsing)
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            var response = new MockResponse(503);
            response.SetContent(CreateCborProblemDetailsBytes("ServiceTooBusy"));
            return response;
        });

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — 4 calls (1 initial + 3 retries) since we retry any 503 on /entries/
        Assert.That(callCount, Is.EqualTo(4));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 5));
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
        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), maxRetries));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 0));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/ENTRIES/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — path matching is case-insensitive
        Assert.That(callCount, Is.EqualTo(2));
    }

    [Test]
    public async Task ProcessAsync_503WithInvalidCborBody_StillRetries()
    {
        // Arrange — 503 with garbage body (not valid CBOR)
        // With simplified policy, we retry ANY 503 on /entries/ (no CBOR parsing)
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            var response = new MockResponse(503);
            response.SetContent(new byte[] { 0xFF, 0xFE, 0x00 });
            return response;
        });

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — 4 calls (1 initial + 3 retries) since we retry any 503 on /entries/
        Assert.That(callCount, Is.EqualTo(4));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 5));
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

        var pipeline = CreatePipeline(transport, new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(1), 3));
        var message = CreateHttpMessage(pipeline, RequestMethod.Post, "https://mst.example.com/entries/1.234");

        // Act
        pipeline.Send(message, CancellationToken.None);

        // Assert
        Assert.That(callCount, Is.EqualTo(1));
    }

    #endregion

    #region MstClientOptionsExtensions Tests

    [Test]
    public void ConfigureMstPerformanceOptimizations_NullOptions_ThrowsArgumentNullException()
    {
        CodeTransparencyClientOptions? options = null;

        Assert.Throws<ArgumentNullException>(() =>
            options!.ConfigureMstPerformanceOptimizations());
    }

    [Test]
    public void ConfigureMstPerformanceOptimizations_DefaultParams_ReturnsSameInstance()
    {
        var options = new CodeTransparencyClientOptions();

        var result = options.ConfigureMstPerformanceOptimizations();

        Assert.That(result, Is.SameAs(options));
    }

    [Test]
    public void ConfigureMstPerformanceOptimizations_CustomParams_ReturnsSameInstance()
    {
        var options = new CodeTransparencyClientOptions();

        var result = options.ConfigureMstPerformanceOptimizations(
            retryDelay: TimeSpan.FromMilliseconds(100),
            maxRetries: 16);

        Assert.That(result, Is.SameAs(options));
    }

    #endregion

    #region Pipeline Integration Tests — SDK Retry Interaction

    /// <summary>
    /// Baseline: Without the fast retry policy, the SDK's RetryPolicy respects the
    /// Retry-After: 1 header and waits approximately 1 second before retrying.
    /// This establishes the latency floor that the policy is designed to eliminate.
    /// </summary>
    [Test]
    public async Task Baseline_WithoutPolicy_SdkRespectsRetryAfterDelay()
    {
        // Arrange — 503/TransactionNotCached on first call, 200 on second
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount == 1)
            {
                return CreateTransactionNotCachedResponse();
            }
            return new MockResponse(200);
        });

        var options = new SdkRetryTestClientOptions(transport, policy: null);
        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        var sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert — SDK retried after respecting Retry-After: 1 (should take >= ~900ms)
        Assert.That(message.Response.Status, Is.EqualTo(200), "Should eventually succeed via SDK retry");
        Assert.That(callCount, Is.EqualTo(2), "SDK should have made 2 transport calls (initial + 1 retry)");
        Assert.That(sw.ElapsedMilliseconds, Is.GreaterThanOrEqualTo(900),
            $"SDK should wait approximately 1 second for the Retry-After header before retrying, but only waited {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// With the policy at PerRetry, verifies whether the fast retry intercepts the 503
    /// BEFORE the SDK's RetryPolicy applies its Retry-After delay.
    /// </summary>
    [Test]
    public async Task PolicyAtPerRetry_FastRetryResolvesBeforeSdkRetryAfterDelay()
    {
        // Arrange — 503/TransactionNotCached on first call, 200 on second
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount == 1)
            {
                return CreateTransactionNotCachedResponse();
            }
            return new MockResponse(200);
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 5);
        var options = new SdkRetryTestClientOptions(transport, policy, HttpPipelinePosition.PerRetry);
        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        var sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert — fast retry should resolve in well under 1 second
        Assert.That(message.Response.Status, Is.EqualTo(200), "Fast retry should succeed");
        Assert.That(callCount, Is.EqualTo(2), "Should be 2 transport calls (initial 503 + 1 fast retry 200)");
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(500),
            $"Fast retry at PerRetry position should resolve in <500ms, but took {sw.ElapsedMilliseconds}ms. " +
            "If this takes >=1s, the policy is NOT intercepting before the SDK's Retry-After delay.");
    }

    /// <summary>
    /// With a 100 ms retry delay the fast retry should still resolve well under 500 ms,
    /// demonstrating that tighter intervals pull latency down further.
    /// </summary>
    [Test]
    public async Task PolicyAt100msDelay_ResolvesWellUnder500ms()
    {
        // Arrange — 503 on first call, 200 on second
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount == 1)
            {
                return CreateTransactionNotCachedResponse();
            }
            return new MockResponse(200);
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(100), 5);
        var options = new SdkRetryTestClientOptions(transport, policy, HttpPipelinePosition.PerRetry);
        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        var sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert — with 100ms delay and 1 retry needed, should finish in ~100-200ms
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(callCount, Is.EqualTo(2));
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(300),
            $"With 100ms retry delay, expected resolution in <300ms, but took {sw.ElapsedMilliseconds}ms.");
    }

    /// <summary>
    /// When the policy's fast retries are set to 0, the 503 propagates back with Retry-After stripped.
    /// This verifies that header stripping still occurs even without policy retries.
    /// </summary>
    [Test]
    public async Task PolicyWithZeroRetries_StillStripsRetryAfterHeader()
    {
        // Arrange — 503 with Retry-After header
        // Policy configured with 0 fast retries: passes the 503 straight through
        // but still strips the Retry-After header
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            return CreateTransactionNotCachedResponse(); // Returns 503 with Retry-After: 1
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 0);
        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 0 } // Disable SDK retries to observe policy behavior
        };
        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — Single call (no policy retries, no SDK retries)
        // 503 is returned, but Retry-After header should be stripped
        Assert.That(message.Response.Status, Is.EqualTo(503));
        Assert.That(callCount, Is.EqualTo(1), "Should be 1 call with 0 policy retries and 0 SDK retries");
        Assert.That(message.Response.Headers.Contains("Retry-After"), Is.False,
            "Retry-After header should be stripped even with 0 policy retries");
    }

    /// <summary>
    /// Verifies that all three Azure SDK Retry-After header variations are stripped.
    /// The SDK checks: Retry-After (standard), retry-after-ms, and x-ms-retry-after-ms.
    /// </summary>
    [TestCase("Retry-After", "1", Description = "Standard HTTP header (seconds)")]
    [TestCase("retry-after-ms", "1000", Description = "Azure SDK specific (milliseconds)")]
    [TestCase("x-ms-retry-after-ms", "1000", Description = "Azure SDK specific with x-ms prefix")]
    public async Task PolicyStrips_AllRetryAfterHeaderVariations(string headerName, string headerValue)
    {
        // Arrange — 503 with the specified retry header
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            var response = new MockResponse(503);
            response.AddHeader(headerName, headerValue);
            response.AddHeader("Content-Type", "application/problem+cbor");
            return response;
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 0);
        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 0 }
        };
        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — Header should be stripped
        Assert.That(message.Response.Headers.Contains(headerName), Is.False,
            $"{headerName} header should be stripped by the policy");
    }

    /// <summary>
    /// Verifies that when multiple retry headers are present, all are stripped.
    /// </summary>
    [Test]
    public async Task PolicyStrips_AllRetryAfterHeaders_WhenMultiplePresent()
    {
        // Arrange — 503 with all three retry headers
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            var response = new MockResponse(503);
            response.AddHeader("Retry-After", "1");
            response.AddHeader("retry-after-ms", "1000");
            response.AddHeader("x-ms-retry-after-ms", "1000");
            response.AddHeader("Content-Type", "application/problem+cbor");
            return response;
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 0);
        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 0 }
        };
        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert — All retry headers should be stripped
        Assert.Multiple(() =>
        {
            Assert.That(message.Response.Headers.Contains("Retry-After"), Is.False,
                "Retry-After header should be stripped");
            Assert.That(message.Response.Headers.Contains("retry-after-ms"), Is.False,
                "retry-after-ms header should be stripped");
            Assert.That(message.Response.Headers.Contains("x-ms-retry-after-ms"), Is.False,
                "x-ms-retry-after-ms header should be stripped");
        });
    }

    /// <summary>
    /// Validates the extension method's registered position intercepts before SDK delay.
    /// This tests the actual production registration path.
    /// </summary>
    [Test]
    public async Task ConfigureMstPerformanceOptimizations_PolicyInterceptsBeforeSdkDelay()
    {
        // Arrange
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount == 1)
            {
                return CreateTransactionNotCachedResponse();
            }
            return new MockResponse(200);
        });

        var options = new CodeTransparencyClientOptions();
        options.ConfigureMstPerformanceOptimizations(
            retryDelay: TimeSpan.FromMilliseconds(10),
            maxRetries: 5);
        options.Transport = transport;
        // SDK retries enabled with small base delay so only Retry-After dominates
        options.Retry.MaxRetries = 3;
        options.Retry.Delay = TimeSpan.FromMilliseconds(1);

        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        var sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(callCount, Is.EqualTo(2));
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(500),
            $"Extension method should register policy at a position that intercepts before SDK Retry-After delay. Took {sw.ElapsedMilliseconds}ms.");
    }

    /// <summary>
    /// With multiple consecutive 503s, the fast retry resolves them without incurring
    /// multiple SDK Retry-After delays.
    /// </summary>
    [Test]
    public async Task PolicyAtPerRetry_Multiple503s_AllResolvedByFastRetry()
    {
        // Arrange — first 3 calls return 503, fourth returns 200
        // Policy has 5 fast retries, so it should catch all 3 within ONE SDK retry iteration
        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount <= 3)
            {
                return CreateTransactionNotCachedResponse();
            }
            return new MockResponse(200);
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 5);
        var options = new SdkRetryTestClientOptions(transport, policy, HttpPipelinePosition.PerRetry);
        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/1.234");

        var sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert — all resolved by fast retries with no SDK Retry-After delays
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(callCount, Is.EqualTo(4), "1 initial + 3 fast retries");
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(500),
            $"Multiple 503s should all be resolved by fast retry without SDK delay. Took {sw.ElapsedMilliseconds}ms.");
    }

    #endregion

    #region Test Helpers

    /// <summary>
    /// Builds a pipeline with the policy under test at PerRetry position.
    /// The pipeline has no SDK retry policy — just the custom policy + transport.
    /// </summary>
    private static HttpPipeline CreatePipeline(MockTransport transport, MstPerformanceOptimizationPolicy policy)
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
        public TestClientOptions(MockTransport transport, MstPerformanceOptimizationPolicy policy)
        {
            Transport = transport;
            Retry.MaxRetries = 0; // Disable SDK retries to test policy in isolation
            AddPolicy(policy, HttpPipelinePosition.PerRetry);
        }
    }

    /// <summary>
    /// ClientOptions subclass with SDK retries enabled (MaxRetries=3) to test interaction
    /// between the fast retry policy and the SDK's built-in RetryPolicy.
    /// Uses a small base delay so that Retry-After: 1 from the server dominates timing.
    /// </summary>
    private sealed class SdkRetryTestClientOptions : ClientOptions
    {
        public SdkRetryTestClientOptions(
            MockTransport transport,
            MstPerformanceOptimizationPolicy? policy,
            HttpPipelinePosition position = HttpPipelinePosition.PerRetry)
        {
            Transport = transport;
            Retry.MaxRetries = 3;
            Retry.Delay = TimeSpan.FromMilliseconds(1); // Small base so Retry-After dominates
            Retry.MaxDelay = TimeSpan.FromSeconds(10);
            Retry.NetworkTimeout = TimeSpan.FromSeconds(30);

            if (policy != null)
            {
                AddPolicy(policy, position);
            }
        }
    }

    #endregion

    #region Diagnostic Pipeline Tests

    /// <summary>
    /// Diagnostic test using real CodeTransparencyClientOptions with SDK retries enabled
    /// to verify our policy intercepts 503 before RetryPolicy applies its delay.
    /// </summary>
    [Test]
    public async Task Diagnostic_RealSdkOptions_PolicyInterceptsBeforeRetryPolicy()
    {
        // Arrange - replicate exact production setup
        int transportCallCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            transportCallCount++;
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;
            Console.WriteLine($"  [Transport] Call #{transportCallCount}: {msg.Request.Method} {uri}");

            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                if (transportCallCount == 1)
                {
                    Console.WriteLine($"  [Transport] Returning 503 with Retry-After:1");
                    var response = new MockResponse(503);
                    response.AddHeader("Retry-After", "1");
                    return response;
                }
                Console.WriteLine($"  [Transport] Returning 200");
                return new MockResponse(200);
            }
            return new MockResponse(200);
        });

        // Use REAL CodeTransparencyClientOptions (not TestClientOptions)
        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
        };
        options.ConfigureMstPerformanceOptimizations(
            retryDelay: TimeSpan.FromMilliseconds(50),
            maxRetries: 8);

        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
        HttpMessage message = pipeline.CreateMessage();
        message.Request.Method = RequestMethod.Get;
        message.Request.Uri.Reset(new Uri(
            "https://esrp-cts-dev.confidential-ledger.azure.com/entries/702.1048242/statement?api-version=2025-01-31-preview"));

        Console.WriteLine("[Test] Sending request through pipeline...");
        Stopwatch sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();
        Console.WriteLine($"[Test] Completed in {sw.ElapsedMilliseconds}ms, Status: {message.Response.Status}");
        Console.WriteLine($"[Test] Transport was called {transportCallCount} times");

        // Assert
        Assert.That(message.Response.Status, Is.EqualTo(200));
        // If our policy works: ~50ms delay. If SDK RetryPolicy handles it: ~800ms+
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(500),
            $"Policy should intercept 503 and retry in ~50ms, not wait for SDK retry (~800ms). Took {sw.ElapsedMilliseconds}ms");
        Assert.That(transportCallCount, Is.EqualTo(2), "Transport should be called exactly twice (503, then 200)");
    }

    #endregion

    #region ActivitySource Tracing Tests

    private static readonly ActivitySource TestActivitySource = new("MstPerformanceOptimizationPolicyTests");

    // Ensure TestActivitySource activities are always sampled
    private static readonly ActivityListener TestParentListener = CreateTestParentListener();
    private static ActivityListener CreateTestParentListener()
    {
        ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == "MstPerformanceOptimizationPolicyTests",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    [OneTimeTearDown]
    public void CleanupActivitySourceResources()
    {
        TestParentListener.Dispose();
        TestActivitySource.Dispose();
    }

    private static (ActivityListener Listener, ConcurrentBag<Activity> Activities) CreateScopedActivityCollector(Activity parentActivity)
    {
        ActivityTraceId traceId = parentActivity.TraceId;
        ConcurrentBag<Activity> collected = new();
        ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == MstPerformanceOptimizationPolicy.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> options) =>
                options.Parent.TraceId == traceId
                    ? ActivitySamplingResult.AllDataAndRecorded
                    : ActivitySamplingResult.None,
            ActivityStopped = activity =>
            {
                if (activity.TraceId == traceId)
                {
                    collected.Add(activity);
                }
            }
        };
        ActivitySource.AddActivityListener(listener);
        return (listener, collected);
    }

    /// <summary>
    /// Verifies that the policy emits an AcceleratedRetry activity with child RetryAttempt
    /// activities when it intercepts a 503 on /entries/ and resolves on the 2nd attempt.
    /// </summary>
    [Test]
    public async Task ActivitySource_503Resolved_EmitsRetryActivityWithAttempts()
    {
        // Arrange
        using Activity parentActivity = TestActivitySource.StartActivity("Test.503Resolved")!;
        (ActivityListener scopedListener, ConcurrentBag<Activity> collectedActivities) = CreateScopedActivityCollector(parentActivity);

        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount <= 1)
            {
                var response = new MockResponse(503);
                response.AddHeader("Retry-After", "1");
                return response;
            }
            return new MockResponse(200);
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 5);
        var options = new TestClientOptions(transport, policy);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        HttpMessage message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/test-id/statement");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(callCount, Is.EqualTo(2));

        List<Activity> activities = collectedActivities.ToList();
        Activity? retryActivity = activities.Find(a => a.OperationName == "MstPerformanceOptimization.AcceleratedRetry");
        Assert.That(retryActivity, Is.Not.Null, "Should emit an AcceleratedRetry activity");
        Assert.That(retryActivity!.GetTagItem("mst.policy.initial_status"), Is.EqualTo(503));
        Assert.That(retryActivity.GetTagItem("mst.policy.resolved_at_attempt"), Is.EqualTo(1));
        Assert.That(retryActivity.GetTagItem("mst.policy.max_retries"), Is.EqualTo(5));
        Assert.That(retryActivity.GetTagItem("mst.policy.retry_delay_ms"), Is.EqualTo(10.0));
        Assert.That(retryActivity.GetTagItem("http.url"), Does.Contain("/entries/"));
        Assert.That(retryActivity.GetTagItem("mst.policy.final_status"), Is.EqualTo(200));

        List<Activity> attemptActivities = activities.FindAll(a =>
            a.OperationName == "MstPerformanceOptimization.RetryAttempt");
        Assert.That(attemptActivities, Has.Count.EqualTo(1), "Should have 1 retry attempt (resolved on first retry)");
        Assert.That(attemptActivities[0].GetTagItem("mst.policy.attempt"), Is.EqualTo(1));
        Assert.That(attemptActivities[0].GetTagItem("http.status_code"), Is.EqualTo(200));
        Assert.That(attemptActivities[0].GetTagItem("mst.policy.result"), Is.EqualTo("resolved"));

        scopedListener.Dispose();
    }

    /// <summary>
    /// Verifies that multiple retry attempts emit individual child activities with correct tags.
    /// </summary>
    [Test]
    public async Task ActivitySource_MultipleRetries_EmitsActivityPerAttempt()
    {
        // Arrange
        using Activity parentActivity = TestActivitySource.StartActivity("Test.MultipleRetries")!;
        (ActivityListener scopedListener, ConcurrentBag<Activity> collectedActivities) = CreateScopedActivityCollector(parentActivity);

        int callCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
        {
            callCount++;
            if (callCount <= 3)
            {
                var response = new MockResponse(503);
                response.AddHeader("Retry-After", "1");
                return response;
            }
            return new MockResponse(200);
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 5);
        var options = new TestClientOptions(transport, policy);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        HttpMessage message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/test-id/statement");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(callCount, Is.EqualTo(4));

        List<Activity> activities = collectedActivities.ToList();
        Activity? retryActivity = activities.Find(a => a.OperationName == "MstPerformanceOptimization.AcceleratedRetry");
        Assert.That(retryActivity, Is.Not.Null);

        List<Activity> attemptActivities = activities
            .FindAll(a => a.OperationName == "MstPerformanceOptimization.RetryAttempt")
            .OrderBy(a => (int?)a.GetTagItem("mst.policy.attempt") ?? 0)
            .ToList();
        Assert.That(attemptActivities, Has.Count.EqualTo(3), "Should have 3 retry attempts");

        Assert.That(attemptActivities[0].GetTagItem("mst.policy.attempt"), Is.EqualTo(1));
        Assert.That(attemptActivities[0].GetTagItem("mst.policy.result"), Is.EqualTo("still_503"));
        Assert.That(attemptActivities[0].GetTagItem("http.status_code"), Is.EqualTo(503));

        Assert.That(attemptActivities[1].GetTagItem("mst.policy.attempt"), Is.EqualTo(2));
        Assert.That(attemptActivities[1].GetTagItem("mst.policy.result"), Is.EqualTo("still_503"));

        Assert.That(attemptActivities[2].GetTagItem("mst.policy.attempt"), Is.EqualTo(3));
        Assert.That(attemptActivities[2].GetTagItem("mst.policy.result"), Is.EqualTo("resolved"));
        Assert.That(attemptActivities[2].GetTagItem("http.status_code"), Is.EqualTo(200));

        scopedListener.Dispose();
    }

    /// <summary>
    /// Verifies that when all retries are exhausted, the parent activity reports "exhausted".
    /// </summary>
    [Test]
    public async Task ActivitySource_RetriesExhausted_EmitsExhaustedActivity()
    {
        // Arrange
        using Activity parentActivity = TestActivitySource.StartActivity("Test.RetriesExhausted")!;
        (ActivityListener scopedListener, ConcurrentBag<Activity> collectedActivities) = CreateScopedActivityCollector(parentActivity);

        var transport = MockTransport.FromMessageCallback(msg =>
        {
            var response = new MockResponse(503);
            response.AddHeader("Retry-After", "1");
            return response;
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 3);
        var options = new TestClientOptions(transport, policy);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        HttpMessage message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/test-id/statement");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert
        Assert.That(message.Response.Status, Is.EqualTo(503));

        List<Activity> activities = collectedActivities.ToList();
        Activity? retryActivity = activities.Find(a => a.OperationName == "MstPerformanceOptimization.AcceleratedRetry");
        Assert.That(retryActivity, Is.Not.Null);
        Assert.That(retryActivity!.GetTagItem("mst.policy.result"), Is.EqualTo("exhausted"));
        Assert.That(retryActivity.GetTagItem("mst.policy.resolved_at_attempt"), Is.EqualTo(0));
        Assert.That(retryActivity.GetTagItem("mst.policy.final_status"), Is.EqualTo(503));

        List<Activity> attemptActivities = activities.FindAll(a =>
            a.OperationName == "MstPerformanceOptimization.RetryAttempt");
        Assert.That(attemptActivities, Has.Count.EqualTo(3), "Should have 3 retry attempts (all exhausted)");
        Assert.That(attemptActivities.TrueForAll(a => (string?)a.GetTagItem("mst.policy.result") == "still_503"), Is.True);

        scopedListener.Dispose();
    }

    /// <summary>
    /// Verifies that no activities are emitted for non-503 responses or non-/entries/ paths.
    /// </summary>
    [Test]
    public async Task ActivitySource_Non503Response_NoActivitiesEmitted()
    {
        // Arrange
        using Activity parentActivity = TestActivitySource.StartActivity("Test.Non503Response")!;
        (ActivityListener scopedListener, ConcurrentBag<Activity> collectedActivities) = CreateScopedActivityCollector(parentActivity);

        var transport = MockTransport.FromMessageCallback(msg => new MockResponse(200));

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 3);
        var options = new TestClientOptions(transport, policy);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        HttpMessage message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/entries/test-id/statement");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert
        Assert.That(message.Response.Status, Is.EqualTo(200));
        List<Activity> activities = collectedActivities.ToList();
        Activity? evalActivity = activities.Find(a =>
            a.OperationName == "MstPerformanceOptimization.Evaluate");
        Assert.That(evalActivity, Is.Not.Null, "Should emit an Evaluate activity");
        Assert.That(evalActivity!.GetTagItem("mst.policy.action"), Is.EqualTo("passthrough"));
        Assert.That(evalActivity.GetTagItem("http.response.status_code"), Is.EqualTo(200));

        List<Activity> retryActivities = activities
            .FindAll(a => a.OperationName == "MstPerformanceOptimization.AcceleratedRetry");
        Assert.That(retryActivities, Is.Empty, "No retry activities should be emitted for 200 responses");

        scopedListener.Dispose();
    }

    /// <summary>
    /// Verifies that operations responses (LRO polling) do not emit retry activities.
    /// </summary>
    [Test]
    public async Task ActivitySource_OperationsPath_NoRetryActivitiesEmitted()
    {
        // Arrange
        using Activity parentActivity = TestActivitySource.StartActivity("Test.OperationsPath")!;
        (ActivityListener scopedListener, ConcurrentBag<Activity> collectedActivities) = CreateScopedActivityCollector(parentActivity);

        var transport = MockTransport.FromMessageCallback(msg =>
        {
            var response = new MockResponse(202);
            response.AddHeader("Retry-After", "1");
            return response;
        });

        var policy = new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(10), 3);
        var options = new TestClientOptions(transport, policy);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        HttpMessage message = CreateHttpMessage(pipeline, RequestMethod.Get, "https://mst.example.com/operations/op-123");

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert
        List<Activity> activities = collectedActivities.ToList();
        Activity? evalActivity = activities.Find(a =>
            a.OperationName == "MstPerformanceOptimization.Evaluate");
        Assert.That(evalActivity, Is.Not.Null, "Should emit an Evaluate activity for /operations/");
        Assert.That(evalActivity!.GetTagItem("mst.policy.action"), Is.EqualTo("strip_operations_headers"));
        Assert.That(evalActivity.GetTagItem("mst.policy.is_operations"), Is.EqualTo(true));

        List<Activity> retryActivities = activities
            .FindAll(a => a.OperationName == "MstPerformanceOptimization.AcceleratedRetry");
        Assert.That(retryActivities, Is.Empty, "No retry activities for /operations/ paths");

        scopedListener.Dispose();
    }

    /// <summary>
    /// Verifies the <see cref="MstPerformanceOptimizationPolicy.ActivitySourceName"/> constant
    /// matches the actual ActivitySource name used.
    /// </summary>
    [Test]
    public void ActivitySourceName_IsCorrectValue()
    {
        Assert.That(MstPerformanceOptimizationPolicy.ActivitySourceName,
            Is.EqualTo("CoseSign1.Transparent.MST.PerformanceOptimizationPolicy"));
    }

    #endregion
}
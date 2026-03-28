// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Core.TestCommon;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST;

/// <summary>
/// End-to-end timing tests that simulate realistic MST latency patterns to:
/// 1. Replicate the observed ~3-second behavior
/// 2. Identify timing contributions from LRO polling vs GetEntryAsync 503 retries
/// 3. Demonstrate tuning strategies for optimal performance
///
/// Real-world pattern:
/// - CreateEntryAsync: Quick initial response with operation ID, then polling until operation completes (~400ms)
/// - GetEntryStatementAsync: First few calls return 503 TransactionNotCached, then success
///
/// NOTE: Tests that exercise the full MstTransparencyService integration (LRO polling + GetEntry)
/// are omitted from this V2 port. They require MstTransparencyService which does not yet exist in V2.
/// The pipeline-level tests below fully validate the MstPerformanceOptimizationPolicy behavior.
/// </summary>
[TestFixture]
[NonParallelizable] // Timing tests should not run in parallel
public class MstEndToEndTimingTests
{
    #region GetEntryAsync 503 Pattern Tests

    /// <summary>
    /// Simulates the full scenario:
    /// - GetEntryStatementAsync returns 503 on first 2 calls, success on 3rd
    /// - WITHOUT the MstPerformanceOptimizationPolicy
    ///
    /// This should show the 3-second behavior due to SDK's Retry-After: 1 delay.
    /// </summary>
    [Test]
    public async Task FullScenario_Without_TransactionNotCachedPolicy_Shows3SecondBehavior()
    {
        // Arrange - simulate the real HTTP pipeline without our custom policy
        int getEntryCallCount = 0;
        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            // For GetEntryStatement calls (GET /entries/)
            if (msg.Request.Method == RequestMethod.Get &&
                msg.Request.Uri.ToUri().AbsoluteUri.Contains("/entries/"))
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    // Return 503 with Retry-After: 1 (1 second)
                    return CreateTransactionNotCachedResponse();
                }
                // Third call succeeds
                return CreateSuccessfulEntryResponse();
            }
            // Other calls pass through
            return new MockResponse(200);
        });

        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };

        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");

        Stopwatch sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Console.WriteLine($"[Without Policy] Duration: {sw.ElapsedMilliseconds}ms, GetEntry calls: {getEntryCallCount}");
        Assert.That(message.Response.Status, Is.EqualTo(200));
        // Should take ~2 seconds (2x Retry-After: 1 delays)
        Assert.That(sw.ElapsedMilliseconds, Is.GreaterThanOrEqualTo(1800),
            $"Without custom policy, SDK should respect Retry-After: 1 header, causing ~2s delay. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// Same scenario but WITH the MstPerformanceOptimizationPolicy.
    /// Should resolve much faster due to aggressive fast retries.
    /// </summary>
    [Test]
    public async Task FullScenario_With_TransactionNotCachedPolicy_ResolvesQuickly()
    {
        // Arrange
        int getEntryCallCount = 0;
        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            if (msg.Request.Method == RequestMethod.Get &&
                msg.Request.Uri.ToUri().AbsoluteUri.Contains("/entries/"))
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    return CreateTransactionNotCachedResponse();
                }
                return CreateSuccessfulEntryResponse();
            }
            return new MockResponse(200);
        });

        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        // Add the fast retry policy with 100ms interval
        options.ConfigureMstPerformanceOptimizations(
            retryDelay: TimeSpan.FromMilliseconds(100),
            maxRetries: 8);

        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");

        Stopwatch sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Console.WriteLine($"[With Policy] Duration: {sw.ElapsedMilliseconds}ms, GetEntry calls: {getEntryCallCount}");
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(getEntryCallCount, Is.EqualTo(3), "Should make exactly 3 calls (2 failures + 1 success)");
        // Should complete in ~200-300ms (2x 100ms retry delays + network latency simulation)
        // Allow 700ms for CI runner overhead
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(700),
            $"With custom policy, should resolve in <700ms. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// Test with even more aggressive 50ms retry delay.
    /// </summary>
    [Test]
    public async Task FullScenario_With_TransactionNotCachedPolicy_50msDelay()
    {
        // Arrange
        int getEntryCallCount = 0;
        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            if (msg.Request.Method == RequestMethod.Get &&
                msg.Request.Uri.ToUri().AbsoluteUri.Contains("/entries/"))
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    return CreateTransactionNotCachedResponse();
                }
                return CreateSuccessfulEntryResponse();
            }
            return new MockResponse(200);
        });

        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        options.ConfigureMstPerformanceOptimizations(
            retryDelay: TimeSpan.FromMilliseconds(50),
            maxRetries: 8);

        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");

        Stopwatch sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Console.WriteLine($"[With Policy 50ms] Duration: {sw.ElapsedMilliseconds}ms, GetEntry calls: {getEntryCallCount}");
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(500),
            $"With 50ms retry delay, should resolve in <500ms. Got {sw.ElapsedMilliseconds}ms");
    }

    #endregion

    #region True End-to-End Integration Tests

    /// <summary>
    /// True integration test that measures the total time through:
    /// 1. LRO polling (simulated via WaitForCompletionAsync with real delays)
    /// 2. GetEntryStatementAsync through HTTP pipeline with actual 503/TransactionNotCached retries
    ///
    /// WITHOUT tuning: Expected ~3+ seconds
    /// - LRO polling with SDK default: ~1 second (first poll waits 1s)
    /// - GetEntry with 2x 503 and SDK Retry-After: 1: ~2 seconds
    /// </summary>
    [Test]
    public async Task TrueIntegration_Baseline_NoTuning_Measures3SecondBehavior()
    {
        // Arrange
        int lroPollCount = 0;
        int getEntryCallCount = 0;
        DateTimeOffset lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

        // Create transport that simulates GetEntry 503 pattern
        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;

            // GetEntryStatement calls
            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    return CreateTransactionNotCachedResponse();
                }
                // Third call succeeds - return valid COSE Sign1 message bytes
                MockResponse response = new(200);
                response.SetContent(CreateMessageWithReceipt().Encode());
                return response;
            }

            // Default pass-through for other calls
            return new MockResponse(200);
        });

        // Use SDK defaults (no custom policy, no fast polling)
        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        // Mock the Operation to simulate LRO timing with SDK default backoff
        Moq.Mock<Operation<BinaryData>> mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

        Stopwatch sw = Stopwatch.StartNew();

        // Phase 1: Wait for LRO completion (simulates CreateEntryAsync waiting)
        await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
        long lroDuration = sw.ElapsedMilliseconds;

        // Phase 2: GetEntryStatement through HTTP pipeline with SDK retry
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Console.WriteLine($"[True Integration Baseline] Total: {sw.ElapsedMilliseconds}ms, " +
            $"LRO: {lroDuration}ms (polls: {lroPollCount}), " +
            $"GetEntry: {sw.ElapsedMilliseconds - lroDuration}ms (calls: {getEntryCallCount})");

        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(getEntryCallCount, Is.EqualTo(3), "Should make 3 GetEntry calls (2 failures + 1 success)");

        // Should take ~3 seconds total:
        // - ~1 second for LRO (SDK default first poll is 1s)
        // - ~2 seconds for 2x Retry-After: 1
        Assert.That(sw.ElapsedMilliseconds, Is.GreaterThanOrEqualTo(2500),
            $"Without tuning, should take >2.5s total. Got {sw.ElapsedMilliseconds}ms (LRO: {lroDuration}ms)");
    }

    /// <summary>
    /// True integration test with BOTH tuning strategies applied:
    /// 1. Aggressive LRO polling (100ms fixed interval)
    /// 2. Fast TransactionNotCached retries (100ms via MstPerformanceOptimizationPolicy)
    ///
    /// Expected: ~600-800ms total (down from ~3 seconds)
    /// </summary>
    [Test]
    public async Task TrueIntegration_FullyTuned_BothPolicies()
    {
        // Arrange
        int lroPollCount = 0;
        int getEntryCallCount = 0;
        DateTimeOffset lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;

            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    return CreateTransactionNotCachedResponse();
                }
                MockResponse response = new(200);
                response.SetContent(CreateMessageWithReceipt().Encode());
                return response;
            }

            return new MockResponse(200);
        });

        // Configure with BOTH tuning strategies
        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        // Add fast retry policy (100ms instead of 1s Retry-After)
        options.ConfigureMstPerformanceOptimizations(
            retryDelay: TimeSpan.FromMilliseconds(100),
            maxRetries: 8);

        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        // Mock the Operation with fast polling (100ms instead of SDK default)
        Moq.Mock<Operation<BinaryData>> mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

        Stopwatch sw = Stopwatch.StartNew();

        // Phase 1: Wait for LRO with fast polling (100ms interval)
        await mockOperation.Object.WaitForCompletionAsync(
            TimeSpan.FromMilliseconds(100),
            CancellationToken.None);
        long lroDuration = sw.ElapsedMilliseconds;

        // Phase 2: GetEntryStatement through HTTP pipeline with fast retry policy
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Console.WriteLine($"[True Integration Tuned] Total: {sw.ElapsedMilliseconds}ms, " +
            $"LRO: {lroDuration}ms (polls: {lroPollCount}), " +
            $"GetEntry: {sw.ElapsedMilliseconds - lroDuration}ms (calls: {getEntryCallCount})");

        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(getEntryCallCount, Is.EqualTo(3));

        // Should take ~600-800ms total:
        // - ~400-500ms for LRO (100ms polling, ready at 400ms)
        // - ~200ms for 2x 100ms fast retries
        // Allow 1200ms for CI runner overhead
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(1200),
            $"With full tuning, should complete in <1.2s total. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// True integration with 50ms aggressive tuning.
    /// </summary>
    [Test]
    public async Task TrueIntegration_AggressiveTuning_50ms()
    {
        // Arrange
        int lroPollCount = 0;
        int getEntryCallCount = 0;
        DateTimeOffset lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;

            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    return CreateTransactionNotCachedResponse();
                }
                MockResponse response = new(200);
                response.SetContent(CreateMessageWithReceipt().Encode());
                return response;
            }

            return new MockResponse(200);
        });

        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        options.ConfigureMstPerformanceOptimizations(
            retryDelay: TimeSpan.FromMilliseconds(50),
            maxRetries: 8);

        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
        Moq.Mock<Operation<BinaryData>> mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

        Stopwatch sw = Stopwatch.StartNew();

        // Fast LRO polling (50ms)
        await mockOperation.Object.WaitForCompletionAsync(
            TimeSpan.FromMilliseconds(50),
            CancellationToken.None);
        long lroDuration = sw.ElapsedMilliseconds;

        // GetEntryStatement with fast retry
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Console.WriteLine($"[True Integration 50ms] Total: {sw.ElapsedMilliseconds}ms, " +
            $"LRO: {lroDuration}ms (polls: {lroPollCount}), " +
            $"GetEntry: {sw.ElapsedMilliseconds - lroDuration}ms (calls: {getEntryCallCount})");

        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(getEntryCallCount, Is.EqualTo(3));

        // Should take ~500-600ms total:
        // - ~400-450ms for LRO (50ms polling, ready at 400ms)
        // - ~100ms for 2x 50ms fast retries
        // Allow 1200ms for CI runner overhead
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(1200),
            $"With 50ms tuning, should complete in <1.2s total. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// Comparison test showing improvement ratio.
    /// </summary>
    [Test]
    public async Task TrueIntegration_ComparisonSummary()
    {
        List<(string Config, long TotalMs, long LroMs, long GetEntryMs)> results = new();

        // Test 1: Baseline (SDK defaults) - LRO ready at 400ms
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            DateTimeOffset lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

            MockTransport transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                    {
                        return CreateTransactionNotCachedResponse();
                    }

                    MockResponse response = new(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            CodeTransparencyClientOptions options = new()
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
            Moq.Mock<Operation<BinaryData>> mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            Stopwatch sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
            long lroMs = sw.ElapsedMilliseconds;
            HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Baseline (no tuning)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs));
        }

        // Test 2: Pipeline Policy ONLY (no LRO tuning) - simulates user's current fix
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            DateTimeOffset lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

            MockTransport transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                    {
                        return CreateTransactionNotCachedResponse();
                    }

                    MockResponse response = new(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            CodeTransparencyClientOptions options = new()
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            // Pipeline policy WITH fast retry (user's current fix)
            options.ConfigureMstPerformanceOptimizations(TimeSpan.FromMilliseconds(100), 8);
            HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
            Moq.Mock<Operation<BinaryData>> mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            Stopwatch sw = Stopwatch.StartNew();
            // SDK default LRO polling (NO fast polling - as user has now)
            await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
            long lroMs = sw.ElapsedMilliseconds;
            HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Policy only (no LRO)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs));
        }

        // Test 3: Both tuned (100ms/100ms)
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            DateTimeOffset lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

            MockTransport transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                    {
                        return CreateTransactionNotCachedResponse();
                    }

                    MockResponse response = new(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            CodeTransparencyClientOptions options = new()
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            options.ConfigureMstPerformanceOptimizations(TimeSpan.FromMilliseconds(100), 8);
            HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
            Moq.Mock<Operation<BinaryData>> mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            Stopwatch sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(TimeSpan.FromMilliseconds(100), CancellationToken.None);
            long lroMs = sw.ElapsedMilliseconds;
            HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Both tuned (100ms)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs));
        }

        // Test 4: Aggressive (50ms/50ms)
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            DateTimeOffset lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

            MockTransport transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                    {
                        return CreateTransactionNotCachedResponse();
                    }

                    MockResponse response = new(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            CodeTransparencyClientOptions options = new()
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            options.ConfigureMstPerformanceOptimizations(TimeSpan.FromMilliseconds(50), 8);
            HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
            Moq.Mock<Operation<BinaryData>> mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            Stopwatch sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None);
            long lroMs = sw.ElapsedMilliseconds;
            HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Aggressive (50ms/50ms)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs));
        }

        // Output comparison
        Console.WriteLine("\n=== TIMING COMPARISON ===");
        Console.WriteLine($"{"Configuration",-25} {"Total",-10} {"LRO",-10} {"GetEntry",-10} {"Speedup",-10}");
        Console.WriteLine(new string('-', 65));

        long baseline = results[0].TotalMs;
        foreach ((string Config, long TotalMs, long LroMs, long GetEntryMs) r in results)
        {
            double speedup = (double)baseline / r.TotalMs;
            Console.WriteLine($"{r.Config,-25} {r.TotalMs + "ms",-10} {r.LroMs + "ms",-10} {r.GetEntryMs + "ms",-10} {speedup:F1}x");
        }

        // Assert baseline is significantly slower
        Assert.That(results[0].TotalMs, Is.GreaterThanOrEqualTo(2500), "Baseline should be >2.5s");
        // Policy only should be ~1.2s (SDK LRO ~1s + fast GetEntry ~200ms)
        Assert.That(results[1].TotalMs, Is.LessThan(1800), "Policy only should be <1.8s");
        Assert.That(results[1].TotalMs, Is.GreaterThanOrEqualTo(1000), "Policy only should be >1s (LRO delay)");
        Assert.That(results[2].TotalMs, Is.LessThan(1200), "Both tuned should be <1.2s");
        Assert.That(results[3].TotalMs, Is.LessThan(1200), "Aggressive should be <1.2s");

        // Assert improvement ratio for full tuning
        double improvementRatio = (double)results[0].TotalMs / results[3].TotalMs;
        Assert.That(improvementRatio, Is.GreaterThan(3.0),
            $"Aggressive tuning should provide >3x improvement. Got {improvementRatio:F1}x");
    }

    #endregion

    #region Root Cause Confirmation Tests - Proving Retry-After Impact

    /// <summary>
    /// DEFINITIVE PROOF: The Azure SDK's RetryPolicy respects Retry-After headers on 503 responses.
    /// This test proves that WITHOUT our policy, 2x 503 responses with "Retry-After: 1" cause ~2 seconds delay.
    /// This is the root cause for the slow /entries/ GET path.
    /// </summary>
    [Test]
    [Category("RootCauseProof")]
    public async Task RootCause_Entries503_SdkRespectsRetryAfterHeader_Causes2SecondDelay()
    {
        // Arrange - 503 responses with Retry-After: 1 header
        int callCount = 0;
        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;
            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                callCount++;
                if (callCount <= 2)
                {
                    MockResponse response = new(503);
                    response.AddHeader("Retry-After", "1"); // 1 second
                    response.AddHeader("Content-Type", "application/problem+cbor");
                    response.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
                    return response;
                }
                MockResponse success = new(200);
                success.SetContent(CreateMessageWithReceipt().Encode());
                return success;
            }
            return new MockResponse(200);
        });

        // NO custom policy - SDK defaults
        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            // Small base delay so ONLY Retry-After affects timing
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(1) }
        };
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");

        Stopwatch sw = Stopwatch.StartNew();
        await pipeline.SendAsync(message, CancellationToken.None);
        sw.Stop();

        // Assert - DEFINITIVE: 2x Retry-After: 1 = ~2 seconds
        Console.WriteLine($"[ROOT CAUSE PROOF - entries 503] Duration: {sw.ElapsedMilliseconds}ms, Calls: {callCount}");
        Assert.That(message.Response.Status, Is.EqualTo(200), "Should eventually succeed");
        Assert.That(callCount, Is.EqualTo(3), "Should make 3 calls (2 failures + 1 success)");
        Assert.That(sw.ElapsedMilliseconds, Is.GreaterThanOrEqualTo(1800),
            $"PROOF: SDK respects Retry-After: 1 header. Expected ~2s for 2 retries, got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// DEFINITIVE PROOF: With our policy, the same scenario resolves in ~200ms instead of ~2 seconds.
    /// This proves the policy effectively strips Retry-After headers.
    /// </summary>
    [Test]
    [Category("RootCauseProof")]
    public async Task RootCause_Entries503_WithPolicy_ResolvesIn200ms()
    {
        // Arrange - same 503 pattern
        int callCount = 0;
        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;
            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                callCount++;
                if (callCount <= 2)
                {
                    MockResponse response = new(503);
                    response.AddHeader("Retry-After", "1");
                    response.AddHeader("Content-Type", "application/problem+cbor");
                    response.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
                    return response;
                }
                MockResponse success = new(200);
                success.SetContent(CreateMessageWithReceipt().Encode());
                return success;
            }
            return new MockResponse(200);
        });

        // WITH our policy - fast retries + header stripping
        MstPerformanceOptimizationPolicy policy = new(TimeSpan.FromMilliseconds(50), 8);
        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(1) }
        };
        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");

        Stopwatch sw = Stopwatch.StartNew();
        await pipeline.SendAsync(message, CancellationToken.None);
        sw.Stop();

        // Assert - DEFINITIVE: ~100-200ms instead of ~2 seconds
        Console.WriteLine($"[ROOT CAUSE FIX - entries 503] Duration: {sw.ElapsedMilliseconds}ms, Calls: {callCount}");
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(callCount, Is.EqualTo(3));
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(600),
            $"PROOF: Policy overrides Retry-After. Expected <600ms, got {sw.ElapsedMilliseconds}ms (vs ~2s without policy)");
    }

    /// <summary>
    /// ROOT CAUSE CONFIRMATION: The /operations/ endpoint (LRO polling) also returns Retry-After headers.
    /// This test verifies that our policy strips Retry-After from /operations/ responses.
    /// </summary>
    [Test]
    [Category("RootCauseProof")]
    public async Task RootCause_Operations202_SdkRespectsRetryAfterHeader_PolicyStripsIt()
    {
        // Arrange - LRO polling response with Retry-After
        int pollCount = 0;
        bool retryAfterPresentBefore = false;
        bool retryAfterPresentAfter = false;

        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;
            if (uri.Contains("/operations/"))
            {
                pollCount++;
                MockResponse response = new(pollCount < 3 ? 202 : 200); // 2x pending, then complete
                response.AddHeader("Retry-After", "1"); // Server says "wait 1 second"
                response.AddHeader("retry-after-ms", "1000"); // Also the ms variant
                response.AddHeader("x-ms-retry-after-ms", "1000"); // And the x-ms variant
                response.SetContent("{}");
                retryAfterPresentBefore = response.Headers.Contains("Retry-After");
                return response;
            }
            return new MockResponse(200);
        });

        // WITH policy to demonstrate header stripping
        MstPerformanceOptimizationPolicy policy = new(TimeSpan.FromMilliseconds(50), 8);
        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 0 } // Disable retries, we're testing LRO polling
        };
        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        // Act - simulate a single LRO poll request
        HttpMessage message = pipeline.CreateMessage();
        message.Request.Method = RequestMethod.Get;
        message.Request.Uri.Reset(new Uri("https://mst.example.com/operations/test-op-123"));
        await pipeline.SendAsync(message, CancellationToken.None);

        // Check headers after policy processing
        retryAfterPresentAfter = message.Response.Headers.Contains("Retry-After") ||
                                  message.Response.Headers.Contains("retry-after-ms") ||
                                  message.Response.Headers.Contains("x-ms-retry-after-ms");

        // Assert
        Console.WriteLine($"[ROOT CAUSE - operations LRO] Polls: {pollCount}, " +
            $"Retry-After before policy: {retryAfterPresentBefore}, after: {retryAfterPresentAfter}");

        Assert.That(retryAfterPresentBefore, Is.True,
            "Server response should have Retry-After header (this is what causes slow LRO polling)");
        Assert.That(retryAfterPresentAfter, Is.False,
            "Policy should strip ALL Retry-After variants from /operations/ responses, " +
            "enabling our configured polling interval instead of server-dictated 1s delay");
    }

    /// <summary>
    /// SUMMARY TEST: Demonstrates the complete impact.
    /// Without policy: ~3 seconds (1s LRO first poll + 2x 1s Retry-After on entries)
    /// With policy: ~600ms (fast polling + fast retries)
    /// </summary>
    [Test]
    [Category("RootCauseProof")]
    public async Task RootCause_CombinedScenario_3SecondVs600ms()
    {
        List<(string Config, long Ms)> results = new();

        // Scenario 1: Without policy - expected ~2s+ just for entries
        {
            int callCount = 0;
            MockTransport transport = MockTransport.FromMessageCallback(msg =>
            {
                if (msg.Request.Method == RequestMethod.Get && msg.Request.Uri.ToUri().AbsoluteUri.Contains("/entries/"))
                {
                    callCount++;
                    if (callCount <= 2)
                    {
                        MockResponse r = new(503);
                        r.AddHeader("Retry-After", "1");
                        r.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
                        return r;
                    }
                    MockResponse s = new(200);
                    s.SetContent(CreateMessageWithReceipt().Encode());
                    return s;
                }
                return new MockResponse(200);
            });

            CodeTransparencyClientOptions options = new() { Transport = transport };
            options.Retry.MaxRetries = 5;
            options.Retry.Delay = TimeSpan.FromMilliseconds(1);
            HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

            Stopwatch sw = Stopwatch.StartNew();
            HttpMessage msg = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");
            await pipeline.SendAsync(msg, CancellationToken.None);
            sw.Stop();
            results.Add(("Without Policy", sw.ElapsedMilliseconds));
        }

        // Scenario 2: With policy - expected <400ms
        {
            int callCount = 0;
            MockTransport transport = MockTransport.FromMessageCallback(msg =>
            {
                if (msg.Request.Method == RequestMethod.Get && msg.Request.Uri.ToUri().AbsoluteUri.Contains("/entries/"))
                {
                    callCount++;
                    if (callCount <= 2)
                    {
                        MockResponse r = new(503);
                        r.AddHeader("Retry-After", "1");
                        r.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
                        return r;
                    }
                    MockResponse s = new(200);
                    s.SetContent(CreateMessageWithReceipt().Encode());
                    return s;
                }
                return new MockResponse(200);
            });

            MstPerformanceOptimizationPolicy policy = new(TimeSpan.FromMilliseconds(50), 8);
            CodeTransparencyClientOptions options = new() { Transport = transport };
            options.Retry.MaxRetries = 5;
            options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
            HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

            Stopwatch sw = Stopwatch.StartNew();
            HttpMessage msg = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");
            await pipeline.SendAsync(msg, CancellationToken.None);
            sw.Stop();
            results.Add(("With Policy", sw.ElapsedMilliseconds));
        }

        // Assert
        Console.WriteLine("\n=== ROOT CAUSE IMPACT SUMMARY ===");
        Console.WriteLine($"Without Policy: {results[0].Ms}ms (SDK respects Retry-After: 1)");
        Console.WriteLine($"With Policy:    {results[1].Ms}ms (fast retries + header stripped)");
        Console.WriteLine($"Speedup:        {(double)results[0].Ms / results[1].Ms:F1}x faster\n");

        Assert.That(results[0].Ms, Is.GreaterThanOrEqualTo(1800),
            "Without policy should take ~2s due to 2x Retry-After: 1");
        Assert.That(results[1].Ms, Is.LessThan(600),
            "With policy should take <600ms");
        Assert.That(results[0].Ms, Is.GreaterThan(results[1].Ms * 4),
            "Policy should provide at least 4x speedup");
    }

    #endregion

    #region Retry-After Header Stripping Tests

    /// <summary>
    /// Verifies that the policy strips Retry-After headers from 503 /entries/ responses.
    /// Without header stripping, SDK would wait 1 second per retry.
    /// </summary>
    [Test]
    public async Task RetryAfterStripping_Entries503_HeaderIsStripped()
    {
        // Arrange
        int callCount = 0;
        bool retryAfterWasPresentOnOriginal = false;
        bool retryAfterWasPresentAfterPolicy = false;

        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;
            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                callCount++;
                if (callCount <= 2)
                {
                    MockResponse response = new(503);
                    response.AddHeader("Retry-After", "1");
                    response.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
                    retryAfterWasPresentOnOriginal = response.Headers.Contains("Retry-After");
                    return response;
                }
                MockResponse successResponse = new(200);
                successResponse.SetContent(CreateMessageWithReceipt().Encode());
                return successResponse;
            }
            return new MockResponse(200);
        });

        // Configure with our policy (fast retries + header stripping)
        MstPerformanceOptimizationPolicy policy = new(TimeSpan.FromMilliseconds(50), 8);
        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 0 } // Disable SDK retries so we can observe policy behavior
        };
        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        Stopwatch sw = Stopwatch.StartNew();

        // Act
        HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Check if Retry-After is present after policy processed the response
        retryAfterWasPresentAfterPolicy = message.Response.Headers.Contains("Retry-After");

        // Assert
        Console.WriteLine($"[Entries 503 Header Strip] Duration: {sw.ElapsedMilliseconds}ms, " +
            $"Calls: {callCount}, Retry-After present on original: {retryAfterWasPresentOnOriginal}, " +
            $"Retry-After present after policy: {retryAfterWasPresentAfterPolicy}");

        Assert.That(retryAfterWasPresentOnOriginal, Is.True, "Original response should have Retry-After header");
        Assert.That(retryAfterWasPresentAfterPolicy, Is.False, "Policy should strip Retry-After header from final response");
        Assert.That(message.Response.Status, Is.EqualTo(200), "Final response should be success");
        Assert.That(callCount, Is.EqualTo(3), "Should make 3 calls (2 failures + 1 success)");
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(700), "With 50ms retries, should complete in <700ms");
    }

    /// <summary>
    /// Verifies that the policy strips Retry-After headers from /operations/ responses.
    /// This enables our configured LRO polling interval to be used.
    /// </summary>
    [Test]
    public async Task RetryAfterStripping_Operations_HeaderIsStripped()
    {
        // Arrange
        int callCount = 0;
        bool retryAfterWasPresentOnOriginal = false;
        bool retryAfterWasPresentAfterPolicy = false;

        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;
            if (uri.Contains("/operations/"))
            {
                callCount++;
                MockResponse response = new(200);
                response.AddHeader("Retry-After", "1");
                response.SetContent("{}");
                retryAfterWasPresentOnOriginal = response.Headers.Contains("Retry-After");
                return response;
            }
            return new MockResponse(200);
        });

        // Configure with our policy
        MstPerformanceOptimizationPolicy policy = new(TimeSpan.FromMilliseconds(50), 8);
        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 0 }
        };
        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        // Act
        HttpMessage message = pipeline.CreateMessage();
        message.Request.Method = RequestMethod.Get;
        message.Request.Uri.Reset(new Uri("https://mst.example.com/operations/test-op-123"));
        await pipeline.SendAsync(message, CancellationToken.None);

        // Check if Retry-After is present after policy processed the response
        retryAfterWasPresentAfterPolicy = message.Response.Headers.Contains("Retry-After");

        // Assert
        Console.WriteLine($"[Operations Header Strip] Calls: {callCount}, " +
            $"Retry-After present on original: {retryAfterWasPresentOnOriginal}, " +
            $"Retry-After present after policy: {retryAfterWasPresentAfterPolicy}");

        Assert.That(retryAfterWasPresentOnOriginal, Is.True, "Original response should have Retry-After header");
        Assert.That(retryAfterWasPresentAfterPolicy, Is.False, "Policy should strip Retry-After header from operations response");
        Assert.That(callCount, Is.EqualTo(1), "Should make 1 call (operations don't retry, just strip header)");
    }

    /// <summary>
    /// Demonstrates the timing difference with and without the policy.
    /// Without policy: SDK respects Retry-After: 1 → ~3 seconds
    /// With policy: Headers stripped, fast retries → ~600ms
    /// </summary>
    [Test]
    public async Task RetryAfterStripping_TimingComparison_WithAndWithoutPolicy()
    {
        List<(string Config, long DurationMs, int CallCount)> results = new();

        // Scenario 1: WITHOUT policy - SDK respects Retry-After: 1
        {
            int callCount = 0;
            MockTransport transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    callCount++;
                    if (callCount <= 2)
                    {
                        MockResponse response = new(503);
                        response.AddHeader("Retry-After", "1");
                        response.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
                        return response;
                    }
                    MockResponse successResponse = new(200);
                    successResponse.SetContent(CreateMessageWithReceipt().Encode());
                    return successResponse;
                }
                return new MockResponse(200);
            });

            // NO policy - SDK will use default retry behavior respecting Retry-After
            CodeTransparencyClientOptions options = new()
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(100) }
            };
            HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

            Stopwatch sw = Stopwatch.StartNew();
            HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Without Policy", sw.ElapsedMilliseconds, callCount));
        }

        // Scenario 2: WITH policy - Headers stripped, fast retries
        {
            int callCount = 0;
            MockTransport transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    callCount++;
                    if (callCount <= 2)
                    {
                        MockResponse response = new(503);
                        response.AddHeader("Retry-After", "1");
                        response.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
                        return response;
                    }
                    MockResponse successResponse = new(200);
                    successResponse.SetContent(CreateMessageWithReceipt().Encode());
                    return successResponse;
                }
                return new MockResponse(200);
            });

            // WITH policy - fast retries + header stripping
            MstPerformanceOptimizationPolicy policy = new(TimeSpan.FromMilliseconds(100), 8);
            CodeTransparencyClientOptions options = new()
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(100) }
            };
            options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
            HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

            Stopwatch sw = Stopwatch.StartNew();
            HttpMessage message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("With Policy", sw.ElapsedMilliseconds, callCount));
        }

        // Output comparison
        Console.WriteLine("\n=== RETRY-AFTER STRIPPING TIMING COMPARISON ===");
        Console.WriteLine($"{"Configuration",-20} {"Duration",-15} {"Calls",-10}");
        Console.WriteLine(new string('-', 45));

        foreach ((string Config, long DurationMs, int CallCount) r in results)
        {
            Console.WriteLine($"{r.Config,-20} {r.DurationMs + "ms",-15} {r.CallCount,-10}");
        }

        double speedup = (double)results[0].DurationMs / results[1].DurationMs;
        Console.WriteLine($"\nSpeedup: {speedup:F1}x (saved {results[0].DurationMs - results[1].DurationMs}ms)");

        // Assertions
        Assert.That(results[0].DurationMs, Is.GreaterThanOrEqualTo(1800),
            $"Without policy, should take >=1.8s due to Retry-After: 1 headers. Got {results[0].DurationMs}ms");

        Assert.That(results[1].DurationMs, Is.LessThan(800),
            $"With policy, should complete in <800ms. Got {results[1].DurationMs}ms");

        Assert.That(speedup, Is.GreaterThan(3.0),
            $"Policy should provide >3x speedup. Got {speedup:F1}x");
    }

    /// <summary>
    /// Verifies that non-entries/operations requests are NOT modified by the policy.
    /// </summary>
    [Test]
    public async Task RetryAfterStripping_OtherEndpoints_NotModified()
    {
        // Arrange
        MockTransport transport = MockTransport.FromMessageCallback(msg =>
        {
            MockResponse response = new(200);
            response.AddHeader("Retry-After", "1");
            response.SetContent("{}");
            return response;
        });

        // Configure with our policy
        MstPerformanceOptimizationPolicy policy = new(TimeSpan.FromMilliseconds(50), 8);
        CodeTransparencyClientOptions options = new()
        {
            Transport = transport,
            Retry = { MaxRetries = 0 }
        };
        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        HttpPipeline pipeline = HttpPipelineBuilder.Build(options);

        // Act - call a different endpoint (not /entries/ or /operations/)
        HttpMessage message = pipeline.CreateMessage();
        message.Request.Method = RequestMethod.Get;
        message.Request.Uri.Reset(new Uri("https://mst.example.com/other/endpoint"));
        await pipeline.SendAsync(message, CancellationToken.None);

        // Assert - Retry-After should NOT be stripped
        bool hasRetryAfter = message.Response.Headers.Contains("Retry-After");
        Console.WriteLine($"[Other Endpoint] Retry-After present: {hasRetryAfter}");

        Assert.That(hasRetryAfter, Is.True, "Policy should NOT modify responses for other endpoints");
    }

    #endregion

    #region Helpers

    /// <summary>
    /// Creates a CoseSign1Message with a dummy receipt for use in mock response content.
    /// Adapted for V2 using System.Security.Cryptography.Cose directly.
    /// </summary>
    private static CoseSign1Message CreateMessageWithReceipt()
    {
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate("EndToEndTest", useEcc: true);
        using ECDsa key = testCert.GetECDsaPrivateKey()!;
        CoseSigner signer = new(key, HashAlgorithmName.SHA256);
        byte[] testPayload = Encoding.ASCII.GetBytes("TestPayload");
        byte[] signedBytes = CoseSign1Message.SignDetached(testPayload, signer);
        CoseSign1Message message = CoseMessage.DecodeSign1(signedBytes);
        message.AddReceipts(new List<byte[]> { new byte[] { 1, 2, 3 } });
        return message;
    }

    /// <summary>
    /// Creates a mock Operation that simulates time-based completion.
    /// The operation will report HasValue=false until the specified time is reached.
    /// </summary>
    private static Moq.Mock<Operation<BinaryData>> CreateTimedOperation(DateTimeOffset readyTime, Action onPoll)
    {
        Moq.Mock<Operation<BinaryData>> mock = new();
        bool isComplete = false;

        mock.Setup(op => op.HasValue).Returns(() =>
        {
            onPoll();
            if (DateTimeOffset.UtcNow >= readyTime)
            {
                isComplete = true;
            }
            return isComplete;
        });

        CborWriter cborWriter = new();
        cborWriter.WriteStartMap(1);
        cborWriter.WriteTextString("EntryId");
        cborWriter.WriteTextString("test-entry-timing-12345");
        cborWriter.WriteEndMap();
        mock.Setup(op => op.Value).Returns(BinaryData.FromBytes(cborWriter.Encode()));

        // Make WaitForCompletionAsync actually wait with the specified delay strategy
        mock.Setup(op => op.WaitForCompletionAsync(Moq.It.IsAny<TimeSpan>(), Moq.It.IsAny<CancellationToken>()))
            .Returns<TimeSpan, CancellationToken>(async (pollingInterval, ct) =>
            {
                while (!isComplete && DateTimeOffset.UtcNow < readyTime)
                {
                    await Task.Delay(pollingInterval, ct);
                    onPoll();
                    if (DateTimeOffset.UtcNow >= readyTime)
                    {
                        isComplete = true;
                    }
                }
                return Response.FromValue(BinaryData.FromBytes(cborWriter.Encode()), Moq.Mock.Of<Response>());
            });

        mock.Setup(op => op.WaitForCompletionAsync(Moq.It.IsAny<DelayStrategy>(), Moq.It.IsAny<CancellationToken>()))
            .Returns<DelayStrategy, CancellationToken>(async (strategy, ct) =>
            {
                int attempt = 0;
                while (!isComplete && DateTimeOffset.UtcNow < readyTime)
                {
                    await Task.Delay(strategy.GetNextDelay(Moq.Mock.Of<Response>(), attempt++), ct);
                    onPoll();
                    if (DateTimeOffset.UtcNow >= readyTime)
                    {
                        isComplete = true;
                    }
                }
                return Response.FromValue(BinaryData.FromBytes(cborWriter.Encode()), Moq.Mock.Of<Response>());
            });

        mock.Setup(op => op.WaitForCompletionAsync(Moq.It.IsAny<CancellationToken>()))
            .Returns<CancellationToken>(async ct =>
            {
                // Simulate SDK default exponential backoff starting at 1 second
                TimeSpan delay = TimeSpan.FromSeconds(1);
                while (!isComplete && DateTimeOffset.UtcNow < readyTime)
                {
                    await Task.Delay(delay, ct);
                    onPoll();
                    delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, TimeSpan.FromSeconds(30).Ticks));
                    if (DateTimeOffset.UtcNow >= readyTime)
                    {
                        isComplete = true;
                    }
                }
                return Response.FromValue(BinaryData.FromBytes(cborWriter.Encode()), Moq.Mock.Of<Response>());
            });

        return mock;
    }

    /// <summary>
    /// Creates a 503 response with CBOR problem details containing TransactionNotCached.
    /// </summary>
    private static MockResponse CreateTransactionNotCachedResponse()
    {
        MockResponse response = new(503);
        response.AddHeader("Retry-After", "1");
        response.SetContent(CreateCborProblemDetailsBytes("TransactionNotCached"));
        return response;
    }

    /// <summary>
    /// Creates a successful entry response with a valid COSE Sign1 message.
    /// </summary>
    private static MockResponse CreateSuccessfulEntryResponse()
    {
        // Create a minimal valid response
        MockResponse response = new(200);
        // Note: In a real scenario, this would be a valid COSE Sign1 message
        response.SetContent(new byte[] { 0xD2, 0x84 }); // Minimal COSE tag
        return response;
    }

    /// <summary>
    /// Creates CBOR problem details bytes.
    /// </summary>
    private static byte[] CreateCborProblemDetailsBytes(string detailValue)
    {
        CborWriter writer = new();
        writer.WriteStartMap(2);
        writer.WriteInt32(-3); // status
        writer.WriteInt32(503);
        writer.WriteInt32(-4); // detail
        writer.WriteTextString(detailValue);
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>
    /// Creates an HTTP message for GetEntry requests.
    /// </summary>
    private static HttpMessage CreateGetEntryMessage(HttpPipeline pipeline, string uri)
    {
        HttpMessage message = pipeline.CreateMessage();
        message.Request.Method = RequestMethod.Get;
        message.Request.Uri.Reset(new Uri(uri));
        return message;
    }

    #endregion
}
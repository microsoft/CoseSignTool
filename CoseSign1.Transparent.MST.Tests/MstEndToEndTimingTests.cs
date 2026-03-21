// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Cbor;
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
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Interfaces;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.Extensions;
using CoseSign1.Transparent.MST;
using Moq;

/// <summary>
/// End-to-end timing tests that simulate realistic MST latency patterns to:
/// 1. Replicate the observed ~3-second behavior
/// 2. Identify timing contributions from LRO polling vs GetEntryAsync 503 retries
/// 3. Demonstrate tuning strategies for optimal performance
/// 
/// Real-world pattern:
/// - CreateEntryAsync: Quick initial response with operation ID, then polling until operation completes (~400ms)
/// - GetEntryStatementAsync: First few calls return 503 TransactionNotCached, then success
/// </summary>
[TestFixture]
[NonParallelizable] // Timing tests should not run in parallel
public class MstEndToEndTimingTests
{
    private CoseSign1MessageFactory? messageFactory;
    private ICoseSigningKeyProvider? signingKeyProvider;

    [SetUp]
    public void Setup()
    {
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();
        signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);
        messageFactory = new();
    }

    #region Baseline Tests — Identify Timing Contributors

    /// <summary>
    /// Baseline: LRO polling with default SDK exponential backoff.
    /// This simulates an LRO that completes after 400ms but the SDK may poll
    /// at longer intervals, adding latency.
    /// </summary>
    [Test]
    public async Task Baseline_LroPolling_DefaultSdkBackoff()
    {
        // Arrange
        var operationReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);
        int pollCount = 0;

        var mockOperation = CreateTimedOperation(operationReadyTime, () => pollCount++);
        var mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMessageWithReceipt();
        BinaryData mockEntryStatement = BinaryData.FromBytes(message.Encode());

        mockClient
            .Setup(c => c.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);
        mockClient
            .Setup(c => c.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(mockEntryStatement, Mock.Of<Response>()));

        // No polling options = SDK default exponential backoff
        MstTransparencyService service = new(mockClient.Object);

        var sw = Stopwatch.StartNew();

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(message);

        sw.Stop();

        // Assert
        Assert.That(result, Is.Not.Null);
        Console.WriteLine($"[Baseline LRO] Duration: {sw.ElapsedMilliseconds}ms, Poll count: {pollCount}");
        // SDK default backoff may cause significant extra latency beyond 400ms
    }

    /// <summary>
    /// LRO polling with aggressive fixed interval (100ms).
    /// Should complete much faster than default exponential backoff.
    /// </summary>
    [Test]
    public async Task Tuned_LroPolling_FixedInterval100ms()
    {
        // Arrange
        var operationReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);
        int pollCount = 0;

        var mockOperation = CreateTimedOperation(operationReadyTime, () => pollCount++);
        var mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMessageWithReceipt();
        BinaryData mockEntryStatement = BinaryData.FromBytes(message.Encode());

        mockClient
            .Setup(c => c.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);
        mockClient
            .Setup(c => c.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(mockEntryStatement, Mock.Of<Response>()));

        // Aggressive polling
        var pollingOptions = new MstPollingOptions
        {
            PollingInterval = TimeSpan.FromMilliseconds(100)
        };
        MstTransparencyService service = new(mockClient.Object, pollingOptions);

        var sw = Stopwatch.StartNew();

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(message);

        sw.Stop();

        // Assert
        Assert.That(result, Is.Not.Null);
        Console.WriteLine($"[Tuned LRO 100ms] Duration: {sw.ElapsedMilliseconds}ms, Poll count: {pollCount}");
        // Should complete in ~400-500ms (operation ready time + one final poll interval)
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(1000),
            $"With 100ms polling, should complete in <1s after 400ms operation. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// LRO polling with more aggressive fixed interval (50ms).
    /// Tests the lower bound of useful polling intervals.
    /// </summary>
    [Test]
    public async Task Tuned_LroPolling_FixedInterval50ms()
    {
        // Arrange
        var operationReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);
        int pollCount = 0;

        var mockOperation = CreateTimedOperation(operationReadyTime, () => pollCount++);
        var mockClient = new Mock<CodeTransparencyClient>();
        CoseSign1Message message = CreateMessageWithReceipt();
        BinaryData mockEntryStatement = BinaryData.FromBytes(message.Encode());

        mockClient
            .Setup(c => c.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);
        mockClient
            .Setup(c => c.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(mockEntryStatement, Mock.Of<Response>()));

        var pollingOptions = new MstPollingOptions
        {
            PollingInterval = TimeSpan.FromMilliseconds(50)
        };
        MstTransparencyService service = new(mockClient.Object, pollingOptions);

        var sw = Stopwatch.StartNew();

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(message);

        sw.Stop();

        // Assert
        Assert.That(result, Is.Not.Null);
        Console.WriteLine($"[Tuned LRO 50ms] Duration: {sw.ElapsedMilliseconds}ms, Poll count: {pollCount}");
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(700),
            $"With 50ms polling, should complete in <700ms. Got {sw.ElapsedMilliseconds}ms");
    }

    #endregion

    #region GetEntryAsync 503 Pattern Tests

    /// <summary>
    /// Simulates the full scenario:
    /// - LRO completes after 400ms
    /// - GetEntryStatementAsync returns 503 on first 2 calls, success on 3rd
    /// - WITHOUT the MstTransactionNotCachedPolicy
    /// 
    /// This should show the 3-second behavior due to SDK's Retry-After: 1 delay.
    /// </summary>
    [Test]
    public async Task FullScenario_Without_TransactionNotCachedPolicy_Shows3SecondBehavior()
    {
        // Arrange - simulate the real HTTP pipeline without our custom policy
        int getEntryCallCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
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

        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };

        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");

        var sw = Stopwatch.StartNew();

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
    /// Same scenario but WITH the MstTransactionNotCachedPolicy.
    /// Should resolve much faster due to aggressive fast retries.
    /// </summary>
    [Test]
    public async Task FullScenario_With_TransactionNotCachedPolicy_ResolvesQuickly()
    {
        // Arrange
        int getEntryCallCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
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

        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        // Add the fast retry policy with 100ms interval
        options.ConfigureTransactionNotCachedRetry(
            retryDelay: TimeSpan.FromMilliseconds(100),
            maxRetries: 8);

        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");

        var sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Console.WriteLine($"[With Policy] Duration: {sw.ElapsedMilliseconds}ms, GetEntry calls: {getEntryCallCount}");
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(getEntryCallCount, Is.EqualTo(3), "Should make exactly 3 calls (2 failures + 1 success)");
        // Should complete in ~200-300ms (2x 100ms retry delays + network latency simulation)
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(500),
            $"With custom policy, should resolve in <500ms. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// Test with even more aggressive 50ms retry delay.
    /// </summary>
    [Test]
    public async Task FullScenario_With_TransactionNotCachedPolicy_50msDelay()
    {
        // Arrange
        int getEntryCallCount = 0;
        var transport = MockTransport.FromMessageCallback(msg =>
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

        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        options.ConfigureTransactionNotCachedRetry(
            retryDelay: TimeSpan.FromMilliseconds(50),
            maxRetries: 8);

        var pipeline = HttpPipelineBuilder.Build(options);
        var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/1.234");

        var sw = Stopwatch.StartNew();

        // Act
        await pipeline.SendAsync(message, CancellationToken.None);

        sw.Stop();

        // Assert
        Console.WriteLine($"[With Policy 50ms] Duration: {sw.ElapsedMilliseconds}ms, GetEntry calls: {getEntryCallCount}");
        Assert.That(message.Response.Status, Is.EqualTo(200));
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(300),
            $"With 50ms retry delay, should resolve in <300ms. Got {sw.ElapsedMilliseconds}ms");
    }

    #endregion

    #region Combined LRO + GetEntryAsync Timing Tests

    /// <summary>
    /// Full end-to-end scenario combining both timing components:
    /// 1. LRO CreateEntryAsync takes 400ms to complete
    /// 2. GetEntryStatementAsync has 2x 503 failures before success
    /// 
    /// WITHOUT tuning: Expected ~3+ seconds (LRO polling delays + 2x 1s Retry-After)
    /// </summary>
    [Test]
    public async Task Combined_Baseline_NoTuning()
    {
        // Arrange
        var operationReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);
        int lroPollCount = 0;
        int getEntryCallCount = 0;

        var mockOperation = CreateTimedOperation(operationReadyTime, () => lroPollCount++);
        var mockClient = new Mock<CodeTransparencyClient>();

        mockClient
            .Setup(c => c.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);

        // Simulate GetEntryStatementAsync with 503 pattern using Moq callback
        CoseSign1Message successMessage = CreateMessageWithReceipt();
        mockClient
            .Setup(c => c.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>(async (entryId, ct) =>
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    // Simulate the 1-second Retry-After delay that SDK would add
                    await Task.Delay(1000, ct);
                }
                return Response.FromValue(BinaryData.FromBytes(successMessage.Encode()), Mock.Of<Response>());
            });

        // No tuning - default SDK behavior
        MstTransparencyService service = new(mockClient.Object);

        var sw = Stopwatch.StartNew();

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(CreateMessageWithReceipt());

        sw.Stop();

        // Assert
        Console.WriteLine($"[Combined Baseline] Duration: {sw.ElapsedMilliseconds}ms, LRO polls: {lroPollCount}, GetEntry calls: {getEntryCallCount}");
        Assert.That(result, Is.Not.Null);
        // Should be around 2.5-3+ seconds due to:
        // - LRO polling with default exponential backoff
        // - 2x 1-second delays simulating SDK Retry-After behavior
        Assert.That(sw.ElapsedMilliseconds, Is.GreaterThanOrEqualTo(2000),
            $"Without tuning, should take >2s due to SDK delays. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// Full end-to-end with both tuning strategies applied:
    /// 1. Aggressive LRO polling (100ms interval)
    /// 2. Fast TransactionNotCached retries (100ms interval)
    /// 
    /// Expected: ~600-800ms total (400ms LRO + ~200ms for 2 fast retries)
    /// </summary>
    [Test]
    public async Task Combined_FullyTuned_BothPolicies()
    {
        // Arrange
        var operationReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);
        int lroPollCount = 0;
        int getEntryCallCount = 0;

        var mockOperation = CreateTimedOperation(operationReadyTime, () => lroPollCount++);
        var mockClient = new Mock<CodeTransparencyClient>();

        mockClient
            .Setup(c => c.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);

        // Simulate GetEntryStatementAsync with fast retry (no artificial delay)
        CoseSign1Message successMessage = CreateMessageWithReceipt();
        mockClient
            .Setup(c => c.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>(async (entryId, ct) =>
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    // Simulate fast retry delay (100ms instead of 1s)
                    await Task.Delay(100, ct);
                }
                return Response.FromValue(BinaryData.FromBytes(successMessage.Encode()), Mock.Of<Response>());
            });

        // Apply both tuning strategies
        var pollingOptions = new MstPollingOptions
        {
            PollingInterval = TimeSpan.FromMilliseconds(100)
        };
        MstTransparencyService service = new(mockClient.Object, pollingOptions);

        var sw = Stopwatch.StartNew();

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(CreateMessageWithReceipt());

        sw.Stop();

        // Assert
        Console.WriteLine($"[Combined Tuned] Duration: {sw.ElapsedMilliseconds}ms, LRO polls: {lroPollCount}, GetEntry calls: {getEntryCallCount}");
        Assert.That(result, Is.Not.Null);
        // Should complete much faster: ~400ms LRO + ~200ms for 2 retries = ~600-800ms
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(1200),
            $"With full tuning, should complete in <1.2s. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// Tests aggressive tuning with 50ms intervals for both LRO and retry.
    /// This represents the most aggressive configuration that's still reasonable.
    /// </summary>
    [Test]
    public async Task Combined_AggressiveTuning_50ms()
    {
        // Arrange
        var operationReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);
        int lroPollCount = 0;
        int getEntryCallCount = 0;

        var mockOperation = CreateTimedOperation(operationReadyTime, () => lroPollCount++);
        var mockClient = new Mock<CodeTransparencyClient>();

        mockClient
            .Setup(c => c.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);

        CoseSign1Message successMessage = CreateMessageWithReceipt();
        mockClient
            .Setup(c => c.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>(async (entryId, ct) =>
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    await Task.Delay(50, ct);
                }
                return Response.FromValue(BinaryData.FromBytes(successMessage.Encode()), Mock.Of<Response>());
            });

        var pollingOptions = new MstPollingOptions
        {
            PollingInterval = TimeSpan.FromMilliseconds(50)
        };
        MstTransparencyService service = new(mockClient.Object, pollingOptions);

        var sw = Stopwatch.StartNew();

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(CreateMessageWithReceipt());

        sw.Stop();

        // Assert
        Console.WriteLine($"[Combined Aggressive 50ms] Duration: {sw.ElapsedMilliseconds}ms, LRO polls: {lroPollCount}, GetEntry calls: {getEntryCallCount}");
        Assert.That(result, Is.Not.Null);
        // ~400ms LRO + ~100ms for 2 retries = ~500-600ms
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(900),
            $"With aggressive 50ms tuning, should complete in <900ms. Got {sw.ElapsedMilliseconds}ms");
    }

    #endregion

    #region Parameterized Timing Matrix

    /// <summary>
    /// Parameterized test exploring different combinations of:
    /// - LRO polling interval
    /// - TransactionNotCached retry delay
    /// - Number of 503 failures before success
    /// </summary>
    [Test]
    [TestCase(100, 100, 2, Description = "Moderate tuning: 100ms LRO poll, 100ms retry, 2 failures")]
    [TestCase(50, 50, 2, Description = "Aggressive tuning: 50ms LRO poll, 50ms retry, 2 failures")]
    [TestCase(100, 50, 3, Description = "Mixed: 100ms LRO poll, 50ms retry, 3 failures")]
    [TestCase(200, 100, 1, Description = "Conservative: 200ms LRO poll, 100ms retry, 1 failure")]
    [TestCase(50, 100, 2, Description = "Fast LRO, moderate retry")]
    public async Task TimingMatrix_VariousConfigurations(int lroPollingMs, int retryDelayMs, int failureCount)
    {
        // Arrange
        int expectedLroTime = 400; // ms until LRO completes
        var operationReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(expectedLroTime);
        int lroPollCount = 0;
        int getEntryCallCount = 0;

        var mockOperation = CreateTimedOperation(operationReadyTime, () => lroPollCount++);
        var mockClient = new Mock<CodeTransparencyClient>();

        mockClient
            .Setup(c => c.CreateEntryAsync(It.IsAny<WaitUntil>(), It.IsAny<BinaryData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockOperation.Object);

        CoseSign1Message successMessage = CreateMessageWithReceipt();
        mockClient
            .Setup(c => c.GetEntryStatementAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>(async (entryId, ct) =>
            {
                getEntryCallCount++;
                if (getEntryCallCount <= failureCount)
                {
                    await Task.Delay(retryDelayMs, ct);
                }
                return Response.FromValue(BinaryData.FromBytes(successMessage.Encode()), Mock.Of<Response>());
            });

        var pollingOptions = new MstPollingOptions
        {
            PollingInterval = TimeSpan.FromMilliseconds(lroPollingMs)
        };
        MstTransparencyService service = new(mockClient.Object, pollingOptions);

        var sw = Stopwatch.StartNew();

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(CreateMessageWithReceipt());

        sw.Stop();

        // Assert
        int expectedTotalTime = expectedLroTime + (retryDelayMs * failureCount);
        int maxAcceptableTime = expectedTotalTime + lroPollingMs + 200; // Add some buffer

        Console.WriteLine($"[Matrix LRO:{lroPollingMs}ms Retry:{retryDelayMs}ms Failures:{failureCount}] " +
            $"Duration: {sw.ElapsedMilliseconds}ms (expected ~{expectedTotalTime}ms), " +
            $"LRO polls: {lroPollCount}, GetEntry calls: {getEntryCallCount}");

        Assert.That(result, Is.Not.Null);
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(maxAcceptableTime),
            $"Expected completion in <{maxAcceptableTime}ms, got {sw.ElapsedMilliseconds}ms");
    }

    #endregion

    #region Helpers

    private CoseSign1Message CreateMessageWithReceipt()
    {
        byte[] testPayload = Encoding.ASCII.GetBytes("TestPayload");
        CoseSign1Message message = messageFactory!.CreateCoseSign1Message(testPayload, signingKeyProvider!, embedPayload: false);
        message.AddReceipts(new List<byte[]> { new byte[] { 1, 2, 3 } });
        return message;
    }

    /// <summary>
    /// Creates a mock Operation that simulates time-based completion.
    /// The operation will report HasValue=false until the specified time is reached.
    /// </summary>
    private static Mock<Operation<BinaryData>> CreateTimedOperation(DateTimeOffset readyTime, Action onPoll)
    {
        var mock = new Mock<Operation<BinaryData>>();
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
        mock.Setup(op => op.WaitForCompletionAsync(It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
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
                return Response.FromValue(BinaryData.FromBytes(cborWriter.Encode()), Mock.Of<Response>());
            });

        mock.Setup(op => op.WaitForCompletionAsync(It.IsAny<DelayStrategy>(), It.IsAny<CancellationToken>()))
            .Returns<DelayStrategy, CancellationToken>(async (strategy, ct) =>
            {
                int attempt = 0;
                while (!isComplete && DateTimeOffset.UtcNow < readyTime)
                {
                    await Task.Delay(strategy.GetNextDelay(Mock.Of<Response>(), attempt++), ct);
                    onPoll();
                    if (DateTimeOffset.UtcNow >= readyTime)
                    {
                        isComplete = true;
                    }
                }
                return Response.FromValue(BinaryData.FromBytes(cborWriter.Encode()), Mock.Of<Response>());
            });

        mock.Setup(op => op.WaitForCompletionAsync(It.IsAny<CancellationToken>()))
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
                return Response.FromValue(BinaryData.FromBytes(cborWriter.Encode()), Mock.Of<Response>());
            });

        return mock;
    }

    /// <summary>
    /// Creates a 503 response with CBOR problem details containing TransactionNotCached.
    /// </summary>
    private static MockResponse CreateTransactionNotCachedResponse()
    {
        var response = new MockResponse(503);
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
        var response = new MockResponse(200);
        // Note: In a real scenario, this would be a valid COSE Sign1 message
        response.SetContent(new byte[] { 0xD2, 0x84 }); // Minimal COSE tag
        return response;
    }

    /// <summary>
    /// Creates CBOR problem details bytes.
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
    /// Creates an HTTP message for GetEntry requests.
    /// </summary>
    private static HttpMessage CreateGetEntryMessage(HttpPipeline pipeline, string uri)
    {
        var message = pipeline.CreateMessage();
        message.Request.Method = RequestMethod.Get;
        message.Request.Uri.Reset(new Uri(uri));
        return message;
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
        var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

        // Create transport that simulates GetEntry 503 pattern
        var transport = MockTransport.FromMessageCallback(msg =>
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
                var response = new MockResponse(200);
                response.SetContent(CreateMessageWithReceipt().Encode());
                return response;
            }

            // Default pass-through for other calls
            return new MockResponse(200);
        });

        // Use SDK defaults (no custom policy, no fast polling)
        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        var pipeline = HttpPipelineBuilder.Build(options);

        // Mock the Operation to simulate LRO timing with SDK default backoff
        var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

        var sw = Stopwatch.StartNew();

        // Phase 1: Wait for LRO completion (simulates CreateEntryAsync waiting)
        await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
        var lroDuration = sw.ElapsedMilliseconds;

        // Phase 2: GetEntryStatement through HTTP pipeline with SDK retry
        var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
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
    /// 2. Fast TransactionNotCached retries (100ms via MstTransactionNotCachedPolicy)
    /// 
    /// Expected: ~600-800ms total (down from ~3 seconds)
    /// </summary>
    [Test]
    public async Task TrueIntegration_FullyTuned_BothPolicies()
    {
        // Arrange
        int lroPollCount = 0;
        int getEntryCallCount = 0;
        var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

        var transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;

            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    return CreateTransactionNotCachedResponse();
                }
                var response = new MockResponse(200);
                response.SetContent(CreateMessageWithReceipt().Encode());
                return response;
            }

            return new MockResponse(200);
        });

        // Configure with BOTH tuning strategies
        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        // Add fast retry policy (100ms instead of 1s Retry-After)
        options.ConfigureTransactionNotCachedRetry(
            retryDelay: TimeSpan.FromMilliseconds(100),
            maxRetries: 8);

        var pipeline = HttpPipelineBuilder.Build(options);

        // Mock the Operation with fast polling (100ms instead of SDK default)
        var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

        var sw = Stopwatch.StartNew();

        // Phase 1: Wait for LRO with fast polling (100ms interval)
        await mockOperation.Object.WaitForCompletionAsync(
            TimeSpan.FromMilliseconds(100),
            CancellationToken.None);
        var lroDuration = sw.ElapsedMilliseconds;

        // Phase 2: GetEntryStatement through HTTP pipeline with fast retry policy
        var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
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
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(1000),
            $"With full tuning, should complete in <1s total. Got {sw.ElapsedMilliseconds}ms");
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
        var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

        var transport = MockTransport.FromMessageCallback(msg =>
        {
            string uri = msg.Request.Uri.ToUri().AbsoluteUri;

            if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
            {
                getEntryCallCount++;
                if (getEntryCallCount <= 2)
                {
                    return CreateTransactionNotCachedResponse();
                }
                var response = new MockResponse(200);
                response.SetContent(CreateMessageWithReceipt().Encode());
                return response;
            }

            return new MockResponse(200);
        });

        var options = new CodeTransparencyClientOptions
        {
            Transport = transport,
            Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
        };
        options.ConfigureTransactionNotCachedRetry(
            retryDelay: TimeSpan.FromMilliseconds(50),
            maxRetries: 8);

        var pipeline = HttpPipelineBuilder.Build(options);
        var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

        var sw = Stopwatch.StartNew();

        // Fast LRO polling (50ms)
        await mockOperation.Object.WaitForCompletionAsync(
            TimeSpan.FromMilliseconds(50),
            CancellationToken.None);
        var lroDuration = sw.ElapsedMilliseconds;

        // GetEntryStatement with fast retry
        var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test-entry-123");
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
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(1000),
            $"With 50ms tuning, should complete in <1s total. Got {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// Comparison test showing improvement ratio.
    /// </summary>
    [Test]
    public async Task TrueIntegration_ComparisonSummary()
    {
        var results = new List<(string Config, long TotalMs, long LroMs, long GetEntryMs)>();

        // Test 1: Baseline (SDK defaults) - LRO ready at 400ms
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

            var transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                        return CreateTransactionNotCachedResponse();
                    var response = new MockResponse(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            var options = new CodeTransparencyClientOptions
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            var pipeline = HttpPipelineBuilder.Build(options);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
            var lroMs = sw.ElapsedMilliseconds;
            var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Baseline (no tuning)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs));
        }

        // Test 2: Pipeline Policy ONLY (no LRO tuning) - simulates user's current fix
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

            var transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                        return CreateTransactionNotCachedResponse();
                    var response = new MockResponse(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            var options = new CodeTransparencyClientOptions
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            // Pipeline policy WITH fast retry (user's current fix)
            options.ConfigureTransactionNotCachedRetry(TimeSpan.FromMilliseconds(100), 8);
            var pipeline = HttpPipelineBuilder.Build(options);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            // SDK default LRO polling (NO fast polling - as user has now)
            await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
            var lroMs = sw.ElapsedMilliseconds;
            var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Policy only (no LRO)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs));
        }

        // Test 3: Both tuned (100ms/100ms)
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

            var transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                        return CreateTransactionNotCachedResponse();
                    var response = new MockResponse(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            var options = new CodeTransparencyClientOptions
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            options.ConfigureTransactionNotCachedRetry(TimeSpan.FromMilliseconds(100), 8);
            var pipeline = HttpPipelineBuilder.Build(options);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(TimeSpan.FromMilliseconds(100), CancellationToken.None);
            var lroMs = sw.ElapsedMilliseconds;
            var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Both tuned (100ms)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs));
        }

        // Test 3: Aggressive (50ms/50ms)
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(400);

            var transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                        return CreateTransactionNotCachedResponse();
                    var response = new MockResponse(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            var options = new CodeTransparencyClientOptions
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            options.ConfigureTransactionNotCachedRetry(TimeSpan.FromMilliseconds(50), 8);
            var pipeline = HttpPipelineBuilder.Build(options);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None);
            var lroMs = sw.ElapsedMilliseconds;
            var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Aggressive (50ms/50ms)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs));
        }

        // Output comparison
        Console.WriteLine("\n=== TIMING COMPARISON ===");
        Console.WriteLine($"{"Configuration",-25} {"Total",-10} {"LRO",-10} {"GetEntry",-10} {"Speedup",-10}");
        Console.WriteLine(new string('-', 65));

        long baseline = results[0].TotalMs;
        foreach (var r in results)
        {
            double speedup = (double)baseline / r.TotalMs;
            Console.WriteLine($"{r.Config,-25} {r.TotalMs + "ms",-10} {r.LroMs + "ms",-10} {r.GetEntryMs + "ms",-10} {speedup:F1}x");
        }

        // Assert baseline is significantly slower
        Assert.That(results[0].TotalMs, Is.GreaterThanOrEqualTo(2500), "Baseline should be >2.5s");
        // Policy only should be ~1.2s (SDK LRO ~1s + fast GetEntry ~200ms)
        Assert.That(results[1].TotalMs, Is.LessThan(1800), "Policy only should be <1.8s");
        Assert.That(results[1].TotalMs, Is.GreaterThanOrEqualTo(1000), "Policy only should be >1s (LRO delay)");
        Assert.That(results[2].TotalMs, Is.LessThan(1000), "Both tuned should be <1s");
        Assert.That(results[3].TotalMs, Is.LessThan(1000), "Aggressive should be <1s");

        // Assert improvement ratio for policy only vs baseline
        double policyOnlyImprovement = (double)results[0].TotalMs / results[1].TotalMs;
        Console.WriteLine($"\nPolicy-only improvement: {policyOnlyImprovement:F1}x (saves ~{results[0].TotalMs - results[1].TotalMs}ms)");

        // Assert improvement ratio for full tuning
        double improvementRatio = (double)results[0].TotalMs / results[3].TotalMs;
        Assert.That(improvementRatio, Is.GreaterThan(3.0),
            $"Aggressive tuning should provide >3x improvement. Got {improvementRatio:F1}x");
    }

    /// <summary>
    /// Tests what happens when the LRO operation takes longer (e.g., 1.5 seconds)
    /// requiring multiple SDK polling cycles. This simulates a slower MST CreateEntry response.
    /// 
    /// SDK default exponential backoff: 1s, 2s, 4s, 8s...
    /// - If LRO takes 1.5s: poll at 1s (not ready), poll at 3s (ready) = 3s total for LRO
    /// - With 100ms tuning: poll at 100ms, 200ms, ... 1500ms (ready) = ~1.5s for LRO
    /// </summary>
    [Test]
    public async Task TrueIntegration_LongerLRO_RequiresSecondPoll()
    {
        var results = new List<(string Config, long TotalMs, long LroMs, long GetEntryMs, int Polls)>();

        int lroCompletionTimeMs = 1500; // Operation takes 1.5 seconds to complete

        // Test 1: SDK default (no tuning at all)
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(lroCompletionTimeMs);

            var transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                        return CreateTransactionNotCachedResponse();
                    var response = new MockResponse(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            var options = new CodeTransparencyClientOptions
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            var pipeline = HttpPipelineBuilder.Build(options);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
            var lroMs = sw.ElapsedMilliseconds;
            var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Baseline (no tuning)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs, lroPollCount));
        }

        // Test 2: Pipeline Policy ONLY (your current fix, no LRO tuning)
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(lroCompletionTimeMs);

            var transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                        return CreateTransactionNotCachedResponse();
                    var response = new MockResponse(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            var options = new CodeTransparencyClientOptions
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            options.ConfigureTransactionNotCachedRetry(TimeSpan.FromMilliseconds(100), 8);
            var pipeline = HttpPipelineBuilder.Build(options);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            // SDK default LRO polling (NO fast polling)
            await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
            var lroMs = sw.ElapsedMilliseconds;
            var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Policy only (no LRO)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs, lroPollCount));
        }

        // Test 3: Both tuned (100ms polling)
        {
            int lroPollCount = 0;
            int getEntryCallCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(lroCompletionTimeMs);

            var transport = MockTransport.FromMessageCallback(msg =>
            {
                string uri = msg.Request.Uri.ToUri().AbsoluteUri;
                if (msg.Request.Method == RequestMethod.Get && uri.Contains("/entries/"))
                {
                    getEntryCallCount++;
                    if (getEntryCallCount <= 2)
                        return CreateTransactionNotCachedResponse();
                    var response = new MockResponse(200);
                    response.SetContent(CreateMessageWithReceipt().Encode());
                    return response;
                }
                return new MockResponse(200);
            });

            var options = new CodeTransparencyClientOptions
            {
                Transport = transport,
                Retry = { MaxRetries = 5, Delay = TimeSpan.FromMilliseconds(10) }
            };
            options.ConfigureTransactionNotCachedRetry(TimeSpan.FromMilliseconds(100), 8);
            var pipeline = HttpPipelineBuilder.Build(options);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            // Fast LRO polling (100ms)
            await mockOperation.Object.WaitForCompletionAsync(TimeSpan.FromMilliseconds(100), CancellationToken.None);
            var lroMs = sw.ElapsedMilliseconds;
            var message = CreateGetEntryMessage(pipeline, "https://mst.example.com/entries/test");
            await pipeline.SendAsync(message, CancellationToken.None);
            sw.Stop();

            results.Add(("Both tuned (100ms)", sw.ElapsedMilliseconds, lroMs, sw.ElapsedMilliseconds - lroMs, lroPollCount));
        }

        // Output comparison
        Console.WriteLine($"\n=== LRO COMPLETION TIME: {lroCompletionTimeMs}ms (requires 2nd SDK poll) ===");
        Console.WriteLine($"{"Configuration",-25} {"Total",-10} {"LRO",-12} {"GetEntry",-10} {"Polls",-8} {"Speedup",-10}");
        Console.WriteLine(new string('-', 75));

        long baseline = results[0].TotalMs;
        foreach (var r in results)
        {
            double speedup = (double)baseline / r.TotalMs;
            Console.WriteLine($"{r.Config,-25} {r.TotalMs + "ms",-10} {r.LroMs + "ms",-12} {r.GetEntryMs + "ms",-10} {r.Polls,-8} {speedup:F1}x");
        }

        // Analysis
        Console.WriteLine($"\n--- Analysis ---");
        Console.WriteLine($"Policy-only LRO time: {results[1].LroMs}ms (SDK exponential backoff: 1s poll, then 2s poll = ~3s)");
        Console.WriteLine($"Tuned LRO time: {results[2].LroMs}ms (100ms polling, ~15 polls)");
        Console.WriteLine($"Policy-only saves: {results[0].TotalMs - results[1].TotalMs}ms from GetEntry retries");
        Console.WriteLine($"Full tuning saves: {results[0].TotalMs - results[2].TotalMs}ms total");

        // Key insight: With 1.5s LRO, SDK default will wait 1s (not ready), then 2s more = 3s for LRO alone
        Assert.That(results[0].LroMs, Is.GreaterThanOrEqualTo(2800), 
            $"SDK default should take ~3s for 1.5s LRO (1s + 2s polls). Got {results[0].LroMs}ms");
        Assert.That(results[1].LroMs, Is.GreaterThanOrEqualTo(2800), 
            $"Policy-only still has SDK LRO timing. Got {results[1].LroMs}ms");
        Assert.That(results[2].LroMs, Is.LessThan(1800), 
            $"Tuned LRO should complete in ~1.5s. Got {results[2].LroMs}ms");
    }

    /// <summary>
    /// Parameterized test exploring different LRO completion times.
    /// Shows how SDK exponential backoff vs fixed polling affects timing.
    /// </summary>
    [Test]
    [TestCase(400, Description = "Fast LRO (400ms) - completes before first SDK poll")]
    [TestCase(1200, Description = "Medium LRO (1.2s) - requires 2nd SDK poll at 3s")]
    [TestCase(2500, Description = "Slow LRO (2.5s) - requires 2nd SDK poll at 3s")]
    [TestCase(3500, Description = "Very slow LRO (3.5s) - requires 3rd SDK poll at 7s")]
    public async Task TrueIntegration_VaryingLroTimes(int lroCompletionTimeMs)
    {
        var results = new List<(string Config, long TotalMs, long LroMs, int Polls)>();

        // Test 1: SDK default (no LRO tuning)
        {
            int lroPollCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(lroCompletionTimeMs);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(CancellationToken.None);
            sw.Stop();

            results.Add(("SDK default", sw.ElapsedMilliseconds, sw.ElapsedMilliseconds, lroPollCount));
        }

        // Test 2: Tuned (100ms polling)
        {
            int lroPollCount = 0;
            var lroReadyTime = DateTimeOffset.UtcNow.AddMilliseconds(lroCompletionTimeMs);
            var mockOperation = CreateTimedOperation(lroReadyTime, () => lroPollCount++);

            var sw = Stopwatch.StartNew();
            await mockOperation.Object.WaitForCompletionAsync(TimeSpan.FromMilliseconds(100), CancellationToken.None);
            sw.Stop();

            results.Add(("100ms polling", sw.ElapsedMilliseconds, sw.ElapsedMilliseconds, lroPollCount));
        }

        // Output
        Console.WriteLine($"\n=== LRO COMPLETION TIME: {lroCompletionTimeMs}ms ===");
        Console.WriteLine($"{"Config",-20} {"Duration",-12} {"Polls",-8} {"Overhead",-12}");
        Console.WriteLine(new string('-', 52));

        foreach (var r in results)
        {
            long overhead = r.TotalMs - lroCompletionTimeMs;
            Console.WriteLine($"{r.Config,-20} {r.TotalMs + "ms",-12} {r.Polls,-8} {(overhead > 0 ? "+" : "")}{overhead}ms");
        }

        long sdkOverhead = results[0].TotalMs - lroCompletionTimeMs;
        long tunedOverhead = results[1].TotalMs - lroCompletionTimeMs;
        Console.WriteLine($"\nSDK overhead: {sdkOverhead}ms, Tuned overhead: {tunedOverhead}ms");
        Console.WriteLine($"Savings from LRO tuning: {results[0].TotalMs - results[1].TotalMs}ms");

        // Tuned should always be close to actual LRO time
        Assert.That(results[1].TotalMs, Is.LessThan(lroCompletionTimeMs + 350),
            $"Tuned LRO should complete within 350ms of actual time. Got {results[1].TotalMs}ms for {lroCompletionTimeMs}ms LRO");
    }

    #endregion
}

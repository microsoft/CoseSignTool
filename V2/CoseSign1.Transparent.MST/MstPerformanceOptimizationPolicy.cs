// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Cose.Abstractions;

/// <summary>
/// An Azure SDK pipeline policy that optimizes MST (Microsoft Signing Transparency)
/// client performance by implementing fast retries for 503 responses and stripping
/// <c>Retry-After</c> headers to enable client-controlled timing.
/// </summary>
/// <remarks>
/// <para>
/// <b>Problem:</b> The Azure Code Transparency Service returns HTTP 503 with a
/// <c>Retry-After: 1</c> header (1 second) when a newly registered entry has not yet
/// propagated to the serving node. The entry typically becomes available in well under
/// 1 second, but the Azure SDK's default <see cref="RetryPolicy"/> respects the server's
/// <c>Retry-After</c> header, causing unnecessary 1-second delays. Additionally,
/// long-running operation (LRO) polling responses include <c>Retry-After</c> headers
/// that override client-configured polling intervals.
/// </para>
///
/// <para>
/// <b>Solution:</b> This policy:
/// <list type="number">
/// <item>Intercepts 503 responses on <c>/entries/</c> endpoints and performs fast retries
/// (default: 250 ms intervals, up to 8 retries ≈ 2 seconds).</item>
/// <item>Strips all retry-related headers (<c>Retry-After</c>, <c>retry-after-ms</c>,
/// <c>x-ms-retry-after-ms</c>) from responses to <c>/entries/</c> and <c>/operations/</c>
/// endpoints so the SDK uses client-configured delays instead.</item>
/// </list>
/// </para>
///
/// <para>
/// <b>Scope:</b> Only HTTP 503 responses to <c>GET</c> requests whose URI path contains
/// <c>/entries/</c> are retried by this policy. Retry header stripping (<c>Retry-After</c>,
/// <c>retry-after-ms</c>, <c>x-ms-retry-after-ms</c>) applies to both <c>/entries/</c> and
/// <c>/operations/</c> endpoints. All other requests pass through unchanged.
/// </para>
///
/// <para>
/// <b>Pipeline position:</b> Register this policy in the
/// <see cref="HttpPipelinePosition.PerRetry"/> position so it runs inside the SDK's
/// retry loop and above the tracing layer (<c>RequestActivityPolicy</c>). This ensures
/// fast retries are visible in distributed traces (e.g., OpenTelemetry / Aspire).
/// </para>
///
/// <para>
/// <b>Usage:</b>
/// <code>
/// var options = new CodeTransparencyClientOptions();
/// options.AddPolicy(new MstPerformanceOptimizationPolicy(), HttpPipelinePosition.PerRetry);
/// var client = new CodeTransparencyClient(endpoint, credential, options);
/// </code>
/// Or use the convenience extension:
/// <code>
/// var options = new CodeTransparencyClientOptions();
/// options.ConfigureMstPerformanceOptimizations();
/// </code>
/// </para>
/// </remarks>
public class MstPerformanceOptimizationPolicy : HttpPipelinePolicy
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Exception messages
        public const string RetryDelayNegative = "Retry delay must not be negative.";
        public const string MaxRetriesNegative = "Max retries must not be negative.";

        // Activity operation names
        public const string ActivityEvaluate = "MstPerformanceOptimization.Evaluate";
        public const string ActivityAcceleratedRetry = "MstPerformanceOptimization.AcceleratedRetry";
        public const string ActivityRetryAttempt = "MstPerformanceOptimization.RetryAttempt";

        // Activity tag keys
        public const string TagHttpUrl = "http.url";
        public const string TagHttpRequestMethod = "http.request.method";
        public const string TagHttpResponseStatusCode = "http.response.status_code";
        public const string TagIsEntries = "mst.policy.is_entries";
        public const string TagIsOperations = "mst.policy.is_operations";
        public const string TagIs503EntriesGet = "mst.policy.is_503_entries_get";
        public const string TagAction = "mst.policy.action";
        public const string TagInitialStatus = "mst.policy.initial_status";
        public const string TagMaxRetries = "mst.policy.max_retries";
        public const string TagRetryDelayMs = "mst.policy.retry_delay_ms";
        public const string TagAttempt = "mst.policy.attempt";
        public const string TagResult = "mst.policy.result";
        public const string TagResolvedAtAttempt = "mst.policy.resolved_at_attempt";
        public const string TagFinalStatus = "mst.policy.final_status";

        // Activity tag values
        public const string ActionStripOperationsHeaders = "strip_operations_headers";
        public const string ActionPassthrough = "passthrough";
        public const string ActionAcceleratedRetry = "accelerated_retry";
        public const string ResultResolved = "resolved";
        public const string ResultStill503 = "still_503";
        public const string ResultExhausted = "exhausted";

        // HTTP header names
        public const string HeaderRetryAfter = "Retry-After";
        public const string HeaderRetryAfterMs = "retry-after-ms";
        public const string HeaderXMsRetryAfterMs = "x-ms-retry-after-ms";

        // Path segments
        public const string EntriesPathSegment = "/entries/";
        public const string OperationsPathSegment = "/operations/";

        // ActivitySource name
        public const string ActivitySourceName = "CoseSign1.Transparent.MST.PerformanceOptimizationPolicy";
    }

    /// <summary>
    /// The default interval between fast retry attempts.
    /// </summary>
    public static readonly TimeSpan DefaultRetryDelay = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// The default maximum number of fast retry attempts (8 retries × 250 ms ≈ 2 seconds).
    /// </summary>
    public const int DefaultMaxRetries = 8;

    /// <summary>
    /// The name of the <see cref="ActivitySource"/> used by this policy for distributed tracing.
    /// </summary>
    public const string ActivitySourceName = ClassStrings.ActivitySourceName;

    private const int ServiceUnavailableStatusCode = 503;

    private static readonly ActivitySource PolicyActivitySource = new(ActivitySourceName);

    /// <summary>
    /// The set of retry-related headers that the Azure SDK checks for delay information.
    /// All three must be stripped to ensure the SDK uses client-configured timing.
    /// </summary>
    private static readonly string[] RetryAfterHeaders =
    [
        ClassStrings.HeaderRetryAfter,
        ClassStrings.HeaderRetryAfterMs,
        ClassStrings.HeaderXMsRetryAfterMs
    ];

    private readonly TimeSpan retryDelay;
    private readonly int maxRetries;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstPerformanceOptimizationPolicy"/> class
    /// with default retry settings (250 ms delay, 8 retries).
    /// </summary>
    public MstPerformanceOptimizationPolicy()
        : this(DefaultRetryDelay, DefaultMaxRetries)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstPerformanceOptimizationPolicy"/> class
    /// with custom retry settings.
    /// </summary>
    /// <param name="retryDelay">The interval to wait between fast retry attempts.</param>
    /// <param name="maxRetries">The maximum number of fast retry attempts before falling through
    /// to the SDK's standard retry logic.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="retryDelay"/> is negative or <paramref name="maxRetries"/> is negative.
    /// </exception>
    public MstPerformanceOptimizationPolicy(TimeSpan retryDelay, int maxRetries)
    {
        if (retryDelay < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(retryDelay), ClassStrings.RetryDelayNegative);
        }

        if (maxRetries < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRetries), ClassStrings.MaxRetriesNegative);
        }

        this.retryDelay = retryDelay;
        this.maxRetries = maxRetries;
    }

    /// <inheritdoc/>
    public override void Process(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    {
        ProcessCore(message, pipeline, isAsync: false).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public override ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    {
        return ProcessCore(message, pipeline, isAsync: true);
    }

    private async ValueTask ProcessCore(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline, bool isAsync)
    {
        if (isAsync)
        {
            await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
        }
        else
        {
            ProcessNext(message, pipeline);
        }

        // Emit a diagnostic activity for every response so we can confirm in production
        // that the policy is being invoked and what it sees.
        string? requestUri = message.Request.Uri?.ToUri()?.AbsoluteUri;
        int responseStatus = message.Response?.Status ?? 0;
        using Activity? evalActivity = PolicyActivitySource.StartActivity(
            ClassStrings.ActivityEvaluate,
            ActivityKind.Internal);
        evalActivity?.SetTag(ClassStrings.TagHttpUrl, requestUri);
        evalActivity?.SetTag(ClassStrings.TagHttpRequestMethod, message.Request.Method.ToString());
        evalActivity?.SetTag(ClassStrings.TagHttpResponseStatusCode, responseStatus);
        evalActivity?.SetTag(ClassStrings.TagIsEntries, IsEntriesResponse(message));
        evalActivity?.SetTag(ClassStrings.TagIsOperations, IsOperationsResponse(message));
        evalActivity?.SetTag(ClassStrings.TagIs503EntriesGet, IsEntriesServiceUnavailableResponse(message));

        // Strip Retry-After from operations responses (LRO polling) so the SDK uses our configured interval.
        if (IsOperationsResponse(message))
        {
            evalActivity?.SetTag(ClassStrings.TagAction, ClassStrings.ActionStripOperationsHeaders);
            StripRetryAfterHeader(message);
            return;
        }

        // Only process 503 on /entries/ - other responses pass through unchanged.
        if (!IsEntriesServiceUnavailableResponse(message))
        {
            evalActivity?.SetTag(ClassStrings.TagAction, ClassStrings.ActionPassthrough);
            return;
        }

        // 503 on /entries/ - perform fast retries with tracing.
        evalActivity?.SetTag(ClassStrings.TagAction, ClassStrings.ActionAcceleratedRetry);
        using Activity? retryActivity = PolicyActivitySource.StartActivity(
            ClassStrings.ActivityAcceleratedRetry,
            ActivityKind.Internal);

        retryActivity?.SetTag(ClassStrings.TagInitialStatus, 503);
        retryActivity?.SetTag(ClassStrings.TagMaxRetries, this.maxRetries);
        retryActivity?.SetTag(ClassStrings.TagRetryDelayMs, this.retryDelay.TotalMilliseconds);
        retryActivity?.SetTag(ClassStrings.TagHttpUrl, requestUri);

        // Note: Reusing HttpMessage for retries is safe here because:
        // 1. We only retry GET requests (no request body to rewind)
        // 2. ProcessNext replaces message.Response with a fresh response
        // This matches how Azure SDK's RetryPolicy handles retries internally.
        for (int attempt = 0; attempt < this.maxRetries; attempt++)
        {
            using Activity? attemptActivity = PolicyActivitySource.StartActivity(
                ClassStrings.ActivityRetryAttempt,
                ActivityKind.Internal);
            attemptActivity?.SetTag(ClassStrings.TagAttempt, attempt + 1);

            if (isAsync)
            {
                await Task.Delay(this.retryDelay, message.CancellationToken).ConfigureAwait(false);

                // Dispose the previous response before issuing a new request.
                // ProcessNextAsync will assign a fresh Response to message, so the old one
                // must be explicitly released to avoid leaking its content stream and connection.
                message.Response?.Dispose();
                await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
            }
            else
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                Thread.Sleep(this.retryDelay);

                // Dispose the previous response before issuing a new request.
                // ProcessNext will assign a fresh Response to message, so the old one
                // must be explicitly released to avoid leaking its content stream and connection.
                message.Response?.Dispose();
                ProcessNext(message, pipeline);
            }

            int attemptStatus = message.Response?.Status ?? 0;
            attemptActivity?.SetTag(ClassStrings.TagHttpResponseStatusCode, attemptStatus);

            if (!IsEntriesServiceUnavailableResponse(message))
            {
                // Success or different error - strip Retry-After and return.
                attemptActivity?.SetTag(ClassStrings.TagResult, ClassStrings.ResultResolved);
                retryActivity?.SetTag(ClassStrings.TagResolvedAtAttempt, attempt + 1);
                retryActivity?.SetTag(ClassStrings.TagFinalStatus, attemptStatus);
                StripRetryAfterHeader(message);
                return;
            }

            attemptActivity?.SetTag(ClassStrings.TagResult, ClassStrings.ResultStill503);
        }

        // All fast retries exhausted — strip Retry-After before returning the final 503.
        // This prevents the SDK's RetryPolicy from waiting the server-specified delay.
        retryActivity?.SetTag(ClassStrings.TagResolvedAtAttempt, 0);
        retryActivity?.SetTag(ClassStrings.TagFinalStatus, 503);
        retryActivity?.SetTag(ClassStrings.TagResult, ClassStrings.ResultExhausted);
        StripRetryAfterHeader(message);
    }

    /// <summary>
    /// Strips all retry-related headers from the response by wrapping it in a filtering response.
    /// This includes <c>Retry-After</c>, <c>retry-after-ms</c>, and <c>x-ms-retry-after-ms</c>.
    /// </summary>
    private static void StripRetryAfterHeader(HttpMessage message)
    {
        Response? response = message.Response;
        if (response is null)
        {
            return;
        }

        // Check if any retry-related header is present
        bool hasRetryHeader = RetryAfterHeaders.Any(header => response.Headers.Contains(header));

        if (!hasRetryHeader)
        {
            return;
        }

        // Wrap the response in a HeaderFilteringResponse that excludes all retry headers.
        message.Response = new HeaderFilteringResponse(response, RetryAfterHeaders);
    }

    /// <summary>
    /// Returns <see langword="true"/> if the request URI contains the <c>/entries/</c> path segment.
    /// </summary>
    private static bool IsEntriesResponse(HttpMessage message)
    {
        string? requestUri = message.Request.Uri?.ToUri()?.AbsoluteUri;
        return requestUri is not null && requestUri.IndexOf(ClassStrings.EntriesPathSegment, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    /// <summary>
    /// Returns <see langword="true"/> if the request URI contains the <c>/operations/</c> path segment.
    /// </summary>
    private static bool IsOperationsResponse(HttpMessage message)
    {
        string? requestUri = message.Request.Uri?.ToUri()?.AbsoluteUri;
        return requestUri is not null && requestUri.IndexOf(ClassStrings.OperationsPathSegment, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    /// <summary>
    /// Returns <see langword="true"/> if the response is HTTP 503 on a GET request to a <c>/entries/</c> URI.
    /// </summary>
    private static bool IsEntriesServiceUnavailableResponse(HttpMessage message)
    {
        if (message.Response is null)
        {
            return false;
        }

        if (message.Response.Status != ServiceUnavailableStatusCode)
        {
            return false;
        }

        if (!message.Request.Method.Equals(RequestMethod.Get))
        {
            return false;
        }

        return IsEntriesResponse(message);
    }
}

/// <summary>
/// A response wrapper that filters out specific headers from the inner response.
/// This allows modifying the apparent headers of a response without modifying the original.
/// </summary>
internal sealed class HeaderFilteringResponse : Response
{
    private readonly Response inner;
    private readonly HashSet<string> excludedHeaders;

    /// <summary>
    /// Creates a new <see cref="HeaderFilteringResponse"/> that wraps the specified response
    /// and excludes the specified headers.
    /// </summary>
    /// <param name="inner">The response to wrap.</param>
    /// <param name="excludedHeaders">Header names to exclude (case-insensitive).</param>
    public HeaderFilteringResponse(Response inner, params string[] excludedHeaders)
    {
        Guard.ThrowIfNull(inner);
        this.inner = inner;
        this.excludedHeaders = new HashSet<string>(excludedHeaders, StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc/>
    public override int Status => this.inner.Status;

    /// <inheritdoc/>
    public override string ReasonPhrase => this.inner.ReasonPhrase;

    /// <inheritdoc/>
    public override Stream? ContentStream
    {
        get => this.inner.ContentStream;
        set => this.inner.ContentStream = value;
    }

    /// <inheritdoc/>
    public override string ClientRequestId
    {
        get => this.inner.ClientRequestId;
        set => this.inner.ClientRequestId = value;
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        this.inner.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    protected override bool TryGetHeader(string name, out string? value)
    {
        if (this.excludedHeaders.Contains(name))
        {
            value = null;
            return false;
        }

        return this.inner.Headers.TryGetValue(name, out value);
    }

    /// <inheritdoc/>
    protected override bool TryGetHeaderValues(string name, out IEnumerable<string>? values)
    {
        if (this.excludedHeaders.Contains(name))
        {
            values = null;
            return false;
        }

        return this.inner.Headers.TryGetValues(name, out values);
    }

    /// <inheritdoc/>
    protected override bool ContainsHeader(string name)
    {
        if (this.excludedHeaders.Contains(name))
        {
            return false;
        }

        return this.inner.Headers.Contains(name);
    }

    /// <inheritdoc/>
    protected override IEnumerable<HttpHeader> EnumerateHeaders()
    {
        return this.inner.Headers.Where(header => !this.excludedHeaders.Contains(header.Name));
    }
}
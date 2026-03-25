// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;

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
    /// <summary>
    /// The default interval between fast retry attempts.
    /// </summary>
    public static readonly TimeSpan DefaultRetryDelay = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// The default maximum number of fast retry attempts (8 retries × 250 ms ≈ 2 seconds).
    /// </summary>
    public const int DefaultMaxRetries = 8;

    private const int ServiceUnavailableStatusCode = 503;
    private const string EntriesPathSegment = "/entries/";
    private const string OperationsPathSegment = "/operations/";

    /// <summary>
    /// The set of retry-related headers that the Azure SDK checks for delay information.
    /// All three must be stripped to ensure the SDK uses client-configured timing.
    /// </summary>
    private static readonly string[] RetryAfterHeaders =
    [
        "Retry-After",        // Standard HTTP header (seconds or HTTP-date)
        "retry-after-ms",     // Azure SDK specific (milliseconds)
        "x-ms-retry-after-ms" // Azure SDK specific with x-ms prefix (milliseconds)
    ];

    private readonly TimeSpan _retryDelay;
    private readonly int _maxRetries;

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
            throw new ArgumentOutOfRangeException(nameof(retryDelay), "Retry delay must not be negative.");
        }

        if (maxRetries < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRetries), "Max retries must not be negative.");
        }

        _retryDelay = retryDelay;
        _maxRetries = maxRetries;
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

        // Strip Retry-After from operations responses (LRO polling) so the SDK uses our configured interval.
        if (IsOperationsResponse(message))
        {
            StripRetryAfterHeader(message);
            return;
        }

        // Only process 503 on /entries/ - other responses pass through unchanged.
        if (!IsEntriesServiceUnavailableResponse(message))
        {
            return;
        }

        // 503 on /entries/ - perform fast retries.
        // Note: Reusing HttpMessage for retries is safe here because:
        // 1. We only retry GET requests (no request body to rewind)
        // 2. ProcessNext replaces message.Response with a fresh response
        // This matches how Azure SDK's RetryPolicy handles retries internally.
        for (int attempt = 0; attempt < _maxRetries; attempt++)
        {
            if (isAsync)
            {
                await Task.Delay(_retryDelay, message.CancellationToken).ConfigureAwait(false);

                // Dispose the previous response before issuing a new request.
                // ProcessNextAsync will assign a fresh Response to message, so the old one
                // must be explicitly released to avoid leaking its content stream and connection.
                message.Response?.Dispose();
                await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
            }
            else
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                Thread.Sleep(_retryDelay);

                // Dispose the previous response before issuing a new request.
                // ProcessNext will assign a fresh Response to message, so the old one
                // must be explicitly released to avoid leaking its content stream and connection.
                message.Response?.Dispose();
                ProcessNext(message, pipeline);
            }

            if (!IsEntriesServiceUnavailableResponse(message))
            {
                // Success or different error - strip Retry-After and return.
                StripRetryAfterHeader(message);
                return;
            }
        }

        // All fast retries exhausted — strip Retry-After before returning the final 503.
        // This prevents the SDK's RetryPolicy from waiting the server-specified delay.
        StripRetryAfterHeader(message);
    }

    /// <summary>
    /// Strips all retry-related headers from the response by wrapping it in a filtering response.
    /// This includes <c>Retry-After</c>, <c>retry-after-ms</c>, and <c>x-ms-retry-after-ms</c>.
    /// </summary>
    private static void StripRetryAfterHeader(HttpMessage message)
    {
        Response? response = message.Response;
        if (response == null)
        {
            return;
        }

        // Check if any retry-related header is present
        bool hasRetryHeader = false;
        foreach (string header in RetryAfterHeaders)
        {
            if (response.Headers.Contains(header))
            {
                hasRetryHeader = true;
                break;
            }
        }

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
        return requestUri != null && requestUri.IndexOf(EntriesPathSegment, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    /// <summary>
    /// Returns <see langword="true"/> if the request URI contains the <c>/operations/</c> path segment.
    /// </summary>
    private static bool IsOperationsResponse(HttpMessage message)
    {
        string? requestUri = message.Request.Uri?.ToUri()?.AbsoluteUri;
        return requestUri != null && requestUri.IndexOf(OperationsPathSegment, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    /// <summary>
    /// Returns <see langword="true"/> if the response is HTTP 503 on a GET request to a <c>/entries/</c> URI.
    /// </summary>
    private static bool IsEntriesServiceUnavailableResponse(HttpMessage message)
    {
        if (message.Response == null)
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
    private readonly Response _inner;
    private readonly HashSet<string> _excludedHeaders;

    /// <summary>
    /// Creates a new <see cref="HeaderFilteringResponse"/> that wraps the specified response
    /// and excludes the specified headers.
    /// </summary>
    /// <param name="inner">The response to wrap.</param>
    /// <param name="excludedHeaders">Header names to exclude (case-insensitive).</param>
    public HeaderFilteringResponse(Response inner, params string[] excludedHeaders)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _excludedHeaders = new HashSet<string>(excludedHeaders, StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc/>
    public override int Status => _inner.Status;

    /// <inheritdoc/>
    public override string ReasonPhrase => _inner.ReasonPhrase;

    /// <inheritdoc/>
    public override Stream? ContentStream
    {
        get => _inner.ContentStream;
        set => _inner.ContentStream = value;
    }

    /// <inheritdoc/>
    public override string ClientRequestId
    {
        get => _inner.ClientRequestId;
        set => _inner.ClientRequestId = value;
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        _inner.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    protected override bool TryGetHeader(string name, out string? value)
    {
        if (_excludedHeaders.Contains(name))
        {
            value = null;
            return false;
        }

        return _inner.Headers.TryGetValue(name, out value);
    }

    /// <inheritdoc/>
    protected override bool TryGetHeaderValues(string name, out IEnumerable<string>? values)
    {
        if (_excludedHeaders.Contains(name))
        {
            values = null;
            return false;
        }

        return _inner.Headers.TryGetValues(name, out values);
    }

    /// <inheritdoc/>
    protected override bool ContainsHeader(string name)
    {
        if (_excludedHeaders.Contains(name))
        {
            return false;
        }

        return _inner.Headers.Contains(name);
    }

    /// <inheritdoc/>
    protected override IEnumerable<HttpHeader> EnumerateHeaders()
    {
        foreach (HttpHeader header in _inner.Headers)
        {
            if (!_excludedHeaders.Contains(header.Name))
            {
                yield return header;
            }
        }
    }
}

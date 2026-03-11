// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;

/// <summary>
/// An Azure SDK pipeline policy that performs aggressive, fast retries exclusively for the
/// MST <c>GetEntryStatement</c> 503 / <c>TransactionNotCached</c> response pattern.
/// </summary>
/// <remarks>
/// <para>
/// <b>Problem:</b> The Azure Code Transparency Service returns HTTP 503 with a
/// <c>Retry-After: 1</c> header (1 second) when a newly registered entry has not yet
/// propagated to the serving node (<c>TransactionNotCached</c>). The entry typically becomes
/// available in well under 1 second, but the Azure SDK's default <see cref="RetryPolicy"/>
/// respects the server's <c>Retry-After</c> header, causing unnecessary 1-second delays.
/// </para>
///
/// <para>
/// <b>Solution:</b> This policy intercepts that specific response pattern and performs its own
/// fast retry loop (default: 250 ms intervals, up to 8 retries ≈ 2 seconds) <em>inside</em>
/// the pipeline, before the SDK's standard <see cref="RetryPolicy"/> ever sees the response.
/// </para>
///
/// <para>
/// <b>Scope:</b> Only HTTP 503 responses to <c>GET</c> requests whose URI path contains
/// <c>/entries/</c> are retried by this policy. All other requests and response codes
/// pass through with a single <c>ProcessNext</c> call — the SDK's normal retry
/// infrastructure handles them with whatever <see cref="RetryOptions"/> the caller configured.
/// </para>
///
/// <para>
/// <b>Pipeline position:</b> Register this policy in the
/// <see cref="HttpPipelinePosition.PerRetry"/> position so it runs inside the SDK's
/// retry loop. Each of the policy's internal retries re-sends the request through
/// the remaining pipeline (transport). If the fast retries succeed, the SDK sees a
/// successful response. If they exhaust without success, the SDK sees the final 503
/// and applies its own retry logic as usual.
/// </para>
///
/// <para>
/// <b>Usage:</b>
/// <code>
/// var options = new CodeTransparencyClientOptions();
/// options.AddPolicy(new MstTransactionNotCachedPolicy(), HttpPipelinePosition.PerRetry);
/// var client = new CodeTransparencyClient(endpoint, credential, options);
/// </code>
/// Or use the convenience extension:
/// <code>
/// var options = new CodeTransparencyClientOptions();
/// options.ConfigureTransactionNotCachedRetry();
/// </code>
/// </para>
/// </remarks>
public class MstTransactionNotCachedPolicy : HttpPipelinePolicy
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
    private const string TransactionNotCachedErrorCode = "TransactionNotCached";

    private readonly TimeSpan _retryDelay;
    private readonly int _maxRetries;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransactionNotCachedPolicy"/> class
    /// with default retry settings (250 ms delay, 8 retries).
    /// </summary>
    public MstTransactionNotCachedPolicy()
        : this(DefaultRetryDelay, DefaultMaxRetries)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransactionNotCachedPolicy"/> class
    /// with custom retry settings.
    /// </summary>
    /// <param name="retryDelay">The interval to wait between fast retry attempts.</param>
    /// <param name="maxRetries">The maximum number of fast retry attempts before falling through
    /// to the SDK's standard retry logic.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="retryDelay"/> is negative or <paramref name="maxRetries"/> is negative.
    /// </exception>
    public MstTransactionNotCachedPolicy(TimeSpan retryDelay, int maxRetries)
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

        if (!IsTransactionNotCachedResponse(message))
        {
            return;
        }

        for (int attempt = 0; attempt < _maxRetries; attempt++)
        {
            if (isAsync)
            {
                await Task.Delay(_retryDelay).ConfigureAwait(false);
                await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
            }
            else
            {
                Thread.Sleep(_retryDelay);
                ProcessNext(message, pipeline);
            }

            if (!IsTransactionNotCachedResponse(message))
            {
                return;
            }
        }

        // All fast retries exhausted — return the final 503 to the outer pipeline.
        // The SDK's RetryPolicy will handle it from here (respecting Retry-After as usual).
    }

    /// <summary>
    /// Returns <see langword="true"/> if the response matches the MST TransactionNotCached pattern:
    /// HTTP 503 on a GET request to a <c>/entries/</c> URI with a CBOR problem-details body
    /// containing the <c>TransactionNotCached</c> error code.
    /// </summary>
    private static bool IsTransactionNotCachedResponse(HttpMessage message)
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

        string? requestUri = message.Request.Uri?.ToUri()?.AbsoluteUri;
        if (requestUri == null || requestUri.IndexOf(EntriesPathSegment, StringComparison.OrdinalIgnoreCase) < 0)
        {
            return false;
        }

        // Parse the CBOR problem details body to confirm this is TransactionNotCached.
        return HasTransactionNotCachedErrorCode(message.Response);
    }

    /// <summary>
    /// Reads the response body as CBOR problem details and checks whether the error code
    /// matches <c>TransactionNotCached</c> in any of the standard fields (Detail, Title, Type)
    /// or extension values.
    /// </summary>
    private static bool HasTransactionNotCachedErrorCode(Response response)
    {
        try
        {
            // Read the response body. The stream must be seekable so subsequent retries
            // (and the SDK's own retry infrastructure) can re-read it.
            if (response.ContentStream == null)
            {
                return false;
            }

            if (!response.ContentStream.CanSeek)
            {
                // Buffer into a seekable MemoryStream so the body is re-readable.
                MemoryStream buffer = new();
                response.ContentStream.CopyTo(buffer);
                buffer.Position = 0;
                response.ContentStream = buffer;
            }

            long startPosition = response.ContentStream.Position;
            byte[] body;
            try
            {
                response.ContentStream.Position = 0;
                body = new byte[response.ContentStream.Length];
                _ = response.ContentStream.Read(body, 0, body.Length);
            }
            finally
            {
                // Always rewind so the body remains available for subsequent reads.
                response.ContentStream.Position = startPosition;
            }

            if (body.Length == 0)
            {
                return false;
            }

            CborProblemDetails? details = CborProblemDetails.TryParse(body);
            if (details == null)
            {
                return false;
            }

            // Check standard fields for the error code string.
            if (ContainsErrorCode(details.Detail) ||
                ContainsErrorCode(details.Title) ||
                ContainsErrorCode(details.Type))
            {
                return true;
            }

            // Check extension values.
            if (details.Extensions?.Any(ext => ext.Value is string strValue && ContainsErrorCode(strValue)) == true)
            {
                return true;
            }

            return false;
        }
        catch (IOException)
        {
            // Stream read/seek failure — can't confirm it's TransactionNotCached, don't retry.
            return false;
        }
        catch (ObjectDisposedException)
        {
            // Response stream was disposed — can't confirm it's TransactionNotCached, don't retry.
            return false;
        }
        catch (NotSupportedException)
        {
            // Stream doesn't support seek/read — can't confirm it's TransactionNotCached, don't retry.
            return false;
        }
    }

    private static bool ContainsErrorCode(string? value)
    {
        return value != null
            && value.IndexOf(TransactionNotCachedErrorCode, StringComparison.OrdinalIgnoreCase) >= 0;
    }
}

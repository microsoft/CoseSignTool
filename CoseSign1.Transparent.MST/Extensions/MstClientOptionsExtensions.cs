// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Azure.Security.CodeTransparency;

using System;
using Azure.Core;
using Azure.Core.Pipeline;
using CoseSign1.Transparent.MST;

/// <summary>
/// Extension methods for configuring <see cref="CodeTransparencyClientOptions"/> with MST-specific
/// pipeline policies.
/// </summary>
public static class MstClientOptionsExtensions
{
    /// <summary>
    /// Adds the <see cref="MstTransactionNotCachedPolicy"/> to the client options pipeline,
    /// enabling fast retries for the MST <c>GetEntryStatement</c> 503 / <c>TransactionNotCached</c>
    /// response pattern.
    /// </summary>
    /// <param name="options">The <see cref="CodeTransparencyClientOptions"/> to configure.</param>
    /// <param name="retryDelay">
    /// The interval between fast retry attempts. Defaults to 250 ms.
    /// </param>
    /// <param name="maxRetries">
    /// The maximum number of fast retry attempts before falling through to the SDK's standard
    /// retry logic. Defaults to 8 (≈ 2 seconds at 250 ms).
    /// </param>
    /// <returns>The same <paramref name="options"/> instance for fluent chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    /// <remarks>
    /// <para>
    /// This method does <b>not</b> modify the SDK's global <see cref="Azure.Core.RetryOptions"/>
    /// on the client options. The fast retry loop runs entirely within the policy and only targets
    /// HTTP 503 responses to <c>GET /entries/</c> requests. All other API calls retain whatever
    /// retry behavior the caller has configured (or the SDK defaults).
    /// </para>
    ///
    /// <para>
    /// <b>Example:</b>
    /// <code>
    /// var options = new CodeTransparencyClientOptions();
    /// options.ConfigureTransactionNotCachedRetry();                                // defaults
    /// options.ConfigureTransactionNotCachedRetry(TimeSpan.FromMilliseconds(100));  // faster
    /// options.ConfigureTransactionNotCachedRetry(maxRetries: 16);                  // longer window
    ///
    /// var client = new CodeTransparencyClient(endpoint, credential, options);
    /// </code>
    /// </para>
    /// </remarks>
    public static CodeTransparencyClientOptions ConfigureTransactionNotCachedRetry(
        this CodeTransparencyClientOptions options,
        TimeSpan? retryDelay = null,
        int? maxRetries = null)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        var policy = new MstTransactionNotCachedPolicy(
            retryDelay ?? MstTransactionNotCachedPolicy.DefaultRetryDelay,
            maxRetries ?? MstTransactionNotCachedPolicy.DefaultMaxRetries);

        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        return options;
    }
}

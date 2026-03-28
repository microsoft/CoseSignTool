// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Azure.Security.CodeTransparency;

using System;
using Azure.Core;
using Cose.Abstractions;
using CoseSign1.Transparent.MST;

/// <summary>
/// Extension methods for configuring <see cref="CodeTransparencyClientOptions"/> with MST-specific
/// pipeline policies.
/// </summary>
public static class MstClientOptionsExtensions
{
    /// <summary>
    /// Adds the <see cref="MstPerformanceOptimizationPolicy"/> to the client options pipeline,
    /// enabling fast retries for 503 responses and stripping retry-related headers
    /// (<c>Retry-After</c>, <c>retry-after-ms</c>, <c>x-ms-retry-after-ms</c>) for improved
    /// MST client performance.
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
    /// on the client options. The policy performs fast retries for HTTP 503 responses on
    /// <c>/entries/</c> endpoints and strips all retry-related headers (<c>Retry-After</c>,
    /// <c>retry-after-ms</c>, <c>x-ms-retry-after-ms</c>) from both <c>/entries/</c> and
    /// <c>/operations/</c> responses. All other API calls pass through unchanged.
    /// </para>
    ///
    /// <para>
    /// <b>Example:</b>
    /// <code>
    /// var options = new CodeTransparencyClientOptions();
    /// options.ConfigureMstPerformanceOptimizations();                                // defaults
    /// options.ConfigureMstPerformanceOptimizations(TimeSpan.FromMilliseconds(100));  // faster
    /// options.ConfigureMstPerformanceOptimizations(maxRetries: 16);                  // longer window
    ///
    /// var client = new CodeTransparencyClient(endpoint, credential, options);
    /// </code>
    /// </para>
    /// </remarks>
    public static CodeTransparencyClientOptions ConfigureMstPerformanceOptimizations(
        this CodeTransparencyClientOptions options,
        TimeSpan? retryDelay = null,
        int? maxRetries = null)
    {
        Guard.ThrowIfNull(options);

        MstPerformanceOptimizationPolicy policy = new(
            retryDelay ?? MstPerformanceOptimizationPolicy.DefaultRetryDelay,
            maxRetries ?? MstPerformanceOptimizationPolicy.DefaultMaxRetries);

        options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
        return options;
    }
}
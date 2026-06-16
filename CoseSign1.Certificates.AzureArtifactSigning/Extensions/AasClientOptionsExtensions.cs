// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Azure.CodeSigning;

using System;
using Azure.Core;
using Azure.Developer.ArtifactSigning.CryptoProvider.Models;

/// <summary>
/// Extension methods for tuning the Azure Artifact Signing (AAS) client pipeline and signing-context
/// timing knobs for improved interactive signing performance.
/// </summary>
/// <remarks>
/// <para>
/// The Azure SDK's default <see cref="RetryOptions"/> use exponential back-off starting at 800 ms with
/// 3 retries (≈ 5 s before giving up). For interactive signing scenarios — where a user is waiting at
/// a console — that can stretch a transient blip into a multi-second wait. These extensions apply
/// fixed-delay 250 ms retries with up to 8 attempts so the typical recovery window is short, while
/// leaving the <c>AzSignContext</c> long-running signing operation knobs
/// (<see cref="AzSignContextOptions"/>) adjustable via <see cref="ConfigureAasSigningPerformance"/>.
/// </para>
/// <para>
/// <b>Retry-After honoured.</b> Azure.Core's <c>RetryPolicy</c> always honours a server-supplied
/// <c>Retry-After</c> header even when <see cref="RetryMode.Fixed"/> is configured. If AAS asks the
/// client to back off (e.g. <c>Retry-After: 30</c>), that value wins over the configured 250 ms delay,
/// so the practical worst-case latency is bounded by the server's policy, not the SDK ceiling. This is
/// intentional: AAS uses <c>Retry-After</c> correctly and the client should respect it. Unlike the MST
/// equivalent (<c>MstClientOptionsExtensions.ConfigureMstPerformanceOptimizations</c>) this helper does
/// <b>not</b> strip <c>Retry-After</c> headers — that is an MST-specific work-around for the Code
/// Transparency Service's eventual-consistency window where the server returns optimistic 1-second
/// hints that the client can safely beat.
/// </para>
/// </remarks>
public static class AasClientOptionsExtensions
{
    /// <summary>
    /// The default interval between fast retry attempts when the server does not supply
    /// <c>Retry-After</c>. A server-supplied value will override this.
    /// </summary>
    public static readonly TimeSpan DefaultRetryDelay = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// The default maximum number of fast retry attempts. With no <c>Retry-After</c> back-pressure
    /// the worst-case ceiling is approximately <c>MaxRetries * DefaultRetryDelay</c> (≈ 2 seconds).
    /// </summary>
    public const int DefaultMaxRetries = 8;

    /// <summary>
    /// The default <see cref="AzSignContextOptions.TaskRetryCount"/> applied by
    /// <see cref="ConfigureAasSigningPerformance"/>. Matches the SDK default; surfaced as a constant
    /// so callers can tune relative to a known baseline.
    /// </summary>
    public const int DefaultSigningTaskRetryCount = 3;

    /// <summary>
    /// The default <see cref="AzSignContextOptions.TaskTimeOutInSeconds"/> applied by
    /// <see cref="ConfigureAasSigningPerformance"/>. Matches the SDK default.
    /// </summary>
    public const int DefaultSigningTaskTimeoutSeconds = 60;

    /// <summary>
    /// Configures the Azure SDK retry pipeline on a <see cref="CertificateProfileClientOptions"/>
    /// instance to use a short fixed delay between retries so transient certificate-profile lookups
    /// do not stretch interactive signing latency. Server-supplied <c>Retry-After</c> values are
    /// still honoured and override the configured delay.
    /// </summary>
    /// <param name="options">The <see cref="CertificateProfileClientOptions"/> to configure.</param>
    /// <param name="retryDelay">
    /// Interval between fast retry attempts. Defaults to <see cref="DefaultRetryDelay"/> (250 ms).
    /// </param>
    /// <param name="maxRetries">
    /// Maximum number of fast retry attempts before failing. Defaults to <see cref="DefaultMaxRetries"/> (8).
    /// </param>
    /// <returns>The same <paramref name="options"/> instance for fluent chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    /// <example>
    /// <code>
    /// CertificateProfileClientOptions options = new CertificateProfileClientOptions();
    /// options.ConfigureAasPerformanceOptimizations();
    /// CertificateProfileClient client = new CertificateProfileClient(credential, endpoint, options);
    /// </code>
    /// </example>
    public static CertificateProfileClientOptions ConfigureAasPerformanceOptimizations(
        this CertificateProfileClientOptions options,
        TimeSpan? retryDelay = null,
        int? maxRetries = null)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.Retry.Mode = RetryMode.Fixed;
        options.Retry.Delay = retryDelay ?? DefaultRetryDelay;
        options.Retry.MaxRetries = maxRetries ?? DefaultMaxRetries;

        return options;
    }

    /// <summary>
    /// Builds an <see cref="AzSignContextOptions"/> instance with the supplied long-running signing
    /// timing knobs, falling back to the SDK defaults when a value is not specified.
    /// </summary>
    /// <param name="taskRetryCount">
    /// Maximum number of times the signing task is retried before failing. Defaults to
    /// <see cref="DefaultSigningTaskRetryCount"/>.
    /// </param>
    /// <param name="taskTimeoutSeconds">
    /// Per-task timeout in seconds for the signing long-running operation. Defaults to
    /// <see cref="DefaultSigningTaskTimeoutSeconds"/>.
    /// </param>
    /// <returns>A populated <see cref="AzSignContextOptions"/>.</returns>
    /// <example>
    /// <code>
    /// AzSignContextOptions opts = AasClientOptionsExtensions.ConfigureAasSigningPerformance(
    ///     taskRetryCount: 5,
    ///     taskTimeoutSeconds: 30);
    /// AzSignContext signContext = new AzSignContext(account, profile, client, null, opts);
    /// </code>
    /// </example>
    public static AzSignContextOptions ConfigureAasSigningPerformance(
        int? taskRetryCount = null,
        int? taskTimeoutSeconds = null)
    {
        return new AzSignContextOptions
        {
            TaskRetryCount = taskRetryCount ?? DefaultSigningTaskRetryCount,
            TaskTimeOutInSeconds = taskTimeoutSeconds ?? DefaultSigningTaskTimeoutSeconds
        };
    }
}

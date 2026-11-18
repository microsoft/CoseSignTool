// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System;

/// <summary>
/// Configuration options for controlling how <see cref="MstTransparencyService"/> polls the
/// Azure Code Transparency Service for completed receipt registrations.
/// </summary>
/// <remarks>
/// <para><b>These options no longer have any effect.</b> Starting with Azure.Security.CodeTransparency
/// 1.0.0, registration uses <c>CreateEntryAsync(body, waitForCommit: true)</c>, which returns only once
/// the entry is committed, so there is no long-running operation to poll. To tune how the SDK retries
/// a not-yet-committed entry, configure <c>CodeTransparencyClientOptions.Retry</c> on the client.</para>
///
/// <para>The type is retained for source compatibility.</para>
/// </remarks>
public class MstPollingOptions
{
    /// <summary>
    /// Gets or sets the fixed interval between polling attempts.
    /// </summary>
    /// <remarks>
    /// Has no effect; see the <see cref="MstPollingOptions"/> remarks.
    /// </remarks>
    /// <example>
    /// <code>
    /// var options = new MstPollingOptions { PollingInterval = TimeSpan.FromSeconds(2) };
    /// </code>
    /// </example>
    public TimeSpan? PollingInterval { get; set; }

    /// <summary>
    /// Gets or sets a custom <see cref="Azure.Core.DelayStrategy"/> that controls the
    /// back-off pattern between polling attempts.
    /// </summary>
    /// <remarks>
    /// Has no effect; see the <see cref="MstPollingOptions"/> remarks.
    /// </remarks>
    /// <example>
    /// <code>
    /// var options = new MstPollingOptions
    /// {
    ///     DelayStrategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(500))
    /// };
    /// </code>
    /// </example>
    public Azure.Core.DelayStrategy? DelayStrategy { get; set; }
}
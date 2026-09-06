// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System;

/// <summary>
/// Configuration options for controlling how <see cref="MstTransparencyService"/> polls the
/// Azure Code Transparency Service for completed receipt registrations.
/// </summary>
/// <remarks>
/// <para><b>These options do not affect request timing with the referenced
/// Azure.Security.CodeTransparency 1.0.0-beta.12:</b> registration returns an already-completed
/// operation, so <c>WaitForCompletionAsync</c> performs no long-running-operation polling. They are
/// still passed to it and apply to any SDK version that returns a genuinely pending operation.</para>
///
/// <para>If neither <see cref="PollingInterval"/> nor <see cref="DelayStrategy"/> is set,
/// the Azure SDK's default exponential back-off strategy is used.</para>
///
/// <para>If both are set, <see cref="DelayStrategy"/> takes precedence.</para>
/// </remarks>
public class MstPollingOptions
{
    /// <summary>
    /// Gets or sets the fixed interval between polling attempts.
    /// </summary>
    /// <remarks>
    /// When set, <c>Operation&lt;T&gt;.WaitForCompletionAsync(TimeSpan, CancellationToken)</c>
    /// is called with this value. Set to <c>null</c> (the default) to use the SDK's built-in
    /// delay strategy instead.
    ///
    /// <para>Typical values range from 100 ms (aggressive, local dev) to 5 s (production).</para>
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
    /// When set, this strategy is passed to the
    /// <c>Operation&lt;T&gt;.WaitForCompletionAsync(DelayStrategy, CancellationToken)</c> overload.
    /// This takes precedence over <see cref="PollingInterval"/> if both are specified.
    ///
    /// <para>Use <see cref="Azure.Core.DelayStrategy.CreateFixedDelayStrategy(TimeSpan)"/>
    /// for a constant interval, or implement a custom strategy for exponential back-off
    /// with jitter.</para>
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
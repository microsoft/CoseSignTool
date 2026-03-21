// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

/// <summary>
/// Configuration options for controlling how <see cref="MstTransparencyProvider"/> polls the
/// Azure Code Transparency Service for completed receipt registrations.
/// </summary>
/// <remarks>
/// When a COSE_Sign1 message is submitted to MST via <c>CreateEntryAsync</c>, the service
/// returns a long-running operation that must be polled until completion. These options let
/// callers tune the polling behavior to balance latency against cost.
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
    public TimeSpan? PollingInterval { get; set; }

    /// <summary>
    /// Gets or sets a custom <see cref="Azure.Core.DelayStrategy"/> that controls the
    /// back-off pattern between polling attempts.
    /// </summary>
    /// <remarks>
    /// When set, this strategy is assigned to <c>Operation&lt;T&gt;.DelayStrategy</c> before
    /// calling <c>WaitForCompletionAsync</c>. This takes precedence over
    /// <see cref="PollingInterval"/> if both are specified.
    ///
    /// <para>Use <c>DelayStrategy.CreateFixedDelayStrategy(TimeSpan)</c>
    /// for a constant interval, or implement a custom strategy for exponential back-off
    /// with jitter.</para>
    /// </remarks>
    public Azure.Core.DelayStrategy? DelayStrategy { get; set; }
}
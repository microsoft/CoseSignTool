// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Telemetry;

using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Tracing;

/// <summary>
/// ETW/EventPipe event source for MST transparency telemetry.
/// </summary>
/// <remarks>
/// <para>
/// Emits events for MST transparency operations: submission start/completion/failure,
/// receipt verification failures, and CBOR parse failures in silent catch blocks.
/// These events are zero-cost when no listener is attached (ETW pattern) — the
/// <see cref="EventSource.IsEnabled()"/> check short-circuits before any allocation.
/// </para>
/// <para>
/// Green/blue teams can subscribe via:
/// <list type="bullet">
///   <item><c>dotnet-trace collect --providers CoseSign1-MST</c></item>
///   <item><c>PerfView /providers=CoseSign1-MST</c></item>
///   <item>Application Insights / OpenTelemetry EventSource listener</item>
/// </list>
/// </para>
/// </remarks>
[ExcludeFromCodeCoverage]
internal static class ClassStrings
{
    public const string EventSourceName = "CoseSign1-MST";
    public const string EventTransparencySubmissionStarted = "Transparency submission started: provider={0}, messageSizeBytes={1}";
    public const string EventTransparencySubmissionCompleted = "Transparency submission completed: provider={0}, entryId={1}";
    public const string EventTransparencySubmissionFailed = "Transparency submission failed: provider={0}, [{1}] {2}";
    public const string EventReceiptVerificationFailed = "Receipt verification failed: {0}";
    public const string EventCborParseFailed = "CBOR parse failed: context={0}, [{1}] {2}";
}

[EventSource(Name = ClassStrings.EventSourceName)]
internal sealed class CoseSign1MstEventSource : EventSource
{
    /// <summary>Singleton instance.</summary>
    public static readonly CoseSign1MstEventSource Log = new();

    /// <summary>
    /// Raised when a transparency submission to MST service starts.
    /// </summary>
    /// <param name="providerName">The name of the transparency provider.</param>
    /// <param name="messageSizeBytes">The size of the message being submitted in bytes.</param>
    [Event(1, Level = EventLevel.Informational, Message = ClassStrings.EventTransparencySubmissionStarted)]
    public void TransparencySubmissionStarted(string providerName, int messageSizeBytes)
    {
        if (IsEnabled())
        {
            WriteEvent(1, providerName, messageSizeBytes);
        }
    }

    /// <summary>
    /// Raised when a transparency submission completes successfully.
    /// </summary>
    /// <param name="providerName">The name of the transparency provider.</param>
    /// <param name="entryId">The MST entry ID returned by the service.</param>
    [Event(2, Level = EventLevel.Informational, Message = ClassStrings.EventTransparencySubmissionCompleted)]
    public void TransparencySubmissionCompleted(string providerName, string entryId)
    {
        if (IsEnabled())
        {
            WriteEvent(2, providerName, entryId);
        }
    }

    /// <summary>
    /// Raised when a transparency submission fails.
    /// </summary>
    /// <param name="providerName">The name of the transparency provider.</param>
    /// <param name="exceptionType">The exception type name.</param>
    /// <param name="message">The exception message.</param>
    [Event(3, Level = EventLevel.Error, Message = ClassStrings.EventTransparencySubmissionFailed)]
    public void TransparencySubmissionFailed(string providerName, string exceptionType, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(3, providerName, exceptionType, message);
        }
    }

    /// <summary>
    /// Raised when receipt verification fails.
    /// </summary>
    /// <param name="reason">The reason the verification failed.</param>
    [Event(4, Level = EventLevel.Warning, Message = ClassStrings.EventReceiptVerificationFailed)]
    public void ReceiptVerificationFailed(string reason)
    {
        if (IsEnabled())
        {
            WriteEvent(4, reason);
        }
    }

    /// <summary>
    /// Raised when CBOR parsing fails in a context that would otherwise be silently swallowed.
    /// </summary>
    /// <param name="context">The parsing context (e.g., "TryParse", "TryGetMstEntryId").</param>
    /// <param name="exceptionType">The exception type name.</param>
    /// <param name="message">The exception message.</param>
    [Event(5, Level = EventLevel.Warning, Message = ClassStrings.EventCborParseFailed)]
    public void CborParseFailed(string context, string exceptionType, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(5, context, exceptionType, message);
        }
    }
}
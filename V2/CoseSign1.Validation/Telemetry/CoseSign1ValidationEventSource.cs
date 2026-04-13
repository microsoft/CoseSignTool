// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Telemetry;

using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Tracing;

/// <summary>
/// ETW/EventPipe event source for validation telemetry.
/// </summary>
/// <remarks>
/// <para>
/// Emits events for validation lifecycle: start, stage completion/failure,
/// overall result, and kid header decode failures.
/// These events are zero-cost when no listener is attached (ETW pattern) — the
/// <see cref="EventSource.IsEnabled()"/> check short-circuits before any allocation.
/// </para>
/// <para>
/// Green/blue teams can subscribe via:
/// <list type="bullet">
///   <item><c>dotnet-trace collect --providers CoseSign1-Validation</c></item>
///   <item><c>PerfView /providers=CoseSign1-Validation</c></item>
///   <item>Application Insights / OpenTelemetry EventSource listener</item>
/// </list>
/// </para>
/// </remarks>
[ExcludeFromCodeCoverage]
internal static class ClassStrings
{
    public const string EventSourceName = "CoseSign1-Validation";
    public const string EventValidationStarted = "Validation started: messageId={0}";
    public const string EventValidationStageCompleted = "Validation stage completed: stage={0}, elapsedMs={1}, success={2}";
    public const string EventValidationStageFailed = "Validation stage failed: stage={0}, errorCode={1}, {2}";
    public const string EventValidationCompleted = "Validation completed: isValid={0}, totalElapsedMs={1}";
    public const string EventKidHeaderDecodeFailed = "Kid header decode failed: [{0}] {1}";
}

[EventSource(Name = ClassStrings.EventSourceName)]
internal sealed class CoseSign1ValidationEventSource : EventSource
{
    /// <summary>Singleton instance.</summary>
    public static readonly CoseSign1ValidationEventSource Log = new();

    /// <summary>
    /// Raised when validation of a COSE Sign1 message starts.
    /// </summary>
    /// <param name="messageId">An identifier for the message being validated.</param>
    [Event(1, Level = EventLevel.Informational, Message = ClassStrings.EventValidationStarted)]
    public void ValidationStarted(string messageId)
    {
        if (IsEnabled())
        {
            WriteEvent(1, messageId);
        }
    }

    /// <summary>
    /// Raised when a validation stage completes.
    /// </summary>
    /// <param name="stage">The name of the validation stage.</param>
    /// <param name="elapsedMs">The elapsed time in milliseconds for this stage.</param>
    /// <param name="success">Whether the stage succeeded.</param>
    [Event(2, Level = EventLevel.Informational, Message = ClassStrings.EventValidationStageCompleted)]
    public void ValidationStageCompleted(string stage, long elapsedMs, bool success)
    {
        if (IsEnabled())
        {
            WriteEvent(2, stage, elapsedMs, success ? 1 : 0);
        }
    }

    /// <summary>
    /// Raised when a validation stage fails.
    /// </summary>
    /// <param name="stage">The name of the validation stage that failed.</param>
    /// <param name="errorCode">The error code for the failure.</param>
    /// <param name="message">The error message.</param>
    [Event(3, Level = EventLevel.Warning, Message = ClassStrings.EventValidationStageFailed)]
    public void ValidationStageFailed(string stage, string errorCode, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(3, stage, errorCode, message);
        }
    }

    /// <summary>
    /// Raised when the overall validation completes.
    /// </summary>
    /// <param name="isValid">Whether the message is valid.</param>
    /// <param name="totalElapsedMs">The total elapsed time in milliseconds.</param>
    [Event(4, Level = EventLevel.Informational, Message = ClassStrings.EventValidationCompleted)]
    public void ValidationCompleted(bool isValid, long totalElapsedMs)
    {
        if (IsEnabled())
        {
            WriteEvent(4, isValid ? 1 : 0, totalElapsedMs);
        }
    }

    /// <summary>
    /// Raised when the kid header cannot be decoded from the COSE message.
    /// </summary>
    /// <param name="exceptionType">The exception type name.</param>
    /// <param name="message">The exception message.</param>
    [Event(5, Level = EventLevel.Warning, Message = ClassStrings.EventKidHeaderDecodeFailed)]
    public void KidHeaderDecodeFailed(string exceptionType, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(5, exceptionType, message);
        }
    }
}
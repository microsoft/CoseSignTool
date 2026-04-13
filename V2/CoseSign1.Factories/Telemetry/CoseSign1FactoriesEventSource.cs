// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Telemetry;

using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Tracing;

/// <summary>
/// ETW/EventPipe event source for signature factory telemetry.
/// </summary>
/// <remarks>
/// <para>
/// Emits events for signature creation lifecycle: start, completion, failure,
/// transparency provider errors, and post-sign verification failures.
/// These events are zero-cost when no listener is attached (ETW pattern) — the
/// <see cref="EventSource.IsEnabled()"/> check short-circuits before any allocation.
/// </para>
/// <para>
/// Green/blue teams can subscribe via:
/// <list type="bullet">
///   <item><c>dotnet-trace collect --providers CoseSign1-Factories</c></item>
///   <item><c>PerfView /providers=CoseSign1-Factories</c></item>
///   <item>Application Insights / OpenTelemetry EventSource listener</item>
/// </list>
/// </para>
/// </remarks>
[ExcludeFromCodeCoverage]
internal static class ClassStrings
{
    public const string EventSourceName = "CoseSign1-Factories";
    public const string EventSignatureCreationStarted = "Signature creation started: operationId={0}, signatureType={1}";
    public const string EventSignatureCreationCompleted = "Signature creation completed: operationId={0}, elapsedMs={1}";
    public const string EventSignatureCreationFailed = "Signature creation failed: operationId={0}, [{1}] {2}";
    public const string EventTransparencyProviderFailed = "Transparency provider failed: operationId={0}, provider={1}, {2}";
    public const string EventPostSignVerificationFailed = "Post-sign verification failed: operationId={0}";
}

[EventSource(Name = ClassStrings.EventSourceName)]
internal sealed class CoseSign1FactoriesEventSource : EventSource
{
    /// <summary>Singleton instance.</summary>
    public static readonly CoseSign1FactoriesEventSource Log = new();

    /// <summary>
    /// Raised when a signature creation operation starts.
    /// </summary>
    /// <param name="operationId">The unique operation identifier.</param>
    /// <param name="signatureType">The type of signature being created (e.g., "Direct", "Indirect").</param>
    [Event(1, Level = EventLevel.Informational, Message = ClassStrings.EventSignatureCreationStarted)]
    public void SignatureCreationStarted(string operationId, string signatureType)
    {
        if (IsEnabled())
        {
            WriteEvent(1, operationId, signatureType);
        }
    }

    /// <summary>
    /// Raised when a signature creation operation completes successfully.
    /// </summary>
    /// <param name="operationId">The unique operation identifier.</param>
    /// <param name="elapsedMs">The elapsed time in milliseconds.</param>
    [Event(2, Level = EventLevel.Informational, Message = ClassStrings.EventSignatureCreationCompleted)]
    public void SignatureCreationCompleted(string operationId, long elapsedMs)
    {
        if (IsEnabled())
        {
            WriteEvent(2, operationId, elapsedMs);
        }
    }

    /// <summary>
    /// Raised when a signature creation operation fails.
    /// </summary>
    /// <param name="operationId">The unique operation identifier.</param>
    /// <param name="exceptionType">The exception type name.</param>
    /// <param name="message">The exception message.</param>
    [Event(3, Level = EventLevel.Error, Message = ClassStrings.EventSignatureCreationFailed)]
    public void SignatureCreationFailed(string operationId, string exceptionType, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(3, operationId, exceptionType, message);
        }
    }

    /// <summary>
    /// Raised when a transparency provider fails during signature creation.
    /// </summary>
    /// <param name="operationId">The unique operation identifier.</param>
    /// <param name="providerName">The name of the transparency provider that failed.</param>
    /// <param name="message">The error message.</param>
    [Event(4, Level = EventLevel.Warning, Message = ClassStrings.EventTransparencyProviderFailed)]
    public void TransparencyProviderFailed(string operationId, string providerName, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(4, operationId, providerName, message);
        }
    }

    /// <summary>
    /// Raised when post-sign verification fails.
    /// </summary>
    /// <param name="operationId">The unique operation identifier.</param>
    [Event(5, Level = EventLevel.Warning, Message = ClassStrings.EventPostSignVerificationFailed)]
    public void PostSignVerificationFailed(string operationId)
    {
        if (IsEnabled())
        {
            WriteEvent(5, operationId);
        }
    }
}
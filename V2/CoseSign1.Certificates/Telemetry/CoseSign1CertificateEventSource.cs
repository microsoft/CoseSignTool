// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Telemetry;

using System.Diagnostics.Tracing;

/// <summary>
/// ETW/EventPipe event source for certificate parsing telemetry.
/// </summary>
/// <remarks>
/// <para>
/// Emits events when certificate extraction from COSE headers encounters errors.
/// These events are zero-cost when no listener is attached (ETW pattern) — the
/// <see cref="EventSource.IsEnabled()"/> check short-circuits before any allocation.
/// </para>
/// <para>
/// Green/blue teams can subscribe via:
/// <list type="bullet">
///   <item><c>dotnet-trace collect --providers CoseSign1-Certificates</c></item>
///   <item><c>PerfView /providers=CoseSign1-Certificates</c></item>
///   <item>Application Insights / OpenTelemetry EventSource listener</item>
/// </list>
/// </para>
/// </remarks>
internal static class ClassStrings
{
    public const string EventSourceName = "CoseSign1-Certificates";
    public const string EventCertHeaderParseFailed = "Certificate header '{0}' CBOR parse failed: [{1}] {2}";
    public const string EventCertDerDecodeFailed = "Certificate DER decode failed in '{0}': [{1}] {2}";
    public const string EventThumbprintMatchFailed = "Thumbprint match failed (algo {0}): [{1}] {2}";
    public const string EventCertChainExtracted = "Extracted {1} certificate(s) from '{0}' header";
}

[EventSource(Name = ClassStrings.EventSourceName)]
internal sealed class CoseSign1CertificateEventSource : EventSource
{
    /// <summary>Singleton instance.</summary>
    public static readonly CoseSign1CertificateEventSource Log = new();

    /// <summary>
    /// Raised when CBOR parsing of x5chain/x5bag header fails.
    /// </summary>
    /// <param name="headerLabel">The COSE header label being parsed (e.g., "x5chain", "x5bag").</param>
    /// <param name="exceptionType">The exception type name (e.g., "CborContentException").</param>
    /// <param name="message">The exception message.</param>
    [Event(1, Level = EventLevel.Warning, Message = ClassStrings.EventCertHeaderParseFailed)]
    public void CertificateHeaderParseFailed(string headerLabel, string exceptionType, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(1, headerLabel, exceptionType, message);
        }
    }

    /// <summary>
    /// Raised when a certificate's DER encoding is invalid.
    /// </summary>
    /// <param name="headerLabel">The COSE header label being parsed.</param>
    /// <param name="exceptionType">The exception type name.</param>
    /// <param name="message">The exception message.</param>
    [Event(2, Level = EventLevel.Warning, Message = ClassStrings.EventCertDerDecodeFailed)]
    public void CertificateDerDecodeFailed(string headerLabel, string exceptionType, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(2, headerLabel, exceptionType, message);
        }
    }

    /// <summary>
    /// Raised when x5t thumbprint matching encounters an error.
    /// </summary>
    /// <param name="hashAlgorithmId">The COSE hash algorithm identifier.</param>
    /// <param name="exceptionType">The exception type name.</param>
    /// <param name="message">The exception message.</param>
    [Event(3, Level = EventLevel.Warning, Message = ClassStrings.EventThumbprintMatchFailed)]
    public void ThumbprintMatchFailed(int hashAlgorithmId, string exceptionType, string message)
    {
        if (IsEnabled())
        {
            WriteEvent(3, hashAlgorithmId, exceptionType, message);
        }
    }

    /// <summary>
    /// Raised when certificate chain extraction succeeds.
    /// </summary>
    /// <param name="headerLabel">The COSE header label parsed.</param>
    /// <param name="certificateCount">Number of certificates extracted.</param>
    [Event(4, Level = EventLevel.Informational, Message = ClassStrings.EventCertChainExtracted)]
    public void CertificateChainExtracted(string headerLabel, int certificateCount)
    {
        if (IsEnabled())
        {
            WriteEvent(4, headerLabel, certificateCount);
        }
    }
}

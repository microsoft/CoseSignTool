// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;

namespace CoseSign1.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSign1 library.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSign1:
/// - 1000-1099: Signing operations (direct and indirect)
/// 
/// For validation operations, see <see cref="CoseSign1.Validation.Logging.LogEvents"/>.
/// </remarks>
public static class LogEvents
{
    // Signing Operations (1000-1099)
    /// <summary>Starting a signing operation.</summary>
    public const int SigningStarted = 1000;
    /// <summary>Signing operation completed successfully.</summary>
    public const int SigningCompleted = 1001;
    /// <summary>Signing operation failed.</summary>
    public const int SigningFailed = 1002;
    /// <summary>Payload information during signing.</summary>
    public const int SigningPayloadInfo = 1010;
    /// <summary>Header contribution during signing.</summary>
    public const int SigningHeaderContribution = 1020;
    /// <summary>Signing key acquisition.</summary>
    public const int SigningKeyAcquired = 1030;
    /// <summary>Signing key acquisition failed.</summary>
    public const int SigningKeyAcquisitionFailed = 1031;

    // Static EventId instances to avoid allocations on each log call
    /// <summary>EventId for signing started.</summary>
    public static readonly EventId SigningStartedEvent = new(SigningStarted, nameof(SigningStarted));
    /// <summary>EventId for signing completed.</summary>
    public static readonly EventId SigningCompletedEvent = new(SigningCompleted, nameof(SigningCompleted));
    /// <summary>EventId for signing failed.</summary>
    public static readonly EventId SigningFailedEvent = new(SigningFailed, nameof(SigningFailed));
    /// <summary>EventId for payload info.</summary>
    public static readonly EventId SigningPayloadInfoEvent = new(SigningPayloadInfo, nameof(SigningPayloadInfo));
    /// <summary>EventId for header contribution.</summary>
    public static readonly EventId SigningHeaderContributionEvent = new(SigningHeaderContribution, nameof(SigningHeaderContribution));
    /// <summary>EventId for signing key acquired.</summary>
    public static readonly EventId SigningKeyAcquiredEvent = new(SigningKeyAcquired, nameof(SigningKeyAcquired));
    /// <summary>EventId for signing key acquisition failed.</summary>
    public static readonly EventId SigningKeyAcquisitionFailedEvent = new(SigningKeyAcquisitionFailed, nameof(SigningKeyAcquisitionFailed));
}
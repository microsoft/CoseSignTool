// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
}
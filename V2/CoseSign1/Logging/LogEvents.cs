// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSign1 library.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSign1:
/// - 1000-1099: Signing operations (direct and indirect)
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

    // Validation Operations (2000-2099)
    /// <summary>Starting a validation operation.</summary>
    public const int ValidationStarted = 2000;
    /// <summary>Validation operation completed.</summary>
    public const int ValidationCompleted = 2001;
    /// <summary>Validation operation failed.</summary>
    public const int ValidationFailed = 2002;
    /// <summary>Signature verification result.</summary>
    public const int SignatureVerified = 2030;
    /// <summary>Signature verification failed.</summary>
    public const int SignatureVerificationFailed = 2031;
}
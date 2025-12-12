// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSign1.Certificates library.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSign1.Certificates:
/// - 1020-1039: Signing-related header contributions
/// - 1030-1039: Signing key operations
/// - 3000-3099: Certificate operations
/// </remarks>
public static class LogEvents
{
    // Signing Operations (certificate-specific)
    /// <summary>Header contribution during signing.</summary>
    public const int SigningHeaderContribution = 1020;
    /// <summary>Signing key acquisition.</summary>
    public const int SigningKeyAcquired = 1030;
    /// <summary>Signing key acquisition failed.</summary>
    public const int SigningKeyAcquisitionFailed = 1031;

    // Certificate Operations (3000-3099)
    /// <summary>Certificate loaded.</summary>
    public const int CertificateLoaded = 3000;
    /// <summary>Certificate load failed.</summary>
    public const int CertificateLoadFailed = 3001;
    /// <summary>Certificate chain building started.</summary>
    public const int CertificateChainBuildStarted = 3010;
    /// <summary>Certificate chain built successfully.</summary>
    public const int CertificateChainBuilt = 3011;
    /// <summary>Certificate chain building failed.</summary>
    public const int CertificateChainBuildFailed = 3012;
    /// <summary>Certificate validation started.</summary>
    public const int CertificateValidationStarted = 3020;
    /// <summary>Certificate validation completed.</summary>
    public const int CertificateValidationCompleted = 3021;
    /// <summary>Certificate validation failed.</summary>
    public const int CertificateValidationFailed = 3022;
    /// <summary>Certificate store access.</summary>
    public const int CertificateStoreAccess = 3030;
    /// <summary>Certificate expiration warning.</summary>
    public const int CertificateExpirationWarning = 3040;
    /// <summary>Certificate expired.</summary>
    public const int CertificateExpired = 3041;
}
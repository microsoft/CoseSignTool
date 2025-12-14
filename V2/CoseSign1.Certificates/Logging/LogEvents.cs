// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;

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
    /// <summary>Certificate store access.</summary>
    public const int CertificateStoreAccess = 3030;

    // Static EventId instances to avoid allocations on each log call
    /// <summary>EventId for header contribution.</summary>
    public static readonly EventId SigningHeaderContributionEvent = new(SigningHeaderContribution, nameof(SigningHeaderContribution));
    /// <summary>EventId for signing key acquired.</summary>
    public static readonly EventId SigningKeyAcquiredEvent = new(SigningKeyAcquired, nameof(SigningKeyAcquired));
    /// <summary>EventId for signing key acquisition failed.</summary>
    public static readonly EventId SigningKeyAcquisitionFailedEvent = new(SigningKeyAcquisitionFailed, nameof(SigningKeyAcquisitionFailed));
    /// <summary>EventId for certificate loaded.</summary>
    public static readonly EventId CertificateLoadedEvent = new(CertificateLoaded, nameof(CertificateLoaded));
    /// <summary>EventId for certificate load failed.</summary>
    public static readonly EventId CertificateLoadFailedEvent = new(CertificateLoadFailed, nameof(CertificateLoadFailed));
    /// <summary>EventId for certificate chain build started.</summary>
    public static readonly EventId CertificateChainBuildStartedEvent = new(CertificateChainBuildStarted, nameof(CertificateChainBuildStarted));
    /// <summary>EventId for certificate chain built.</summary>
    public static readonly EventId CertificateChainBuiltEvent = new(CertificateChainBuilt, nameof(CertificateChainBuilt));
    /// <summary>EventId for certificate chain build failed.</summary>
    public static readonly EventId CertificateChainBuildFailedEvent = new(CertificateChainBuildFailed, nameof(CertificateChainBuildFailed));
    /// <summary>EventId for certificate store access.</summary>
    public static readonly EventId CertificateStoreAccessEvent = new(CertificateStoreAccess, nameof(CertificateStoreAccess));
}
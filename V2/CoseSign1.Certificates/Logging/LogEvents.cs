// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSign1.Certificates library.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSign1.Certificates:
/// - 1020-1039: Signing-related header contributions and key operations
/// - 3000-3049: Certificate loading and chain building
/// - 3050-3099: Certificate validation operations
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

    // Certificate Operations (3000-3049)
    /// <summary>Certificate loaded.</summary>
    public const int CertificateLoaded = 3000;
    /// <summary>Certificate load failed.</summary>
    public const int CertificateLoadFailed = 3001;
    /// <summary>Certificate extracted from message.</summary>
    public const int CertificateExtracted = 3002;
    /// <summary>Certificate extraction failed.</summary>
    public const int CertificateExtractionFailed = 3003;
    /// <summary>Certificate chain building started.</summary>
    public const int CertificateChainBuildStarted = 3010;
    /// <summary>Certificate chain built successfully.</summary>
    public const int CertificateChainBuilt = 3011;
    /// <summary>Certificate chain building failed.</summary>
    public const int CertificateChainBuildFailed = 3012;
    /// <summary>Certificate chain retry.</summary>
    public const int CertificateChainRetry = 3013;
    /// <summary>Certificate store access.</summary>
    public const int CertificateStoreAccess = 3030;

    // Certificate Validation Operations (3050-3099)
    /// <summary>Certificate chain validation started.</summary>
    public const int ChainValidationStarted = 3050;
    /// <summary>Certificate chain validation succeeded.</summary>
    public const int ChainValidationSucceeded = 3051;
    /// <summary>Certificate chain validation failed.</summary>
    public const int ChainValidationFailed = 3052;
    /// <summary>Certificate signature verification started.</summary>
    public const int SignatureValidationStarted = 3060;
    /// <summary>Certificate signature verification succeeded.</summary>
    public const int SignatureValidationSucceeded = 3061;
    /// <summary>Certificate signature verification failed.</summary>
    public const int SignatureValidationFailed = 3062;
    /// <summary>Certificate property validation (CN, expiry, key usage, etc.).</summary>
    public const int CertificatePropertyValidation = 3070;
    /// <summary>Custom roots configured.</summary>
    public const int CustomRootsConfigured = 3080;
    /// <summary>Allow untrusted mode enabled.</summary>
    public const int AllowUntrustedEnabled = 3081;

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
    /// <summary>EventId for certificate extracted.</summary>
    public static readonly EventId CertificateExtractedEvent = new(CertificateExtracted, nameof(CertificateExtracted));
    /// <summary>EventId for certificate extraction failed.</summary>
    public static readonly EventId CertificateExtractionFailedEvent = new(CertificateExtractionFailed, nameof(CertificateExtractionFailed));
    /// <summary>EventId for certificate chain build started.</summary>
    public static readonly EventId CertificateChainBuildStartedEvent = new(CertificateChainBuildStarted, nameof(CertificateChainBuildStarted));
    /// <summary>EventId for certificate chain built.</summary>
    public static readonly EventId CertificateChainBuiltEvent = new(CertificateChainBuilt, nameof(CertificateChainBuilt));
    /// <summary>EventId for certificate chain build failed.</summary>
    public static readonly EventId CertificateChainBuildFailedEvent = new(CertificateChainBuildFailed, nameof(CertificateChainBuildFailed));
    /// <summary>EventId for certificate chain retry.</summary>
    public static readonly EventId CertificateChainRetryEvent = new(CertificateChainRetry, nameof(CertificateChainRetry));
    /// <summary>EventId for certificate store access.</summary>
    public static readonly EventId CertificateStoreAccessEvent = new(CertificateStoreAccess, nameof(CertificateStoreAccess));
    /// <summary>EventId for chain validation started.</summary>
    public static readonly EventId ChainValidationStartedEvent = new(ChainValidationStarted, nameof(ChainValidationStarted));
    /// <summary>EventId for chain validation succeeded.</summary>
    public static readonly EventId ChainValidationSucceededEvent = new(ChainValidationSucceeded, nameof(ChainValidationSucceeded));
    /// <summary>EventId for chain validation failed.</summary>
    public static readonly EventId ChainValidationFailedEvent = new(ChainValidationFailed, nameof(ChainValidationFailed));
    /// <summary>EventId for signature validation started.</summary>
    public static readonly EventId SignatureValidationStartedEvent = new(SignatureValidationStarted, nameof(SignatureValidationStarted));
    /// <summary>EventId for signature validation succeeded.</summary>
    public static readonly EventId SignatureValidationSucceededEvent = new(SignatureValidationSucceeded, nameof(SignatureValidationSucceeded));
    /// <summary>EventId for signature validation failed.</summary>
    public static readonly EventId SignatureValidationFailedEvent = new(SignatureValidationFailed, nameof(SignatureValidationFailed));
    /// <summary>EventId for certificate property validation.</summary>
    public static readonly EventId CertificatePropertyValidationEvent = new(CertificatePropertyValidation, nameof(CertificatePropertyValidation));
    /// <summary>EventId for custom roots configured.</summary>
    public static readonly EventId CustomRootsConfiguredEvent = new(CustomRootsConfigured, nameof(CustomRootsConfigured));
    /// <summary>EventId for allow untrusted enabled.</summary>
    public static readonly EventId AllowUntrustedEnabledEvent = new(AllowUntrustedEnabled, nameof(AllowUntrustedEnabled));
}
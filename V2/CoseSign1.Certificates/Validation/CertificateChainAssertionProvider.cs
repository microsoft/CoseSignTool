// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Validates the certificate chain trust using the provided chain builder.
/// </summary>
public sealed partial class CertificateChainAssertionProvider : CertificateValidationComponentBase, ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateChainAssertionProvider);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeCertNotFound = "CERTIFICATE_NOT_FOUND";
        public static readonly string ErrorCodeChainBuildFailed = "CHAIN_BUILD_FAILED";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageCertNotFound = "Could not extract signing certificate from message";
        public static readonly string ErrorMessageChainBuildFailed = "Certificate chain validation failed";

        // Metadata keys
        public static readonly string MetaKeyCertThumbprint = "CertificateThumbprint";
        public static readonly string MetaKeyRetryAttempts = "RetryAttempts";
        public static readonly string MetaKeyAllowedUntrusted = "AllowedUntrusted";
        public static readonly string MetaKeyTrustedCustomRoot = "TrustedCustomRoot";

        public static readonly string TrustDetailsAllowedUntrusted = "AllowedUntrusted";

        // Separators
        public static readonly string SeparatorSemicolon = "; ";
    }

    #region LoggerMessage methods

    [LoggerMessage(
        EventId = 3001,
        Level = LogLevel.Debug,
        Message = "Starting certificate chain validation for thumbprint {Thumbprint}")]
    private partial void LogChainValidationStarted(string thumbprint);

    [LoggerMessage(
        EventId = 3002,
        Level = LogLevel.Information,
        Message = "Certificate chain validation succeeded for thumbprint {Thumbprint} in {ElapsedMs}ms")]
    private partial void LogChainValidationSucceeded(string thumbprint, long elapsedMs);

    [LoggerMessage(
        EventId = 3003,
        Level = LogLevel.Warning,
        Message = "Certificate chain validation failed for thumbprint {Thumbprint}: {ErrorCount} errors")]
    private partial void LogChainValidationFailed(string thumbprint, int errorCount);

    [LoggerMessage(
        EventId = 3004,
        Level = LogLevel.Debug,
        Message = "Retrying chain build due to revocation status unknown (attempt {Attempt}/3)")]
    private partial void LogChainRetrying(int attempt);

    [LoggerMessage(
        EventId = 3005,
        Level = LogLevel.Information,
        Message = "Chain build succeeded on retry attempt {Attempt}")]
    private partial void LogChainRetrySucceeded(int attempt);

    [LoggerMessage(
        EventId = 3006,
        Level = LogLevel.Information,
        Message = "AllowUntrusted mode enabled - accepting untrusted root for thumbprint {Thumbprint}")]
    private partial void LogAllowUntrustedEnabled(string thumbprint);

    [LoggerMessage(
        EventId = 3007,
        Level = LogLevel.Information,
        Message = "Custom root certificate trusted: {RootThumbprint}")]
    private partial void LogCustomRootTrusted(string rootThumbprint);

    [LoggerMessage(
        EventId = 3008,
        Level = LogLevel.Debug,
        Message = "Configured {Count} custom root certificates")]
    private partial void LogCustomRootsConfigured(int count);

    [LoggerMessage(
        EventId = 3009,
        Level = LogLevel.Warning,
        Message = "Validation failed: input message is null")]
    private partial void LogNullInput();

    [LoggerMessage(
        EventId = 3010,
        Level = LogLevel.Warning,
        Message = "Validation failed: could not extract signing certificate from message")]
    private partial void LogCertNotFound();

    #endregion

    private readonly ICertificateChainBuilder ChainBuilder;
    private readonly bool AllowUntrusted;
    private readonly X509Certificate2Collection? CustomRoots;
    private readonly bool TrustUserRoots;
    private readonly ILogger<CertificateChainAssertionProvider> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainAssertionProvider"/> class.
    /// Uses system roots for trust validation.
    /// </summary>
    /// <param name="allowUntrusted">Whether to allow untrusted roots to pass validation.</param>
    /// <param name="revocationMode">The revocation check mode.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateChainAssertionProvider(
        bool allowUntrusted = false,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        ILogger<CertificateChainAssertionProvider>? logger = null)
    {
        ChainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = revocationMode
            }
        };
        AllowUntrusted = allowUntrusted;
        CustomRoots = null;
        TrustUserRoots = true;
        Logger = logger ?? NullLogger<CertificateChainAssertionProvider>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainAssertionProvider"/> class.
    /// Uses custom roots for trust validation.
    /// </summary>
    /// <param name="customRoots">Custom root certificates to trust.</param>
    /// <param name="trustUserRoots">Whether to trust the custom roots.</param>
    /// <param name="revocationMode">The revocation check mode.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="customRoots"/> is null.</exception>
    public CertificateChainAssertionProvider(
        X509Certificate2Collection customRoots,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        ILogger<CertificateChainAssertionProvider>? logger = null)
    {
        ChainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = revocationMode
            }
        };
        AllowUntrusted = false;
        CustomRoots = customRoots ?? throw new ArgumentNullException(nameof(customRoots));
        TrustUserRoots = trustUserRoots;
        Logger = logger ?? NullLogger<CertificateChainAssertionProvider>.Instance;

        LogCustomRootsConfigured(customRoots.Count);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainAssertionProvider"/> class.
    /// Uses a custom chain builder.
    /// </summary>
    /// <param name="chainBuilder">The chain builder to use for validation.</param>
    /// <param name="allowUntrusted">Whether to allow untrusted roots to pass validation.</param>
    /// <param name="customRoots">Optional custom root certificates.</param>
    /// <param name="trustUserRoots">Whether to trust the custom roots.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="chainBuilder"/> is null.</exception>
    public CertificateChainAssertionProvider(
        ICertificateChainBuilder chainBuilder,
        bool allowUntrusted = false,
        X509Certificate2Collection? customRoots = null,
        bool trustUserRoots = true,
        ILogger<CertificateChainAssertionProvider>? logger = null)
    {
        ChainBuilder = chainBuilder ?? throw new ArgumentNullException(nameof(chainBuilder));
        AllowUntrusted = allowUntrusted;
        CustomRoots = customRoots;
        TrustUserRoots = trustUserRoots;
        Logger = logger ?? NullLogger<CertificateChainAssertionProvider>.Instance;
    }

    /// <inheritdoc/>
    public override string ComponentName => ClassStrings.ValidatorName;

    /// <inheritdoc/>
    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null)
    {
        CoseHeaderLocation headerLocation = options?.CertificateHeaderLocation ?? CoseHeaderLocation.Protected;

        if (signingKey is not X509CertificateSigningKey certKey)
        {
            LogNullInput();
            return Array.Empty<ISigningKeyAssertion>();
        }

        var signingCert = certKey.Certificate;
        if (signingCert == null)
        {
            LogCertNotFound();
            return Array.Empty<ISigningKeyAssertion>();
        }

        var stopwatch = Stopwatch.StartNew();
        LogChainValidationStarted(signingCert.Thumbprint);

        // Get the certificate chain from the message
        message.TryGetCertificateChain(out var messageChain, headerLocation);
        message.TryGetExtraCertificates(out var extraCerts, headerLocation);

        // Configure custom roots if provided
        if (CustomRoots != null && CustomRoots.Count > 0)
        {
            ChainBuilder.ChainPolicy.ExtraStore.Clear();

#if NET5_0_OR_GREATER
            if (TrustUserRoots)
            {
                ChainBuilder.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                ChainBuilder.ChainPolicy.CustomTrustStore.Clear();
                ChainBuilder.ChainPolicy.CustomTrustStore.AddRange(CustomRoots);
            }
            else
            {
                ChainBuilder.ChainPolicy.TrustMode = X509ChainTrustMode.System;
            }
#endif
        }

        // Add message chain and extra certificates to the extra store
        if (messageChain != null && messageChain.Count > 0)
        {
            ChainBuilder.ChainPolicy.ExtraStore.AddRange(messageChain);
        }

        if (extraCerts != null && extraCerts.Count > 0)
        {
            ChainBuilder.ChainPolicy.ExtraStore.AddRange(extraCerts);
        }

        // Build the chain
        bool chainBuildSuccess = ChainBuilder.Build(signingCert);

        if (chainBuildSuccess)
        {
            stopwatch.Stop();
            LogChainValidationSucceeded(signingCert.Thumbprint, stopwatch.ElapsedMilliseconds);
            return new ISigningKeyAssertion[]
            {
                new X509ChainTrustedAssertion(true) { SigningKey = signingKey }
            };
        }

        // Retry if revocation check failed (server might be temporarily down)
        if (ChainBuilder.ChainPolicy.RevocationMode != X509RevocationMode.NoCheck)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (ChainBuilder.ChainStatus.Any(s => (s.Status & X509ChainStatusFlags.RevocationStatusUnknown) != 0))
                {
                    LogChainRetrying(attempt + 1);
                    Thread.Sleep(1000);
                    if (ChainBuilder.Build(signingCert))
                    {
                        stopwatch.Stop();
                        LogChainRetrySucceeded(attempt + 1);
                        return new ISigningKeyAssertion[]
                        {
                            new X509ChainTrustedAssertion(true) { SigningKey = signingKey }
                        };
                    }
                }
                else
                {
                    break;
                }
            }
        }

        // Check if we should allow untrusted roots
        if (AllowUntrusted && ChainBuilder.ChainStatus.All(s => s.Status == X509ChainStatusFlags.UntrustedRoot || s.Status == X509ChainStatusFlags.NoError))
        {
            stopwatch.Stop();
            LogAllowUntrustedEnabled(signingCert.Thumbprint);
            // Explicitly NOT trusted; allowed by policy.
            return new ISigningKeyAssertion[]
            {
                new X509ChainTrustedAssertion(false, ClassStrings.TrustDetailsAllowedUntrusted) { SigningKey = signingKey }
            };
        }

        // Check if custom root is trusted
        if (CustomRoots != null && TrustUserRoots)
        {
            var chainRoot = ChainBuilder.ChainElements?.FirstOrDefault(e => e.Subject.Equals(e.Issuer));
            if (chainRoot != null && CustomRoots.Cast<X509Certificate2>().Any(r => r.Thumbprint == chainRoot.Thumbprint))
            {
                // User-supplied root found in chain
                if (ChainBuilder.ChainStatus.All(s => s.Status == X509ChainStatusFlags.UntrustedRoot || s.Status == X509ChainStatusFlags.NoError))
                {
                    stopwatch.Stop();
                    LogCustomRootTrusted(chainRoot.Thumbprint);
                    return new ISigningKeyAssertion[]
                    {
                        new X509ChainTrustedAssertion(true) { SigningKey = signingKey }
                    };
                }
            }
        }

        // Chain validation failed - return assertion indicating failure
        stopwatch.Stop();
        var failureDetails = string.Join(ClassStrings.SeparatorSemicolon, ChainBuilder.ChainStatus
            .Where(s => s.Status != X509ChainStatusFlags.NoError)
            .Select(s => s.StatusInformation.Trim()));

        if (string.IsNullOrEmpty(failureDetails))
        {
            failureDetails = ClassStrings.ErrorMessageChainBuildFailed;
        }

        LogChainValidationFailed(signingCert.Thumbprint, ChainBuilder.ChainStatus.Length);
        return new ISigningKeyAssertion[]
        {
            new X509ChainTrustedAssertion(false, failureDetails) { SigningKey = signingKey }
        };
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(ExtractAssertions(signingKey, message, options));
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates the certificate chain trust using the provided chain builder.
/// </summary>
public sealed class CertificateChainValidator : IValidator<CoseSign1Message>
{
    private readonly ICertificateChainBuilder ChainBuilder;
    private readonly bool AllowUnprotectedHeaders;
    private readonly bool AllowUntrusted;
    private readonly X509Certificate2Collection? CustomRoots;
    private readonly bool TrustUserRoots;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainValidator"/> class.
    /// Uses system roots for trust validation.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="allowUntrusted">Whether to allow untrusted roots to pass validation.</param>
    /// <param name="revocationMode">The revocation check mode.</param>
    public CertificateChainValidator(
        bool allowUnprotectedHeaders = false,
        bool allowUntrusted = false,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        ChainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = revocationMode
            }
        };
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        AllowUntrusted = allowUntrusted;
        CustomRoots = null;
        TrustUserRoots = true;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainValidator"/> class.
    /// Uses custom roots for trust validation.
    /// </summary>
    /// <param name="customRoots">Custom root certificates to trust.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="trustUserRoots">Whether to trust the custom roots.</param>
    /// <param name="revocationMode">The revocation check mode.</param>
    public CertificateChainValidator(
        X509Certificate2Collection customRoots,
        bool allowUnprotectedHeaders = false,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        ChainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = revocationMode
            }
        };
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        AllowUntrusted = false;
        CustomRoots = customRoots ?? throw new ArgumentNullException(nameof(customRoots));
        TrustUserRoots = trustUserRoots;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainValidator"/> class.
    /// Uses a custom chain builder.
    /// </summary>
    /// <param name="chainBuilder">The chain builder to use for validation.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="allowUntrusted">Whether to allow untrusted roots to pass validation.</param>
    /// <param name="customRoots">Optional custom root certificates.</param>
    /// <param name="trustUserRoots">Whether to trust the custom roots.</param>
    public CertificateChainValidator(
        ICertificateChainBuilder chainBuilder,
        bool allowUnprotectedHeaders = false,
        bool allowUntrusted = false,
        X509Certificate2Collection? customRoots = null,
        bool trustUserRoots = true)
    {
        ChainBuilder = chainBuilder ?? throw new ArgumentNullException(nameof(chainBuilder));
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        AllowUntrusted = allowUntrusted;
        CustomRoots = customRoots;
        TrustUserRoots = trustUserRoots;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateChainValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (!input.TryGetSigningCertificate(out var signingCert, AllowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                nameof(CertificateChainValidator),
                "Could not extract signing certificate from message",
                "CERTIFICATE_NOT_FOUND");
        }

        // Get the certificate chain from the message
        input.TryGetCertificateChain(out var messageChain, AllowUnprotectedHeaders);
        input.TryGetExtraCertificates(out var extraCerts, AllowUnprotectedHeaders);

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
            return ValidationResult.Success(nameof(CertificateChainValidator), new Dictionary<string, object>
            {
                ["CertificateThumbprint"] = signingCert.Thumbprint
            });
        }

        // Retry if revocation check failed (server might be temporarily down)
        if (ChainBuilder.ChainPolicy.RevocationMode != X509RevocationMode.NoCheck)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (ChainBuilder.ChainStatus.Any(s => (s.Status & X509ChainStatusFlags.RevocationStatusUnknown) != 0))
                {
                    Thread.Sleep(1000);
                    if (ChainBuilder.Build(signingCert))
                    {
                        return ValidationResult.Success(nameof(CertificateChainValidator), new Dictionary<string, object>
                        {
                            ["CertificateThumbprint"] = signingCert.Thumbprint,
                            ["RetryAttempts"] = attempt + 1
                        });
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
            return ValidationResult.Success(nameof(CertificateChainValidator), new Dictionary<string, object>
            {
                ["CertificateThumbprint"] = signingCert.Thumbprint,
                ["AllowedUntrusted"] = true
            });
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
                    return ValidationResult.Success(nameof(CertificateChainValidator), new Dictionary<string, object>
                    {
                        ["CertificateThumbprint"] = signingCert.Thumbprint,
                        ["TrustedCustomRoot"] = chainRoot.Thumbprint
                    });
                }
            }
        }

        // Build failure messages
        var failures = ChainBuilder.ChainStatus
            .Where(s => s.Status != X509ChainStatusFlags.NoError)
            .Select(s => new ValidationFailure
            {
                Message = s.StatusInformation,
                ErrorCode = s.Status.ToString()
            })
            .ToArray();

        if (failures.Length == 0)
        {
            failures = new[]
            {
                new ValidationFailure
                {
                    Message = "Certificate chain validation failed",
                    ErrorCode = "CHAIN_BUILD_FAILED"
                }
            };
        }

        return ValidationResult.Failure(nameof(CertificateChainValidator), failures);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}
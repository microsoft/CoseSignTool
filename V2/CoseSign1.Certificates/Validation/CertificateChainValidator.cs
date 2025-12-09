// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Validation;
using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates the certificate chain trust using the provided chain builder.
/// </summary>
public sealed class CertificateChainValidator : IValidator<CoseSign1Message>
{
    private readonly ICertificateChainBuilder _chainBuilder;
    private readonly bool _allowUnprotectedHeaders;
    private readonly bool _allowUntrusted;
    private readonly X509Certificate2Collection? _customRoots;
    private readonly bool _trustUserRoots;

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
        _chainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = revocationMode
            }
        };
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
        _allowUntrusted = allowUntrusted;
        _customRoots = null;
        _trustUserRoots = true;
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
        _chainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = revocationMode
            }
        };
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
        _allowUntrusted = false;
        _customRoots = customRoots ?? throw new ArgumentNullException(nameof(customRoots));
        _trustUserRoots = trustUserRoots;
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
        _chainBuilder = chainBuilder ?? throw new ArgumentNullException(nameof(chainBuilder));
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
        _allowUntrusted = allowUntrusted;
        _customRoots = customRoots;
        _trustUserRoots = trustUserRoots;
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

        if (!input.TryGetSigningCertificate(out var signingCert, _allowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                nameof(CertificateChainValidator),
                "Could not extract signing certificate from message",
                "CERTIFICATE_NOT_FOUND");
        }

        // Get the certificate chain from the message
        input.TryGetCertificateChain(out var messageChain, _allowUnprotectedHeaders);
        input.TryGetExtraCertificates(out var extraCerts, _allowUnprotectedHeaders);

        // Configure custom roots if provided
        if (_customRoots != null && _customRoots.Count > 0)
        {
            _chainBuilder.ChainPolicy.ExtraStore.Clear();

#if NET5_0_OR_GREATER
            if (_trustUserRoots)
            {
                _chainBuilder.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                _chainBuilder.ChainPolicy.CustomTrustStore.Clear();
                _chainBuilder.ChainPolicy.CustomTrustStore.AddRange(_customRoots);
            }
            else
            {
                _chainBuilder.ChainPolicy.TrustMode = X509ChainTrustMode.System;
            }
#endif
        }

        // Add message chain and extra certificates to the extra store
        if (messageChain != null && messageChain.Count > 0)
        {
            _chainBuilder.ChainPolicy.ExtraStore.AddRange(messageChain);
        }

        if (extraCerts != null && extraCerts.Count > 0)
        {
            _chainBuilder.ChainPolicy.ExtraStore.AddRange(extraCerts);
        }

        // Build the chain
        bool chainBuildSuccess = _chainBuilder.Build(signingCert);

        if (chainBuildSuccess)
        {
            return ValidationResult.Success(nameof(CertificateChainValidator), new Dictionary<string, object>
            {
                ["CertificateThumbprint"] = signingCert.Thumbprint
            });
        }

        // Retry if revocation check failed (server might be temporarily down)
        if (_chainBuilder.ChainPolicy.RevocationMode != X509RevocationMode.NoCheck)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (_chainBuilder.ChainStatus.Any(s => (s.Status & X509ChainStatusFlags.RevocationStatusUnknown) != 0))
                {
                    Thread.Sleep(1000);
                    if (_chainBuilder.Build(signingCert))
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
        if (_allowUntrusted && _chainBuilder.ChainStatus.All(s => s.Status == X509ChainStatusFlags.UntrustedRoot || s.Status == X509ChainStatusFlags.NoError))
        {
            return ValidationResult.Success(nameof(CertificateChainValidator), new Dictionary<string, object>
            {
                ["CertificateThumbprint"] = signingCert.Thumbprint,
                ["AllowedUntrusted"] = true
            });
        }

        // Check if custom root is trusted
        if (_customRoots != null && _trustUserRoots)
        {
            var chainRoot = _chainBuilder.ChainElements?.FirstOrDefault(e => e.Subject.Equals(e.Issuer));
            if (chainRoot != null && _customRoots.Cast<X509Certificate2>().Any(r => r.Thumbprint == chainRoot.Thumbprint))
            {
                // User-supplied root found in chain
                if (_chainBuilder.ChainStatus.All(s => s.Status == X509ChainStatusFlags.UntrustedRoot || s.Status == X509ChainStatusFlags.NoError))
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
        var failures = _chainBuilder.ChainStatus
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

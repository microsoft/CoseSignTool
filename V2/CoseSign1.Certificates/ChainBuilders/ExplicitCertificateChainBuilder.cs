// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Logging;
using CoseSign1.Certificates.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Certificates.ChainBuilders;

/// <summary>
/// A certificate chain builder that uses an explicitly provided chain with cryptographic validation of chain order.
/// Uses X509ChainBuilder internally to handle ordering and signature verification.
/// </summary>
public sealed class ExplicitCertificateChainBuilder : ICertificateChainBuilder, IDisposable
{
    private readonly X509ChainBuilder _chainBuilder;
    private readonly IReadOnlyList<X509Certificate2> _providedCertificates;
    private readonly ILogger<ExplicitCertificateChainBuilder> _logger;
    private bool _disposed;

    /// <summary>
    /// Gets the default chain policy used by this class unless overridden.
    /// Disables all validation except signature verification.
    /// </summary>
    public static X509ChainPolicy DefaultChainPolicy => new()
    {
        RevocationMode = X509RevocationMode.NoCheck,
        VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority |
                           X509VerificationFlags.IgnoreNotTimeValid |
                           X509VerificationFlags.IgnoreNotTimeNested |
                           X509VerificationFlags.IgnoreInvalidBasicConstraints |
                           X509VerificationFlags.IgnoreWrongUsage |
                           X509VerificationFlags.IgnoreInvalidName |
                           X509VerificationFlags.IgnoreInvalidPolicy |
                           X509VerificationFlags.IgnoreEndRevocationUnknown |
                           X509VerificationFlags.IgnoreCtlSignerRevocationUnknown |
                           X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                           X509VerificationFlags.IgnoreRootRevocationUnknown
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="ExplicitCertificateChainBuilder"/> class.
    /// </summary>
    /// <param name="certificateChain">The explicitly provided certificate chain to use.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateChain"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="certificateChain"/> is empty.</exception>
    public ExplicitCertificateChainBuilder(IReadOnlyList<X509Certificate2> certificateChain, ILogger<ExplicitCertificateChainBuilder>? logger = null)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(certificateChain);
#else
        if (certificateChain == null) { throw new ArgumentNullException(nameof(certificateChain)); }
#endif
        if (certificateChain.Count == 0)
        {
            throw new ArgumentException("Certificate chain cannot be empty.", nameof(certificateChain));
        }

        _logger = logger ?? NullLogger<ExplicitCertificateChainBuilder>.Instance;
        _providedCertificates = certificateChain;

        // Use the default chain policy unless overridden via the ChainPolicy property
        var policy = DefaultChainPolicy;

        // Add all provided certificates to the extra store for chain building
        foreach (var cert in certificateChain)
        {
            policy.ExtraStore.Add(cert);
        }

        _chainBuilder = new X509ChainBuilder(policy);

        _logger.LogTrace(
            new EventId(LogEvents.CertificateChainBuildStarted, nameof(LogEvents.CertificateChainBuildStarted)),
            "ExplicitCertificateChainBuilder initialized. ProvidedCertificateCount: {Count}",
            certificateChain.Count);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ExplicitCertificateChainBuilder"/> class with a single certificate.
    /// </summary>
    /// <param name="certificate">The certificate to use for chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is null.</exception>
    public ExplicitCertificateChainBuilder(X509Certificate2 certificate, ILogger<ExplicitCertificateChainBuilder>? logger = null)
        : this(new[] { certificate ?? throw new ArgumentNullException(nameof(certificate)) }, logger)
    {
    }

    /// <summary>
    /// Checks if a certificate is self-signed (issuer equals subject).
    /// </summary>
    private static bool IsSelfSigned(X509Certificate2 certificate)
    {
        return certificate.Subject.Equals(certificate.Issuer, StringComparison.OrdinalIgnoreCase);
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<X509Certificate2> ChainElements => _chainBuilder.ChainElements;

    /// <inheritdoc/>
    public X509ChainPolicy ChainPolicy
    {
        get => _chainBuilder.ChainPolicy;
        set => _chainBuilder.ChainPolicy = value;
    }

    /// <inheritdoc/>
    public X509ChainStatus[] ChainStatus => _chainBuilder.ChainStatus;

    /// <inheritdoc/>
    /// <remarks>
    /// This method builds and validates the certificate chain by:
    /// 1. Verifying the target certificate is in the provided certificates (if any were provided)
    /// 2. Using X509ChainBuilder to build and order the chain with cryptographic signature verification
    /// 3. Validating that only certificates from the provided set are in the resulting chain (if certificates were explicitly provided)
    /// The provided certificates can be in any order; X509ChainBuilder will correctly order them.
    /// </remarks>
    public bool Build(X509Certificate2 certificate)
    {
#if NET5_0_OR_GREATER
        ObjectDisposedException.ThrowIf(_disposed, this);
#else
        if (_disposed) { throw new ObjectDisposedException(GetType().FullName); }
#endif

        _logger.LogTrace(
            new EventId(LogEvents.CertificateChainBuildStarted, nameof(LogEvents.CertificateChainBuildStarted)),
            "Building explicit certificate chain. Subject: {Subject}, Thumbprint: {Thumbprint}",
            certificate.Subject,
            certificate.Thumbprint);

        // Delegate to X509ChainBuilder which will:
        // - Find the correct chain order
        // - Verify signatures cryptographically
        // - Handle self-signed roots properly
        var buildResult = _chainBuilder.Build(certificate);

        // If we provided explicit certificates, verify that all chain elements are from our provided set
        // This ensures we don't inadvertently use system certificates when an explicit chain was given
        if (_providedCertificates.Count > 0)
        {
            foreach (var chainElement in _chainBuilder.ChainElements)
            {
                var isFromProvidedCerts = _providedCertificates.Any(c =>
                    c.Thumbprint.Equals(chainElement.Thumbprint, StringComparison.OrdinalIgnoreCase));

                if (!isFromProvidedCerts)
                {
                    _logger.LogTrace(
                        new EventId(LogEvents.CertificateChainBuildFailed, nameof(LogEvents.CertificateChainBuildFailed)),
                        "Chain element not from provided certificates. Subject: {Subject}, Thumbprint: {Thumbprint}",
                        chainElement.Subject,
                        chainElement.Thumbprint);
                    // Chain contains a certificate not in our provided list
                    return false;
                }
            }
        }

        if (buildResult)
        {
            _logger.LogTrace(
                new EventId(LogEvents.CertificateChainBuilt, nameof(LogEvents.CertificateChainBuilt)),
                "Explicit certificate chain built successfully. ChainLength: {ChainLength}",
                _chainBuilder.ChainElements.Count);
        }
        else
        {
            _logger.LogTrace(
                new EventId(LogEvents.CertificateChainBuildFailed, nameof(LogEvents.CertificateChainBuildFailed)),
                "Explicit certificate chain build failed. ChainLength: {ChainLength}",
                _chainBuilder.ChainElements.Count);
        }

        return buildResult;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!_disposed)
        {
            _chainBuilder.Dispose();
            _disposed = true;
        }
    }
}

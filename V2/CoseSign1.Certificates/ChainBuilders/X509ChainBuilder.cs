// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Logging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Certificates.ChainBuilders;

/// <summary>
/// A certificate chain builder that wraps the standard <see cref="X509Chain"/> for automatic chain building.
/// </summary>
public sealed class X509ChainBuilder : ICertificateChainBuilder, IDisposable
{
    private readonly X509Chain _chain;
    private readonly ILogger<X509ChainBuilder> _logger;
    private bool _disposed;

    /// <summary>
    /// Gets the default chain policy used by this class when no policy is provided.
    /// Uses standard X509 validation with online revocation checking enabled.
    /// Excludes root certificate revocation checking because root certificates are self-signed
    /// and lack a higher authority to issue revocation information.
    /// </summary>
    public static readonly X509ChainPolicy DefaultChainPolicy = new()
    {
        RevocationMode = X509RevocationMode.Online,
        RevocationFlag = X509RevocationFlag.ExcludeRoot, // Root certs are self-signed with no issuing CA to revoke them
        VerificationFlags = X509VerificationFlags.NoFlag,
        UrlRetrievalTimeout = TimeSpan.FromSeconds(30),
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ChainBuilder"/> class with the default chain policy.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public X509ChainBuilder(ILogger<X509ChainBuilder>? logger = null)
        : this(DefaultChainPolicy, logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ChainBuilder"/> class with a specific chain policy.
    /// </summary>
    /// <param name="chainPolicy">The chain policy to use for chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="chainPolicy"/> is null.</exception>
    public X509ChainBuilder(X509ChainPolicy chainPolicy, ILogger<X509ChainBuilder>? logger = null)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(chainPolicy);
#else
        if (chainPolicy == null) { throw new ArgumentNullException(nameof(chainPolicy)); }
#endif
        _logger = logger ?? NullLogger<X509ChainBuilder>.Instance;
        _chain = new X509Chain();

        // Create a new policy to avoid any shared state issues
        _chain.ChainPolicy.RevocationMode = chainPolicy.RevocationMode;
        _chain.ChainPolicy.RevocationFlag = chainPolicy.RevocationFlag;
        _chain.ChainPolicy.VerificationFlags = chainPolicy.VerificationFlags;
        _chain.ChainPolicy.UrlRetrievalTimeout = chainPolicy.UrlRetrievalTimeout;

        // Copy application policies if any
        if (chainPolicy.ApplicationPolicy.Count > 0)
        {
            foreach (var oid in chainPolicy.ApplicationPolicy)
            {
                _chain.ChainPolicy.ApplicationPolicy.Add(oid);
            }
        }

        // Copy certificate policies if any
        if (chainPolicy.CertificatePolicy.Count > 0)
        {
            foreach (var oid in chainPolicy.CertificatePolicy)
            {
                _chain.ChainPolicy.CertificatePolicy.Add(oid);
            }
        }

        // Copy extra store if any
        if (chainPolicy.ExtraStore.Count > 0)
        {
            _chain.ChainPolicy.ExtraStore.AddRange(chainPolicy.ExtraStore);
        }

#if NET5_0_OR_GREATER
        // Copy trust mode and custom trust store if applicable
        _chain.ChainPolicy.TrustMode = chainPolicy.TrustMode;
        if (chainPolicy.CustomTrustStore.Count > 0)
        {
            _chain.ChainPolicy.CustomTrustStore.AddRange(chainPolicy.CustomTrustStore);
        }
#endif

        _logger.LogTrace(
            new EventId(LogEvents.CertificateChainBuildStarted, nameof(LogEvents.CertificateChainBuildStarted)),
            "X509ChainBuilder initialized. RevocationMode: {RevocationMode}, RevocationFlag: {RevocationFlag}, VerificationFlags: {VerificationFlags}",
            chainPolicy.RevocationMode,
            chainPolicy.RevocationFlag,
            chainPolicy.VerificationFlags);
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<X509Certificate2> ChainElements
    {
        get
        {
#if NET5_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed) { throw new ObjectDisposedException(GetType().FullName); }
#endif
            var elements = new List<X509Certificate2>(_chain.ChainElements.Count);
            foreach (var element in _chain.ChainElements)
            {
                elements.Add(element.Certificate);
            }
            return elements;
        }
    }

    /// <inheritdoc/>
    public X509ChainPolicy ChainPolicy
    {
        get
        {
#if NET5_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed) { throw new ObjectDisposedException(GetType().FullName); }
#endif
            return _chain.ChainPolicy;
        }
        set
        {
#if NET5_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentNullException.ThrowIfNull(value);
#else
            if (_disposed) { throw new ObjectDisposedException(GetType().FullName); }
            if (value == null) { throw new ArgumentNullException(nameof(value)); }
#endif
            _chain.ChainPolicy = value;
        }
    }

    /// <inheritdoc/>
    public X509ChainStatus[] ChainStatus
    {
        get
        {
#if NET5_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed) { throw new ObjectDisposedException(GetType().FullName); }
#endif
            return _chain.ChainStatus;
        }
    }

    /// <inheritdoc/>
    public bool Build(X509Certificate2 certificate)
    {
#if NET5_0_OR_GREATER
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(certificate);
#else
        if (_disposed) { throw new ObjectDisposedException(GetType().FullName); }
        if (certificate == null) { throw new ArgumentNullException(nameof(certificate)); }
#endif

        _logger.LogTrace(
            new EventId(LogEvents.CertificateChainBuildStarted, nameof(LogEvents.CertificateChainBuildStarted)),
            "Building certificate chain. Subject: {Subject}, Thumbprint: {Thumbprint}",
            certificate.Subject,
            certificate.Thumbprint);

        bool result = _chain.Build(certificate);

        if (result)
        {
            _logger.LogTrace(
                new EventId(LogEvents.CertificateChainBuilt, nameof(LogEvents.CertificateChainBuilt)),
                "Certificate chain built successfully. ChainLength: {ChainLength}",
                _chain.ChainElements.Count);
        }
        else
        {
            var statusSummary = string.Join(", ", _chain.ChainStatus.Select(s => s.Status.ToString()));
            _logger.LogTrace(
                new EventId(LogEvents.CertificateChainBuildFailed, nameof(LogEvents.CertificateChainBuildFailed)),
                "Certificate chain build failed. ChainLength: {ChainLength}, ChainStatus: {ChainStatus}",
                _chain.ChainElements.Count,
                statusSummary);
        }

        return result;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!_disposed)
        {
            _chain.Dispose();
            _disposed = true;
        }
    }
}
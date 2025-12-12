// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Certificates;

/// <summary>
/// Abstract base class for certificate sources.
/// Provides common chain builder management logic.
/// </summary>
public abstract class CertificateSourceBase : ICertificateSource
{
    private readonly ICertificateChainBuilder _chainBuilder;
    private bool _disposed;

    /// <summary>
    /// Gets the logger instance for derived classes to use.
    /// </summary>
    protected ILogger Logger { get; }

    /// <summary>
    /// Initializes a new instance with an optional custom chain builder.
    /// If not provided, creates an ExplicitCertificateChainBuilder with the provided certificates.
    /// </summary>
    /// <param name="certificates">Certificates for the chain</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    protected CertificateSourceBase(IReadOnlyList<X509Certificate2> certificates, ICertificateChainBuilder? chainBuilder = null, ILogger? logger = null)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(certificates);
#else
        if (certificates == null) { throw new ArgumentNullException(nameof(certificates)); }
#endif
        _chainBuilder = chainBuilder ?? new ExplicitCertificateChainBuilder(certificates);
        Logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Initializes a new instance with a chain builder that will be used for automatic chain building.
    /// </summary>
    /// <param name="chainBuilder">Chain builder to use</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    protected CertificateSourceBase(ICertificateChainBuilder chainBuilder, ILogger? logger = null)
    {
        _chainBuilder = chainBuilder ?? throw new ArgumentNullException(nameof(chainBuilder));
        Logger = logger ?? NullLogger.Instance;
    }

    /// <inheritdoc/>
    public abstract X509Certificate2 GetSigningCertificate();

    /// <inheritdoc/>
    public abstract bool HasPrivateKey { get; }

    /// <inheritdoc/>
    public ICertificateChainBuilder GetChainBuilder() => _chainBuilder;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Dispose(disposing: true);
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes resources used by the certificate source.
    /// </summary>
    /// <param name="disposing">True if disposing managed resources</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            (_chainBuilder as IDisposable)?.Dispose();
        }
    }
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.ChainBuilders;

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// A certificate chain builder that wraps the standard <see cref="X509Chain"/> for automatic chain building.
/// </summary>
public sealed class X509ChainBuilder : ICertificateChainBuilder, IDisposable
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string LogInitializedFormat =
            "X509ChainBuilder initialized. RevocationMode: {RevocationMode}, RevocationFlag: {RevocationFlag}, VerificationFlags: {VerificationFlags}";

        public const string LogBuildingChainFormat =
            "Building certificate chain. Subject: {Subject}, Thumbprint: {Thumbprint}";

        public const string LogChainBuiltFormat =
            "Certificate chain built successfully. ChainLength: {ChainLength}";

        public const string LogChainBuildFailedFormat =
            "Certificate chain build failed. ChainLength: {ChainLength}, ChainStatus: {ChainStatus}";

        public const string ChainStatusJoinSeparator = ", ";
    }

    private readonly X509Chain Chain;
    private readonly ILogger<X509ChainBuilder> LoggerField;
    private bool Disposed;

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
        LoggerField = logger ?? NullLogger<X509ChainBuilder>.Instance;
        Chain = new X509Chain();

        // Create a new policy to avoid any shared state issues
        Chain.ChainPolicy.RevocationMode = chainPolicy.RevocationMode;
        Chain.ChainPolicy.RevocationFlag = chainPolicy.RevocationFlag;
        Chain.ChainPolicy.VerificationFlags = chainPolicy.VerificationFlags;
        Chain.ChainPolicy.UrlRetrievalTimeout = chainPolicy.UrlRetrievalTimeout;

        // Copy application policies if any
        if (chainPolicy.ApplicationPolicy.Count > 0)
        {
            foreach (var oid in chainPolicy.ApplicationPolicy)
            {
                Chain.ChainPolicy.ApplicationPolicy.Add(oid);
            }
        }

        // Copy certificate policies if any
        if (chainPolicy.CertificatePolicy.Count > 0)
        {
            foreach (var oid in chainPolicy.CertificatePolicy)
            {
                Chain.ChainPolicy.CertificatePolicy.Add(oid);
            }
        }

        // Copy extra store if any
        if (chainPolicy.ExtraStore.Count > 0)
        {
            Chain.ChainPolicy.ExtraStore.AddRange(chainPolicy.ExtraStore);
        }

#if NET5_0_OR_GREATER
        // Copy trust mode and custom trust store if applicable
        Chain.ChainPolicy.TrustMode = chainPolicy.TrustMode;
        if (chainPolicy.CustomTrustStore.Count > 0)
        {
            Chain.ChainPolicy.CustomTrustStore.AddRange(chainPolicy.CustomTrustStore);
        }
#endif

        LoggerField.LogTrace(
            LogEvents.CertificateChainBuildStartedEvent,
            ClassStrings.LogInitializedFormat,
            chainPolicy.RevocationMode,
            chainPolicy.RevocationFlag,
            chainPolicy.VerificationFlags);
    }

    /// <inheritdoc/>
    /// <exception cref="ObjectDisposedException">Thrown when the builder has been disposed.</exception>
    public IReadOnlyCollection<X509Certificate2> ChainElements
    {
        get
        {
#if NET5_0_OR_GREATER
            ObjectDisposedException.ThrowIf(Disposed, this);
#else
            if (Disposed) { throw new ObjectDisposedException(GetType().FullName); }
#endif
            var elements = new List<X509Certificate2>(Chain.ChainElements.Count);
            foreach (var element in Chain.ChainElements)
            {
                elements.Add(element.Certificate);
            }
            return elements;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ObjectDisposedException">Thrown when the builder has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    public X509ChainPolicy ChainPolicy
    {
        get
        {
#if NET5_0_OR_GREATER
            ObjectDisposedException.ThrowIf(Disposed, this);
#else
            if (Disposed) { throw new ObjectDisposedException(GetType().FullName); }
#endif
            return Chain.ChainPolicy;
        }
        set
        {
#if NET5_0_OR_GREATER
            ObjectDisposedException.ThrowIf(Disposed, this);
            ArgumentNullException.ThrowIfNull(value);
#else
            if (Disposed) { throw new ObjectDisposedException(GetType().FullName); }
            if (value == null) { throw new ArgumentNullException(nameof(value)); }
#endif
            Chain.ChainPolicy = value;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ObjectDisposedException">Thrown when the builder has been disposed.</exception>
    public X509ChainStatus[] ChainStatus
    {
        get
        {
#if NET5_0_OR_GREATER
            ObjectDisposedException.ThrowIf(Disposed, this);
#else
            if (Disposed) { throw new ObjectDisposedException(GetType().FullName); }
#endif
            return Chain.ChainStatus;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ObjectDisposedException">Thrown when the builder has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is null.</exception>
    public bool Build(X509Certificate2 certificate)
    {
#if NET5_0_OR_GREATER
        ObjectDisposedException.ThrowIf(Disposed, this);
        ArgumentNullException.ThrowIfNull(certificate);
#else
        if (Disposed) { throw new ObjectDisposedException(GetType().FullName); }
        if (certificate == null) { throw new ArgumentNullException(nameof(certificate)); }
#endif

        LoggerField.LogTrace(
            LogEvents.CertificateChainBuildStartedEvent,
            ClassStrings.LogBuildingChainFormat,
            certificate.Subject,
            certificate.Thumbprint);

        bool result = Chain.Build(certificate);

        if (result)
        {
            LoggerField.LogTrace(
                LogEvents.CertificateChainBuiltEvent,
                ClassStrings.LogChainBuiltFormat,
                Chain.ChainElements.Count);
        }
        else
        {
            var statusSummary = string.Join(ClassStrings.ChainStatusJoinSeparator, Chain.ChainStatus.Select(s => s.Status.ToString()));
            LoggerField.LogTrace(
                LogEvents.CertificateChainBuildFailedEvent,
                ClassStrings.LogChainBuildFailedFormat,
                Chain.ChainElements.Count,
                statusSummary);
        }

        return result;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!Disposed)
        {
            Chain.Dispose();
            Disposed = true;
        }
    }
}
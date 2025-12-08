// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.ChainBuilders;

/// <summary>
/// A certificate chain builder that wraps the standard <see cref="X509Chain"/> for automatic chain building.
/// </summary>
public sealed class X509ChainBuilder : ICertificateChainBuilder, IDisposable
{
    private readonly X509Chain _chain;
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
    public X509ChainBuilder()
        : this(DefaultChainPolicy)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ChainBuilder"/> class with a specific chain policy.
    /// </summary>
    /// <param name="chainPolicy">The chain policy to use for chain building.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="chainPolicy"/> is null.</exception>
    public X509ChainBuilder(X509ChainPolicy chainPolicy)
    {
        ArgumentNullException.ThrowIfNull(chainPolicy);
        _chain = new X509Chain
        {
            ChainPolicy = chainPolicy
        };
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<X509Certificate2> ChainElements
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
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
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _chain.ChainPolicy;
        }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentNullException.ThrowIfNull(value);
            _chain.ChainPolicy = value;
        }
    }

    /// <inheritdoc/>
    public X509ChainStatus[] ChainStatus
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _chain.ChainStatus;
        }
    }

    /// <inheritdoc/>
    public bool Build(X509Certificate2 certificate)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(certificate);
        return _chain.Build(certificate);
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

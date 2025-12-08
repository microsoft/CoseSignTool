// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates;

/// <summary>
/// Shared certificate signing key implementation that works for both local and remote scenarios.
/// Uses ICertificateSource for certificate management and ISigningKeyProvider for signing operations.
/// </summary>
public class CertificateSigningKey : ICertificateSigningKey
{
    private readonly ICertificateSource _certificateSource;
    private readonly ISigningKeyProvider _signingKeyProvider;
    private readonly ISigningService _signingService;
    private CoseKey? _coseKey;
    private readonly object _coseKeyLock = new();
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of CertificateSigningKey.
    /// </summary>
    /// <param name="certificateSource">Source for the signing certificate</param>
    /// <param name="signingKeyProvider">Provider for signing operations</param>
    /// <param name="signingService">The signing service that owns this key</param>
    public CertificateSigningKey(
        ICertificateSource certificateSource,
        ISigningKeyProvider signingKeyProvider,
        ISigningService signingService)
    {
        _certificateSource = certificateSource ?? throw new ArgumentNullException(nameof(certificateSource));
        _signingKeyProvider = signingKeyProvider ?? throw new ArgumentNullException(nameof(signingKeyProvider));
        _signingService = signingService ?? throw new ArgumentNullException(nameof(signingService));
    }

    /// <inheritdoc/>
    public CoseKey GetCoseKey()
    {
        if (_coseKey != null)
        {
            return _coseKey;
        }

        lock (_coseKeyLock)
        {
            if (_coseKey != null)
            {
                return _coseKey;
            }

            _coseKey = _signingKeyProvider.GetCoseKey();
            return _coseKey;
        }
    }

    /// <inheritdoc/>
    public X509Certificate2 GetSigningCertificate()
    {
        return _certificateSource.GetSigningCertificate();
    }

    /// <inheritdoc/>
    public IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
    {
        var chainBuilder = _certificateSource.GetChainBuilder();
        var cert = _certificateSource.GetSigningCertificate();
        
        chainBuilder.Build(cert);
        
        var chainElements = sortOrder == X509ChainSortOrder.LeafFirst 
            ? chainBuilder.ChainElements 
            : chainBuilder.ChainElements.Reverse();
            
        return chainElements;
    }

    /// <inheritdoc/>
    public SigningKeyMetadata Metadata => new SigningKeyMetadata(
        coseAlgorithmId: -37, // PS256 (placeholder, should be detected)
        keyType: CryptographicKeyType.RSA, // Placeholder
        isRemote: _signingKeyProvider.IsRemote,
        hashAlgorithm: HashAlgorithmName.SHA256,
        keySizeInBits: null,
        additionalMetadata: null);

    /// <inheritdoc/>
    public ISigningService SigningService => _signingService;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _signingKeyProvider?.Dispose();
        _certificateSource?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

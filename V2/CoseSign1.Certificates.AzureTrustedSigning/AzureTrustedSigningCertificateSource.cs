// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;

namespace CoseSign1.Certificates.AzureTrustedSigning;

/// <summary>
/// Provides certificate and signing operations using Azure Trusted Signing service.
/// Implements the RemoteCertificateSource pattern for V2 architecture.
/// </summary>
/// <remarks>
/// Azure Trusted Signing is a Microsoft-managed cloud service that provides:
/// - Certificate lifecycle management
/// - Secure key storage in FIPS 140-2 Level 3 HSMs
/// - Remote signing operations for RSA, ECDSA, and ML-DSA algorithms
/// - Compliance with industry standards (e.g., SCITT)
/// 
/// This class wraps the Azure Developer Trusted Signing SDK (AzSignContext) and adapts it
/// to the V2 RemoteCertificateSource pattern.
/// </remarks>
public class AzureTrustedSigningCertificateSource : RemoteCertificateSource
{
    private readonly AzSignContext _signContext;
    private X509Certificate2? _leafCertificate;
    private IReadOnlyList<X509Certificate2>? _certificateChain;
    private readonly object _certificateLock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureTrustedSigningCertificateSource"/> class.
    /// </summary>
    /// <param name="signContext">The Azure Trusted Signing context from the SDK.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder.</param>
    public AzureTrustedSigningCertificateSource(
        AzSignContext signContext,
        ICertificateChainBuilder? chainBuilder = null)
        : base(chainBuilder)
    {
        _signContext = signContext ?? throw new ArgumentNullException(nameof(signContext));
    }

    /// <inheritdoc/>
    public override X509Certificate2 GetLeafCertificate()
    {
        if (_leafCertificate != null)
        {
            return _leafCertificate;
        }

        lock (_certificateLock)
        {
            if (_leafCertificate != null)
            {
                return _leafCertificate;
            }

            // Get the full chain and extract the leaf
            var chain = GetCertificateChainInternal();
            _leafCertificate = chain.FirstOrDefault()
                ?? throw new InvalidOperationException("Azure Trusted Signing did not return a certificate chain.");
            
            return _leafCertificate;
        }
    }

    /// <inheritdoc/>
    public override IReadOnlyList<X509Certificate2> GetCertificateChain()
    {
        return GetCertificateChainInternal();
    }

    private IReadOnlyList<X509Certificate2> GetCertificateChainInternal()
    {
        if (_certificateChain != null)
        {
            return _certificateChain;
        }

        lock (_certificateLock)
        {
            if (_certificateChain != null)
            {
                return _certificateChain;
            }

            // Get chain from Azure Trusted Signing SDK
            _certificateChain = _signContext.GetCertChain()
                ?? throw new InvalidOperationException(
                    "Azure Trusted Signing did not return a certificate chain. " +
                    "Please check the Azure Trusted Signing configuration and ensure the signing profile is valid.");

            if (_certificateChain.Count == 0)
            {
                throw new InvalidOperationException(
                    "Azure Trusted Signing returned an empty certificate chain. " +
                    "Please check the Azure Trusted Signing configuration.");
            }

            return _certificateChain;
        }
    }

    #region RSA Signing Operations

    /// <inheritdoc/>
    public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (data == null) { throw new ArgumentNullException(nameof(data)); }
        
        using var rsa = _signContext.GetRsa();
        if (rsa == null)
        {
            throw new NotSupportedException("Azure Trusted Signing did not return an RSA key. The signing profile may not support RSA operations.");
        }

        return rsa.SignData(data, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    public override async Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
    {
        if (data == null) { throw new ArgumentNullException(nameof(data)); }
        
        using var rsa = _signContext.GetRsa();
        if (rsa == null)
        {
            throw new NotSupportedException("Azure Trusted Signing did not return an RSA key. The signing profile may not support RSA operations.");
        }

        // Note: RSA.SignData is synchronous, but we wrap it for async pattern consistency
        return await Task.Run(() => rsa.SignData(data, hashAlgorithm, padding), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
        
        using var rsa = _signContext.GetRsa();
        if (rsa == null)
        {
            throw new NotSupportedException("Azure Trusted Signing did not return an RSA key. The signing profile may not support RSA operations.");
        }

        return rsa.SignHash(hash, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    public override async Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
    {
        if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
        
        using var rsa = _signContext.GetRsa();
        if (rsa == null)
        {
            throw new NotSupportedException("Azure Trusted Signing did not return an RSA key. The signing profile may not support RSA operations.");
        }

        return await Task.Run(() => rsa.SignHash(hash, hashAlgorithm, padding), cancellationToken).ConfigureAwait(false);
    }

    #endregion

    #region ECDSA Signing Operations

    /// <inheritdoc/>
    public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        if (data == null) { throw new ArgumentNullException(nameof(data)); }
        
        using var ecdsa = _signContext.GetEcdsa();
        if (ecdsa == null)
        {
            throw new NotSupportedException("Azure Trusted Signing did not return an ECDSA key. The signing profile may not support ECDSA operations.");
        }

        return ecdsa.SignData(data, hashAlgorithm);
    }

    /// <inheritdoc/>
    public override async Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
    {
        if (data == null) { throw new ArgumentNullException(nameof(data)); }
        
        using var ecdsa = _signContext.GetEcdsa();
        if (ecdsa == null)
        {
            throw new NotSupportedException("Azure Trusted Signing did not return an ECDSA key. The signing profile may not support ECDSA operations.");
        }

        return await Task.Run(() => ecdsa.SignData(data, hashAlgorithm), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override byte[] SignHashWithEcdsa(byte[] hash)
    {
        if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
        
        using var ecdsa = _signContext.GetEcdsa();
        if (ecdsa == null)
        {
            throw new NotSupportedException("Azure Trusted Signing did not return an ECDSA key. The signing profile may not support ECDSA operations.");
        }

        return ecdsa.SignHash(hash);
    }

    /// <inheritdoc/>
    public override async Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
    {
        if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
        
        using var ecdsa = _signContext.GetEcdsa();
        if (ecdsa == null)
        {
            throw new NotSupportedException("Azure Trusted Signing did not return an ECDSA key. The signing profile may not support ECDSA operations.");
        }

        return await Task.Run(() => ecdsa.SignHash(hash), cancellationToken).ConfigureAwait(false);
    }

    #endregion

    #region ML-DSA (Post-Quantum) Signing Operations

    /// <inheritdoc/>
    public override byte[] SignDataWithMlDsa(byte[] data)
    {
        throw new NotSupportedException(
            "Azure Trusted Signing does not currently support ML-DSA (post-quantum) signing operations. " +
            "This feature may be available in future versions of the service.");
    }

    /// <inheritdoc/>
    public override Task<byte[]> SignDataWithMlDsaAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(
            "Azure Trusted Signing does not currently support ML-DSA (post-quantum) signing operations. " +
            "This feature may be available in future versions of the service.");
    }

    #endregion

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _leafCertificate?.Dispose();
            _leafCertificate = null;

            if (_certificateChain != null)
            {
                foreach (var cert in _certificateChain)
                {
                    cert?.Dispose();
                }
                _certificateChain = null;
            }

            // Note: We don't dispose _signContext as it's owned by the caller
        }

        base.Dispose(disposing);
    }
}

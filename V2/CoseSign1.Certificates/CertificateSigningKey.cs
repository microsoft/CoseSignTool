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
    public SigningKeyMetadata Metadata => GetMetadata();

    /// <inheritdoc/>
    public ISigningService SigningService => _signingService;

    private SigningKeyMetadata GetMetadata()
    {
        var cert = _certificateSource.GetSigningCertificate();
        
        // Detect key type and algorithm from certificate
        var keyType = CryptographicKeyType.RSA;
        int coseAlgorithmId = -37; // Default to PS256
        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
        int? keySizeInBits = null;

        // Try RSA first
        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null)
        {
            keyType = CryptographicKeyType.RSA;
            keySizeInBits = rsa.KeySize;
            
            // Determine COSE algorithm based on key size
            // -37: PS256 (RSA-PSS with SHA-256)
            // -38: PS384 (RSA-PSS with SHA-384)
            // -39: PS512 (RSA-PSS with SHA-512)
            coseAlgorithmId = keySizeInBits switch
            {
                >= 4096 => -39, // PS512
                >= 3072 => -38, // PS384
                _ => -37        // PS256
            };
            
            hashAlgorithm = coseAlgorithmId switch
            {
                -39 => HashAlgorithmName.SHA512,
                -38 => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA256
            };
            
            return new SigningKeyMetadata(
                coseAlgorithmId: coseAlgorithmId,
                keyType: keyType,
                isRemote: _signingKeyProvider.IsRemote,
                hashAlgorithm: hashAlgorithm,
                keySizeInBits: keySizeInBits,
                additionalMetadata: null);
        }

        // Try ECDSA
        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            keyType = CryptographicKeyType.ECDsa;
            keySizeInBits = ecdsa.KeySize;
            
            // Determine COSE algorithm based on curve
            // -7: ES256 (ECDSA with SHA-256, P-256 curve)
            // -35: ES384 (ECDSA with SHA-384, P-384 curve)
            // -36: ES512 (ECDSA with SHA-512, P-521 curve)
            coseAlgorithmId = keySizeInBits switch
            {
                521 => -36, // ES512 (P-521)
                384 => -35, // ES384 (P-384)
                _ => -7     // ES256 (P-256)
            };
            
            hashAlgorithm = coseAlgorithmId switch
            {
                -36 => HashAlgorithmName.SHA512,
                -35 => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA256
            };
            
            return new SigningKeyMetadata(
                coseAlgorithmId: coseAlgorithmId,
                keyType: keyType,
                isRemote: _signingKeyProvider.IsRemote,
                hashAlgorithm: hashAlgorithm,
                keySizeInBits: keySizeInBits,
                additionalMetadata: null);
        }

        // Try ML-DSA (Post-Quantum)
        // ML-DSA uses different OIDs that are supported in .NET 10.0+
        // Check for ML-DSA by examining the public key algorithm OID
        var publicKeyOid = cert.PublicKey.Oid.Value;
        
        // ML-DSA OIDs (NIST standardized):
        // 2.16.840.1.101.3.4.3.17 - ML-DSA-44
        // 2.16.840.1.101.3.4.3.18 - ML-DSA-65
        // 2.16.840.1.101.3.4.3.19 - ML-DSA-87
        if (publicKeyOid?.StartsWith("2.16.840.1.101.3.4.3.") == true)
        {
            keyType = CryptographicKeyType.MLDSA;
            
            // Determine COSE algorithm and security level based on ML-DSA variant
            // TBD: COSE algorithm IDs for ML-DSA (these are provisional)
            // -48: ML-DSA-44 (128-bit security)
            // -49: ML-DSA-65 (192-bit security)
            // -50: ML-DSA-87 (256-bit security)
            (coseAlgorithmId, keySizeInBits, hashAlgorithm) = publicKeyOid switch
            {
                "2.16.840.1.101.3.4.3.17" => (-48, (int?)44, HashAlgorithmName.SHA256),  // ML-DSA-44
                "2.16.840.1.101.3.4.3.18" => (-49, (int?)65, HashAlgorithmName.SHA384),  // ML-DSA-65
                "2.16.840.1.101.3.4.3.19" => (-50, (int?)87, HashAlgorithmName.SHA512),  // ML-DSA-87
                _ => (-48, (int?)null, HashAlgorithmName.SHA256) // Default to ML-DSA-44 equivalent
            };
            
            return new SigningKeyMetadata(
                coseAlgorithmId: coseAlgorithmId,
                keyType: keyType,
                isRemote: _signingKeyProvider.IsRemote,
                hashAlgorithm: hashAlgorithm,
                keySizeInBits: keySizeInBits,
                additionalMetadata: new Dictionary<string, object>
                {
                    ["PublicKeyAlgorithmOid"] = publicKeyOid ?? "unknown"
                });
        }

        // Fallback: Unknown key type
        return new SigningKeyMetadata(
            coseAlgorithmId: -37, // Default to PS256
            keyType: CryptographicKeyType.RSA,
            isRemote: _signingKeyProvider.IsRemote,
            hashAlgorithm: HashAlgorithmName.SHA256,
            keySizeInBits: null,
            additionalMetadata: new Dictionary<string, object>
            {
                ["Warning"] = "Unable to determine key type from certificate"
            });
    }

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

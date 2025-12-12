// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;

namespace CoseSign1.Certificates.Remote;

/// <summary>
/// Provides signing key operations using a remote certificate source.
/// Automatically detects the key type (RSA, ECDSA, ML-DSA) and uses the appropriate signing method.
/// </summary>
public class RemoteSigningKeyProvider : ISigningKey
{
    private readonly RemoteCertificateSource _certificateSource;
    private readonly Lazy<SigningKeyMetadata> _metadata;
    private CoseKey? _coseKey;
    private readonly object _coseKeyLock = new();
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="RemoteSigningKeyProvider"/> class.
    /// </summary>
    /// <param name="certificateSource">The remote certificate source that provides the signing operations.</param>
    /// <param name="signingService">The signing service that owns this key.</param>
    public RemoteSigningKeyProvider(RemoteCertificateSource certificateSource, ISigningService<SigningOptions> signingService)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(certificateSource);
        ArgumentNullException.ThrowIfNull(signingService);
#else
        if (certificateSource == null) { throw new ArgumentNullException(nameof(certificateSource)); }
        if (signingService == null) { throw new ArgumentNullException(nameof(signingService)); }
#endif
        _certificateSource = certificateSource;
        SigningService = signingService;
        _metadata = new Lazy<SigningKeyMetadata>(() => CreateMetadata());
    }

    /// <inheritdoc/>
    public SigningKeyMetadata Metadata => _metadata.Value;

    /// <inheritdoc/>
    public ISigningService<SigningOptions> SigningService { get; }

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

            _coseKey = CreateCoseKeyForRemote();
            return _coseKey;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _coseKey = null;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private SigningKeyMetadata CreateMetadata()
    {
        var cert = _certificateSource.GetSigningCertificate();
        var publicKeyOid = cert.PublicKey.Oid.Value;

        // RSA: 1.2.840.113549.1.1.1
        if (publicKeyOid == "1.2.840.113549.1.1.1")
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null)
            {
                int coseAlgorithmId = rsa.KeySize switch
                {
                    >= 4096 => -39, // PS512
                    >= 3072 => -38, // PS384
                    _ => -37        // PS256
                };

                var hashAlgorithm = coseAlgorithmId switch
                {
                    -39 => HashAlgorithmName.SHA512,
                    -38 => HashAlgorithmName.SHA384,
                    _ => HashAlgorithmName.SHA256
                };

                return new SigningKeyMetadata(
                    coseAlgorithmId: coseAlgorithmId,
                    keyType: CryptographicKeyType.RSA,
                    isRemote: true,
                    hashAlgorithm: hashAlgorithm,
                    keySizeInBits: rsa.KeySize,
                    additionalMetadata: null);
            }
        }

        // ECDSA: 1.2.840.10045.2.1
        if (publicKeyOid == "1.2.840.10045.2.1")
        {
            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                int coseAlgorithmId = ecdsa.KeySize switch
                {
                    521 => -36, // ES512 (P-521)
                    384 => -35, // ES384 (P-384)
                    _ => -7     // ES256 (P-256)
                };

                var hashAlgorithm = coseAlgorithmId switch
                {
                    -36 => HashAlgorithmName.SHA512,
                    -35 => HashAlgorithmName.SHA384,
                    _ => HashAlgorithmName.SHA256
                };

                return new SigningKeyMetadata(
                    coseAlgorithmId: coseAlgorithmId,
                    keyType: CryptographicKeyType.ECDsa,
                    isRemote: true,
                    hashAlgorithm: hashAlgorithm,
                    keySizeInBits: ecdsa.KeySize,
                    additionalMetadata: null);
            }
        }

        // ML-DSA-44: 2.16.840.1.101.3.4.3.17
        // ML-DSA-65: 2.16.840.1.101.3.4.3.18
        // ML-DSA-87: 2.16.840.1.101.3.4.3.19
        if (publicKeyOid?.StartsWith("2.16.840.1.101.3.4.3.") == true)
        {
            (int coseAlgorithmId, int? keySizeInBits, HashAlgorithmName hashAlgorithm) = publicKeyOid switch
            {
                "2.16.840.1.101.3.4.3.17" => (-48, (int?)44, HashAlgorithmName.SHA256),  // ML-DSA-44
                "2.16.840.1.101.3.4.3.18" => (-49, (int?)65, HashAlgorithmName.SHA384),  // ML-DSA-65
                "2.16.840.1.101.3.4.3.19" => (-50, (int?)87, HashAlgorithmName.SHA512),  // ML-DSA-87
                _ => (-48, (int?)null, HashAlgorithmName.SHA256) // Default
            };

            return new SigningKeyMetadata(
                coseAlgorithmId: coseAlgorithmId,
                keyType: CryptographicKeyType.MLDSA,
                isRemote: true,
                hashAlgorithm: hashAlgorithm,
                keySizeInBits: keySizeInBits,
                additionalMetadata: new Dictionary<string, object>
                {
                    ["PublicKeyAlgorithmOid"] = publicKeyOid ?? "unknown"
                });
        }

        throw new NotSupportedException($"Unsupported key algorithm OID: {publicKeyOid}");
    }

    private CoseKey CreateCoseKeyForRemote()
    {
        var cert = _certificateSource.GetSigningCertificate();
        var publicKeyOid = cert.PublicKey.Oid.Value;

        // RSA: 1.2.840.113549.1.1.1
        if (publicKeyOid == "1.2.840.113549.1.1.1")
        {
            var rsa = _certificateSource.GetRemoteRsa();
            var hashAlgorithm = Metadata.HashAlgorithm ?? HashAlgorithmName.SHA256;
            return new CoseKey(rsa, RSASignaturePadding.Pss, hashAlgorithm);
        }

        // ECDSA: 1.2.840.10045.2.1
        if (publicKeyOid == "1.2.840.10045.2.1")
        {
            var ecdsa = _certificateSource.GetRemoteECDsa();
            var hashAlgorithm = Metadata.HashAlgorithm ?? HashAlgorithmName.SHA256;
            return new CoseKey(ecdsa, hashAlgorithm);
        }

        // ML-DSA
        if (publicKeyOid?.StartsWith("2.16.840.1.101.3.4.3.") == true)
        {
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview in .NET 10
            var mldsa = _certificateSource.GetRemoteMLDsa();
            return new CoseKey(mldsa);
#pragma warning restore SYSLIB5006
        }

        throw new NotSupportedException($"Unable to create CoseKey for algorithm OID {publicKeyOid}");
    }
}
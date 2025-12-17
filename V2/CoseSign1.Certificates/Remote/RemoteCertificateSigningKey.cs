// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.Remote;

/// <summary>
/// Certificate signing key implementation for remote certificate sources.
/// Combines the remote certificate source (which provides both the certificate and signing operations)
/// into a unified <see cref="ICertificateSigningKey"/>.
/// </summary>
/// <remarks>
/// This class enables any <see cref="RemoteCertificateSource"/> implementation (Azure Key Vault,
/// Azure Trusted Signing, HSM, etc.) to work with the standard <see cref="CertificateSigningService"/>.
/// </remarks>
public class RemoteCertificateSigningKey : ICertificateSigningKey
{
    private readonly RemoteCertificateSource CertificateSource;
    private readonly ISigningService<SigningOptions> SigningServiceField;
    private readonly Lazy<SigningKeyMetadata> LazyMetadata;
    private CoseKey? CoseKeyField;
    private readonly object CoseKeyLock = new();
    private bool Disposed;

    /// <summary>
    /// Initializes a new instance of <see cref="RemoteCertificateSigningKey"/>.
    /// </summary>
    /// <param name="certificateSource">The remote certificate source.</param>
    /// <param name="signingService">The signing service that owns this key.</param>
    public RemoteCertificateSigningKey(
        RemoteCertificateSource certificateSource,
        ISigningService<SigningOptions> signingService)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(certificateSource);
        ArgumentNullException.ThrowIfNull(signingService);
#else
        if (certificateSource == null) { throw new ArgumentNullException(nameof(certificateSource)); }
        if (signingService == null) { throw new ArgumentNullException(nameof(signingService)); }
#endif
        CertificateSource = certificateSource;
        SigningServiceField = signingService;
        LazyMetadata = new Lazy<SigningKeyMetadata>(() => CreateMetadata());
    }

    /// <inheritdoc/>
    public SigningKeyMetadata Metadata => LazyMetadata.Value;

    /// <inheritdoc/>
    public ISigningService<SigningOptions> SigningService => SigningServiceField;

    /// <inheritdoc/>
    public CoseKey GetCoseKey()
    {
        if (CoseKeyField != null)
        {
            return CoseKeyField;
        }

        lock (CoseKeyLock)
        {
            if (CoseKeyField != null)
            {
                return CoseKeyField;
            }

            CoseKeyField = CreateCoseKeyForRemote();
            return CoseKeyField;
        }
    }

    /// <inheritdoc/>
    public X509Certificate2 GetSigningCertificate()
    {
        return CertificateSource.GetSigningCertificate();
    }

    /// <inheritdoc/>
    public IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
    {
        var chainBuilder = CertificateSource.GetChainBuilder();
        var cert = CertificateSource.GetSigningCertificate();

        chainBuilder.Build(cert);

        var chainElements = sortOrder == X509ChainSortOrder.LeafFirst
            ? chainBuilder.ChainElements
            : chainBuilder.ChainElements.Reverse();

        return chainElements;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        CoseKeyField = null;
        Disposed = true;
        GC.SuppressFinalize(this);
    }

    private SigningKeyMetadata CreateMetadata()
    {
        var cert = CertificateSource.GetSigningCertificate();
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
        var cert = CertificateSource.GetSigningCertificate();
        var publicKeyOid = cert.PublicKey.Oid.Value;

        // RSA: 1.2.840.113549.1.1.1
        if (publicKeyOid == "1.2.840.113549.1.1.1")
        {
            var rsa = CertificateSource.GetRemoteRsa();
            var hashAlgorithm = Metadata.HashAlgorithm ?? HashAlgorithmName.SHA256;
            return new CoseKey(rsa, RSASignaturePadding.Pss, hashAlgorithm);
        }

        // ECDSA: 1.2.840.10045.2.1
        if (publicKeyOid == "1.2.840.10045.2.1")
        {
            var ecdsa = CertificateSource.GetRemoteECDsa();
            var hashAlgorithm = Metadata.HashAlgorithm ?? HashAlgorithmName.SHA256;
            return new CoseKey(ecdsa, hashAlgorithm);
        }

#if NET10_0_OR_GREATER
        // ML-DSA
        if (publicKeyOid?.StartsWith("2.16.840.1.101.3.4.3.") == true)
        {
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview in .NET 10
            var mldsa = CertificateSource.GetRemoteMLDsa();
            return new CoseKey(mldsa);
#pragma warning restore SYSLIB5006
        }
#endif

        throw new NotSupportedException($"Unable to create CoseKey for algorithm OID {publicKeyOid}");
    }
}

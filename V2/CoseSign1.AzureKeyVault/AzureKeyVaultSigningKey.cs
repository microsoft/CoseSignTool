// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault.Common;

namespace CoseSign1.AzureKeyVault;

/// <summary>
/// An <see cref="ISigningKey"/> implementation for Azure Key Vault keys.
/// Wraps a Key Vault key and provides remote signing via the CryptographyClient.
/// </summary>
/// <remarks>
/// <para>
/// This class is designed for standalone key signing (no certificate).
/// It uses the common <see cref="KeyVaultCryptoClientWrapper"/> for algorithm
/// mapping and cryptographic operations.
/// </para>
/// <para>
/// Per RFC 9052, when signing without a certificate chain, the kid (Key ID)
/// header should be included to identify the signing key.
/// </para>
/// </remarks>
public sealed class AzureKeyVaultSigningKey : ISigningKey
{
    private readonly KeyVaultCryptoClientWrapper CryptoWrapper;
    private readonly Lazy<SigningKeyMetadata> LazyMetadata;
    private CoseKey? CoseKeyField;
    private readonly object CoseKeyLock = new();
    private bool Disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultSigningKey"/> class.
    /// </summary>
    /// <param name="signingService">The parent signing service.</param>
    /// <param name="cryptoWrapper">The Key Vault crypto wrapper for signing operations.</param>
    /// <remarks>
    /// This constructor is public to enable dependency injection and testing scenarios.
    /// </remarks>
    public AzureKeyVaultSigningKey(
        ISigningService<SigningOptions> signingService,
        KeyVaultCryptoClientWrapper cryptoWrapper)
    {
        SigningService = signingService ?? throw new ArgumentNullException(nameof(signingService));
        CryptoWrapper = cryptoWrapper ?? throw new ArgumentNullException(nameof(cryptoWrapper));
        LazyMetadata = new Lazy<SigningKeyMetadata>(() => CreateMetadata());
    }

    /// <inheritdoc/>
    public SigningKeyMetadata Metadata => LazyMetadata.Value;

    /// <inheritdoc/>
    public ISigningService<SigningOptions> SigningService { get; }

    /// <summary>
    /// Gets the Key Vault key ID (URI format).
    /// </summary>
    public string KeyId => CryptoWrapper.KeyId;

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

            CoseKeyField = CreateCoseKey();
            return CoseKeyField;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        CoseKeyField = null;
        CryptoWrapper.Dispose();
        Disposed = true;
        GC.SuppressFinalize(this);
    }

    private SigningKeyMetadata CreateMetadata()
    {
        var keyType = CryptoWrapper.KeyType;
        var key = CryptoWrapper.KeyVaultKey;
        int coseAlgorithmId;
        HashAlgorithmName hashAlgorithm;
        CryptographicKeyType cryptoKeyType;

        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
        {
            cryptoKeyType = CryptographicKeyType.RSA;
            var keySize = (key.Key.N?.Length ?? 256) * 8;
            if (keySize >= 4096)
            {
                coseAlgorithmId = -39; // PS512
                hashAlgorithm = HashAlgorithmName.SHA512;
            }
            else if (keySize >= 3072)
            {
                coseAlgorithmId = -38; // PS384
                hashAlgorithm = HashAlgorithmName.SHA384;
            }
            else
            {
                coseAlgorithmId = -37; // PS256
                hashAlgorithm = HashAlgorithmName.SHA256;
            }
        }
        else if (keyType == KeyType.Ec || keyType == KeyType.EcHsm)
        {
            cryptoKeyType = CryptographicKeyType.ECDsa;
            var curveName = key.Key.CurveName?.ToString() ?? "P-256";
            if (curveName == "P-521")
            {
                coseAlgorithmId = -36; // ES512
                hashAlgorithm = HashAlgorithmName.SHA512;
            }
            else if (curveName == "P-384")
            {
                coseAlgorithmId = -35; // ES384
                hashAlgorithm = HashAlgorithmName.SHA384;
            }
            else
            {
                coseAlgorithmId = -7; // ES256
                hashAlgorithm = HashAlgorithmName.SHA256;
            }
        }
        else
        {
            throw new NotSupportedException($"Key type {keyType} is not supported for COSE signing.");
        }

        return new SigningKeyMetadata(coseAlgorithmId, cryptoKeyType, isRemote: true, hashAlgorithm);
    }

    private CoseKey CreateCoseKey()
    {
        var keyType = CryptoWrapper.KeyType;
        var key = CryptoWrapper.KeyVaultKey;
        var hashAlgorithm = Metadata.HashAlgorithm ?? HashAlgorithmName.SHA256;

        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
        {
            var rsaParams = new RSAParameters
            {
                Modulus = key.Key.N,
                Exponent = key.Key.E
            };

            var rsa = RSA.Create(rsaParams);
            var remoteRsa = new KeyVaultRemoteRsa(rsa, CryptoWrapper);
            return new CoseKey(remoteRsa, RSASignaturePadding.Pss, hashAlgorithm);
        }
        else if (keyType == KeyType.Ec || keyType == KeyType.EcHsm)
        {
            var curveName = key.Key.CurveName?.ToString() ?? "P-256";
            ECCurve curve;
            if (curveName == "P-521")
            {
                curve = ECCurve.NamedCurves.nistP521;
            }
            else if (curveName == "P-384")
            {
                curve = ECCurve.NamedCurves.nistP384;
            }
            else
            {
                curve = ECCurve.NamedCurves.nistP256;
            }

            var ecParams = new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = key.Key.X,
                    Y = key.Key.Y
                }
            };

            var ecdsa = ECDsa.Create(ecParams);
            var remoteEcdsa = new KeyVaultRemoteECDsa(ecdsa, CryptoWrapper);
            return new CoseKey(remoteEcdsa, hashAlgorithm);
        }

        throw new NotSupportedException($"Key type {keyType} is not supported for COSE signing.");
    }
}

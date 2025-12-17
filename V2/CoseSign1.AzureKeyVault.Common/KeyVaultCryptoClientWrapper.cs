// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace CoseSign1.AzureKeyVault.Common;

/// <summary>
/// Wraps an Azure Key Vault CryptographyClient to provide remote signing operations.
/// This is the core signing abstraction used by both certificate-based and key-only signing.
/// </summary>
/// <remarks>
/// <para>
/// This wrapper provides a common interface for signing operations that delegate to
/// Azure Key Vault. The private key never leaves Key Vault - all cryptographic
/// operations happen remotely.
/// </para>
/// <para>
/// Both HSM-protected keys and software-protected keys are supported. The key type
/// is determined by the Key Vault key properties.
/// </para>
/// </remarks>
public sealed class KeyVaultCryptoClientWrapper : IDisposable
{
    private readonly CryptographyClient CryptoClient;
    private readonly KeyVaultKey Key;
    private bool Disposed;

    /// <summary>
    /// Gets the Key Vault key URI as a string (used as kid header in COSE signatures).
    /// </summary>
    public string KeyId => Key.Id.ToString();

    /// <summary>
    /// Gets the key type (RSA, EC, RSA-HSM, EC-HSM).
    /// </summary>
    public KeyType KeyType => Key.KeyType;

    /// <summary>
    /// Gets whether this key is HSM-protected.
    /// </summary>
    public bool IsHsmProtected => Key.KeyType == KeyType.RsaHsm || Key.KeyType == KeyType.EcHsm;

    /// <summary>
    /// Gets the key version.
    /// </summary>
    public string Version => Key.Properties.Version;

    /// <summary>
    /// Gets the key name.
    /// </summary>
    public string Name => Key.Name;

    /// <summary>
    /// Gets the underlying KeyVaultKey for access to public key material.
    /// </summary>
    public KeyVaultKey KeyVaultKey => Key;

    /// <summary>
    /// Creates a new KeyVaultCryptoClientWrapper asynchronously.
    /// </summary>
    /// <param name="keyClient">The Key Vault key client.</param>
    /// <param name="credential">The Azure credential.</param>
    /// <param name="keyName">The name of the key.</param>
    /// <param name="keyVersion">Optional specific version. If null, uses latest.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A configured wrapper ready for signing.</returns>
    public static async Task<KeyVaultCryptoClientWrapper> CreateAsync(
        KeyClient keyClient,
        TokenCredential credential,
        string keyName,
        string? keyVersion = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyClient);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(keyName);

        var keyResponse = await keyClient.GetKeyAsync(keyName, keyVersion, cancellationToken).ConfigureAwait(false);
        var key = keyResponse.Value;

        var cryptoClient = new CryptographyClient(key.Id, credential);

        return new KeyVaultCryptoClientWrapper(key, cryptoClient);
    }

    /// <summary>
    /// Creates a wrapper from an existing key and crypto client.
    /// </summary>
    /// <param name="key">The Key Vault key containing public key material and metadata.</param>
    /// <param name="cryptoClient">The cryptography client for signing operations.</param>
    /// <remarks>
    /// This constructor enables dependency injection for testing scenarios.
    /// For production use, prefer the <see cref="CreateAsync"/> factory method.
    /// </remarks>
    public KeyVaultCryptoClientWrapper(KeyVaultKey key, CryptographyClient cryptoClient)
    {
        Key = key ?? throw new ArgumentNullException(nameof(key));
        CryptoClient = cryptoClient ?? throw new ArgumentNullException(nameof(cryptoClient));
    }

    #region RSA Signing

    /// <summary>
    /// Signs a hash using RSA.
    /// </summary>
    public byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        return SignHashWithRsaAsync(hash, hashAlgorithm, padding).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Signs a hash using RSA asynchronously.
    /// </summary>
    public async Task<byte[]> SignHashWithRsaAsync(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureRsaKey();

        var algorithm = KeyVaultAlgorithmMapper.MapRsaAlgorithm(hashAlgorithm, padding);
        var result = await CryptoClient.SignAsync(algorithm, hash, cancellationToken).ConfigureAwait(false);
        return result.Signature;
    }

    /// <summary>
    /// Signs data using RSA (computes hash first).
    /// </summary>
    public byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        return SignDataWithRsaAsync(data, hashAlgorithm, padding).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Signs data using RSA asynchronously (computes hash first).
    /// </summary>
    public async Task<byte[]> SignDataWithRsaAsync(
        byte[] data,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureRsaKey();

        using var hashAlgo = CreateHashAlgorithm(hashAlgorithm);
        var hash = hashAlgo.ComputeHash(data);

        return await SignHashWithRsaAsync(hash, hashAlgorithm, padding, cancellationToken).ConfigureAwait(false);
    }

    #endregion

    #region ECDSA Signing

    /// <summary>
    /// Signs a hash using ECDSA.
    /// </summary>
    public byte[] SignHashWithEcdsa(byte[] hash)
    {
        return SignHashWithEcdsaAsync(hash).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Signs a hash using ECDSA asynchronously.
    /// </summary>
    public async Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureEcKey();

        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(hash.Length);
        var result = await CryptoClient.SignAsync(algorithm, hash, cancellationToken).ConfigureAwait(false);
        return result.Signature;
    }

    /// <summary>
    /// Signs data using ECDSA (computes hash first).
    /// </summary>
    public byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        return SignDataWithEcdsaAsync(data, hashAlgorithm).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Signs data using ECDSA asynchronously (computes hash first).
    /// </summary>
    public async Task<byte[]> SignDataWithEcdsaAsync(
        byte[] data,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureEcKey();

        using var hashAlgo = CreateHashAlgorithm(hashAlgorithm);
        var hash = hashAlgo.ComputeHash(data);

        return await SignHashWithEcdsaAsync(hash, cancellationToken).ConfigureAwait(false);
    }

    #endregion

    #region Generic Signing

    /// <summary>
    /// Signs a hash using the appropriate algorithm based on key type.
    /// </summary>
    public async Task<byte[]> SignHashAsync(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding? rsaPadding = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (Key.KeyType == KeyType.Rsa || Key.KeyType == KeyType.RsaHsm)
        {
            var padding = rsaPadding ?? RSASignaturePadding.Pss;
            return await SignHashWithRsaAsync(hash, hashAlgorithm, padding, cancellationToken).ConfigureAwait(false);
        }
        else if (Key.KeyType == KeyType.Ec || Key.KeyType == KeyType.EcHsm)
        {
            return await SignHashWithEcdsaAsync(hash, cancellationToken).ConfigureAwait(false);
        }

        throw new NotSupportedException($"Key type {Key.KeyType} is not supported for signing.");
    }

    #endregion

    #region Helpers

    private void EnsureRsaKey()
    {
        if (Key.KeyType != KeyType.Rsa && Key.KeyType != KeyType.RsaHsm)
        {
            throw new NotSupportedException(
                $"This operation requires an RSA or RSA-HSM key, but the key is {Key.KeyType}.");
        }
    }

    private void EnsureEcKey()
    {
        if (Key.KeyType != KeyType.Ec && Key.KeyType != KeyType.EcHsm)
        {
            throw new NotSupportedException(
                $"This operation requires an EC or EC-HSM key, but the key is {Key.KeyType}.");
        }
    }

    private static HashAlgorithm CreateHashAlgorithm(HashAlgorithmName name)
    {
        if (name == HashAlgorithmName.SHA256)
        {
            return SHA256.Create();
        }

        if (name == HashAlgorithmName.SHA384)
        {
            return SHA384.Create();
        }

        if (name == HashAlgorithmName.SHA512)
        {
            return SHA512.Create();
        }

        throw new NotSupportedException($"Hash algorithm {name} is not supported.");
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Disposed, this);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        Disposed = true;
    }

    #endregion
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CoseSign1.AzureKeyVault.Common;

namespace CoseSign1.AzureKeyVault;

/// <summary>
/// RSA implementation that delegates signing to Azure Key Vault via the common wrapper.
/// </summary>
/// <remarks>
/// <para>
/// This class wraps an RSA public key and delegates all signing operations to Azure Key Vault
/// via the <see cref="KeyVaultCryptoClientWrapper"/>. The private key never leaves Key Vault.
/// </para>
/// <para>
/// Verification operations are performed locally using the public key for efficiency.
/// </para>
/// </remarks>
internal sealed class KeyVaultRemoteRsa : RSA
{
    private readonly RSA PublicKey;
    private readonly KeyVaultCryptoClientWrapper CryptoWrapper;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyVaultRemoteRsa"/> class.
    /// </summary>
    /// <param name="publicKey">The RSA public key for verification operations.</param>
    /// <param name="cryptoWrapper">The wrapper for Key Vault cryptographic operations.</param>
    public KeyVaultRemoteRsa(RSA publicKey, KeyVaultCryptoClientWrapper cryptoWrapper)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        CryptoWrapper = cryptoWrapper ?? throw new ArgumentNullException(nameof(cryptoWrapper));
    }

    /// <inheritdoc/>
    public override int KeySize => PublicKey.KeySize;

    /// <inheritdoc/>
    /// <exception cref="CryptographicException">Thrown if private parameters are requested.</exception>
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException("Private key is not available - signing is performed remotely in Key Vault.");
        }
        return PublicKey.ExportParameters(false);
    }

    /// <inheritdoc/>
    public override void ImportParameters(RSAParameters parameters) => PublicKey.ImportParameters(parameters);

    /// <inheritdoc/>
    /// <remarks>
    /// Signing is delegated to Azure Key Vault via the CryptographyClient.
    /// </remarks>
    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        // Use the common algorithm mapper for consistent mapping
        return CryptoWrapper.SignHashWithRsa(hash, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Verification is performed locally using the public key for efficiency.
    /// </remarks>
    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        return PublicKey.VerifyHash(hash, signature, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            PublicKey.Dispose();
        }
        base.Dispose(disposing);
    }
}

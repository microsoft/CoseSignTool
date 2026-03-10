// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault.Common;

/// <summary>
/// ECDSA implementation that delegates signing to Azure Key Vault via the common wrapper.
/// </summary>
/// <remarks>
/// <para>
/// This class wraps an ECDSA public key and delegates all signing operations to Azure Key Vault
/// via the <see cref="KeyVaultCryptoClientWrapper"/>. The private key never leaves Key Vault.
/// </para>
/// <para>
/// Verification operations are performed locally using the public key for efficiency.
/// </para>
/// </remarks>
internal sealed class KeyVaultRemoteECDsa : ECDsa
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorPrivateKeyNotAvailableRemoteSigning = "Private key is not available - signing is performed remotely in Key Vault.";
        public static readonly string ErrorKeyGenerationNotSupported = "Key generation is not supported - keys must be created in Azure Key Vault.";
    }

    private readonly ECDsa PublicKey;
    private readonly KeyVaultCryptoClientWrapper CryptoWrapper;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyVaultRemoteECDsa"/> class.
    /// </summary>
    /// <param name="publicKey">The ECDSA public key for verification operations.</param>
    /// <param name="cryptoWrapper">The wrapper for Key Vault cryptographic operations.</param>
    public KeyVaultRemoteECDsa(ECDsa publicKey, KeyVaultCryptoClientWrapper cryptoWrapper)
    {
        Guard.ThrowIfNull(publicKey);
        Guard.ThrowIfNull(cryptoWrapper);

        PublicKey = publicKey;
        CryptoWrapper = cryptoWrapper;
    }

    /// <inheritdoc/>
    public override int KeySize => PublicKey.KeySize;

    /// <inheritdoc/>
    /// <exception cref="CryptographicException">Thrown if private parameters are requested.</exception>
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException(ClassStrings.ErrorPrivateKeyNotAvailableRemoteSigning);
        }
        return PublicKey.ExportParameters(false);
    }

    /// <inheritdoc/>
    public override void ImportParameters(ECParameters parameters) => PublicKey.ImportParameters(parameters);

    /// <inheritdoc/>
    /// <remarks>
    /// Signing is delegated to Azure Key Vault via the CryptographyClient.
    /// </remarks>
    public override byte[] SignHash(byte[] hash)
    {
        // Use the common algorithm mapper for consistent mapping
        return CryptoWrapper.SignHashWithEcdsa(hash);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Verification is performed locally using the public key for efficiency.
    /// </remarks>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        return PublicKey.VerifyHash(hash, signature);
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

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown - key generation must be done in Key Vault.</exception>
    public override void GenerateKey(ECCurve curve) =>
        throw new NotSupportedException(ClassStrings.ErrorKeyGenerationNotSupported);
}

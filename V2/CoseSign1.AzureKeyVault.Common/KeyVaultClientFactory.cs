// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Common;

using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;

/// <summary>
/// Factory abstraction for creating and providing Azure Key Vault SDK clients.
/// This enables dependency injection and mocking for unit tests.
/// </summary>
public interface IKeyVaultClientFactory
{
    /// <summary>
    /// Gets the Key Vault base URI.
    /// </summary>
    Uri VaultUri { get; }

    /// <summary>
    /// Gets the certificates plane client.
    /// </summary>
    CertificateClient CertificateClient { get; }

    /// <summary>
    /// Gets the secrets plane client.
    /// </summary>
    SecretClient SecretClient { get; }

    /// <summary>
    /// Gets the keys plane client.
    /// </summary>
    KeyClient KeyClient { get; }

    /// <summary>
    /// Creates a cryptography client for a specific key id.
    /// </summary>
    /// <param name="keyId">The Key Vault key identifier.</param>
    /// <returns>A cryptography client scoped to <paramref name="keyId"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="keyId"/> is null.</exception>
    CryptographyClient CreateCryptographyClient(Uri keyId);
}

/// <summary>
/// Default implementation of <see cref="IKeyVaultClientFactory"/>.
/// </summary>
public sealed class KeyVaultClientFactory : IKeyVaultClientFactory
{
    private readonly TokenCredential Credential;

    /// <inheritdoc/>
    public Uri VaultUri { get; }

    /// <inheritdoc/>
    public CertificateClient CertificateClient { get; }

    /// <inheritdoc/>
    public SecretClient SecretClient { get; }

    /// <inheritdoc/>
    public KeyClient KeyClient { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyVaultClientFactory"/> class.
    /// </summary>
    /// <param name="vaultUri">The Key Vault base URI.</param>
    /// <param name="credential">The credential used to authenticate with Key Vault.</param>
    public KeyVaultClientFactory(Uri vaultUri, TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentNullException.ThrowIfNull(credential);

        VaultUri = vaultUri;
        Credential = credential;

        CertificateClient = new CertificateClient(vaultUri, credential);
        SecretClient = new SecretClient(vaultUri, credential);
        KeyClient = new KeyClient(vaultUri, credential);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="keyId"/> is null.</exception>
    public CryptographyClient CreateCryptographyClient(Uri keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        return new CryptographyClient(keyId, Credential);
    }
}

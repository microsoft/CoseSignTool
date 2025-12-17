// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;

namespace CoseSign1.AzureKeyVault.Common;

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
    CryptographyClient CreateCryptographyClient(Uri keyId);
}

/// <summary>
/// Default implementation of <see cref="IKeyVaultClientFactory"/>.
/// </summary>
public sealed class KeyVaultClientFactory : IKeyVaultClientFactory
{
    private readonly TokenCredential Credential;

    public Uri VaultUri { get; }

    public CertificateClient CertificateClient { get; }

    public SecretClient SecretClient { get; }

    public KeyClient KeyClient { get; }

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

    public CryptographyClient CreateCryptographyClient(Uri keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        return new CryptographyClient(keyId, Credential);
    }
}
